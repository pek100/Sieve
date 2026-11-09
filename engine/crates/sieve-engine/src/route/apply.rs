//! The only code that writes routing state, and only on the engine's own
//! adapter: a route or an address takes a [`SieveLuid`], which only the
//! adapter the engine created hands out (`tun`). `CreateIpForwardEntry2` and
//! `CreateUnicastIpAddressEntry` write the active store only (the IP Helper
//! API has no persistent flag; `route -p` and `New-NetRoute` are never
//! used), so every entry goes with the adapter and none survives a reboot.
//! Law: `tests/laws/engine-network.test.ts` (no other code names a route or
//! DNS write) and the tests below (each row names the Sieve LUID).
//!
//! Every route is journalled (fsync) before it is added.

use std::net::IpAddr;

use windows::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER,
    DNS_SETTING_REGISTRATION_ENABLED, DeleteIpForwardEntry2, GetIpInterfaceEntry, GetUnicastIpAddressEntry, InitializeIpForwardEntry,
    InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
    SetInterfaceDnsSettings, SetIpInterfaceEntry,
};
use windows::Win32::Networking::WinSock::{IpDadStateDuplicate, IpDadStateInvalid, IpDadStatePreferred, IpDadStateTentative};
use windows::core::{GUID, HSTRING, PWSTR};

pub use super::capture::DNS_FIRST_METRIC;
use crate::tun::ADAPTER_GUID;
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};

use super::journal::{Deleted, Entry, Journal};
use super::prefix::Prefix;

/// The LUID of the adapter the engine created. Only `tun` makes one, from
/// the Wintun adapter it holds, so no route can name another interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SieveLuid(u64);

impl SieveLuid {
    pub(crate) fn of_created_adapter(luid: u64) -> Self {
        Self(luid)
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

pub(crate) fn sockaddr_inet(ip: IpAddr) -> SOCKADDR_INET {
    let mut s = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(v4) => {
            s.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(v4.octets()) } },
                sin_zero: [0; 8],
            };
        }
        IpAddr::V6(v6) => {
            s.Ipv6 = SOCKADDR_IN6 { sin6_family: AF_INET6, sin6_addr: IN6_ADDR { u: IN6_ADDR_0 { Byte: v6.octets() } }, ..Default::default() };
        }
    }
    s
}

/// The row for `prefix` on the engine's adapter: on-link (the next hop is
/// the unspecified address), metric 0 on top of the interface's, protocol
/// "network management" (a static route of this process).
pub fn route_row(luid: SieveLuid, prefix: Prefix) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: initialises a row this function owns.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = NET_LUID_LH { Value: luid.0 };
    row.DestinationPrefix.Prefix = sockaddr_inet(prefix.addr());
    row.DestinationPrefix.PrefixLength = prefix.length();
    row.NextHop = sockaddr_inet(if prefix.is_ipv4() { IpAddr::from([0u8; 4]) } else { IpAddr::from([0u8; 16]) });
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

fn check(code: WIN32_ERROR, what: &str) -> Result<(), String> {
    if code == NO_ERROR || code == ERROR_OBJECT_ALREADY_EXISTS { Ok(()) } else { Err(format!("{what} failed: Win32 error {}", code.0)) }
}

/// Journals the route (fsync), then adds it on the engine's adapter.
pub fn add_route(journal: &Journal, luid: SieveLuid, prefix: Prefix) -> Result<(), String> {
    journal.append(&Entry { prefix, luid: luid.0 })?;
    let row = route_row(luid, prefix);
    // SAFETY: `row` is a valid, initialised row.
    check(unsafe { CreateIpForwardEntry2(&row) }, &format!("CreateIpForwardEntry2 {prefix}"))
}

/// Deletes one route on the adapter with this LUID (the journal's entries
/// name the adapter of an earlier run, which may be gone).
pub fn delete_route(luid: u64, prefix: Prefix) -> Deleted {
    let row = route_row(SieveLuid(luid), prefix);
    // SAFETY: `row` is a valid, initialised row.
    super::classify_delete(unsafe { DeleteIpForwardEntry2(&row) }.0)
}

/// The adapter's own host address (a /32 or /128), active store only.
pub fn add_address(luid: SieveLuid, ip: IpAddr) -> Result<(), String> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: initialises a row this function owns.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = NET_LUID_LH { Value: luid.0 };
    row.Address = sockaddr_inet(ip);
    row.OnLinkPrefixLength = Prefix::host(ip).length();
    // SAFETY: `row` is a valid, initialised row.
    check(unsafe { CreateUnicastIpAddressEntry(&row) }, &format!("CreateUnicastIpAddressEntry {ip}"))
}

/// Where duplicate address detection stands for one of the adapter's addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressState {
    /// A packet may leave with it as its source.
    Preferred,
    /// Still being checked: Windows refuses it as a source (a send through the
    /// adapter's routes fails with "host unreachable").
    Tentative,
    /// Not yet set (`IpDadStateInvalid`), as right after the address was added:
    /// waited on like [`AddressState::Tentative`].
    NotYet,
    /// Another machine or adapter answers for it.
    Duplicate,
    /// It can never be used.
    Unusable(i32),
}

/// Reads the state of one of the adapter's addresses.
pub fn address_state(luid: SieveLuid, ip: IpAddr) -> Result<AddressState, String> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: initialises a row this function owns.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = NET_LUID_LH { Value: luid.0 };
    row.Address = sockaddr_inet(ip);
    // SAFETY: `row` names the address and the interface, as the call requires.
    let code = unsafe { GetUnicastIpAddressEntry(&mut row) };
    if code != NO_ERROR {
        return Err(format!("GetUnicastIpAddressEntry {ip} failed: Win32 error {}", code.0));
    }
    Ok(match row.DadState {
        state if state == IpDadStatePreferred => AddressState::Preferred,
        state if state == IpDadStateTentative => AddressState::Tentative,
        state if state == IpDadStateInvalid => AddressState::NotYet,
        state if state == IpDadStateDuplicate => AddressState::Duplicate,
        other => AddressState::Unusable(other.0),
    })
}

/// Gives the adapter [`DNS_FIRST_METRIC`] in both families, and says whether it
/// has an IPv6 interface that took it. With IPv6 off the adapter has no IPv6
/// interface; a failure to set one that exists is an error.
pub fn put_first_for_dns(luid: SieveLuid) -> Result<bool, String> {
    let mut v6 = false;
    for family in [AF_INET, AF_INET6] {
        let mut row = MIB_IPINTERFACE_ROW::default();
        // SAFETY: initialises a row this function owns.
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = family;
        row.InterfaceLuid = NET_LUID_LH { Value: luid.0 };
        // SAFETY: the row names the interface and its family, as the call requires.
        let read = unsafe { GetIpInterfaceEntry(&mut row) };
        if read != NO_ERROR {
            if family == AF_INET6 {
                continue;
            }
            return Err(format!("GetIpInterfaceEntry failed: Win32 error {}", read.0));
        }
        row.UseAutomaticMetric = false;
        row.Metric = DNS_FIRST_METRIC;
        // Left as read, the call refuses the row on IPv4.
        row.SitePrefixLength = 0;
        // SAFETY: a row read back above, changed in two fields.
        check(unsafe { SetIpInterfaceEntry(&mut row) }, "SetIpInterfaceEntry")?;
        v6 |= family == AF_INET6;
    }
    Ok(v6)
}

/// Names `server` as the DNS server of the engine's own adapter, or none, and
/// keeps Windows from registering the adapter's address in DNS. The only DNS
/// setting the engine writes, and only on its adapter's GUID ([`ADAPTER_GUID`]).
/// Windows keeps it in that interface's registry key, which it deletes when the
/// adapter is removed; after a kill the key stays, naming a server only an adapter
/// that no longer exists would use (live check of 2026-11-09), until the next
/// start or `uninstall` ([`forget_adapter_key`]). Called only while the adapter
/// exists, so it creates no key.
pub fn set_adapter_dns(server: Option<std::net::Ipv4Addr>) -> Result<(), String> {
    let text = HSTRING::from(server.map(|s| s.to_string()).unwrap_or_default());
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(DNS_SETTING_NAMESERVER | DNS_SETTING_REGISTRATION_ENABLED),
        NameServer: PWSTR(text.as_ptr().cast_mut()),
        RegistrationEnabled: 0,
        ..Default::default()
    };
    // SAFETY: `settings` and the string it points at outlive the call, which only reads them.
    check(unsafe { SetInterfaceDnsSettings(GUID::from_u128(ADAPTER_GUID), &settings) }, "SetInterfaceDnsSettings")
}

/// The interface registry key of the adapter's own GUID, under `root` (Tcpip or Tcpip6).
fn adapter_key(root: &str) -> String {
    let g = ADAPTER_GUID;
    let guid = format!("{{{:08x}-{:04x}-{:04x}-{:04x}-{:012x}}}", g >> 96, (g >> 80) & 0xffff, (g >> 64) & 0xffff, (g >> 48) & 0xffff, g & 0xffff_ffff_ffff);
    format!(r"SYSTEM\CurrentControlSet\Services\{root}\Parameters\Interfaces\{guid}")
}

/// Deletes what [`set_adapter_dns`] left in the registry when no adapter with the
/// engine's GUID exists (after a kill, Windows never removed it): that GUID's
/// interface key in both families, and nothing else. With the adapter there, its
/// key is Windows' own and stays.
pub fn forget_adapter_key() -> Result<String, String> {
    use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
    use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceGuidToLuid;
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RegDeleteTreeW};
    let mut luid = NET_LUID_LH::default();
    // SAFETY: both pointers are this frame's.
    if unsafe { ConvertInterfaceGuidToLuid(&GUID::from_u128(ADAPTER_GUID), &mut luid) } == NO_ERROR {
        return Ok("the adapter exists, its key is Windows'".into());
    }
    let mut deleted = 0;
    for root in ["Tcpip", "Tcpip6"] {
        // SAFETY: a NUL-terminated path; HKLM is predefined.
        match unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, &HSTRING::from(adapter_key(root))) } {
            NO_ERROR => deleted += 1,
            ERROR_FILE_NOT_FOUND => {}
            other => return Err(format!("{root} key: Win32 error {}", other.0)),
        }
    }
    Ok(format!("{deleted} key{} deleted", if deleted == 1 { "" } else { "s" }))
}

/// The start-up and off-path cleanup: every route on an adapter named
/// "Sieve" and every journalled route, then the journal emptied (plan 1.6.3),
/// and the adapter's leftover DNS key ([`forget_adapter_key`]).
pub fn clear_stale(journal: &Journal) -> String {
    let named = super::delete_sieve_routes();
    let replay = journal.replay(|e| delete_route(e.luid, e.prefix));
    format!(
        "routes on \"Sieve\": {}; journal: {}; DNS key: {}",
        match named {
            Ok(r) => r.summary(),
            Err(e) => format!("FAILED, {e}"),
        },
        match replay {
            Ok(r) => format!("{}{}, {} unreadable lines", if r.failed > 0 { "FAILED, " } else { "" }, r.summary(), r.skipped),
            Err(e) => format!("FAILED, {e}"),
        },
        forget_adapter_key().unwrap_or_else(|e| format!("FAILED, {e}"))
    )
}

/// Asks the DNS Client for `name` (fully qualified) bypassing its cache, hosts
/// file, LLMNR and NetBIOS, and returns its status (0, or `DNS_INFO_NO_RECORDS`
/// 9501 for NODATA). Blocks until the DNS Client returns: call it off the runtime.
pub fn ask_dns_client(name: &str) -> i32 {
    use windows::Win32::NetworkManagement::Dns::{
        DNS_QUERY_BYPASS_CACHE, DNS_QUERY_NO_HOSTS_FILE, DNS_QUERY_NO_MULTICAST, DNS_QUERY_NO_NETBT, DNS_RECORDA, DNS_TYPE_A, DnsFree, DnsFreeRecordList, DnsQuery_W,
    };
    let mut records: *mut DNS_RECORDA = std::ptr::null_mut();
    let options = DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE | DNS_QUERY_NO_MULTICAST | DNS_QUERY_NO_NETBT;
    // SAFETY: a NUL-terminated name; the result list is freed below.
    let status = unsafe { DnsQuery_W(&HSTRING::from(name), DNS_TYPE_A, options, None, &mut records, None) };
    if !records.is_null() {
        // SAFETY: a list DnsQuery_W allocated, freed once.
        unsafe { DnsFree(Some(records.cast()), DnsFreeRecordList) };
    }
    i32::try_from(status.0).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one key the cleanup may delete: the adapter's own GUID, either family.
    #[test]
    fn the_leftover_key_is_the_adapters_own_guid_only() {
        assert_eq!(adapter_key("Tcpip"), r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{5e7e5e7e-51e7-4e00-8a11-5e7e00000003}");
        assert!(adapter_key("Tcpip6").starts_with(r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{5e7e5e7e-"));
    }

    /// Every route the engine writes names the Sieve adapter's LUID, is
    /// on-link, and is a plain static route (no persistent store exists in
    /// this API; the law checks no other writer exists).
    #[test]
    fn a_route_row_names_the_sieve_adapter_and_nothing_else() {
        let luid = SieveLuid::of_created_adapter(0x0035_0000_0100_0000);
        for p in ["0.0.0.0/5", "192.168.7.1/32", "2000::/4"] {
            let prefix: Prefix = p.parse().unwrap();
            let row = route_row(luid, prefix);
            // SAFETY: reading the union's only field.
            assert_eq!(unsafe { row.InterfaceLuid.Value }, luid.value(), "{p}");
            assert_eq!(row.InterfaceIndex, 0, "the LUID decides the interface, {p}");
            assert_eq!(row.DestinationPrefix.PrefixLength, prefix.length());
            assert_eq!(super::super::table::read::inet_ip(&row.DestinationPrefix.Prefix), Some(prefix.addr()));
            assert!(super::super::table::read::inet_ip(&row.NextHop).is_some_and(|ip| ip.is_unspecified()), "on-link, {p}");
            assert_eq!(row.Protocol, MIB_IPPROTO_NETMGMT);
            assert_eq!(row.Metric, 0);
        }
    }
}
