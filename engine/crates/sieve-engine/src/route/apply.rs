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
    DeleteIpForwardEntry2, GetIpInterfaceEntry, GetUnicastIpAddressEntry, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
    InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetInterfaceDnsSettings,
    SetIpInterfaceEntry,
};
use windows::Win32::Networking::WinSock::{IpDadStatePreferred, IpDadStateTentative};
use windows::core::{GUID, HSTRING, PWSTR};

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
        other => AddressState::Unusable(other.0),
    })
}

/// The interface metric that makes the adapter the DNS Client's first network
/// (`route::capture`). Routes are unaffected: none of the engine's has the same
/// prefix as a route of another adapter.
pub const DNS_FIRST_METRIC: u32 = 1;

/// Gives the adapter [`DNS_FIRST_METRIC`] in both families. IPv6 is best effort:
/// with IPv6 off the adapter has no IPv6 interface.
pub fn put_first_for_dns(luid: SieveLuid) -> Result<(), String> {
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
    }
    Ok(())
}

/// Names `server` as the DNS server of the engine's own adapter, or none. The only
/// DNS setting the engine writes, and only on its adapter's GUID ([`ADAPTER_GUID`]).
/// Windows keeps it in that interface's registry key, which it deletes when the
/// adapter is removed; after a kill the key stays until the next clean removal, and
/// names a server only an adapter that no longer exists would use (live check of
/// 2026-11-09). Called only while the adapter exists, so it creates no key.
pub fn set_adapter_dns(server: Option<std::net::Ipv4Addr>) -> Result<(), String> {
    let text = HSTRING::from(server.map(|s| s.to_string()).unwrap_or_default());
    let settings = DNS_INTERFACE_SETTINGS { Version: DNS_INTERFACE_SETTINGS_VERSION1, Flags: u64::from(DNS_SETTING_NAMESERVER), NameServer: PWSTR(text.as_ptr().cast_mut()), ..Default::default() };
    // SAFETY: `settings` and the string it points at outlive the call, which only reads them.
    check(unsafe { SetInterfaceDnsSettings(GUID::from_u128(ADAPTER_GUID), &settings) }, "SetInterfaceDnsSettings")
}

/// The start-up and off-path cleanup: every route on an adapter named
/// "Sieve" and every journalled route, then the journal emptied (plan 1.6.3).
pub fn clear_stale(journal: &Journal) -> String {
    let named = super::delete_sieve_routes();
    let replay = journal.replay(|e| delete_route(e.luid, e.prefix));
    format!(
        "routes on \"Sieve\": {}; journal: {}",
        match named {
            Ok(r) => r.summary(),
            Err(e) => format!("FAILED, {e}"),
        },
        match replay {
            Ok(r) => format!("{}{}, {} unreadable lines", if r.failed > 0 { "FAILED, " } else { "" }, r.summary(), r.skipped),
            Err(e) => format!("FAILED, {e}"),
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
