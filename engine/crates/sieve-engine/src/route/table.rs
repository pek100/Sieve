//! The machine's adapters and forwarding table as plain data, so the route
//! plan, the pinning choice and the coexistence check are pure functions
//! tested on fixture tables (`engine/crates/sieve-engine/fixtures/net-*.json`).
//! The Windows readers (`read`) fill the same shapes, read only.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::prefix::Prefix;
use super::is_sieve_interface;

/// IANA ifType values the engine tells apart (ipifcons.h).
pub mod if_type {
    pub const ETHERNET: u32 = 6;
    pub const PPP: u32 = 23;
    pub const SOFTWARE_LOOPBACK: u32 = 24;
    /// Wintun, WireGuard-NT, OpenVPN DCO and most user-mode TUN drivers.
    pub const PROP_VIRTUAL: u32 = 53;
    pub const IEEE80211: u32 = 71;
    pub const TUNNEL: u32 = 131;
}

/// One adapter (GetAdaptersAddresses).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Adapter {
    pub index: u32,
    pub luid: u64,
    pub alias: String,
    pub description: String,
    pub if_type: u32,
    /// Operational status up.
    pub up: bool,
    /// Unicast addresses with their on-link prefix length (`192.168.7.20/24`
    /// is stored as address 192.168.7.20 and length 24).
    pub addresses: Vec<AddressOnLink>,
    /// DNS servers in force for the adapter.
    pub dns: Vec<IpAddr>,
    /// The adapter's connection-specific suffix and search list, read only,
    /// for DNS's split-horizon rules (plan 1.4).
    #[serde(default)]
    pub dns_suffixes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressOnLink {
    pub ip: IpAddr,
    pub len: u8,
}

impl AddressOnLink {
    pub fn on_link(&self) -> Option<Prefix> {
        Prefix::new(self.ip, self.len)
    }
}

/// One forwarding-table row (GetIpForwardTable2), with the metric Windows
/// compares: the route's plus its interface's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRow {
    pub dest: Prefix,
    pub if_index: u32,
    /// None for an on-link route.
    pub next_hop: Option<IpAddr>,
    pub metric: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetTables {
    pub adapters: Vec<Adapter>,
    pub routes: Vec<RouteRow>,
    /// The machine's own suffixes, read only: the primary DNS suffix (the one in
    /// force and the one set for the next start) and the global search list, the
    /// policy's first. The DNS Client appends them to a short name on every
    /// network, so a domain's names are asked under them (`dns::upstream::split_rules`).
    #[serde(default)]
    pub global_suffixes: Vec<String>,
}

impl NetTables {
    pub fn adapter(&self, index: u32) -> Option<&Adapter> {
        self.adapters.iter().find(|a| a.index == index)
    }

    /// Adapters that are up and not Sieve's own (by name).
    pub fn others(&self) -> impl Iterator<Item = &Adapter> {
        self.adapters.iter().filter(|a| a.up && !is_sieve_interface(&a.alias))
    }

    /// Routes on `adapter`.
    pub fn routes_on(&self, adapter: &Adapter) -> impl Iterator<Item = &RouteRow> {
        self.routes.iter().filter(move |r| r.if_index == adapter.index)
    }

    /// These tables without Sieve's adapter and its routes: the network as it
    /// would be without Sieve, so Sieve's own route changes do not look like a
    /// network change.
    pub fn outside_sieve(&self) -> NetTables {
        let adapters: Vec<Adapter> = self.adapters.iter().filter(|a| !is_sieve_interface(&a.alias)).cloned().collect();
        let routes = self.routes.iter().filter(|r| adapters.iter().any(|a| a.index == r.if_index)).cloned().collect();
        NetTables { adapters, routes, global_suffixes: self.global_suffixes.clone() }
    }

    /// The adapter Windows sends through: the other up adapter with the
    /// lowest-metric IPv4 default route, else IPv6. The tables' order breaks a tie.
    pub fn default_adapter(&self) -> Option<&Adapter> {
        let best = |v4: bool| {
            self.others()
                .filter_map(|a| self.routes_on(a).filter(|r| r.dest.length() == 0 && r.dest.is_ipv4() == v4).map(|r| r.metric).min().map(|m| (m, a)))
                .min_by_key(|(m, _)| *m)
                .map(|(_, a)| a)
        };
        best(true).or_else(|| best(false))
    }

    /// True when some up adapter other than Sieve holds a default route of this family.
    pub fn has_default(&self, v4: bool) -> bool {
        self.others().any(|a| self.routes_on(a).any(|r| r.dest.length() == 0 && r.dest.is_ipv4() == v4))
    }
}

/// The Windows readers, read only.
#[cfg(windows)]
pub mod read {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetIpForwardTable2,
        GetIpInterfaceEntry, IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET};

    use super::super::prefix::Prefix;
    use super::{AddressOnLink, Adapter, NetTables, RouteRow};

    /// A SOCKADDR as an address, for the two families.
    ///
    /// # Safety
    /// `sa` is null or points at a SOCKADDR_IN or SOCKADDR_IN6 as its family says.
    unsafe fn sockaddr_ip(sa: *const SOCKADDR) -> Option<IpAddr> {
        if sa.is_null() {
            return None;
        }
        // SAFETY: per the contract, the family field tells which struct this is.
        unsafe {
            match (*sa).sa_family {
                AF_INET => Some(IpAddr::V4(Ipv4Addr::from((*sa.cast::<SOCKADDR_IN>()).sin_addr.S_un.S_addr.to_ne_bytes()))),
                AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from((*sa.cast::<SOCKADDR_IN6>()).sin6_addr.u.Byte))),
                _ => None,
            }
        }
    }

    pub(crate) fn inet_ip(s: &SOCKADDR_INET) -> Option<IpAddr> {
        // SAFETY: SOCKADDR_INET is a union whose family field is common to both arms.
        unsafe { sockaddr_ip((&raw const *s).cast::<SOCKADDR>()) }
    }

    fn wide(p: windows::core::PWSTR) -> String {
        // SAFETY: Windows hands NUL-terminated strings or null.
        if p.is_null() { String::new() } else { unsafe { p.to_string() }.unwrap_or_default() }
    }

    pub fn adapters() -> Result<Vec<Adapter>, String> {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        let mut size: u32 = 16 * 1024;
        for _ in 0..4 {
            let mut buf = vec![0u64; (size as usize).div_ceil(8)];
            let head = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            // SAFETY: `buf` holds `size` bytes, aligned for the struct.
            let code = unsafe { GetAdaptersAddresses(u32::from(AF_UNSPEC.0), flags, None, Some(head), &mut size) };
            if code == ERROR_BUFFER_OVERFLOW.0 {
                continue;
            }
            if code != NO_ERROR.0 {
                return Err(format!("GetAdaptersAddresses: Win32 error {code}"));
            }
            let mut out = Vec::new();
            let mut cur = head.cast_const();
            // SAFETY: a linked list Windows wrote into `buf`, alive until the end of this loop.
            unsafe {
                while !cur.is_null() {
                    let a = &*cur;
                    let mut addresses = Vec::new();
                    let mut u = a.FirstUnicastAddress;
                    while !u.is_null() {
                        if let Some(ip) = sockaddr_ip((*u).Address.lpSockaddr) {
                            addresses.push(AddressOnLink { ip, len: (*u).OnLinkPrefixLength });
                        }
                        u = (*u).Next;
                    }
                    let mut dns = Vec::new();
                    let mut d = a.FirstDnsServerAddress;
                    while !d.is_null() {
                        if let Some(ip) = sockaddr_ip((*d).Address.lpSockaddr) {
                            dns.push(ip);
                        }
                        d = (*d).Next;
                    }
                    let mut dns_suffixes = vec![wide(a.DnsSuffix)];
                    let mut s = a.FirstDnsSuffix;
                    while !s.is_null() {
                        // A fixed array, NUL-terminated within.
                        let text = &(*s).String;
                        let len = text.iter().position(|c| *c == 0).unwrap_or(text.len());
                        dns_suffixes.push(String::from_utf16_lossy(&text[..len]));
                        s = (*s).Next;
                    }
                    dns_suffixes.retain(|suffix| !suffix.is_empty());
                    dns_suffixes.dedup();
                    out.push(Adapter {
                        index: if a.Anonymous1.Anonymous.IfIndex != 0 { a.Anonymous1.Anonymous.IfIndex } else { a.Ipv6IfIndex },
                        luid: a.Luid.Value,
                        alias: wide(a.FriendlyName),
                        description: wide(a.Description),
                        if_type: a.IfType,
                        up: a.OperStatus == IfOperStatusUp,
                        addresses,
                        dns,
                        dns_suffixes,
                    });
                    cur = a.Next;
                }
            }
            return Ok(out);
        }
        Err("GetAdaptersAddresses: the table kept growing".into())
    }

    /// An adapter's interface metric in one family, or None when it has no
    /// interface of that family.
    pub fn interface_metric_of(luid: u64, v4: bool) -> Option<u32> {
        let mut row = MIB_IPINTERFACE_ROW {
            Family: if v4 { AF_INET } else { AF_INET6 },
            InterfaceLuid: windows::Win32::NetworkManagement::Ndis::NET_LUID_LH { Value: luid },
            ..Default::default()
        };
        // SAFETY: `row` is initialised with the family and LUID the call needs.
        (unsafe { GetIpInterfaceEntry(&mut row) } == NO_ERROR).then_some(row.Metric)
    }

    fn interface_metric(luid: windows::Win32::NetworkManagement::Ndis::NET_LUID_LH, family: u16) -> u32 {
        let mut row = MIB_IPINTERFACE_ROW { Family: windows::Win32::Networking::WinSock::ADDRESS_FAMILY(family), InterfaceLuid: luid, ..Default::default() };
        // SAFETY: `row` is initialised with the family and LUID the call needs.
        if unsafe { GetIpInterfaceEntry(&mut row) } == NO_ERROR { row.Metric } else { 0 }
    }

    pub fn routes() -> Result<Vec<RouteRow>, String> {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        // SAFETY: Windows allocates the table; it is freed with FreeMibTable below.
        let code = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
        if code != NO_ERROR || table.is_null() {
            return Err(format!("GetIpForwardTable2: {code:?}"));
        }
        let mut out = Vec::new();
        // SAFETY: `table` is valid until FreeMibTable; NumEntries rows follow.
        unsafe {
            let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
            for r in rows {
                let (Some(dest), next) = (inet_ip(&r.DestinationPrefix.Prefix), inet_ip(&r.NextHop)) else { continue };
                let Some(dest) = Prefix::new(dest, r.DestinationPrefix.PrefixLength) else { continue };
                let family = if dest.is_ipv4() { AF_INET.0 } else { AF_INET6.0 };
                out.push(RouteRow {
                    dest,
                    if_index: r.InterfaceIndex,
                    next_hop: next.filter(|ip| !ip.is_unspecified()),
                    metric: r.Metric.saturating_add(interface_metric(r.InterfaceLuid, family)),
                });
            }
            FreeMibTable(table.cast());
        }
        Ok(out)
    }

    /// One REG_SZ value under HKLM, or None when it is absent or empty.
    fn hklm_text(path: &str, name: &str) -> Option<String> {
        use windows::Win32::Foundation::ERROR_SUCCESS;
        use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
        use windows::core::HSTRING;
        const CHARS: usize = 2_048;
        let mut value = vec![0u16; CHARS];
        let mut bytes = (CHARS * 2) as u32;
        // SAFETY: the buffer and its byte length are this frame's.
        let status = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, &HSTRING::from(path), &HSTRING::from(name), RRF_RT_REG_SZ, None, Some(value.as_mut_ptr().cast()), Some(&mut bytes)) };
        if status != ERROR_SUCCESS {
            return None;
        }
        let text = String::from_utf16_lossy(&value[..(bytes as usize / 2).saturating_sub(1)]);
        Some(text).filter(|t| !t.trim().is_empty())
    }

    /// The machine's suffixes (`NetTables::global_suffixes`), read only: the
    /// policy's search list and primary suffix, then the local ones.
    pub fn global_suffixes() -> Vec<String> {
        const POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
        const TCPIP: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
        let values = [(POLICY, "SearchList"), (POLICY, "PrimaryDnsSuffix"), (TCPIP, "SearchList"), (TCPIP, "Domain"), (TCPIP, "NV Domain")];
        crate::dns::upstream::suffix_list(values.iter().filter_map(|(path, name)| hklm_text(path, name)))
    }

    pub fn tables() -> Result<NetTables, String> {
        Ok(NetTables { adapters: adapters()?, routes: routes()?, global_suffixes: global_suffixes() })
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::NetTables;

    /// This machine's tables on 2026-10-18 (read only), addresses moved to
    /// documentation ranges: Wi-Fi with both defaults, Hyper-V and
    /// VirtualBox host-only adapters up without one.
    pub const HOME: &str = include_str!("../../fixtures/net-home.json");
    /// Added to HOME: a full-tunnel VPN (the /1s of both families on a
    /// PROP_VIRTUAL adapter) and its endpoint's host route on Wi-Fi.
    pub const VPN_FULL: &str = include_str!("../../fixtures/net-vpn-full.json");
    /// Added to HOME: a split-tunnel VPN (a private /16 and a public /24), and
    /// a TAP adapter that is down although it holds a default route.
    pub const VPN_SPLIT: &str = include_str!("../../fixtures/net-vpn-split.json");
    /// Added to HOME: Sieve's adapter up with some of its routes in place.
    pub const SIEVE_UP: &str = include_str!("../../fixtures/net-sieve-up.json");

    /// HOME, or HOME with the adapters and routes of `extra` added.
    pub fn load(extra: &str) -> NetTables {
        let mut t: NetTables = serde_json::from_str(HOME).expect("home fixture parses");
        if extra != HOME {
            let more: NetTables = serde_json::from_str(extra).expect("fixture parses");
            t.adapters.extend(more.adapters);
            t.routes.extend(more.routes);
        }
        t
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;

    #[test]
    fn every_fixture_parses_and_home_has_both_defaults_on_wifi() {
        for f in [HOME, VPN_FULL, VPN_SPLIT, SIEVE_UP] {
            let t = load(f);
            assert!(!t.adapters.is_empty() && !t.routes.is_empty());
        }
        let home = load(HOME);
        assert!(home.has_default(true) && home.has_default(false));
        assert!(home.others().all(|a| a.alias != "Sieve"));
        assert!(load(SIEVE_UP).adapters.iter().any(|a| a.alias == "Sieve"));
    }

    #[test]
    fn sieves_own_adapter_and_routes_are_no_network_change_and_old_fixtures_parse() {
        assert_eq!(load(SIEVE_UP).outside_sieve(), load(HOME).outside_sieve());
        assert_ne!(load(VPN_SPLIT).outside_sieve(), load(HOME).outside_sieve());
        assert!(load(HOME).adapters.iter().all(|a| a.dns_suffixes.is_empty()), "no fixture states suffixes");
    }
}
