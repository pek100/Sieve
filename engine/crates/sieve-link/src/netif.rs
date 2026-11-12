//! The hub's own network, read from the operating system: every interface
//! address with its on-link prefix length, the gateways, and the destination
//! of every non-default route. The hub denies all of it to devices by default
//! (`local_net`), so a device cannot reach the hub itself or the machines
//! around it:
//!
//! - each interface address is the hub itself (`LocalNet::own`);
//! - each on-link prefix, each gateway, and each routed prefix (a sibling
//!   VLAN, a VPN subnet, a docker bridge) is the hub's LAN;
//! - so is the IPv6 site prefix around each global IPv6 address, a /56 by
//!   default (`DEFAULT_V6_SITE_PREFIX`): home routers hand out a /56 and put
//!   sibling networks in other /64s of it, and some networks give each host
//!   a /128 with no on-link prefix at all. The owner can narrow it
//!   (`sieve-hub lan v6-prefix 64`).
//!
//! Routes wider than a /8 (IPv4) or a /32 (IPv6) are skipped: VPNs route
//! 0.0.0.0/1 and 128.0.0.0/1, or 2000::/3, to replace the default route, and
//! taking those would deny the whole internet.
//!
//! Read with `GetAdaptersAddresses` and `GetIpForwardTable2` on Windows,
//! `getifaddrs` on Unix plus `/proc/net/route` and `/proc/net/ipv6_route` on
//! Linux (other Unix systems: no route table is read, see `unix_routes`). The
//! hub reads it at start-up and again every `HubConfig::lan_refresh_every`; a
//! block that disappears stays denied for `HOLD` (10 minutes) so a network
//! change cannot open a gap between two reads (`Held`). Tests feed a fixed
//! list through `InterfaceSource`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::rules::{Cidr, LocalNet};

/// The IPv6 site prefix denied around each global IPv6 address by default.
pub const DEFAULT_V6_SITE_PREFIX: u8 = 56;
/// The range the owner may set the site prefix to.
pub const V6_SITE_PREFIX_RANGE: std::ops::RangeInclusive<u8> = 32..=128;
/// How long a block stays denied after it was last seen.
pub const HOLD: Duration = Duration::from_secs(600);
/// Routes wider than these are not taken (they stand in for the default route).
const WIDEST_ROUTE_V4: u8 = 8;
const WIDEST_ROUTE_V6: u8 = 32;

/// One address on one of the hub's interfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IfAddr {
    pub addr: IpAddr,
    /// The on-link prefix length (the subnet the address sits in).
    pub prefix: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostNet {
    pub addrs: Vec<IfAddr>,
    pub gateways: Vec<IpAddr>,
    /// Destination prefixes of the route table (default routes included;
    /// `local_net` drops them).
    pub routes: Vec<Cidr>,
}

/// Where the hub's interface list comes from.
pub trait InterfaceSource: Send + Sync {
    fn snapshot(&self) -> io::Result<HostNet>;
}

/// The operating system's interface list.
#[derive(Debug, Default)]
pub struct SystemInterfaces;

impl InterfaceSource for SystemInterfaces {
    fn snapshot(&self) -> io::Result<HostNet> {
        system_snapshot()
    }
}

/// A fixed list (tests).
#[derive(Debug, Default, Clone)]
pub struct FixedInterfaces(pub HostNet);

impl InterfaceSource for FixedInterfaces {
    fn snapshot(&self) -> io::Result<HostNet> {
        Ok(self.0.clone())
    }
}

/// Reads the list and refuses an empty one: a hub with no addresses at all
/// has not been read correctly, and the hub fails closed on that.
pub fn detect(src: &dyn InterfaceSource) -> io::Result<HostNet> {
    let net = src.snapshot()?;
    if net.addrs.is_empty() {
        return Err(io::Error::other("no interface addresses were found"));
    }
    Ok(net)
}

fn push(out: &mut Vec<Cidr>, c: Cidr) {
    if !out.contains(&c) {
        out.push(c);
    }
}

/// A global unicast IPv6 address (2000::/3).
fn global_v6(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.segments()[0] & 0xe000 == 0x2000)
}

/// What to deny (see the module docs). A prefix of 0 (seen on some tunnel
/// adapters) would deny the whole internet, so only the address itself is
/// taken from it; so are routes wider than a /8 or /32.
pub fn local_net(net: &HostNet, v6_site_prefix: u8) -> LocalNet {
    let mut out = LocalNet::default();
    for a in &net.addrs {
        let ip = a.addr.to_canonical();
        if ip.is_unspecified() {
            continue;
        }
        let max = if ip.is_ipv4() { 32 } else { 128 };
        push(&mut out.own, Cidr::host(ip));
        let p = a.prefix.min(max);
        if p > 0 && p < max {
            push(&mut out.lan, Cidr::new(ip, p));
        }
        let site = v6_site_prefix.clamp(*V6_SITE_PREFIX_RANGE.start(), *V6_SITE_PREFIX_RANGE.end());
        if global_v6(ip) && site < 128 {
            push(&mut out.lan, Cidr::new(ip, site));
        }
    }
    for g in &net.gateways {
        let ip = g.to_canonical();
        if !ip.is_unspecified() {
            push(&mut out.lan, Cidr::host(ip));
        }
    }
    for r in &net.routes {
        let widest = if r.addr.is_ipv4() { WIDEST_ROUTE_V4 } else { WIDEST_ROUTE_V6 };
        if r.prefix >= widest && !r.addr.is_unspecified() {
            push(&mut out.lan, Cidr::new(r.addr, r.prefix));
        }
    }
    out
}

/// Blocks seen recently: a block that vanishes from a read stays denied
/// until `hold` has passed since it was last seen.
#[derive(Debug, Default)]
pub struct Held {
    lan: Vec<(Cidr, Instant)>,
    own: Vec<(Cidr, Instant)>,
}

impl Held {
    /// Merges a fresh read and returns what is denied now.
    pub fn update(&mut self, fresh: &LocalNet, now: Instant, hold: Duration) -> LocalNet {
        fn merge(held: &mut Vec<(Cidr, Instant)>, fresh: &[Cidr], now: Instant, hold: Duration) -> Vec<Cidr> {
            for c in fresh {
                match held.iter_mut().find(|(h, _)| h == c) {
                    Some(e) => e.1 = now,
                    None => held.push((*c, now)),
                }
            }
            held.retain(|(_, seen)| now.saturating_duration_since(*seen) < hold);
            held.iter().map(|(c, _)| *c).collect()
        }
        LocalNet { lan: merge(&mut self.lan, &fresh.lan, now, hold), own: merge(&mut self.own, &fresh.own, now, hold) }
    }
}

/// Parses a raw `sockaddr` (Windows layout: family u16 at offset 0).
#[cfg(windows)]
fn parse_sockaddr(b: &[u8]) -> Option<IpAddr> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    if b.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([b[0], b[1]]);
    if family == AF_INET && b.len() >= 8 {
        Some(IpAddr::V4(Ipv4Addr::new(b[4], b[5], b[6], b[7])))
    } else if family == AF_INET6 && b.len() >= 24 {
        let mut a = [0u8; 16];
        a.copy_from_slice(&b[8..24]);
        Some(IpAddr::V6(Ipv6Addr::from(a)))
    } else {
        None
    }
}

#[cfg(windows)]
fn system_snapshot() -> io::Result<HostNet> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_UNSPEC, SOCKET_ADDRESS};

    // SAFETY (whole function): the buffer is owned, 8-byte aligned and as
    // large as the call says it needs; every pointer walked was written by
    // GetAdaptersAddresses into that buffer and is null-checked; each
    // sockaddr is read only within the length the API gives for it.
    unsafe fn ip_of(sa: &SOCKET_ADDRESS) -> Option<IpAddr> {
        if sa.lpSockaddr.is_null() || sa.iSockaddrLength <= 0 {
            return None;
        }
        let b = unsafe { std::slice::from_raw_parts(sa.lpSockaddr as *const u8, sa.iSockaddrLength as usize) };
        parse_sockaddr(b)
    }

    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME;
    let mut size: u32 = 32 * 1024;
    for _ in 0..5 {
        let mut buf: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
        let head = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let rc = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), head, &mut size) };
        if rc == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if rc == ERROR_NO_DATA {
            return Ok(HostNet::default());
        }
        if rc != NO_ERROR {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let mut net = HostNet::default();
        let mut a = head as *const IP_ADAPTER_ADDRESSES_LH;
        while !a.is_null() {
            let ad = unsafe { &*a };
            let mut u = ad.FirstUnicastAddress as *const windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH;
            while !u.is_null() {
                let ua = unsafe { &*u };
                if let Some(ip) = unsafe { ip_of(&ua.Address) } {
                    net.addrs.push(IfAddr { addr: ip, prefix: ua.OnLinkPrefixLength });
                }
                u = ua.Next;
            }
            let mut g = ad.FirstGatewayAddress as *const windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_GATEWAY_ADDRESS_LH;
            while !g.is_null() {
                let ga = unsafe { &*g };
                if let Some(ip) = unsafe { ip_of(&ga.Address) } {
                    net.gateways.push(ip);
                }
                g = ga.Next;
            }
            a = ad.Next;
        }
        drop(buf);
        net.routes = windows_routes()?;
        return Ok(net);
    }
    Err(io::Error::other("the adapter list kept growing while it was read"))
}

/// The destination prefix of every route (IPv4 and IPv6), read-only.
#[cfg(windows)]
fn windows_routes() -> io::Result<Vec<Cidr>> {
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2};
    use windows_sys::Win32::Networking::WinSock::{AF_UNSPEC, SOCKADDR_INET};

    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: the API allocates the table and stores its pointer in `table`;
    // it is freed with FreeMibTable below, once, on every path.
    let rc = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if rc != NO_ERROR {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    if table.is_null() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    // SAFETY: `table` points at a MIB_IPFORWARD_TABLE2 whose `Table` array has
    // `NumEntries` rows (a C flexible array); each row's prefix is a
    // SOCKADDR_INET read only within its own size.
    unsafe {
        let n = (*table).NumEntries as usize;
        let rows = std::ptr::addr_of!((*table).Table) as *const MIB_IPFORWARD_ROW2;
        for i in 0..n {
            let row = &*rows.add(i);
            let p = &row.DestinationPrefix;
            let b = std::slice::from_raw_parts(&p.Prefix as *const SOCKADDR_INET as *const u8, std::mem::size_of::<SOCKADDR_INET>());
            if let Some(ip) = parse_sockaddr(b) {
                out.push(Cidr::new(ip, p.PrefixLength));
            }
        }
        FreeMibTable(table as *const core::ffi::c_void);
    }
    Ok(out)
}

#[cfg(unix)]
fn system_snapshot() -> io::Result<HostNet> {
    /// SAFETY: `sa` is null or points at a sockaddr from getifaddrs, whose
    /// family says which struct it is.
    unsafe fn ip_of(sa: *const libc::sockaddr) -> Option<IpAddr> {
        if sa.is_null() {
            return None;
        }
        match unsafe { (*sa).sa_family } as i32 {
            libc::AF_INET => {
                let s = unsafe { &*(sa as *const libc::sockaddr_in) };
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(s.sin_addr.s_addr))))
            }
            libc::AF_INET6 => {
                let s = unsafe { &*(sa as *const libc::sockaddr_in6) };
                Some(IpAddr::V6(Ipv6Addr::from(s.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
    fn mask_len(m: IpAddr) -> u8 {
        match m {
            IpAddr::V4(v) => u32::from(v).leading_ones() as u8,
            IpAddr::V6(v) => u128::from(v).leading_ones() as u8,
        }
    }

    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `ifap` with a list we free below.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut net = HostNet::default();
    let mut cur = ifap as *const libc::ifaddrs;
    while !cur.is_null() {
        // SAFETY: a node of the list getifaddrs returned, not yet freed.
        let ifa = unsafe { &*cur };
        if let Some(ip) = unsafe { ip_of(ifa.ifa_addr) } {
            let max = if ip.is_ipv4() { 32 } else { 128 };
            // A netmask of the other family (or none) gives no prefix: deny the
            // address alone rather than guess.
            let prefix = unsafe { ip_of(ifa.ifa_netmask) }.filter(|m| m.is_ipv4() == ip.is_ipv4()).map(mask_len).unwrap_or(max);
            net.addrs.push(IfAddr { addr: ip, prefix });
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: the list from getifaddrs above, freed once.
    unsafe { libc::freeifaddrs(ifap) };
    let (gateways, routes) = unix_routes();
    net.gateways = gateways;
    net.routes = routes;
    Ok(net)
}

/// Parses `/proc/net/route` (IPv4): `(gateways, destination prefixes)`.
/// Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask ...; each
/// address is the raw big-endian word printed as a native-endian integer.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_route(t: &str) -> (Vec<IpAddr>, Vec<Cidr>) {
    let (mut gws, mut routes) = (Vec::new(), Vec::new());
    let word = |s: &str| u32::from_str_radix(s, 16).ok().map(|w| Ipv4Addr::from(w.to_ne_bytes()));
    for line in t.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if let Some(g) = f.get(2).and_then(|g| word(g))
            && !g.is_unspecified()
        {
            gws.push(IpAddr::V4(g));
        }
        if let (Some(d), Some(m)) = (f.get(1).and_then(|d| word(d)), f.get(7).and_then(|m| word(m))) {
            routes.push(Cidr::new(IpAddr::V4(d), u32::from(m).leading_ones() as u8));
        }
    }
    (gws, routes)
}

/// Parses `/proc/net/ipv6_route`: dest plen src plen next_hop metric refcnt
/// use flags iface, addresses as 32 hex digits.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_ipv6_route(t: &str) -> (Vec<IpAddr>, Vec<Cidr>) {
    let (mut gws, mut routes) = (Vec::new(), Vec::new());
    for line in t.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if let Some(g) = f.get(4).and_then(|g| u128::from_str_radix(g, 16).ok())
            && g != 0
        {
            gws.push(IpAddr::V6(Ipv6Addr::from(g)));
        }
        if let (Some(d), Some(p)) = (f.first().and_then(|d| u128::from_str_radix(d, 16).ok()), f.get(1).and_then(|p| u8::from_str_radix(p, 16).ok())) {
            routes.push(Cidr::new(IpAddr::V6(Ipv6Addr::from(d)), p));
        }
    }
    (gws, routes)
}

/// Linux: the gateways and destinations of the main routing tables
/// (read-only /proc files).
#[cfg(target_os = "linux")]
fn unix_routes() -> (Vec<IpAddr>, Vec<Cidr>) {
    let (mut gws, mut routes) = (Vec::new(), Vec::new());
    if let Ok(t) = std::fs::read_to_string("/proc/net/route") {
        let (g, r) = parse_proc_route(&t);
        gws.extend(g);
        routes.extend(r);
    }
    if let Ok(t) = std::fs::read_to_string("/proc/net/ipv6_route") {
        let (g, r) = parse_proc_ipv6_route(&t);
        gws.extend(g);
        routes.extend(r);
    }
    (gws, routes)
}

/// Other Unix systems: no gateway or route list is read (the BSD routing
/// socket is not used yet). The on-link prefixes, the IPv6 site prefix and
/// the default classes still apply; a routed subnet (a VPN, a sibling VLAN
/// behind another router) is NOT denied there unless the owner adds it with
/// `sieve-hub lan add`.
#[cfg(all(unix, not(target_os = "linux")))]
fn unix_routes() -> (Vec<IpAddr>, Vec<Cidr>) {
    (Vec::new(), Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn a(s: &str, prefix: u8) -> IfAddr {
        IfAddr { addr: ip(s), prefix }
    }

    fn denied(n: &LocalNet, s: &str) -> bool {
        n.is_own(ip(s)) || n.in_lan(ip(s))
    }

    fn c(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_cover_prefixes_own_addresses_and_gateways() {
        // A mixed home network: IPv4 private, a global IPv6 /64 handed out by
        // the ISP, a link-local, an odd /0 tunnel and a public /28.
        let net = HostNet {
            addrs: vec![
                a("192.168.1.10", 24),
                a("2a01:4f8:1:2::10", 64),
                a("2a01:4f8:1:2:abcd:1234:5678:9abc", 64),
                a("fe80::1234", 64),
                a("81.2.69.163", 28),
                a("100.100.1.1", 0),
                a("0.0.0.0", 8),
            ],
            gateways: vec![ip("192.168.1.1"), ip("fe80::1"), ip("2a01:4f8:1:2::1"), ip("81.2.69.161")],
            routes: vec![],
        };
        let b = local_net(&net, 64);
        for s in [
            "192.168.1.10",
            "192.168.1.200",
            "2a01:4f8:1:2::10",
            "2a01:4f8:1:2::77",
            "2a01:4f8:1:2:ffff::1",
            "81.2.69.163",
            "81.2.69.170",
            "81.2.69.161",
            "100.100.1.1",
            "2a01:4f8:1:2::1",
        ] {
            assert!(denied(&b, s), "{s} should be denied");
        }
        // The hub's own addresses are "own", its neighbours are not.
        assert!(b.is_own(ip("192.168.1.10")) && b.is_own(ip("2a01:4f8:1:2::10")));
        assert!(!b.is_own(ip("192.168.1.200")));
        // Other addresses stay reachable; the /0 did not swallow the internet.
        for s in ["81.2.69.200", "2a01:4f8:1:3::1", "8.8.8.8", "2606:4700::1111", "100.100.1.2"] {
            assert!(!denied(&b, s), "{s} should not be denied");
        }
        assert!(!b.all().iter().any(|c| c.prefix == 0));
        // No duplicates.
        let all = b.all();
        for (i, x) in all.iter().enumerate() {
            assert!(!all[i + 1..].contains(x), "{x} twice");
        }
    }

    #[test]
    fn the_v6_site_prefix_covers_sibling_networks_and_slash_128_hosts() {
        // A /64 on the LAN, and a /128-only address (no on-link prefix).
        let net = HostNet { addrs: vec![a("2a01:4f8:1:2::10", 64), a("2a02:aaaa:bbbb:cc11::5", 128)], ..Default::default() };
        let b = local_net(&net, DEFAULT_V6_SITE_PREFIX);
        // A sibling /64 inside the same /56 (another VLAN behind the router).
        assert!(denied(&b, "2a01:4f8:1:3::1"));
        assert!(denied(&b, "2a01:4f8:1:ff::1"));
        assert!(!denied(&b, "2a01:4f8:1:100::1"), "outside the /56");
        // The /128-only host: its /56 is denied too.
        assert!(denied(&b, "2a02:aaaa:bbbb:cc00::1"));
        assert!(denied(&b, "2a02:aaaa:bbbb:ccff::1"));
        // The owner narrows it to the /64: the sibling opens.
        let b = local_net(&net, 64);
        assert!(!denied(&b, "2a01:4f8:1:3::1"));
        assert!(denied(&b, "2a01:4f8:1:2::99"));
        // Link-local and unique-local are not "global": no /56 from them.
        let b = local_net(&HostNet { addrs: vec![a("fe80::1", 64), a("fd00:1:2:3::1", 64)], ..Default::default() }, 56);
        assert!(!b.lan.iter().any(|c| c.prefix == 56));
    }

    #[test]
    fn routed_prefixes_are_denied_but_not_default_routes() {
        let net = HostNet {
            addrs: vec![a("192.168.1.10", 24)],
            routes: vec![
                c("0.0.0.0/0"),
                c("0.0.0.0/1"),
                c("128.0.0.0/1"),
                c("::/0"),
                c("2000::/3"),
                // A routed VPN subnet with public addresses, a sibling VLAN,
                // and an IPv6 prefix routed to a VPN.
                c("198.18.40.0/24"),
                c("192.168.7.0/24"),
                c("2a05:d000:1:2::/64"),
            ],
            ..Default::default()
        };
        let b = local_net(&net, 56);
        for s in ["198.18.40.7", "192.168.7.7", "2a05:d000:1:2::5"] {
            assert!(b.in_lan(ip(s)), "{s} should be denied");
        }
        for s in ["8.8.8.8", "200.1.1.1", "2606:4700::1111"] {
            assert!(!b.in_lan(ip(s)), "{s}: a default route must not deny the internet");
        }
    }

    #[test]
    fn a_vanished_block_is_kept_for_the_hold_time() {
        let t0 = Instant::now();
        let mut held = Held::default();
        let with = local_net(&HostNet { addrs: vec![a("192.168.1.10", 24), a("2a01:4f8:1:2::10", 64)], ..Default::default() }, 56);
        let now = held.update(&with, t0, HOLD);
        assert!(now.in_lan(ip("192.168.1.20")) && now.is_own(ip("192.168.1.10")));
        // The interface goes away: everything stays denied for 10 minutes...
        let without = local_net(&HostNet { addrs: vec![a("10.0.0.5", 8)], ..Default::default() }, 56);
        let now = held.update(&without, t0 + Duration::from_secs(9 * 60), HOLD);
        assert!(now.in_lan(ip("192.168.1.20")) && now.is_own(ip("192.168.1.10")) && now.in_lan(ip("2a01:4f8:1:3::1")));
        assert!(now.in_lan(ip("10.1.1.1")), "the new interface counts at once");
        // ...and is dropped after.
        let now = held.update(&without, t0 + Duration::from_secs(10 * 60 + 1), HOLD);
        assert!(!now.in_lan(ip("192.168.1.20")) && !now.is_own(ip("192.168.1.10")));
        assert!(now.in_lan(ip("10.1.1.1")));
        // Seen again: the clock restarts.
        let now = held.update(&with, t0 + Duration::from_secs(11 * 60), HOLD);
        assert!(now.in_lan(ip("192.168.1.20")));
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn proc_route_files_parse() {
        let v4 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                  eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                  eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
                  wg0\t002812C6\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        let (g, r) = parse_proc_route(v4);
        assert_eq!(g, vec![ip("192.168.1.1")]);
        assert_eq!(r, vec![c("0.0.0.0/0"), c("192.168.1.0/24"), c("198.18.40.0/24")]);
        let v6 = "2a0104f8000100020000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n\
                  00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n";
        let (g, r) = parse_proc_ipv6_route(v6);
        assert_eq!(g, vec![ip("fe80::1")]);
        assert_eq!(r, vec![c("2a01:4f8:1:2::/64"), c("::/0")]);
    }

    #[test]
    fn an_empty_or_failing_source_is_a_detection_failure() {
        assert!(detect(&FixedInterfaces(HostNet::default())).is_err());
        struct Broken;
        impl InterfaceSource for Broken {
            fn snapshot(&self) -> io::Result<HostNet> {
                Err(io::Error::other("no"))
            }
        }
        assert!(detect(&Broken).is_err());
    }

    /// Reads this machine's real list (read-only). It must not fail and must
    /// list at least one address.
    #[test]
    fn the_system_list_reads() {
        let net = detect(&SystemInterfaces).expect("interface list");
        assert!(!net.addrs.is_empty());
        let b = local_net(&net, DEFAULT_V6_SITE_PREFIX);
        assert!(!b.own.is_empty());
        // Every machine has some route besides the default one (its on-link
        // prefix, loopback); none of the kept ones is wider than allowed.
        #[cfg(any(windows, target_os = "linux"))]
        assert!(!net.routes.is_empty());
        assert!(b.lan.iter().all(|c| c.prefix > 0));
        assert!(!b.in_lan("8.8.8.8".parse().unwrap()) && !b.in_lan("2606:4700::1111".parse().unwrap()));
    }

    #[cfg(windows)]
    #[test]
    fn windows_sockaddrs_parse() {
        let mut v4 = [0u8; 16];
        v4[..2].copy_from_slice(&2u16.to_ne_bytes());
        v4[4..8].copy_from_slice(&[192, 168, 1, 5]);
        assert_eq!(parse_sockaddr(&v4), Some(ip("192.168.1.5")));
        let mut v6 = [0u8; 28];
        v6[..2].copy_from_slice(&23u16.to_ne_bytes());
        v6[8..24].copy_from_slice(&ip("2a01:4f8::1").to_string().parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(parse_sockaddr(&v6), Some(ip("2a01:4f8::1")));
        assert_eq!(parse_sockaddr(&v6[..10]), None);
    }
}
