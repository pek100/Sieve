//! The hub's own network, read from the operating system: every interface
//! address with its on-link prefix length, and the default gateways. The hub
//! denies all of it to devices by default (`blocks`), so a device cannot reach
//! the hub itself or the machines next to it, IPv6 global addresses included.
//!
//! Read with `GetAdaptersAddresses` on Windows and `getifaddrs` on Unix (plus
//! `/proc/net/route` and `/proc/net/ipv6_route` for gateways on Linux). The
//! hub reads it at start-up and again every `HubConfig::lan_refresh_every`;
//! tests feed a fixed list through `InterfaceSource`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::rules::Cidr;

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

/// The blocks to deny: each address itself, its on-link prefix, and each
/// gateway. A prefix of 0 (seen on some tunnel adapters) would deny the
/// whole internet, so only the address itself is taken from it.
pub fn blocks(net: &HostNet) -> Vec<Cidr> {
    let mut out: Vec<Cidr> = Vec::new();
    let mut add = |c: Cidr| {
        if !out.contains(&c) {
            out.push(c);
        }
    };
    for a in &net.addrs {
        let ip = a.addr.to_canonical();
        if ip.is_unspecified() {
            continue;
        }
        let max = if ip.is_ipv4() { 32 } else { 128 };
        add(Cidr { addr: ip, prefix: max });
        let p = a.prefix.min(max);
        if p > 0 && p < max {
            add(Cidr { addr: network(ip, p), prefix: p });
        }
    }
    for g in &net.gateways {
        let ip = g.to_canonical();
        if ip.is_unspecified() {
            continue;
        }
        add(Cidr { addr: ip, prefix: if ip.is_ipv4() { 32 } else { 128 } });
    }
    out
}

fn network(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
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
        return Ok(net);
    }
    Err(io::Error::other("the adapter list kept growing while it was read"))
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
    net.gateways = unix_gateways();
    Ok(net)
}

/// Linux: the next hops in the main routing tables (read-only /proc files).
#[cfg(target_os = "linux")]
fn unix_gateways() -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Ok(t) = std::fs::read_to_string("/proc/net/route") {
        // Iface Destination Gateway Flags ...; the gateway is the raw
        // big-endian word printed as a native integer.
        for line in t.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if let Some(g) = f.get(2).and_then(|g| u32::from_str_radix(g, 16).ok())
                && g != 0
            {
                out.push(IpAddr::V4(Ipv4Addr::from(g.to_ne_bytes())));
            }
        }
    }
    if let Ok(t) = std::fs::read_to_string("/proc/net/ipv6_route") {
        // dest plen src plen next_hop metric refcnt use flags iface
        for line in t.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if let Some(g) = f.get(4).and_then(|g| u128::from_str_radix(g, 16).ok())
                && g != 0
            {
                out.push(IpAddr::V6(Ipv6Addr::from(g)));
            }
        }
    }
    out
}

/// Other Unix systems: no gateway list is read. In every ordinary set-up the
/// gateway sits inside an on-link prefix (denied above) or is link-local
/// (denied by class).
#[cfg(all(unix, not(target_os = "linux")))]
fn unix_gateways() -> Vec<IpAddr> {
    Vec::new()
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

    fn denied(blocks: &[Cidr], s: &str) -> bool {
        blocks.iter().any(|c| c.contains(ip(s)))
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
        };
        let b = blocks(&net);
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
        // Other addresses stay reachable; the /0 did not swallow the internet.
        for s in ["81.2.69.200", "2a01:4f8:1:3::1", "8.8.8.8", "2606:4700::1111", "100.100.1.2"] {
            assert!(!denied(&b, s), "{s} should not be denied");
        }
        assert!(!b.iter().any(|c| c.prefix == 0));
        // No duplicates.
        let mut d = b.clone();
        d.dedup();
        assert_eq!(d.len(), b.len());
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
        assert!(!blocks(&net).is_empty());
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
