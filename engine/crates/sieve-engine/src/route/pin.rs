//! Loop prevention (plan 1.4): every upstream socket the engine opens is
//! pinned with IP_UNICAST_IF / IPV6_UNICAST_IF to the interface Windows
//! would choose for the destination with Sieve's routes ignored, and bound
//! to that interface's own source address (live run 1: without the bind, an
//! IPv6 connect pinned to Wi-Fi picked the TUN's address and failed with
//! 10049). The choice is computed from the forwarding table, skipping every
//! route on an adapter named "Sieve"; a choice that still lands on the
//! engine's adapter is refused as "would loop".

use std::net::IpAddr;

use super::is_sieve_interface;
use super::table::NetTables;

/// Where an upstream socket for one destination goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Egress {
    pub if_index: u32,
    /// The source address to bind (an address of that interface).
    pub source: IpAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinError {
    #[error("no route to {0} outside Sieve's adapter")]
    NoRoute(IpAddr),
    #[error("{0} would loop: the best route is the engine's own adapter")]
    WouldLoop(IpAddr),
    #[error("interface {1} has no usable source address for {0}")]
    NoSource(IpAddr, u32),
}

/// The egress for `dest` (`own_index`: the engine's adapter, by index, in
/// case it is not named "Sieve").
pub fn egress(tables: &NetTables, own_index: Option<u32>, dest: IpAddr) -> Result<Egress, PinError> {
    let best = tables
        .routes
        .iter()
        .filter(|r| r.dest.contains(dest))
        .filter(|r| tables.adapter(r.if_index).is_some_and(|a| a.up && !is_sieve_interface(&a.alias)))
        .max_by(|a, b| a.dest.length().cmp(&b.dest.length()).then(b.metric.cmp(&a.metric)))
        .ok_or(PinError::NoRoute(dest))?;
    if Some(best.if_index) == own_index {
        return Err(PinError::WouldLoop(dest));
    }
    let adapter = tables.adapter(best.if_index).ok_or(PinError::NoRoute(dest))?;
    // The address on the link the packet leaves by: the one whose on-link
    // prefix holds the next hop (or the destination itself), else any usable
    // one of the family, global before unique-local.
    let toward = best.next_hop.unwrap_or(dest);
    let candidates: Vec<IpAddr> = adapter
        .addresses
        .iter()
        .filter(|a| a.ip.is_ipv4() == dest.is_ipv4() && usable_source(a.ip))
        .map(|a| a.ip)
        .collect();
    let on_link = adapter.addresses.iter().find(|a| candidates.contains(&a.ip) && a.on_link().is_some_and(|p| p.contains(toward)));
    let global = || candidates.iter().find(|ip| !is_unique_local(**ip)).or(candidates.first());
    on_link
        .map(|a| a.ip)
        .or_else(|| global().copied())
        .map(|source| Egress { if_index: best.if_index, source })
        .ok_or(PinError::NoSource(dest, best.if_index))
}

fn usable_source(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !(v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()),
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80),
    }
}

fn is_unique_local(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xfe00) == 0xfc00)
}

/// The 4-byte option value for IP_UNICAST_IF (IPv4: interface index in
/// network byte order) or IPV6_UNICAST_IF (IPv6: host byte order). The spike
/// tested this order live (run 1 found the loop was multicast, not this).
pub fn unicast_if_value(index: u32, ipv4: bool) -> [u8; 4] {
    if ipv4 { index.to_be_bytes() } else { index.to_ne_bytes() }
}

#[cfg(test)]
mod tests {
    use super::super::table::fixtures::*;
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn with_sieves_routes_in_place_the_internet_still_leaves_by_wifi() {
        let t = load(SIEVE_UP);
        let wifi = Egress { if_index: 6, source: ip("192.168.7.20") };
        // 8.8.8.8 is in Sieve's 8.0.0.0/7; ignored, the default route wins.
        assert_eq!(egress(&t, Some(45), ip("8.8.8.8")), Ok(wifi));
        assert_eq!(egress(&t, Some(45), ip("192.168.7.1")), Ok(wifi), "Sieve's DNS host route is ignored too");
        assert_eq!(egress(&t, Some(45), ip("2606:4700::1")), Ok(Egress { if_index: 6, source: ip("2001:db8:7:1::20") }));
    }

    #[test]
    fn the_lan_and_other_adapters_get_their_own_interface_and_address() {
        let t = load(SIEVE_UP);
        assert_eq!(egress(&t, Some(45), ip("172.27.16.50")), Ok(Egress { if_index: 24, source: ip("172.27.16.1") }));
        assert_eq!(egress(&t, Some(45), ip("192.168.56.7")), Ok(Egress { if_index: 8, source: ip("192.168.56.1") }));
    }

    #[test]
    fn a_renamed_engine_adapter_is_still_refused_as_a_loop() {
        let mut t = load(SIEVE_UP);
        let sieve = t.adapters.iter_mut().find(|a| a.alias == "Sieve").unwrap();
        sieve.alias = "Ethernet 9".into();
        assert_eq!(egress(&t, Some(45), ip("8.8.8.8")), Err(PinError::WouldLoop(ip("8.8.8.8"))));
        assert_eq!(egress(&t, Some(99), ip("8.8.8.8")).map(|e| e.if_index), Ok(45), "not ours: a more specific route wins");
    }

    #[test]
    fn no_route_and_no_source_are_errors_never_a_guess() {
        let mut t = load(HOME);
        t.routes.retain(|r| r.dest.length() != 0);
        assert_eq!(egress(&t, None, ip("8.8.8.8")), Err(PinError::NoRoute(ip("8.8.8.8"))));
        let mut t = load(HOME);
        t.adapters[0].addresses.retain(|a| a.ip.is_ipv4());
        assert_eq!(egress(&t, None, ip("2606:4700::1")), Err(PinError::NoSource(ip("2606:4700::1"), 6)));
    }

    #[test]
    fn the_lower_metric_wins_between_equal_prefixes() {
        let mut t = load(HOME);
        let mut second = t.routes[0].clone();
        second.if_index = 24;
        second.metric = 10;
        t.routes.push(second);
        assert_eq!(egress(&t, None, ip("8.8.8.8")).map(|e| e.if_index), Ok(24));
    }

    #[test]
    fn the_option_value_is_network_order_for_v4_and_host_order_for_v6() {
        assert_eq!(unicast_if_value(6, true), [0, 0, 0, 6]);
        assert_eq!(unicast_if_value(6, false), 6u32.to_ne_bytes());
    }
}
