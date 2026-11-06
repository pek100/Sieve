//! Which prefixes the engine routes into its adapter (plan 1.4), derived
//! from the adapter and forwarding tables, never from a per-network list.
//!
//! The full route is "everything except the exclusions". Instead of the two
//! /1s plus more specific exclusion routes on the original interface, the
//! exclusions are cut out of the /1s ([`complement`]): every route the
//! engine adds sits on its own adapter, so all of them vanish with the
//! adapter when the engine's handle closes (a kill, a crash). An exclusion
//! route on Wi-Fi would outlive the engine until a reboot (the rule "Sieve
//! off means a normal network"). Excluded traffic then simply follows the
//! routes Windows already had.
//!
//! Holes (never routed into the engine):
//! - the declared ranges in [`EXCLUDED`] (AdGuard's defaults, E4, plus
//!   loopback, link-local and CGNAT);
//! - every on-link prefix of every other up adapter (the LAN never enters
//!   the stack, whatever its addresses);
//! - every prefix a split-tunnel VPN routes (its traffic keeps bypassing
//!   Sieve, plan 1.7, even where a cut-out piece would be more specific).
//!
//! Additions: each DNS server that sits in a hole gets a host route into the
//! adapter, so DNS is caught on the TUN without touching any DNS setting.
//! IPv6 is routed only when another adapter holds an IPv6 default route, and
//! only global unicast (2000::/3) is ever in its universe.

use std::net::IpAddr;

use super::is_sieve_interface;
use super::prefix::{Prefix, complement};
use super::table::NetTables;

/// Never routed into the engine. Each entry says why (plan 1.4, E4).
pub const EXCLUDED: &[(&str, &str)] = &[
    ("0.0.0.0/8", "this network (RFC 791), never a destination"),
    ("10.0.0.0/8", "private (RFC 1918); AdGuard's default"),
    ("100.64.0.0/10", "carrier-grade NAT (RFC 6598)"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link-local"),
    ("172.16.0.0/12", "private (RFC 1918); AdGuard's default"),
    ("192.168.0.0/16", "private (RFC 1918); AdGuard's default"),
    ("224.0.0.0/3", "multicast, reserved and limited broadcast; AdGuard's default"),
    ("::1/128", "loopback"),
    ("fc00::/7", "unique local; AdGuard's default"),
    ("fe80::/10", "link-local"),
    ("ff00::/8", "multicast; AdGuard's default"),
];

/// The IPv4 and IPv6 address space the engine routes before the holes.
pub const UNIVERSE_V4: &str = "0.0.0.0/0";
/// Global unicast: every other IPv6 range is local or reserved.
pub const UNIVERSE_V6: &str = "2000::/3";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutePlan {
    /// Routes to add on the engine's adapter, in address order.
    pub routes: Vec<Prefix>,
    /// Everything cut out, for the log and tests.
    pub holes: Vec<Prefix>,
}

fn declared() -> Vec<Prefix> {
    // The table is a constant checked by `the_declared_exclusions_parse`.
    EXCLUDED.iter().filter_map(|(p, _)| p.parse().ok()).collect()
}

/// True for an adapter that is a VPN or another tunnel (not Sieve's): the
/// interface types user-mode tunnels and RAS VPNs report, or an Ethernet-type
/// virtual adapter of a VPN product (TAP-Windows, ZeroTier) by description.
pub fn is_tunnel(if_type: u32, description: &str) -> bool {
    use super::table::if_type::{PPP, PROP_VIRTUAL, TUNNEL};
    matches!(if_type, PROP_VIRTUAL | TUNNEL | PPP) || VIRTUAL_ETHERNET_VPNS.iter().any(|v| description.starts_with(v))
}

/// VPN products whose adapters report the Ethernet interface type, by the
/// start of their driver's description (OpenVPN's TAP, ZeroTier). Hyper-V and
/// VirtualBox adapters are not VPNs and are not listed.
pub const VIRTUAL_ETHERNET_VPNS: &[&str] = &["TAP-Windows", "ZeroTier"];

/// What is never routed into the engine, for these tables: the one definition
/// of "excluded from routing", which DNS's split-horizon rules read too.
pub fn holes(tables: &NetTables) -> Vec<Prefix> {
    let mut holes = declared();
    for a in tables.others() {
        holes.extend(a.addresses.iter().filter_map(|addr| addr.on_link()).filter(|p| p.length() > 0));
        if is_tunnel(a.if_type, &a.description) {
            holes.extend(tables.routes_on(a).map(|r| r.dest).filter(|d| d.length() > 1));
        }
    }
    holes.sort();
    holes.dedup();
    holes
}

/// The routes for these tables. The engine's own adapter (named "Sieve")
/// is left out wherever it appears.
pub fn plan(tables: &NetTables) -> RoutePlan {
    let holes = holes(tables);

    let mut routes = Vec::new();
    for (v4, universe) in [(true, UNIVERSE_V4), (false, UNIVERSE_V6)] {
        if !tables.has_default(v4) {
            continue;
        }
        let Ok(universe) = universe.parse::<Prefix>() else { continue };
        routes.extend(complement(universe, &holes));
        // A VPN's own DNS servers are reached through the VPN, never the engine.
        let dns: Vec<IpAddr> = tables
            .others()
            .filter(|a| !is_tunnel(a.if_type, &a.description))
            .flat_map(|a| a.dns.iter().copied()).filter(|ip| ip.is_ipv4() == v4).collect();
        for ip in dns {
            let routable = !(ip.is_loopback() || ip.is_unspecified() || is_link_local(ip));
            if routable && holes.iter().any(|h| h.contains(ip)) {
                routes.push(Prefix::host(ip));
            }
        }
    }
    routes.sort();
    routes.dedup();
    RoutePlan { routes, holes }
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// True when the route is one of the engine's own (on an adapter named
/// "Sieve"), for the tables that list them.
pub fn is_sieve_route(tables: &NetTables, if_index: u32) -> bool {
    tables.adapter(if_index).is_some_and(|a| is_sieve_interface(&a.alias))
}

#[cfg(test)]
mod tests {
    use super::super::table::fixtures::*;
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn routed(plan: &RoutePlan, ip: &str) -> bool {
        let ip: IpAddr = ip.parse().unwrap();
        plan.routes.iter().any(|r| r.contains(ip))
    }

    #[test]
    fn the_declared_exclusions_parse_and_say_why() {
        assert_eq!(declared().len(), EXCLUDED.len());
        assert!(EXCLUDED.iter().all(|(_, why)| !why.is_empty()));
    }

    #[test]
    fn home_routes_the_internet_and_never_the_lan_or_the_declared_ranges() {
        let plan = plan(&load(HOME));
        for public in ["1.1.1.1", "8.8.8.8", "93.184.215.14", "223.255.255.1", "2606:4700::6810:84e5", "2001:4860::8888"] {
            assert!(routed(&plan, public), "{public} is routed");
        }
        for local in [
            "10.1.2.3", "172.20.0.1", "172.27.16.9", "192.168.56.10", "192.168.7.30", "100.64.0.1", "127.0.0.1", "169.254.1.1",
            "224.0.0.251", "239.255.255.250", "255.255.255.255", "fe80::1", "ff02::1:3", "fd00::1", "::1", "0.1.2.3",
        ] {
            assert!(!routed(&plan, local), "{local} is not routed");
        }
        // The Wi-Fi's on-link IPv6 /64 is a hole although it is global unicast.
        assert!(!routed(&plan, "2001:db8:7:1::99"));
        assert!(plan.holes.contains(&p("2001:db8:7:1::/64")));
    }

    #[test]
    fn dns_servers_in_a_hole_get_host_routes_into_the_adapter() {
        let plan = plan(&load(HOME));
        assert!(plan.routes.contains(&p("192.168.7.1/32")), "the router's DNS");
        assert!(plan.routes.contains(&p("2001:db8:7:1::1/128")));
        // The rest of the router's LAN stays out.
        assert!(!routed(&plan, "192.168.7.2"));
    }

    #[test]
    fn a_public_or_loopback_dns_server_adds_nothing() {
        let mut t = load(HOME);
        t.adapters[0].dns = vec!["1.1.1.1".parse().unwrap(), "127.0.0.1".parse().unwrap(), "fe80::1".parse().unwrap()];
        let plan = plan(&t);
        assert!(plan.routes.iter().all(|r| !r.is_host()), "{:?}", plan.routes);
    }

    #[test]
    fn no_ipv6_default_means_no_ipv6_route() {
        let mut t = load(HOME);
        t.routes.retain(|r| r.dest.length() != 0 || r.dest.is_ipv4());
        let plan = plan(&t);
        assert!(plan.routes.iter().all(Prefix::is_ipv4));
        assert!(!plan.routes.is_empty());
    }

    #[test]
    fn nothing_is_routed_without_a_default_route() {
        let mut t = load(HOME);
        t.routes.retain(|r| r.dest.length() != 0);
        assert!(plan(&t).routes.is_empty());
    }

    #[test]
    fn a_split_tunnel_keeps_its_prefixes_and_a_down_adapter_counts_for_nothing() {
        let plan = plan(&load(VPN_SPLIT));
        assert!(!routed(&plan, "203.0.113.9"), "the VPN's public /24 bypasses Sieve");
        assert!(!routed(&plan, "10.8.4.4"));
        assert!(routed(&plan, "203.0.114.1"));
        assert!(!plan.routes.contains(&p("10.8.0.1/32")), "a VPN's DNS server is reached through the VPN");
    }

    #[test]
    fn sieves_own_adapter_and_routes_never_shape_the_plan() {
        assert_eq!(plan(&load(SIEVE_UP)), plan(&load(HOME)));
    }

    #[test]
    fn tunnels_are_told_apart_by_type_and_known_vpn_descriptions_only() {
        assert!(is_tunnel(53, "Wintun Userspace Tunnel"));
        assert!(is_tunnel(131, ""));
        assert!(is_tunnel(23, "WAN Miniport (IKEv2)"));
        assert!(is_tunnel(6, "TAP-Windows Adapter V9"));
        assert!(!is_tunnel(6, "Hyper-V Virtual Ethernet Adapter"));
        assert!(!is_tunnel(71, "Intel(R) Wi-Fi 6E AX211 160MHz"));
    }
}
