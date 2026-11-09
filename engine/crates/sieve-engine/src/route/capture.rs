//! The Windows DNS Client's queries, caught while routes are up.
//!
//! The DNS Client service (Dnscache) sends each query from the address of the
//! adapter whose server it asks, and Windows sends by the strong host rule, so a
//! query bound to the physical adapter leaves that adapter in plain text whatever
//! the engine's routes say. It also asks every network's servers at once and takes
//! the first network's answer (Microsoft-Windows-DNS-Client events 3009 and 3020
//! on a Windows Server 2025 VM, 2026-11-09). With routes up, three things together
//! make its queries reach the engine and nothing else:
//!
//! 1. the engine's adapter names one DNS server, [`TUN_DNS`], whose host route
//!    goes into the adapter and which the DNS service answers;
//! 2. that adapter is the DNS Client's first network ([`DNS_FIRST_METRIC`]): with
//!    the first network blocked, the DNS Client waits out its retries (12 s a
//!    lookup, measured) before it takes another network's answer. An adapter that
//!    already has that metric would tie, so the capture is refused ([`refusal`]);
//! 3. a filter in a dynamic WFP session (`route::wfp`) blocks the DNS Client's
//!    own port-53 connections leaving the adapters that hold a default route
//!    outside Sieve, to the prefixes the engine routes and to those adapters' own
//!    DNS servers ([`blocks`]). The blocked query is dropped without an error the
//!    DNS Client acts on; it takes the first network's answer and cancels the rest.
//!
//! After an NXDOMAIN the DNS Client waits out the blocked networks' retries
//! (12 s) instead. The DNS service may answer the DNS Client's NXDOMAIN as NODATA
//! (`dns::service::NXDOMAIN_AS_NODATA`, not yet the owner's decision), and only
//! while every network the DNS Client could ask is blocked ([`every_network_blocked`]):
//! an unblocked one (a VPN's, a second adapter's, a loopback resolver) answers for
//! itself, and its answer must win.
//!
//! The capture is proven, not assumed: after it opens, after each change and
//! every [`PROBE_EVERY`], the engine asks the DNS Client a fresh name and the DNS
//! service must see it at [`TUN_DNS`] and the answer must come back within
//! [`PROBE_WITHIN`], or the capture closes (`control::routing`).
//!
//! Rejected on the same VM: blocking the DNS Client's binds to the physical
//! adapter's address fails every one of its lookups (WSAEACCES, in 1 ms); a server
//! on the adapter without the block leaves the parallel query to leak; the
//! well-known `fec0:0:0:ffff::1-3` servers are never asked.
//!
//! Lifetime: the filter goes with the engine's process (a dynamic session), the
//! server and the metric with the adapter. After a kill the server's registry
//! value stays under the adapter's own GUID, which no existing adapter reads; the
//! next start and `uninstall` delete it (`apply::forget_adapter_key`). A failure
//! here is reported and routing goes on as before: the DNS Client's queries then
//! leave as they did without the capture.

use std::net::IpAddr;
use std::time::Duration;

use super::plan::is_tunnel;
use super::prefix::Prefix;
use super::table::NetTables;
use crate::tun::TUN_DNS;

/// The interface metric that makes the engine's adapter the DNS Client's first
/// network. Routes are unaffected: none of the engine's has the same prefix as a
/// route of another adapter.
pub const DNS_FIRST_METRIC: u32 = 1;
/// How long a probe's answer may take, from the DNS Client's call to its return.
pub const PROBE_WITHIN: Duration = Duration::from_secs(1);
/// How often a held capture is proven again.
pub const PROBE_EVERY: Duration = Duration::from_secs(60);
/// The probe names' parent: reserved (RFC 6761), answered by the DNS service
/// itself and never sent on.
pub const PROBE_PARENT: &str = "probe.sieve.invalid";

/// One family's block: the DNS Client's port-53 connections leaving one of these
/// adapters (LUIDs) to one of these prefixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub v4: bool,
    pub on: Vec<u64>,
    pub to: Vec<Prefix>,
}

/// True when the plan routes [`TUN_DNS`] into the adapter (`plan::plan` adds its
/// host route whenever it routes anything) and an IPv4 default route exists.
/// Without the route the adapter's server would answer nothing. Without IPv4 the
/// network may be IPv6-only with DNS64, whose synthesized answers only its own
/// server gives: the DNS Client keeps asking it.
pub fn possible(tables: &NetTables, routes: &[Prefix]) -> bool {
    routes.contains(&Prefix::host(IpAddr::V4(TUN_DNS))) && tables.has_default(true)
}

/// A server the DNS Client may be stopped from asking: not on this machine.
fn blockable(ip: IpAddr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified())
}

/// The blocks for these tables and the engine's routes, per family. The adapters
/// blocked are those that hold a default route outside Sieve, other than VPNs and
/// tunnels (their DNS goes through them, never the engine): in a family where
/// they hold its default route or name a server of it. The prefixes are the
/// routed ones of that family and those adapters' own servers of it (an IPv6
/// unique local or link-local one, an IPv4 link-local one, none of which is
/// routed). A family with no such adapter or prefix gets none. Empty when the
/// capture is not [`possible`].
pub fn blocks(tables: &NetTables, routes: &[Prefix]) -> Vec<Block> {
    if !possible(tables, routes) {
        return Vec::new();
    }
    let candidates: Vec<_> = tables
        .others()
        .filter(|a| !is_tunnel(a.if_type, &a.description))
        .filter(|a| tables.routes_on(a).any(|r| r.dest.length() == 0))
        .collect();
    let mut out = Vec::new();
    for v4 in [true, false] {
        let holds = |a: &&&super::table::Adapter| {
            tables.routes_on(a).any(|r| r.dest.length() == 0 && r.dest.is_ipv4() == v4) || a.dns.iter().any(|ip| ip.is_ipv4() == v4)
        };
        let on_adapters: Vec<_> = candidates.iter().filter(holds).collect();
        let mut on: Vec<u64> = on_adapters.iter().map(|a| a.luid).collect();
        on.sort_unstable();
        on.dedup();
        let mut to: Vec<Prefix> = routes.iter().copied().filter(|p| p.is_ipv4() == v4).collect();
        to.extend(on_adapters.iter().flat_map(|a| a.dns.iter().copied()).filter(|ip| ip.is_ipv4() == v4 && blockable(*ip)).map(Prefix::host));
        to.sort();
        to.dedup();
        if !on.is_empty() && !to.is_empty() {
            out.push(Block { v4, on, to });
        }
    }
    out
}

/// True when the DNS Client can get no answer but the engine's: every DNS server
/// of every other up adapter is blocked on that adapter. A VPN's or a second
/// adapter's server, a loopback resolver, a family with no block: any one of
/// them answers for itself, and an NXDOMAIN must then reach the DNS Client as it
/// came. False with no block at all.
pub fn every_network_blocked(tables: &NetTables, blocks: &[Block]) -> bool {
    let blocked = |luid: u64, ip: IpAddr| blocks.iter().any(|b| b.v4 == ip.is_ipv4() && b.on.contains(&luid) && b.to.iter().any(|p| p.contains(ip)));
    !blocks.is_empty() && tables.others().all(|a| a.dns.iter().all(|ip| blocked(a.luid, *ip)))
}

/// Why the capture must not open: an adapter it would block already has the
/// interface metric the engine's adapter takes ([`DNS_FIRST_METRIC`]) or a lower
/// one, so the DNS Client's first network would be a tie and every lookup could
/// wait out the block. `metric` reads an adapter's interface metric (LUID, IPv4).
pub fn refusal(tables: &NetTables, blocks: &[Block], metric: impl Fn(u64, bool) -> Option<u32>) -> Option<String> {
    blocks.iter().find_map(|b| {
        b.on.iter().find_map(|luid| {
            let m = metric(*luid, b.v4).filter(|m| *m <= DNS_FIRST_METRIC)?;
            let alias = tables.adapters.iter().find(|a| a.luid == *luid).map_or("an adapter", |a| a.alias.as_str());
            Some(format!(
                "\"{alias}\" has interface metric {m} for {}, which ties with Sieve's DNS server, so the DNS Client's queries are not caught (give \"{alias}\" a metric above {DNS_FIRST_METRIC} to have them caught)",
                if b.v4 { "IPv4" } else { "IPv6" }
            ))
        })
    })
}

/// A fresh probe name under [`PROBE_PARENT`], fully qualified so no suffix is
/// appended.
pub fn probe_name(nonce: u64) -> String {
    format!("p{nonce:016x}.{PROBE_PARENT}.")
}

/// True for a name the DNS service answers itself as a probe.
pub fn is_probe(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    name.len() > PROBE_PARENT.len() && name.ends_with(PROBE_PARENT) && name.as_bytes()[name.len() - PROBE_PARENT.len() - 1] == b'.'
}

#[cfg(test)]
mod tests {
    use super::super::plan::plan;
    use super::super::table::fixtures::*;
    use super::*;

    fn wifi(tables: &NetTables) -> u64 {
        tables.adapters.iter().find(|a| tables.routes_on(a).any(|r| r.dest.length() == 0)).unwrap().luid
    }

    #[test]
    fn the_default_route_adapter_is_blocked_to_what_sieve_routes_and_its_own_servers() {
        let tables = load(HOME);
        let routes = plan(&tables).routes;
        let blocks = blocks(&tables, &routes);
        assert_eq!(blocks.len(), 2, "both families are routed at home: {blocks:?}");
        for b in &blocks {
            assert_eq!(b.on, [wifi(&tables)]);
            assert!(b.to.iter().all(|p| p.is_ipv4() == b.v4));
        }
        let v4 = &blocks[0];
        assert!(v4.v4 && v4.to.contains(&"192.168.7.1/32".parse().unwrap()), "the router's DNS, routed by its host route");
        let lan: IpAddr = "192.168.7.30".parse().unwrap();
        assert!(!v4.to.iter().any(|p| p.contains(lan)), "the LAN is a hole: a query to another LAN server is never blocked");
    }

    /// The VM's case: IPv6 is not routed, but the adapter names IPv6 servers the
    /// DNS Client asks bound to it.
    #[test]
    fn ipv6_servers_are_blocked_without_an_ipv6_default_route() {
        let mut tables = load(HOME);
        tables.routes.retain(|r| r.dest.length() != 0 || r.dest.is_ipv4());
        let luid = wifi(&tables);
        let at = tables.adapters.iter().position(|a| a.luid == luid).unwrap();
        tables.adapters[at].dns = vec!["192.168.7.1".parse().unwrap(), "fd00::53".parse().unwrap(), "fe80::1".parse().unwrap(), "::1".parse().unwrap()];
        let routes = plan(&tables).routes;
        assert!(routes.iter().all(|p| p.is_ipv4() || p.addr() == "fd00::53".parse::<IpAddr>().unwrap()), "no IPv6 universe routed");
        let blocks = blocks(&tables, &routes);
        let v6 = blocks.iter().find(|b| !b.v4).expect("an IPv6 block");
        assert_eq!(v6.on, [luid]);
        for server in ["fd00::53", "fe80::1"] {
            assert!(v6.to.contains(&Prefix::host(server.parse().unwrap())), "{server}");
        }
        assert!(!v6.to.iter().any(|p| p.contains("::1".parse().unwrap())), "a loopback resolver is never blocked");
        assert!(!every_network_blocked(&tables, &blocks), "the loopback resolver answers for itself");
        tables.adapters[at].dns.pop();
        assert!(every_network_blocked(&tables, &super::blocks(&tables, &plan(&tables).routes)));
    }

    #[test]
    fn a_vpn_adapter_is_never_blocked_and_its_server_keeps_the_nxdomain() {
        let tables = load(VPN_SPLIT);
        let routes = plan(&tables).routes;
        let vpns: Vec<u64> = tables.others().filter(|a| is_tunnel(a.if_type, &a.description)).map(|a| a.luid).collect();
        assert!(!vpns.is_empty());
        let blocks = blocks(&tables, &routes);
        for b in &blocks {
            assert!(b.on.iter().all(|l| !vpns.contains(l)), "{b:?}");
        }
        assert!(tables.others().any(|a| vpns.contains(&a.luid) && !a.dns.is_empty()), "the fixture's VPN names a server");
        assert!(!every_network_blocked(&tables, &blocks), "split DNS: the VPN's server answers its names");
        assert!(every_network_blocked(&load(HOME), &super::blocks(&load(HOME), &plan(&load(HOME)).routes)), "the control: home");
    }

    #[test]
    fn a_second_adapter_with_servers_and_no_default_route_keeps_the_nxdomain() {
        let mut tables = load(HOME);
        let at = tables.adapters.iter().position(|a| a.alias.starts_with("vEthernet")).unwrap();
        tables.adapters[at].dns = vec!["172.27.16.1".parse().unwrap()];
        let blocks = blocks(&tables, &plan(&tables).routes);
        assert!(!blocks.is_empty());
        assert!(!every_network_blocked(&tables, &blocks));
        assert!(!every_network_blocked(&load(HOME), &[]), "no block, no rewrite");
    }

    #[test]
    fn no_route_to_sieves_server_or_no_ipv4_default_means_no_block() {
        let tables = load(HOME);
        assert!(blocks(&tables, &plan(&tables).routes.into_iter().filter(|p| *p != Prefix::host(IpAddr::V4(TUN_DNS))).collect::<Vec<_>>()).is_empty());
        let mut v6_only = load(HOME);
        v6_only.routes.retain(|r| r.dest.length() != 0 || !r.dest.is_ipv4());
        let routes = plan(&v6_only).routes;
        assert!(!routes.is_empty(), "IPv6 is still routed");
        assert!(blocks(&v6_only, &routes).is_empty(), "IPv6-only (DNS64): the DNS Client keeps the network's server");
    }

    #[test]
    fn an_ipv4_only_network_blocks_ipv4_only() {
        let mut tables = load(HOME);
        tables.routes.retain(|r| r.dest.length() != 0 || r.dest.is_ipv4());
        for a in &mut tables.adapters {
            a.dns.retain(IpAddr::is_ipv4);
        }
        let routes = plan(&tables).routes;
        let blocks = blocks(&tables, &routes);
        assert_eq!(blocks.iter().map(|b| b.v4).collect::<Vec<_>>(), [true]);
    }

    #[test]
    fn an_adapter_at_the_first_metric_refuses_the_capture() {
        let tables = load(HOME);
        let blocks = blocks(&tables, &plan(&tables).routes);
        let luid = wifi(&tables);
        assert_eq!(refusal(&tables, &blocks, |_, _| Some(25)), None);
        assert_eq!(refusal(&tables, &blocks, |_, _| None), None, "an interface without that family");
        let why = refusal(&tables, &blocks, |l, v4| (l == luid && v4).then_some(DNS_FIRST_METRIC)).expect("a tie");
        assert!(why.contains("Wi-Fi") && why.contains("metric 1") && why.contains("IPv4"), "{why}");
        assert!(refusal(&tables, &blocks, |l, v4| (l == luid && !v4).then_some(0)).unwrap().contains("IPv6"));
    }

    #[test]
    fn probe_names_are_fully_qualified_and_told_apart() {
        let name = probe_name(0xabc);
        assert_eq!(name, "p0000000000000abc.probe.sieve.invalid.");
        assert!(is_probe(&name) && is_probe(name.trim_end_matches('.')));
        for other in ["probe.sieve.invalid", "xprobe.sieve.invalid", "a.probe.sieve.invalid.example", "www.example"] {
            assert!(!is_probe(other), "{other}");
        }
    }
}
