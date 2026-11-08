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
//! 2. that adapter is the DNS Client's first network (`apply::DNS_FIRST_METRIC`):
//!    with the first network blocked, the DNS Client waits out its retries (12 s
//!    a lookup, measured) before it takes another network's answer;
//! 3. a filter in a dynamic WFP session (`route::wfp`) blocks the DNS Client's
//!    own port-53 connections leaving the adapters that hold a default route
//!    outside Sieve, to the prefixes the engine routes ([`blocks`]). The blocked
//!    query is dropped without an error the DNS Client acts on; it takes the first
//!    network's answer and cancels the rest. After an NXDOMAIN it would wait out
//!    the blocked network's retries instead (12 s), so the DNS service answers the
//!    DNS Client's NXDOMAIN as NODATA (`dns::service::Service::answer`).
//!
//! Rejected on the same VM: blocking the DNS Client's binds to the physical
//! adapter's address fails every one of its lookups (WSAEACCES, in 1 ms); a server
//! on the adapter without the block leaves the parallel query to leak; the
//! well-known `fec0:0:0:ffff::1-3` servers are never asked.
//!
//! Lifetime: the filter goes with the engine's process (a dynamic session), the
//! server and the metric with the adapter. Nothing outlives the engine but the
//! server's registry value under the adapter's own GUID after a kill
//! (`apply::set_adapter_dns`), which no existing adapter reads. A failure here is
//! reported and routing goes on as before: the DNS Client's queries then leave as
//! they did without the capture.

use std::net::IpAddr;

use super::plan::is_tunnel;
use super::prefix::Prefix;
use super::table::NetTables;
use crate::tun::TUN_DNS;

/// One family's block: the DNS Client's port-53 connections leaving one of these
/// adapters (LUIDs) to one of these prefixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub v4: bool,
    pub on: Vec<u64>,
    pub to: Vec<Prefix>,
}

/// True when the plan routes [`TUN_DNS`] into the adapter (`plan::plan` adds its
/// host route whenever it routes anything): without it the adapter's server would
/// answer nothing, and the capture must not start.
pub fn possible(routes: &[Prefix]) -> bool {
    routes.contains(&Prefix::host(IpAddr::V4(TUN_DNS)))
}

/// The blocks for these tables and the engine's routes, per family: the adapters
/// that hold that family's default route outside Sieve, other than VPNs and
/// tunnels (their DNS goes through them, never the engine), and the routed
/// prefixes of that family. A family with no such adapter or no route gets none.
/// Empty when the capture is not [`possible`].
pub fn blocks(tables: &NetTables, routes: &[Prefix]) -> Vec<Block> {
    if !possible(routes) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for v4 in [true, false] {
        let mut on: Vec<u64> = tables
            .others()
            .filter(|a| !is_tunnel(a.if_type, &a.description))
            .filter(|a| tables.routes_on(a).any(|r| r.dest.length() == 0 && r.dest.is_ipv4() == v4))
            .map(|a| a.luid)
            .collect();
        on.sort_unstable();
        on.dedup();
        let to: Vec<Prefix> = routes.iter().copied().filter(|p| p.is_ipv4() == v4).collect();
        if !on.is_empty() && !to.is_empty() {
            out.push(Block { v4, on, to });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::plan::plan;
    use super::super::table::fixtures::*;
    use super::*;

    #[test]
    fn the_default_route_adapter_is_blocked_to_what_sieve_routes_and_nothing_else() {
        let tables = load(HOME);
        let routes = plan(&tables).routes;
        let blocks = blocks(&tables, &routes);
        let wifi = tables.adapters.iter().find(|a| tables.routes_on(a).any(|r| r.dest.length() == 0)).unwrap().luid;
        assert_eq!(blocks.len(), 2, "both families are routed at home: {blocks:?}");
        for b in &blocks {
            assert_eq!(b.on, [wifi]);
            assert!(b.to.iter().all(|p| p.is_ipv4() == b.v4));
        }
        let v4 = &blocks[0];
        assert!(v4.v4 && v4.to.contains(&"192.168.7.1/32".parse().unwrap()), "the router's DNS, routed by its host route");
        let lan: IpAddr = "192.168.7.30".parse().unwrap();
        assert!(!v4.to.iter().any(|p| p.contains(lan)), "the LAN is a hole: a query to another LAN server is never blocked");
    }

    #[test]
    fn a_vpn_adapter_is_never_blocked() {
        let tables = load(VPN_SPLIT);
        let routes = plan(&tables).routes;
        let vpns: Vec<u64> = tables.others().filter(|a| is_tunnel(a.if_type, &a.description)).map(|a| a.luid).collect();
        assert!(!vpns.is_empty());
        for b in blocks(&tables, &routes) {
            assert!(b.on.iter().all(|l| !vpns.contains(l)), "{b:?}");
        }
    }

    #[test]
    fn no_route_to_sieves_server_means_no_block() {
        let tables = load(HOME);
        assert!(blocks(&tables, &plan(&tables).routes.into_iter().filter(|p| *p != Prefix::host(IpAddr::V4(TUN_DNS))).collect::<Vec<_>>()).is_empty());
    }

    #[test]
    fn an_ipv4_only_network_blocks_ipv4_only() {
        let mut tables = load(HOME);
        tables.routes.retain(|r| r.dest.length() != 0 || r.dest.is_ipv4());
        let routes = plan(&tables).routes;
        let blocks = blocks(&tables, &routes);
        assert_eq!(blocks.iter().map(|b| b.v4).collect::<Vec<_>>(), [true]);
    }
}
