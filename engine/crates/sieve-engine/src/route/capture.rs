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
//! 1. the engine's adapter names one DNS server, [`TUN_DNS`](crate::tun::TUN_DNS) (IPv6, in the
//!    adapter's own ULA prefix), whose host route goes into the adapter and which
//!    the DNS service answers. The adapter's IPv6 address [`crate::tun::TUN_V6`] is
//!    the DNS Client's source for it, added by the capture while IPv6 is not routed,
//!    and never skipped as a source (skipped, the DNS Client had no source for the
//!    server and the probe never arrived, live). The adapter's link-local addresses
//!    are skipped as sources while the capture holds, so the machine's own name
//!    answers as without Sieve (live, 2026-11-09);
//! 2. that adapter is the DNS Client's first network by its IPv6 metric alone
//!    ([`DNS_FIRST_METRIC`]; IPv4 keeps its automatic metric, or the machine's own
//!    name answered 198.18.0.1 first): with the first network blocked, the DNS
//!    Client waits out its retries (12 s a lookup, measured) before it takes another
//!    network's answer. An adapter that already has that metric in either family
//!    would tie, so the capture is refused ([`refusal`]), and so is a machine with
//!    IPv6 off on the adapter;
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
//! The capture is proven, not assumed: after it opens, after each change of block
//! or network, and then on the [`probe_after`] schedule (often at first, minutes
//! apart once it has held), the engine asks the DNS Client a fresh name
//! ([`probe_name`]) and the DNS service must see it at [`TUN_DNS`](crate::tun::TUN_DNS)
//! and the answer must come back within [`PROBE_WITHIN`], or the capture closes
//! (`control::routing`). A capture that keeps failing to open is tried again on the
//! same schedule, counted over the failures in a row with the same reason: each
//! failed try stalls lookups for a moment.
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
use sieve_ipc::{CaptureReason, DnsCapture};

/// The IPv6 interface metric that makes the engine's adapter the DNS Client's first
/// network (live: with Ethernet at 5 in both families, Sieve at IPv4 50 and IPv6 1
/// was asked first). Routes are unaffected: none of the engine's has the same
/// prefix as a route of another adapter.
pub const DNS_FIRST_METRIC: u32 = 1;
/// How long a probe's answer may take, from the DNS Client's call to its return.
pub const PROBE_WITHIN: Duration = Duration::from_secs(1);
/// The first wait of [`probe_after`]: how soon a capture just opened or changed
/// is proven again, and a failed open tried again. Until a capture that stopped
/// working is closed, every lookup through the DNS Client waits out its 12 s
/// (live, 2026-11-09: a firewall rule against Sieve's server, closed 48 s later at
/// a 60 s period), so a fresh capture is checked often.
pub const PROBE_FIRST: Duration = Duration::from_secs(15);
/// The longest wait of [`probe_after`]. A probe is one lookup the DNS service
/// answers itself, but the DNS Client also sends it to any network it is not
/// blocked from, so a stable capture asks rarely; and each failed open stalls
/// lookups for up to [`PROBE_WITHIN`], so a failure that repeats is tried rarely.
pub const PROBE_LAST: Duration = Duration::from_secs(300);
/// The probe names' parent: reserved (RFC 6761), so no server anywhere holds a
/// name under it, and with nothing in the name that says who asked.
pub const PROBE_PARENT: &str = "invalid";
/// A probe name's one label: this many lower-case hex digits.
const PROBE_LABEL: usize = 16;

/// How long after the `n`-th proof in a row (0 for the one right after an open or
/// a change) the next is due, or after the `n`-th failed open in a row with the
/// same reason the next try: [`PROBE_FIRST`], doubling, at most [`PROBE_LAST`].
pub fn probe_after(n: u32) -> Duration {
    PROBE_FIRST.saturating_mul(1u32.checked_shl(n).unwrap_or(u32::MAX)).min(PROBE_LAST)
}

/// One family's block: the DNS Client's port-53 connections leaving one of these
/// adapters (LUIDs) to one of these prefixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub v4: bool,
    pub on: Vec<u64>,
    pub to: Vec<Prefix>,
}

/// True when anything is routed and an IPv4 default route exists. Without IPv4
/// the network may be IPv6-only with DNS64, whose synthesized answers only its own
/// server gives: the DNS Client keeps asking it. [`TUN_DNS`](crate::tun::TUN_DNS)'s host route is the
/// capture's own (`control::routing`).
pub fn possible(tables: &NetTables, routes: &[Prefix]) -> bool {
    !routes.is_empty() && tables.has_default(true)
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
    let asked = |ip: &IpAddr| !is_never_asked(*ip);
    !blocks.is_empty()
        && tables
            .others()
            .filter(|a| a.if_type != super::table::if_type::SOFTWARE_LOOPBACK)
            .all(|a| a.dns.iter().filter(|ip| asked(ip)).all(|ip| blocked(a.luid, *ip)))
}

/// The well-known site-local servers Windows lists for an interface with no IPv6
/// server of its own (`fec0:0:0:ffff::1` to `::3`, deprecated by RFC 3879). The DNS
/// Client never asked them on the VM (Server 2025, 2026-11-09), and no network
/// answers there; the loopback pseudo-interface lists them too and is no network.
fn is_never_asked(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if { let s = v6.segments(); s[..7] == [0xfec0, 0, 0, 0xffff, 0, 0, 0] && (1..=3).contains(&s[7]) })
}

/// Why the capture is not held, as the status says it (`sieve_ipc::DnsCapture`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotCaught {
    pub reason: CaptureReason,
    pub adapter: Option<String>,
    pub detail: String,
    /// The DNS Client's status for the check lookup, when that is what failed.
    pub code: Option<u32>,
}

impl NotCaught {
    pub fn new(reason: CaptureReason, detail: impl Into<String>) -> Self {
        Self { reason, adapter: None, detail: detail.into(), code: None }
    }

    pub fn state(&self) -> DnsCapture {
        DnsCapture::NotCaught { reason: self.reason, adapter: self.adapter.clone(), detail: self.detail.clone(), code: self.code }
    }
}

impl From<String> for NotCaught {
    fn from(detail: String) -> Self {
        Self::new(CaptureReason::Failed, detail)
    }
}

/// Whether the user's policy wants the capture: "Also encrypt Windows' own
/// lookups" on (`skip_dns_capture` false) and DNS encryption on. With encryption
/// off the capture would send the DNS Client's queries to the same servers in the
/// same plain text, and only cost: so it is off then too.
pub fn wanted(policy: &sieve_ipc::Policy) -> bool {
    !policy.skip_dns_capture && !policy.plain_dns
}

/// What the routing loop does with the capture on one pass. The user's switch
/// (`Policy::skip_dns_capture`) comes first: off, nothing is opened, and a held
/// capture closes. Then nothing to block closes it too. A held one is proven
/// again when due; an empty one opens when its retry is due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Close,
    Open,
    Prove,
    Keep,
    Nothing,
}

pub fn step(wanted: bool, held: bool, has_blocks: bool, retry_due: bool, proof_due: bool) -> Step {
    match (wanted && has_blocks, held) {
        (false, true) => Step::Close,
        (false, false) => Step::Nothing,
        (true, true) if proof_due => Step::Prove,
        (true, true) => Step::Keep,
        (true, false) if retry_due => Step::Open,
        (true, false) => Step::Nothing,
    }
}

/// The state while routes are up and nothing is held: the user's off, or why
/// there was nothing to catch, or the last failure.
pub fn idle_state(wanted: bool, tables: &NetTables, has_blocks: bool, last: Option<&NotCaught>) -> DnsCapture {
    if !wanted {
        DnsCapture::Off
    } else if !has_blocks && !tables.has_default(true) {
        NotCaught::new(CaptureReason::NoIpv4, "this network has no IPv4 route to the internet").state()
    } else if !has_blocks {
        NotCaught::new(CaptureReason::NothingToCatch, "no network adapter whose DNS queries would leave outside Sieve").state()
    } else {
        last.map_or_else(|| NotCaught::new(CaptureReason::Failed, "not opened yet").state(), NotCaught::state)
    }
}

/// Why the capture must not open: an adapter it would block already has the
/// interface metric the engine's adapter takes ([`DNS_FIRST_METRIC`]) or a lower
/// one, so the DNS Client's first network would be a tie and every lookup could
/// wait out the block. `metric` reads an adapter's interface metric (LUID, IPv4),
/// and both families are checked.
pub fn refusal(tables: &NetTables, blocks: &[Block], metric: impl Fn(u64, bool) -> Option<u32>) -> Option<NotCaught> {
    let mut luids: Vec<u64> = blocks.iter().flat_map(|b| b.on.iter().copied()).collect();
    luids.sort_unstable();
    luids.dedup();
    luids.iter().find_map(|luid| {
        [true, false].into_iter().find_map(|v4| {
            let m = metric(*luid, v4).filter(|m| *m <= DNS_FIRST_METRIC)?;
            let alias = tables.adapters.iter().find(|a| a.luid == *luid).map_or("an adapter", |a| a.alias.as_str());
            let detail = format!(
                "\"{alias}\" has interface metric {m} for {}, which ties with Sieve's DNS server, so the DNS Client's queries are not caught (give \"{alias}\" a metric above {DNS_FIRST_METRIC} to have them caught)",
                if v4 { "IPv4" } else { "IPv6" }
            );
            Some(NotCaught { reason: CaptureReason::Tie, adapter: Some(alias.to_string()), detail, code: None })
        })
    })
}

/// A fresh probe name: one label of random hex digits under [`PROBE_PARENT`], fully
/// qualified so no suffix is appended.
pub fn probe_name(nonce: u64) -> String {
    format!("{nonce:016x}.{PROBE_PARENT}.")
}

/// True for a name the DNS service answers itself as a probe: exactly the shape
/// of [`probe_name`], so any other name under `.invalid` gets its NXDOMAIN.
pub fn is_probe(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    name.split_once('.').is_some_and(|(label, parent)| parent == PROBE_PARENT && label.len() == PROBE_LABEL && label.bytes().all(|b| b.is_ascii_hexdigit()))
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

    /// The VM's tables: the loopback pseudo-interface lists the well-known
    /// site-local servers, which the DNS Client never asks.
    #[test]
    fn the_loopback_and_the_well_known_site_local_servers_are_no_network() {
        use super::super::table::{AddressOnLink, Adapter, if_type};
        let mut tables = load(HOME);
        let site_local: Vec<IpAddr> = (1..=3).map(|i| format!("fec0:0:0:ffff::{i}").parse().unwrap()).collect();
        tables.adapters.push(Adapter {
            index: 1,
            luid: 0x0018_0000_0000_0000,
            alias: "Loopback Pseudo-Interface 1".into(),
            description: "Software Loopback Interface 1".into(),
            if_type: if_type::SOFTWARE_LOOPBACK,
            up: true,
            addresses: vec![AddressOnLink { ip: "127.0.0.1".parse().unwrap(), len: 8 }],
            dns: site_local.clone(),
            dns_suffixes: vec![],
        });
        let blocks = blocks(&tables, &plan(&tables).routes);
        assert!(every_network_blocked(&tables, &blocks));
        let at = tables.adapters.iter().position(|a| a.luid == wifi(&tables)).unwrap();
        tables.adapters[at].dns.extend(site_local);
        assert!(every_network_blocked(&tables, &blocks), "never asked on a real adapter either");
        tables.adapters[at].dns.push("fec0:0:0:ffff::4".parse().unwrap());
        assert!(!every_network_blocked(&tables, &blocks), "any other site-local server counts");
    }

    #[test]
    fn nothing_routed_or_no_ipv4_default_means_no_block() {
        let tables = load(HOME);
        assert!(blocks(&tables, &[]).is_empty(), "nothing routed");
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
        assert_eq!((why.reason, why.adapter.as_deref()), (CaptureReason::Tie, Some("Wi-Fi")));
        let why = why.detail;
        assert!(why.contains("Wi-Fi") && why.contains("metric 1") && why.contains("IPv4"), "{why}");
        assert!(refusal(&tables, &blocks, |l, v4| (l == luid && !v4).then_some(0)).unwrap().detail.contains("IPv6"));
    }

    /// The user's switch: off, nothing is ever opened and a held capture closes,
    /// whatever else holds; back on, it opens at once on a network with blocks.
    #[test]
    fn the_switch_off_opens_nothing_and_closes_a_held_capture() {
        for has_blocks in [true, false] {
            for retry_due in [true, false] {
                for proof_due in [true, false] {
                    assert_eq!(step(false, false, has_blocks, retry_due, proof_due), Step::Nothing, "off never opens");
                    assert_eq!(step(false, true, has_blocks, retry_due, proof_due), Step::Close, "off closes");
                }
            }
        }
        assert_eq!(step(true, false, true, true, false), Step::Open, "back on: opens");
        assert_eq!(step(true, false, true, false, false), Step::Nothing, "a failed open waits for its retry");
        assert_eq!(step(true, true, true, false, true), Step::Prove);
        assert_eq!(step(true, true, true, false, false), Step::Keep);
        assert_eq!(step(true, true, false, true, true), Step::Close, "nothing left to block");
    }

    #[test]
    fn the_capture_is_wanted_only_with_its_switch_and_encryption_on() {
        use sieve_ipc::Policy;
        assert!(wanted(&Policy::default()), "on by default");
        assert!(!wanted(&Policy { skip_dns_capture: true, ..Policy::default() }));
        assert!(!wanted(&Policy { plain_dns: true, ..Policy::default() }), "plain DNS: nothing to encrypt");
    }

    #[test]
    fn the_idle_state_says_off_or_why() {
        let home = load(HOME);
        assert_eq!(idle_state(false, &home, true, None), DnsCapture::Off);
        let mut v6_only = load(HOME);
        v6_only.routes.retain(|r| r.dest.length() != 0 || !r.dest.is_ipv4());
        assert!(matches!(idle_state(true, &v6_only, false, None), DnsCapture::NotCaught { reason: CaptureReason::NoIpv4, .. }));
        assert!(matches!(idle_state(true, &home, false, None), DnsCapture::NotCaught { reason: CaptureReason::NothingToCatch, .. }), "nothing would leave: a fact, not a failure");
        let tie = NotCaught { reason: CaptureReason::Tie, adapter: Some("Wi-Fi".into()), detail: "metric 1".into(), code: None };
        assert_eq!(idle_state(true, &home, true, Some(&tie)), tie.state());
        assert_eq!(NotCaught::from("x".to_string()).reason, CaptureReason::Failed);
    }

    /// The server is IPv6 so the adapter is first by its IPv6 metric alone; it sits
    /// beside the adapter's own ULA and is never one of the plan's routes.
    #[test]
    fn the_adapters_server_is_ipv6_in_its_own_prefix_and_never_planned() {
        use crate::tun::{TUN_DNS, TUN_V6};
        let IpAddr::V6(server) = TUN_DNS else { panic!("IPv6") };
        assert_eq!(server.segments()[..4], TUN_V6.segments()[..4]);
        assert!(super::super::plan::declared().iter().any(|h| h.contains(TUN_DNS)), "a hole: only the capture routes it");
        assert!(!plan(&load(HOME)).routes.iter().any(|p| p.contains(TUN_DNS)));
    }

    /// A probe reaches any network the DNS Client is not blocked from, so its
    /// name says nothing of who asked: random hex under `.invalid`.
    #[test]
    fn probe_names_are_fully_qualified_neutral_and_told_apart() {
        let name = probe_name(0xabc);
        assert_eq!(name, "0000000000000abc.invalid.");
        assert!(!name.contains("sieve"));
        assert!(is_probe(&name) && is_probe(name.trim_end_matches('.')) && is_probe(&probe_name(u64::MAX).to_uppercase()));
        for other in ["invalid", "abc.invalid", "0000000000000abg.invalid", "a.0000000000000abc.invalid", "0000000000000abc.invalid.example", "00000000000000abc.invalid", "www.example"] {
            assert!(!is_probe(other), "{other}");
        }
    }

    #[test]
    fn probes_and_retries_back_off_from_15_s_to_5_minutes() {
        let waits: Vec<u64> = (0..7).map(|n| probe_after(n).as_secs()).collect();
        assert_eq!(waits, [15, 30, 60, 120, 240, 300, 300]);
        assert_eq!(probe_after(u32::MAX), PROBE_LAST, "no overflow");
    }
}
