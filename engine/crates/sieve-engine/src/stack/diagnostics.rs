//! Short diagnostic builds only (A1). Bounded socket metadata, no packet bodies,
//! URL paths, DNS names or process image paths. This evidence never supplies
//! an owner or changes routing. The service writes it into its admin-only dir.
//!
//! Every admitted flow lands in exactly one of four categories, each defined by
//! exact evidence ([`category`]). TTL and TCP fingerprints are recorded as raw
//! values, and no decision reads them: nothing is computed from them, not even
//! a "decremented" verdict, because any host program can set its own TTL.

use std::collections::{HashMap, VecDeque};
use serde::Serialize;
use crate::flow::flows::{FiveTuple, OwnerRow, match_owner};
use crate::flow::nat::NatStats;
use crate::flow::packet::{Proto, SynFingerprint};
use crate::stack::attribution::{Attribution, Unproven};

pub const SAMPLE_CAP: usize = 128;
pub const ROW_CAP: usize = 8;
/// SYN fingerprints held at once, oldest dropped first.
pub const FINGERPRINT_CAP: usize = 256;
/// Raw ETW events kept for live proof L1 to copy into `testdata/`: the newest
/// of each event id, so a busy UDP socket cannot push out the rare ones.
pub const RAW_EVENT_CAP: usize = 48;
pub const RAW_EVENTS_PER_ID: usize = 8;
/// The report's size with every sample at its IPv6 worst and both row lists
/// full (a typical IPv4 report stays under 150 KB, as the test below shows).
pub const REPORT_WORST_CASE_BYTES: usize = 400_000;
/// Bytes of one raw event kept: past every decoded prefix, under any address.
pub const RAW_EVENT_BYTES: usize = 112;

/// The four categories; they sum to the engine's `flows`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    HostAttributed,
    ForwardedExactNat,
    /// A host socket is proven; its owner is not.
    HostUnknown,
    Unexplained,
}

/// The line between the last two needs no TTL: a row on this exact local tuple
/// with PID 0 or several PIDs, or two sources that contradicted each other.
pub fn category(attribution: &Attribution, flow: &FiveTuple, rows: Option<&[OwnerRow]>) -> Category {
    match attribution {
        Attribution::Host { .. } => Category::HostAttributed,
        Attribution::Forwarded(_) => Category::ForwardedExactNat,
        Attribution::Unknown(Unproven::Disagreed | Unproven::OwnerAndNat) => Category::HostUnknown,
        Attribution::Unknown(Unproven::NoAnswer) if ambiguous_row(flow, rows.unwrap_or_default()) => Category::HostUnknown,
        Attribution::Unknown(Unproven::NoAnswer) => Category::Unexplained,
    }
}

fn ambiguous_row(flow: &FiveTuple, rows: &[OwnerRow]) -> bool {
    let exact = |r: &&OwnerRow| {
        r.local == flow.local
            && match (flow.proto, r.remote) {
                (Proto::Tcp, Some(remote)) => remote == flow.remote || (remote.ip().is_unspecified() && remote.port() == 0),
                (Proto::Udp, None) => true,
                _ => false,
            }
    };
    let mut pids = rows.iter().filter(exact).map(|r| r.pid);
    let Some(first) = pids.next() else { return false };
    first == 0 || pids.any(|p| p != first)
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub host_attributed: u64,
    pub forwarded_exact_nat: u64,
    pub host_unknown: u64,
    pub unexplained: u64,
    /// Host flows by protocol; a forwarded flow is in neither known nor
    /// unknown, only in `forwarded_exact_nat`.
    pub known_tcp: u64,
    pub unknown_tcp: u64,
    pub known_udp: u64,
    pub unknown_udp: u64,
    pub unknown_dns: u64,
    pub nat: NatStats,
    pub samples: VecDeque<Sample>,
    /// SYNs seen on the TUN, newest kept; for the flows that stay unknown.
    #[serde(serialize_with = "fingerprint_list")]
    pub fingerprints: Fingerprints,
    pub raw_events: VecDeque<RawEvent>,
}

/// The evidence of one flow left unknown.
#[derive(Debug, Serialize)]
pub struct Sample {
    pub at_ms: u64,
    pub category: Category,
    pub unproven: Option<&'static str>,
    pub lookup_elapsed_ms: u64,
    pub late_match_pid: Option<u32>,
    pub protocol: &'static str,
    pub local: String,
    pub remote: String,
    pub fingerprint: Option<SynFingerprint>,
    pub same_family_read_ok: bool,
    pub other_family_read_ok: bool,
    pub same_family_same_port: Vec<Row>,
    pub other_family_same_port: Vec<Row>,
}

#[derive(Debug, Serialize)]
pub struct Row { pub local: String, pub remote: Option<String>, pub pid: u32 }

/// One event as the session delivered it: its id and first bytes, hex.
#[derive(Debug, Serialize)]
pub struct RawEvent { pub at_ms: u64, pub provider: String, pub id: u16, pub payload_hex: String }

/// Fingerprints by tuple, bounded FIFO.
#[derive(Debug, Default)]
pub struct Fingerprints {
    by_flow: HashMap<FiveTuple, SynFingerprint>,
    order: VecDeque<FiveTuple>,
}

impl Fingerprints {
    fn record(&mut self, flow: FiveTuple, fingerprint: SynFingerprint) {
        if self.by_flow.insert(flow, fingerprint).is_some() {
            return;
        }
        self.order.push_back(flow);
        if self.order.len() > FINGERPRINT_CAP
            && let Some(oldest) = self.order.pop_front()
        {
            self.by_flow.remove(&oldest);
        }
    }

    pub fn len(&self) -> usize {
        self.by_flow.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_flow.is_empty()
    }
}

/// The table on disk: ends as text beside the raw values, oldest first.
fn fingerprint_list<S: serde::Serializer>(f: &Fingerprints, s: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Entry<'a> { local: String, remote: String, syn: &'a SynFingerprint }
    s.collect_seq(f.order.iter().filter_map(|flow| {
        Some(Entry { local: flow.local.to_string(), remote: flow.remote.to_string(), syn: f.by_flow.get(flow)? })
    }))
}

fn rows(source: Option<&[OwnerRow]>, port: u16) -> Vec<Row> {
    source.unwrap_or_default().iter().filter(|r| r.local.port() == port).take(ROW_CAP)
        .map(|r| Row {local: r.local.to_string(), remote: r.remote.map(|a| a.to_string()), pid: r.pid}).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Report {
    /// One SYN from the TUN. Raw values only: nothing here reaches a decision.
    pub fn record_syn(&mut self, flow: FiveTuple, fingerprint: SynFingerprint) {
        self.fingerprints.record(flow, fingerprint);
    }

    pub fn record_raw_event(&mut self, provider: u128, id: u16, payload: &[u8], at_ms: u64) {
        let same_id = self.raw_events.iter().filter(|e| e.id == id).count();
        if same_id >= RAW_EVENTS_PER_ID
            && let Some(oldest) = self.raw_events.iter().position(|e| e.id == id)
        {
            self.raw_events.remove(oldest);
        }
        if self.raw_events.len() == RAW_EVENT_CAP { self.raw_events.pop_front(); }
        self.raw_events.push_back(RawEvent {
            at_ms, provider: format!("{provider:032x}"), id,
            payload_hex: hex(&payload[..payload.len().min(RAW_EVENT_BYTES)]),
        });
    }

    /// One admitted flow. `same` and `other` are the tables read after the
    /// decision, for an unknown flow only.
    pub fn observe(&mut self, flow: FiveTuple, attribution: &Attribution, now_ms: u64, same: Option<&[OwnerRow]>, other: Option<&[OwnerRow]>, lookup_elapsed_ms: u64) {
        let category = category(attribution, &flow, same);
        match category {
            Category::HostAttributed => self.host_attributed += 1,
            Category::ForwardedExactNat => self.forwarded_exact_nat += 1,
            Category::HostUnknown => self.host_unknown += 1,
            Category::Unexplained => self.unexplained += 1,
        }
        // Explained by its exact NAT match: not unknown, and its table reads
        // are empty, so a sample would only evict the evidence L1 needs.
        if category == Category::ForwardedExactNat { return; }
        let known = attribution.pid().is_some();
        match (flow.proto, known) {
            (Proto::Tcp, true) => self.known_tcp += 1,
            (Proto::Tcp, false) => self.unknown_tcp += 1,
            (Proto::Udp, true) => self.known_udp += 1,
            (Proto::Udp, false) => self.unknown_udp += 1,
        }
        if known { return; }
        self.unknown_dns += u64::from(flow.remote.port() == 53);
        if self.samples.len() == SAMPLE_CAP { self.samples.pop_front(); }
        let unproven = match attribution {
            Attribution::Unknown(Unproven::NoAnswer) => Some("no_answer"),
            Attribution::Unknown(Unproven::Disagreed) => Some("disagreed"),
            Attribution::Unknown(Unproven::OwnerAndNat) => Some("owner_and_nat"),
            _ => None,
        };
        self.samples.push_back(Sample {
            at_ms: now_ms, category, unproven, protocol: if flow.proto == Proto::Tcp {"tcp"} else {"udp"},
            lookup_elapsed_ms, late_match_pid: same.and_then(|r| match_owner(&flow, r)),
            fingerprint: self.fingerprints.by_flow.get(&flow).cloned(),
            local: flow.local.to_string(), remote: flow.remote.to_string(),
            same_family_read_ok: same.is_some(), other_family_read_ok: other.is_some(),
            same_family_same_port: rows(same, flow.local.port()),
            other_family_same_port: rows(other, flow.local.port()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::flows::Owner;
    use crate::flow::packet::{build, parse, syn_fingerprint};
    use crate::stack::Meters;
    use crate::stack::attribution::decide;
    use sieve_ipc::Forwarded;

    fn udp53() -> FiveTuple {
        FiveTuple {proto: Proto::Udp, local: "10.0.0.2:5000".parse().unwrap(), remote: "1.1.1.1:53".parse().unwrap()}
    }

    fn tcp() -> FiveTuple {
        FiveTuple {proto: Proto::Tcp, local: "198.18.0.1:5000".parse().unwrap(), remote: "1.1.1.1:443".parse().unwrap()}
    }

    fn no_answer() -> Attribution {
        decide(Owner::Unknown, None)
    }

    #[test]
    fn counts_all_observations_but_bounds_samples_and_rows() {
        let mut report = Report::default();
        let flow = udp53();
        let row = OwnerRow {local: flow.local, remote: None, pid: 7};
        let candidates = vec![row; ROW_CAP + 5];
        for i in 0..SAMPLE_CAP + 3 { report.observe(flow, &no_answer(), i as u64, Some(&candidates), None, 256); }
        report.observe(flow, &decide(Owner::Pid(7), None), 999, None, None, 0);
        assert_eq!((report.known_udp, report.unknown_udp, report.unknown_dns), (1, (SAMPLE_CAP+3) as u64, (SAMPLE_CAP+3) as u64));
        assert_eq!(report.samples.len(), SAMPLE_CAP);
        assert_eq!(report.samples.front().unwrap().at_ms, 3);
        assert_eq!(report.samples.back().unwrap().same_family_same_port.len(), ROW_CAP);
        assert!(!report.samples.back().unwrap().other_family_read_ok);
        assert_eq!(report.samples.back().unwrap().late_match_pid, Some(7));
        assert_eq!(report.samples.back().unwrap().lookup_elapsed_ms, 256);
        assert!(serde_json::to_vec(&report).unwrap().len() < 150_000);
    }

    #[test]
    fn every_flow_lands_in_exactly_one_category() {
        let meters = Meters::default();
        let mut report = Report::default();
        let flow = tcp();
        let pid_zero = OwnerRow {local: flow.local, remote: Some(flow.remote), pid: 0};
        let cases: Vec<(Attribution, Vec<OwnerRow>)> = vec![
            (decide(Owner::Pid(7), None), vec![]),
            (decide(Owner::WitnessOnly(7), None), vec![]),
            (decide(Owner::Unknown, Some(Forwarded {vm: Some("DevBox".into())})), vec![]),
            (decide(Owner::Unknown, Some(Forwarded {vm: None})), vec![]),
            (decide(Owner::Pid(7), Some(Forwarded {vm: None})), vec![]),
            (decide(Owner::Disagreed { table: None }, None), vec![]),
            (no_answer(), vec![pid_zero]),
            (no_answer(), vec![]),
        ];
        for (a, rows) in &cases {
            a.count(&meters);
            report.observe(flow, a, 0, Some(rows), None, 0);
        }
        assert_eq!((report.host_attributed, report.forwarded_exact_nat, report.host_unknown, report.unexplained), (2, 2, 3, 1));
        let sum = report.host_attributed + report.forwarded_exact_nat + report.host_unknown + report.unexplained;
        assert_eq!(sum, meters.counters().flows);
    }

    #[test]
    fn forwarded_flows_cannot_evict_an_unexplained_sample_or_count_as_unknown() {
        let mut report = Report::default();
        let dns = udp53();
        report.observe(dns, &no_answer(), 1, Some(&[]), None, 256);
        let named = decide(Owner::Unknown, Some(Forwarded {vm: Some("DevBox".into())}));
        let unnamed = decide(Owner::Unknown, Some(Forwarded {vm: None}));
        for i in 0..SAMPLE_CAP {
            report.observe(dns, &named, 2, None, None, 0);
            report.observe(tcp(), if i % 2 == 0 {&named} else {&unnamed}, 2, None, None, 0);
        }
        assert_eq!(report.samples.len(), 1, "a forwarded flow is explained: it takes no sample");
        let kept = report.samples.front().unwrap();
        assert_eq!((kept.at_ms, kept.category), (1, Category::Unexplained));
        assert_eq!(report.forwarded_exact_nat, 2 * SAMPLE_CAP as u64);
        assert_eq!((report.known_tcp, report.unknown_tcp, report.known_udp, report.unknown_udp, report.unknown_dns), (0, 0, 0, 1, 1));

        // An owner and a NAT match both answering is unknown, not forwarded: its evidence stays.
        report.observe(tcp(), &decide(Owner::Pid(7), Some(Forwarded {vm: None})), 3, Some(&[]), None, 0);
        assert_eq!(report.samples.back().unwrap().category, Category::HostUnknown);
        assert_eq!((report.samples.len(), report.unknown_tcp), (2, 1));
    }

    #[test]
    fn host_unknown_needs_a_row_or_a_disagreement() {
        let flow = tcp();
        let row = |remote: Option<&str>, pid| OwnerRow {local: flow.local, remote: remote.map(|r| r.parse().unwrap()), pid};
        let exact = "1.1.1.1:443";
        let cases: Vec<(Attribution, Vec<OwnerRow>, Category)> = vec![
            (decide(Owner::Disagreed { table: None }, None), vec![], Category::HostUnknown),
            (decide(Owner::Pid(7), Some(Forwarded {vm: None})), vec![], Category::HostUnknown),
            (no_answer(), vec![row(Some(exact), 0)], Category::HostUnknown),
            (no_answer(), vec![row(Some(exact), 7), row(Some(exact), 8)], Category::HostUnknown),
            (no_answer(), vec![row(Some("0.0.0.0:0"), 0)], Category::HostUnknown),
            (no_answer(), vec![], Category::Unexplained),
            // Another connection on the port proves nothing about this one.
            (no_answer(), vec![row(Some("2.2.2.2:443"), 0)], Category::Unexplained),
            (no_answer(), vec![OwnerRow {local: "198.18.0.1:5001".parse().unwrap(), remote: Some(exact.parse().unwrap()), pid: 0}], Category::Unexplained),
            // One known PID is not "several".
            (no_answer(), vec![row(Some(exact), 7)], Category::Unexplained),
        ];
        for (a, rows, want) in cases {
            assert_eq!(category(&a, &flow, Some(&rows)), want, "{a:?} {rows:?}");
        }
        assert_eq!(category(&no_answer(), &flow, None), Category::Unexplained, "an unreadable table proves nothing");
        let udp = udp53();
        let udp_row = |pid| OwnerRow {local: udp.local, remote: None, pid};
        assert_eq!(category(&no_answer(), &udp, Some(&[udp_row(0)])), Category::HostUnknown);
        assert_eq!(category(&no_answer(), &udp, Some(&[udp_row(7), udp_row(8)])), Category::HostUnknown);
    }

    fn syn(ttl: u8) -> SynFingerprint {
        let mut p = build::ip(Proto::Tcp, "198.18.0.1".parse().unwrap(), "1.1.1.1".parse().unwrap(), 5000, 443, 0, b"");
        p[8] = ttl;
        p[33] = crate::flow::packet::TCP_SYN;
        syn_fingerprint(&p).unwrap()
    }

    #[test]
    fn fingerprints_never_reach_a_decision() {
        let (flow, rows) = (tcp(), Vec::new());
        let mut host = Report::default();
        let mut forwarded = Report::default();
        host.record_syn(flow, syn(128));
        forwarded.record_syn(flow, syn(63));
        // The same evidence with a different TTL: the same decision and the same category.
        for owner in [Owner::Pid(7), Owner::WitnessOnly(7), Owner::Unknown, Owner::Disagreed { table: Some(7) }] {
            for nat in [None, Some(Forwarded {vm: None})] {
                let a = decide(owner, nat.clone());
                host.observe(flow, &a, 0, Some(&rows), None, 0);
                forwarded.observe(flow, &a, 0, Some(&rows), None, 0);
            }
        }
        assert_eq!((host.host_attributed, host.forwarded_exact_nat, host.host_unknown, host.unexplained),
                   (forwarded.host_attributed, forwarded.forwarded_exact_nat, forwarded.host_unknown, forwarded.unexplained));
        for (a, b) in host.samples.iter().zip(&forwarded.samples) {
            assert_eq!(a.category, b.category);
            assert_eq!(a.fingerprint.as_ref().unwrap().ttl, 128, "recorded raw");
            assert_eq!(b.fingerprint.as_ref().unwrap().ttl, 63, "recorded raw");
        }
    }

    #[test]
    fn the_fingerprint_table_and_raw_events_are_bounded_and_the_report_stays_small() {
        let mut report = Report::default();
        let v6 = "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535";
        for i in 0..(FINGERPRINT_CAP + 10) as u32 {
            let flow = FiveTuple {proto: Proto::Tcp, local: format!("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:{:x}]:65535", i + 1).parse().unwrap(), remote: v6.parse().unwrap()};
            report.record_syn(flow, syn(128));
        }
        assert_eq!(report.fingerprints.len(), FINGERPRINT_CAP);
        assert_eq!(report.fingerprints.order.len(), FINGERPRINT_CAP);
        report.record_raw_event(crate::flow::etw::KERNEL_NETWORK, 58, &[0xcd; 44], 0);
        for _ in 0..RAW_EVENT_CAP * 2 {
            report.record_raw_event(crate::flow::etw::KERNEL_NETWORK, 42, &[0xab; 4096], 0);
        }
        assert_eq!(report.raw_events.len(), RAW_EVENTS_PER_ID + 1);
        assert!(report.raw_events.iter().any(|e| e.id == 58), "a busy id does not push out a rare one");
        assert_eq!(report.raw_events.back().unwrap().payload_hex.len(), RAW_EVENT_BYTES * 2, "a payload is cut");
        for id in 0..(RAW_EVENT_CAP as u16 * 2) {
            report.record_raw_event(crate::flow::etw::KERNEL_NETWORK, id + 100, &[0xab; 4096], 0);
        }
        assert_eq!(report.raw_events.len(), RAW_EVENT_CAP, "however many ids there are");
        let flow = FiveTuple {proto: Proto::Tcp, local: v6.parse().unwrap(), remote: v6.parse().unwrap()};
        let row = OwnerRow {local: flow.local, remote: Some(flow.remote), pid: u32::MAX};
        let candidates = vec![row; ROW_CAP];
        for _ in 0..SAMPLE_CAP {
            report.observe(flow, &no_answer(), u64::MAX, Some(&candidates), Some(&candidates), u64::MAX);
        }
        let json = serde_json::to_vec(&report).unwrap();
        assert!(json.len() < REPORT_WORST_CASE_BYTES, "the worst case is {} bytes", json.len());
    }

    #[test]
    fn a_typical_report_with_every_table_full_stays_under_the_existing_bound() {
        let mut report = Report::default();
        for i in 0..FINGERPRINT_CAP as u16 {
            let flow = FiveTuple {proto: Proto::Tcp, local: format!("198.18.0.1:{}", i + 1).parse().unwrap(), remote: "1.1.1.1:443".parse().unwrap()};
            report.record_syn(flow, syn(128));
        }
        for id in [12u16, 28, 42, 58, 1001, 1005] {
            for _ in 0..RAW_EVENTS_PER_ID {
                report.record_raw_event(crate::flow::etw::KERNEL_NETWORK, id, &[0xab; 4096], 0);
            }
        }
        let flow = udp53();
        let candidates = vec![OwnerRow {local: flow.local, remote: None, pid: 7}; ROW_CAP];
        for i in 0..SAMPLE_CAP {
            report.observe(flow, &no_answer(), i as u64, Some(&candidates), None, 256);
        }
        let json = serde_json::to_vec(&report).unwrap();
        assert!(json.len() < 150_000, "a typical report is {} bytes", json.len());
    }

    #[test]
    fn the_report_holds_no_host_name_path_or_payload() {
        let mut report = Report::default();
        let flow = udp53();
        // A DNS query: its name is in the packet, never in the report.
        let packet = build::ip(Proto::Udp, flow.local.ip(), flow.remote.ip(), 5000, 53, 0, b"\x07example\x03com\x00");
        assert!(parse(&packet).is_some());
        assert_eq!(syn_fingerprint(&packet), None, "only a SYN has a fingerprint");
        report.observe(flow, &no_answer(), 0, None, None, 0);
        report.record_raw_event(crate::flow::etw::KERNEL_NETWORK, 42, &[1, 2, 3], 0);
        let json = serde_json::to_string(&report).unwrap();
        for banned in ["example", r"C:\\", ".exe", "\"host\"", "\"exe\""] {
            assert!(!json.contains(banned), "{banned}");
        }
    }
}
