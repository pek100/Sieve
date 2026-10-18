//! Short diagnostic builds only. Bounded socket metadata, no packet bodies,
//! URL paths, DNS names or process image paths. This evidence never supplies
//! an owner or changes routing. The service writes it into its admin-only dir.

use std::collections::VecDeque;
use serde::Serialize;
use crate::flow::flows::{FiveTuple, OwnerRow, match_owner};
use crate::flow::packet::Proto;

pub const SAMPLE_CAP: usize = 128;
pub const ROW_CAP: usize = 8;

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub known_tcp: u64,
    pub unknown_tcp: u64,
    pub known_udp: u64,
    pub unknown_udp: u64,
    pub unknown_dns: u64,
    pub samples: VecDeque<Sample>,
}

#[derive(Debug, Serialize)]
pub struct Sample {
    pub at_ms: u64,
    pub lookup_elapsed_ms: u64,
    pub late_match_pid: Option<u32>,
    pub protocol: &'static str,
    pub local: String,
    pub remote: String,
    pub same_family_read_ok: bool,
    pub other_family_read_ok: bool,
    pub same_family_same_port: Vec<Row>,
    pub other_family_same_port: Vec<Row>,
}

#[derive(Debug, Serialize)]
pub struct Row { pub local: String, pub remote: Option<String>, pub pid: u32 }

fn rows(source: Option<&[OwnerRow]>, port: u16) -> Vec<Row> {
    source.unwrap_or_default().iter().filter(|r| r.local.port() == port).take(ROW_CAP)
        .map(|r| Row {local: r.local.to_string(), remote: r.remote.map(|a| a.to_string()), pid: r.pid}).collect()
}

impl Report {
    pub fn observe(&mut self, flow: FiveTuple, known: bool, now_ms: u64, same: Option<&[OwnerRow]>, other: Option<&[OwnerRow]>, lookup_elapsed_ms: u64) {
        match (flow.proto, known) {
            (Proto::Tcp, true) => self.known_tcp += 1,
            (Proto::Tcp, false) => self.unknown_tcp += 1,
            (Proto::Udp, true) => self.known_udp += 1,
            (Proto::Udp, false) => self.unknown_udp += 1,
        }
        if known { return; }
        self.unknown_dns += u64::from(flow.remote.port() == 53);
        if self.samples.len() == SAMPLE_CAP { self.samples.pop_front(); }
        self.samples.push_back(Sample {
            at_ms: now_ms, protocol: if flow.proto == Proto::Tcp {"tcp"} else {"udp"},
            lookup_elapsed_ms, late_match_pid: same.and_then(|r| match_owner(&flow, r)),
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
    #[test]
    fn counts_all_observations_but_bounds_samples_and_rows() {
        let mut report = Report::default();
        let flow = FiveTuple {proto: Proto::Udp, local: "10.0.0.2:5000".parse().unwrap(), remote: "1.1.1.1:53".parse().unwrap()};
        let row = OwnerRow {local: flow.local, remote: None, pid: 7};
        let candidates = vec![row; ROW_CAP + 5];
        for i in 0..SAMPLE_CAP + 3 { report.observe(flow, false, i as u64, Some(&candidates), None, 256); }
        report.observe(flow, true, 999, None, None, 0);
        assert_eq!((report.known_udp, report.unknown_udp, report.unknown_dns), (1, (SAMPLE_CAP+3) as u64, (SAMPLE_CAP+3) as u64));
        assert_eq!(report.samples.len(), SAMPLE_CAP);
        assert_eq!(report.samples.front().unwrap().at_ms, 3);
        assert_eq!(report.samples.back().unwrap().same_family_same_port.len(), ROW_CAP);
        assert!(!report.samples.back().unwrap().other_family_read_ok);
        assert_eq!(report.samples.back().unwrap().late_match_pid, Some(7));
        assert_eq!(report.samples.back().unwrap().lookup_elapsed_ms, 256);
        assert!(serde_json::to_vec(&report).unwrap().len() < 150_000);
    }
}
