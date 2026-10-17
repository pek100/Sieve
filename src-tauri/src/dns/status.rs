//! `dns_status` wire shape, version 2. The TypeScript mirror is
//! `parseDnsStatus` in src/data/protocol.ts; both read the fixture
//! src/data/fixtures/dns-status-v2.json. Changing a key or its meaning bumps
//! `DNS_STATUS_VERSION`, the fixture and the mirror in the same commit.
//!
//! v2 (phase B): `bind` (one address or null) became `binds` (every listen
//! address, empty when stopped), because the proxy listens on 127.0.0.1 and
//! ::1 at once so Windows can point both address families at it.
//!
//! ```json
//! {
//!   "v": 2,
//!   "running": true,
//!   "binds": ["127.0.0.1:53", "[::1]:53"], // empty when stopped
//!   "started_at": 1800000000000,       // ms since the Unix epoch, null when stopped
//!   "upstreams": ["1.1.1.1:53", "9.9.9.9:53"],
//!   "counters": {
//!     "queries": 120,                  // every query received
//!     "blocked": 14,                   // answered here with the block answer
//!     "forwarded": 105,                // answered by an upstream
//!     "failed": 1,                     // every upstream failed: SERVFAIL sent
//!     "untracked": 0                   // blocked but past the per-name cap
//!   },
//!   "last_error": null,                // newest error text, or null
//!   "list": {
//!     "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
//!     "fetched_at": 1800000000000,     // when the list in use was downloaded; null: no list
//!     "rules": 51234,                  // block rules in force (list plus user)
//!     "allow": 812,                    // allow rules in force
//!     "skipped": 97,                   // lines not understood, so not applied
//!     "user_rules": true,              // user-rules.txt exists and is not blank
//!     "error": null                    // why the list is stale or missing, or null
//!   },
//!   "top_blocked": [{ "domain": "doubleclick.net", "count": 9 }]  // at most 20
//! }
//! ```
//! Counters restart from zero on every `dns_start`.

use serde::Serialize;

pub const DNS_STATUS_VERSION: u32 = 2;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub queries: u64,
    pub blocked: u64,
    pub forwarded: u64,
    pub failed: u64,
    pub untracked: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ListInfo {
    pub url: Option<String>,
    pub fetched_at: Option<u64>,
    pub rules: usize,
    pub allow: usize,
    pub skipped: usize,
    pub user_rules: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainCount {
    pub domain: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsStatus {
    pub v: u32,
    pub running: bool,
    pub binds: Vec<String>,
    pub started_at: Option<u64>,
    pub upstreams: Vec<String>,
    pub counters: Counters,
    pub last_error: Option<String>,
    pub list: ListInfo,
    pub top_blocked: Vec<DomainCount>,
}

impl DnsStatus {
    /// The status while no proxy runs.
    pub fn stopped() -> Self {
        DnsStatus {
            v: DNS_STATUS_VERSION,
            running: false,
            binds: Vec::new(),
            started_at: None,
            upstreams: Vec::new(),
            counters: Counters::default(),
            last_error: None,
            list: ListInfo::default(),
            top_blocked: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../../src/data/fixtures/dns-status-v2.json");

    #[test]
    fn running_status_serialises_to_the_shared_v2_fixture() {
        let status = DnsStatus {
            v: DNS_STATUS_VERSION,
            running: true,
            binds: vec!["127.0.0.1:53".into(), "[::1]:53".into()],
            started_at: Some(1_800_000_000_000),
            upstreams: vec!["1.1.1.1:53".into(), "9.9.9.9:53".into()],
            counters: Counters { queries: 120, blocked: 14, forwarded: 105, failed: 1, untracked: 0 },
            last_error: None,
            list: ListInfo {
                url: Some("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt".into()),
                fetched_at: Some(1_800_000_000_000),
                rules: 51_234,
                allow: 812,
                skipped: 97,
                user_rules: true,
                error: None,
            },
            top_blocked: vec![DomainCount { domain: "doubleclick.net".into(), count: 9 }],
        };
        let expected: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture is JSON");
        assert_eq!(serde_json::to_value(&status).expect("serialises"), expected);
    }

    #[test]
    fn stopped_status_has_nulls_and_no_binds_not_zero_timestamps() {
        let v = serde_json::to_value(DnsStatus::stopped()).expect("serialises");
        assert_eq!(v["v"], 2);
        assert_eq!(v["running"], false);
        assert_eq!(v["binds"], serde_json::json!([]));
        assert!(v["started_at"].is_null());
        assert!(v["list"]["fetched_at"].is_null());
    }
}
