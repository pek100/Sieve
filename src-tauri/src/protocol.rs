//! Snapshot protocol v1 (primitive B1). Mirror of `src/data/protocol.ts`.
//! Changing the shape bumps PROTOCOL_VERSION and the fixture
//! (`src/data/fixtures/snapshot-v1.json`) in the same commit.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

/// Wire names of every flow state, in MIB_TCP_STATE order (codes 1 to 12),
/// then `none` for UDP. The TypeScript law test compares this list with
/// FLOW_STATES in protocol.ts.
pub const FLOW_STATE_NAMES: [&str; 13] = [
    "closed",
    "listen",
    "syn_sent",
    "syn_received",
    "established",
    "fin_wait_1",
    "fin_wait_2",
    "close_wait",
    "closing",
    "last_ack",
    "time_wait",
    "delete_tcb",
    "none",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState {
    #[serde(rename = "closed")]
    Closed,
    #[serde(rename = "listen")]
    Listen,
    #[serde(rename = "syn_sent")]
    SynSent,
    #[serde(rename = "syn_received")]
    SynReceived,
    #[serde(rename = "established")]
    Established,
    #[serde(rename = "fin_wait_1")]
    FinWait1,
    #[serde(rename = "fin_wait_2")]
    FinWait2,
    #[serde(rename = "close_wait")]
    CloseWait,
    #[serde(rename = "closing")]
    Closing,
    #[serde(rename = "last_ack")]
    LastAck,
    #[serde(rename = "time_wait")]
    TimeWait,
    #[serde(rename = "delete_tcb")]
    DeleteTcb,
    #[serde(rename = "none")]
    None,
}

impl FlowState {
    /// Every state in FLOW_STATE_NAMES order.
    pub const ALL: [FlowState; 13] = [
        FlowState::Closed,
        FlowState::Listen,
        FlowState::SynSent,
        FlowState::SynReceived,
        FlowState::Established,
        FlowState::FinWait1,
        FlowState::FinWait2,
        FlowState::CloseWait,
        FlowState::Closing,
        FlowState::LastAck,
        FlowState::TimeWait,
        FlowState::DeleteTcb,
        FlowState::None,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub addr: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    /// Full image path, or None when the OS refused to tell us.
    pub exe: Option<String>,
    /// Exe file name, or "System" / "pid <n>" when exe is None.
    pub name: String,
    /// ProductName from the exe's version info.
    pub product: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flow {
    pub pid: u32,
    pub proto: Proto,
    pub family: Family,
    pub local: Endpoint,
    /// None for listening TCP sockets and every UDP socket.
    pub remote: Option<Endpoint>,
    pub state: FlowState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub v: u32,
    /// Sample time, ms since the Unix epoch, from the Rust clock.
    pub t: u64,
    pub processes: Vec<ProcessInfo>,
    pub flows: Vec<Flow>,
}

// ---------------------------------------------------------------------------
// Persisted history (plan row 77). Mirror of the History types in
// `src/data/protocol.ts`; the grain table is mirrored by GRAINS in
// `src/core/history.ts` (the protocol law compares the three arrays below).
// Fixture: `src/data/fixtures/history-v1.json`.

/// Wire names of the stored grains, finest first.
pub const GRAIN_NAMES: [&str; 3] = ["minute", "hour", "day"];
/// Width of one bucket of each grain, ms.
pub const GRAIN_MS: [u64; 3] = [60_000, 3_600_000, 86_400_000];
/// How long each grain is kept, ms: 2 days of minutes, 35 days of hours, 400 days of days.
pub const GRAIN_KEEP_MS: [u64; 3] = [172_800_000, 3_024_000_000, 34_560_000_000];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Grain {
    Minute,
    Hour,
    Day,
}

impl Grain {
    /// Every grain in GRAIN_NAMES order.
    pub const ALL: [Grain; 3] = [Grain::Minute, Grain::Hour, Grain::Day];

    pub const fn index(self) -> usize {
        match self {
            Grain::Minute => 0,
            Grain::Hour => 1,
            Grain::Day => 2,
        }
    }

    pub const fn ms(self) -> u64 {
        GRAIN_MS[self.index()]
    }

    pub const fn keep_ms(self) -> u64 {
        GRAIN_KEEP_MS[self.index()]
    }
}

/// Active (non-listening) flows of one app in one sample. App identity is
/// decided on the TypeScript side (`appIdentity` in src/core/apps.ts), once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppCount {
    pub app: String,
    pub name: String,
    pub flows: u64,
}

/// One sample folded into history: its time and the apps that had active flows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryRecord {
    pub t: u64,
    pub apps: Vec<AppCount>,
}

/// Ask for history in [from, to) at one grain, summed into buckets `step` wide
/// (a whole multiple of the grain).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryQuery {
    pub from: u64,
    pub to: u64,
    pub grain: Grain,
    pub step: u64,
}

/// How many samples a bucket holds. A bucket with no samples is absent: no data, not zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleBucket {
    pub t: u64,
    pub n: u64,
}

/// Active flows of one app summed over a bucket's samples. Absent in a sampled bucket means 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppBucket {
    pub t: u64,
    pub app: String,
    pub name: String,
    pub flows: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct History {
    pub v: u32,
    pub grain: Grain,
    pub step: u64,
    /// Oldest first.
    pub samples: Vec<SampleBucket>,
    /// Oldest first, then by app key.
    pub apps: Vec<AppBucket>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../src/data/fixtures/snapshot-v1.json");
    const HISTORY_FIXTURE: &str = include_str!("../../src/data/fixtures/history-v1.json");

    #[test]
    fn history_fixture_round_trips_through_rust() {
        let h: History = serde_json::from_str(HISTORY_FIXTURE).expect("history fixture parses");
        assert_eq!(h.v, PROTOCOL_VERSION);
        let original: serde_json::Value = serde_json::from_str(HISTORY_FIXTURE).expect("fixture is json");
        assert_eq!(original, serde_json::to_value(&h).expect("serialises"));
    }

    #[test]
    fn grain_wire_names_match_the_shared_list() {
        for (g, name) in Grain::ALL.iter().zip(GRAIN_NAMES) {
            assert_eq!(serde_json::to_value(g).expect("serialises"), name);
        }
        for g in Grain::ALL {
            assert!(g.keep_ms() > g.ms(), "{g:?} keeps at least one bucket");
        }
    }

    #[test]
    fn fixture_round_trips_through_rust() {
        let snap: Snapshot = serde_json::from_str(FIXTURE).expect("fixture parses");
        assert_eq!(snap.v, PROTOCOL_VERSION);
        let original: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture is json");
        let again = serde_json::to_value(&snap).expect("serialises");
        assert_eq!(original, again);
    }

    #[test]
    fn flow_state_wire_names_match_the_shared_list() {
        for (state, name) in FlowState::ALL.iter().zip(FLOW_STATE_NAMES) {
            assert_eq!(serde_json::to_value(state).expect("serialises"), name);
        }
    }

    #[test]
    fn listening_flow_serialises_remote_as_null() {
        let f = Flow {
            pid: 1,
            proto: Proto::Tcp,
            family: Family::V4,
            local: Endpoint { addr: "127.0.0.1".into(), port: 80 },
            remote: None,
            state: FlowState::Listen,
        };
        let v = serde_json::to_value(&f).expect("serialises");
        assert!(v["remote"].is_null());
        assert_eq!(v["state"], "listen");
    }
}
