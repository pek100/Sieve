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

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../src/data/fixtures/snapshot-v1.json");

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
