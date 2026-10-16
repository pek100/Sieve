//! Per-process connection source (plan row 78, slice S1).
//!
//! Read only, no admin, no drivers: the IP Helper owner-pid tables
//! (`tables.rs`), decoded by pure code (`decode.rs`), plus process image
//! names and version info (`process.rs`). A failure is an error, never an
//! empty or invented snapshot.

pub mod decode;
pub mod process;
pub mod tables;

use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocol::{Flow, PROTOCOL_VERSION, ProcessInfo, Snapshot};
use decode::{DecodeError, TableKind};

#[derive(Debug, thiserror::Error)]
pub enum NetstatError {
    #[error("reading the {kind:?} connection table failed (Windows error {code})")]
    Table { kind: TableKind, code: u32 },
    #[error("the {kind:?} connection table kept growing; gave up after {attempts} tries")]
    TableKeptGrowing { kind: TableKind, attempts: u32 },
    #[error("could not decode a connection table: {0}")]
    Decode(#[from] DecodeError),
    #[error("the system clock reads before 1970")]
    Clock,
    #[error("reading connections is only supported on Windows")]
    Unsupported,
}

/// Take one snapshot of the machine's sockets and their owning processes.
pub fn snapshot() -> Result<Snapshot, NetstatError> {
    let t = now_ms()?;
    let mut flows = Vec::new();
    for kind in TableKind::ALL {
        let buf = tables::read_table(kind)?;
        flows.extend(decode::decode_table(kind, &buf)?);
    }
    Ok(assemble(t, flows, |pid| process::describe(pid, process::exe_path, process::product_name)))
}

/// Build the snapshot: one process entry per distinct pid that owns a flow,
/// sorted by pid. `describe` is the per-pid lookup (injected for tests).
pub fn assemble(t: u64, flows: Vec<Flow>, describe: impl Fn(u32) -> ProcessInfo) -> Snapshot {
    let mut pids: Vec<u32> = flows.iter().map(|f| f.pid).collect();
    pids.sort_unstable();
    pids.dedup();
    let processes = pids.into_iter().map(describe).collect();
    Snapshot { v: PROTOCOL_VERSION, t, processes, flows }
}

/// Sample time from the Rust clock, ms since the Unix epoch.
fn now_ms() -> Result<u64, NetstatError> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| NetstatError::Clock)?;
    u64::try_from(since.as_millis()).map_err(|_| NetstatError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Endpoint, Family, FlowState, Proto};

    fn flow(pid: u32, port: u16) -> Flow {
        Flow {
            pid,
            proto: Proto::Udp,
            family: Family::V4,
            local: Endpoint { addr: "0.0.0.0".into(), port },
            remote: None,
            state: FlowState::None,
        }
    }

    #[test]
    fn assemble_lists_each_owning_pid_once_in_order() {
        let snap = assemble(1_792_224_000_000, vec![flow(9120, 1), flow(4, 2), flow(9120, 3)], |pid| {
            process::describe(pid, |_| None, |_| None)
        });
        assert_eq!(snap.v, PROTOCOL_VERSION);
        assert_eq!(snap.t, 1_792_224_000_000);
        let pids: Vec<u32> = snap.processes.iter().map(|p| p.pid).collect();
        assert_eq!(pids, vec![4, 9120]);
        assert_eq!(snap.processes[0].name, "System");
        assert_eq!(snap.processes[1].name, "pid 9120");
        assert_eq!(snap.flows.len(), 3);
    }

    #[test]
    fn assembled_snapshot_serialises_to_protocol_v1() {
        let snap = assemble(5, vec![flow(4, 53)], |pid| process::describe(pid, |_| None, |_| None));
        let json = serde_json::to_value(&snap).expect("serialises");
        assert_eq!(json["v"], 1);
        assert_eq!(json["processes"][0]["exe"], serde_json::Value::Null);
        assert_eq!(json["flows"][0]["state"], "none");
        let back: Snapshot = serde_json::from_value(json).expect("deserialises");
        assert_eq!(back, snap);
    }

    #[test]
    fn clock_is_after_2020() {
        assert!(now_ms().expect("clock") > 1_577_836_800_000);
    }

    /// Live check (needs the real machine, no admin): our own listener shows
    /// up with our pid, its port, state listen and our exe path.
    /// `cargo test --manifest-path src-tauri/Cargo.toml -- --ignored live_snapshot_reads_own_process`
    #[test]
    #[ignore = "live: reads this machine's connection tables"]
    fn live_snapshot_reads_own_process() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        let port = listener.local_addr().expect("local addr").port();
        let pid = std::process::id();

        let snap = snapshot().expect("snapshot");

        let mine = snap
            .flows
            .iter()
            .find(|f| f.pid == pid && f.local.port == port && f.proto == Proto::Tcp)
            .unwrap_or_else(|| panic!("no flow for pid {pid} port {port} among {} flows", snap.flows.len()));
        assert_eq!(mine.state, FlowState::Listen);
        assert_eq!(mine.family, Family::V4);
        assert_eq!(mine.local.addr, "127.0.0.1");
        assert_eq!(mine.remote, None);

        let me = snap.processes.iter().find(|p| p.pid == pid).expect("own process listed");
        let exe = std::env::current_exe().expect("current exe");
        let exe = exe.to_string_lossy();
        let got = me.exe.as_deref().expect("own exe path is readable");
        assert!(got.eq_ignore_ascii_case(&exe), "exe {got} != {exe}");
        assert_eq!(me.name, process::label(pid, Some(&exe)));

        let hidden = snap.processes.iter().filter(|p| p.exe.is_none()).count();
        eprintln!(
            "live snapshot: {} flows, {} processes, {} without a readable exe",
            snap.flows.len(),
            snap.processes.len(),
            hidden
        );
        drop(listener);
    }
}
