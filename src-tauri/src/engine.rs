//! The filtering engine as the app sees it (plan 1.3, 1.6, 8), no admin:
//! - `engine_probe() -> EngineProbe`, facts only, read only:
//!   - `service`: the `sieve-engine` service's state from the service manager
//!     (connect and query access only), `missing` when not installed;
//!   - `adguard`: AdGuard for Windows' service state, read the same way (the
//!     pause offer and its undo follow it);
//!   - `pipe` (only while the service runs): the engine's own answer over
//!     `\\.\pipe\sieve-engine` (protocol `sieve-ipc` v2): Welcome with its
//!     Status, Incompatible, the engine's refusal (only the installed app may
//!     connect), or unreachable with the reason.
//! - `engine_set_policy(policy) -> EngineStatus`: sends the user's switch
//!   (`filtering.engine`) to the engine.
//! - [`EngineFlows`]: while the engine routes, a subscription to its `Flows`
//!   events; `net_snapshot` then builds the snapshot from them instead of
//!   the connection tables (whose rows would show every flow twice: the
//!   app's and the engine's own upstream socket).
//! - [`EngineLog`], `engine_log_tail(since) -> LogTail`: the same subscription
//!   feeds a memory ring of the engine's `Log` rows, which the window polls.
//!   `seq` is assigned on receipt, so an engine restart (its row ids restart)
//!   cannot strand the window's cursor. Session only, in memory (plan 8.3).
//!
//! The app never starts, stops or installs the engine: the installer and the
//! user do. Wire shape in `src/data/fixtures/engine-probe-v2.json`.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sieve_ipc::{EngineStatus, FlowEvent, FlowProto, LogRow, PIPE_NAME, PROTOCOL, Policy};

use crate::protocol::{Endpoint, Family, Flow, FlowState, Proto};

pub const ENGINE_PROBE_VERSION: u32 = 2;
/// The engine's service name (sieve-engine `service::SERVICE_NAME`).
pub const SERVICE_NAME: &str = "sieve-engine";
/// A probe that gets no answer in this time reports the pipe unreachable.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// The flow subscription retries this often while it is not connected.
pub const SUBSCRIBE_RETRY: Duration = Duration::from_secs(2);
/// `engine_log_tail`'s wire version (`LOG_TAIL_VERSION` in src/data/protocol.ts).
pub const LOG_TAIL_VERSION: u32 = 1;
/// Log rows kept for the window to read; older ones drop and are counted.
pub const ENGINE_LOG_CAP: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceFact {
    Missing,
    Stopped,
    Starting,
    Stopping,
    Running,
    /// Paused, or a state this build does not know.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PipeFact {
    Welcome { engine_version: String, session_id: u32, status: Box<EngineStatus> },
    Incompatible { supported: [u32; 2] },
    /// The engine answered with an error (for example: this is not the
    /// installed app).
    Refused { message: String },
    Unreachable { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineProbe {
    pub v: u32,
    pub service: ServiceFact,
    /// AdGuard for Windows' service (`crate::adguard::ADGUARD_SERVICE`).
    pub adguard: ServiceFact,
    /// None while the service is not running (the pipe is not asked).
    pub pipe: Option<PipeFact>,
}

/// The probe from its facts.
pub fn probe_of(service: ServiceFact, adguard: ServiceFact, pipe: Option<PipeFact>) -> EngineProbe {
    EngineProbe { v: ENGINE_PROBE_VERSION, service, adguard, pipe }
}

/// The engine's open flows as the subscription last heard them, and whether
/// the subscription is live (the engine routes and streams to this app).
#[derive(Debug, Default)]
pub struct EngineFlows {
    inner: Mutex<FlowsState>,
}

#[derive(Debug, Default)]
struct FlowsState {
    live: bool,
    open: HashMap<u64, FlowEvent>,
}

impl EngineFlows {
    fn state(&self) -> std::sync::MutexGuard<'_, FlowsState> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A subscription began (or ended): the flow set starts empty.
    pub fn set_live(&self, live: bool) {
        let mut s = self.state();
        s.live = live;
        s.open.clear();
    }

    /// Applies one `flows` batch: open flows are kept, closed ones dropped.
    pub fn apply(&self, batch: Vec<FlowEvent>) {
        let mut s = self.state();
        for e in batch {
            if e.open {
                s.open.insert(e.id, e);
            } else {
                s.open.remove(&e.id);
            }
        }
    }

    /// The open flows as snapshot rows, while the subscription is live.
    pub fn flows(&self) -> Option<Vec<Flow>> {
        let s = self.state();
        s.live.then(|| {
            let mut events: Vec<&FlowEvent> = s.open.values().collect();
            events.sort_by_key(|e| e.id);
            events.into_iter().filter_map(snapshot_flow).collect()
        })
    }
}

/// A log row and its place in this app's own count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    pub seq: u64,
    pub row: LogRow,
}

/// `engine_log_tail`: the rows after the asked `seq`. Wire shape in
/// `src/data/fixtures/engine-log-v1.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogTail {
    pub v: u32,
    /// Ask for rows after this next time.
    pub next: u64,
    /// Rows the ring dropped before this reader saw them.
    pub dropped: u64,
    pub rows: Vec<LogEntry>,
}

/// The engine's log rows as the subscription heard them, newest last, at most
/// [`ENGINE_LOG_CAP`]. `seq` keeps rising across subscriptions.
#[derive(Debug, Default)]
pub struct EngineLog {
    inner: Mutex<LogRing>,
}

#[derive(Debug, Default)]
struct LogRing {
    last_seq: u64,
    rows: VecDeque<LogEntry>,
}

impl EngineLog {
    fn ring(&self) -> std::sync::MutexGuard<'_, LogRing> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Applies one `log` batch, dropping the oldest past the cap.
    pub fn push(&self, batch: Vec<LogRow>) {
        let mut r = self.ring();
        for row in batch {
            r.last_seq += 1;
            let seq = r.last_seq;
            r.rows.push_back(LogEntry { seq, row });
            if r.rows.len() > ENGINE_LOG_CAP {
                r.rows.pop_front();
            }
        }
    }

    /// The rows after `since`, and how many between it and them are gone.
    pub fn tail(&self, since: u64) -> LogTail {
        let r = self.ring();
        let rows: Vec<LogEntry> = r.rows.iter().filter(|e| e.seq > since).cloned().collect();
        let oldest = r.rows.front().map_or(r.last_seq + 1, |e| e.seq);
        // A cursor from the future (it cannot happen in one run) reads nothing and stays put.
        LogTail { v: LOG_TAIL_VERSION, next: r.last_seq.max(since), dropped: oldest.saturating_sub(since + 1), rows }
    }
}

fn endpoint(text: &str) -> Option<(Family, Endpoint)> {
    let addr: SocketAddr = text.parse().ok()?;
    let family = if addr.is_ipv4() { Family::V4 } else { Family::V6 };
    Some((family, Endpoint { addr: addr.ip().to_string(), port: addr.port() }))
}

/// One engine flow as a snapshot row, with the same meaning as a
/// connection-table row (the same measurand, S20): an open TCP flow is
/// established with its remote end; a UDP flow has no remote end, as UDP
/// owner rows have none. A flow with no process (attribution gave up) is not
/// an app's and is left out; the engine counts it.
pub fn snapshot_flow(e: &FlowEvent) -> Option<Flow> {
    let pid = e.pid?;
    let (family, local) = endpoint(&e.local)?;
    let (proto, remote, state) = match e.proto {
        FlowProto::Tcp => (Proto::Tcp, Some(endpoint(&e.remote)?.1), FlowState::Established),
        FlowProto::Udp => (Proto::Udp, None, FlowState::None),
    };
    Some(Flow { pid, proto, family, local, remote, state })
}

#[cfg(windows)]
mod imp {
    use sieve_ipc::nonblocking::{read_frame, write_frame};
    use sieve_ipc::{ClientMessage, EngineMessage};
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
    use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT, SERVICE_CONTINUE_PENDING,
        SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOP_PENDING,
        SERVICE_STOPPED,
    };
    use windows::core::{HSTRING, PCWSTR};

    use super::*;

    /// A service's state, read with connect and query access only.
    pub fn service_fact(name: &str) -> Result<ServiceFact, String> {
        // SAFETY: plain SCM calls; every handle is closed below.
        unsafe {
            let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT).map_err(|e| format!("service manager: {e}"))?;
            let service = OpenServiceW(scm, &HSTRING::from(name), SERVICE_QUERY_STATUS);
            let fact = match service {
                Err(e) if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => Ok(ServiceFact::Missing),
                Err(e) => Err(format!("{name}: {e}")),
                Ok(handle) => {
                    let mut status = SERVICE_STATUS::default();
                    let read = QueryServiceStatus(handle, &mut status).map_err(|e| format!("{name} status: {e}"));
                    let _ = CloseServiceHandle(handle);
                    read.map(|()| match status.dwCurrentState {
                        SERVICE_STOPPED => ServiceFact::Stopped,
                        SERVICE_START_PENDING | SERVICE_CONTINUE_PENDING => ServiceFact::Starting,
                        SERVICE_STOP_PENDING => ServiceFact::Stopping,
                        SERVICE_RUNNING => ServiceFact::Running,
                        _ => ServiceFact::Other,
                    })
                }
            };
            let _ = CloseServiceHandle(scm);
            fact
        }
    }

    /// Opens the pipe and says Hello; the Welcome's session, or the fact
    /// that ends the conversation.
    async fn hello(name: &str) -> Result<Result<(NamedPipeClient, String, u32), PipeFact>, String> {
        let mut pipe = ClientOptions::new().open(name).map_err(|e| e.to_string())?;
        let hello = ClientMessage::Hello { protocol: PROTOCOL, app_version: env!("CARGO_PKG_VERSION").to_string() };
        write_frame(&mut pipe, &hello).await.map_err(|e| e.to_string())?;
        Ok(match read_frame(&mut pipe).await.map_err(|e| e.to_string())? {
            EngineMessage::Welcome { engine_version, session_id, .. } => Ok((pipe, engine_version, session_id)),
            EngineMessage::Incompatible { supported } => Err(PipeFact::Incompatible { supported }),
            EngineMessage::Error { message } => Err(PipeFact::Refused { message }),
            other => return Err(format!("unexpected answer to hello: {other:?}")),
        })
    }

    /// One request after Hello, answered with a Status (or the engine's error).
    async fn request(name: &str, msg: ClientMessage) -> Result<PipeFact, String> {
        let (mut pipe, engine_version, session_id) = match hello(name).await? {
            Ok(w) => w,
            Err(fact) => return Ok(fact),
        };
        write_frame(&mut pipe, &msg).await.map_err(|e| e.to_string())?;
        match read_frame(&mut pipe).await.map_err(|e| e.to_string())? {
            EngineMessage::Status(status) => Ok(PipeFact::Welcome { engine_version, session_id, status: Box::new(status) }),
            EngineMessage::Error { message } => Ok(PipeFact::Refused { message }),
            other => Err(format!("unexpected answer: {other:?}")),
        }
    }

    /// The engine's own answer on pipe `name`, or why there is none.
    pub async fn pipe_fact(name: &str) -> PipeFact {
        match tokio::time::timeout(PROBE_TIMEOUT, request(name, ClientMessage::Status)).await {
            Ok(Ok(fact)) => fact,
            Ok(Err(message)) => PipeFact::Unreachable { message },
            Err(_) => PipeFact::Unreachable { message: format!("no answer in {} s", PROBE_TIMEOUT.as_secs()) },
        }
    }

    /// Sends the policy; the engine's Status after it, or why not.
    pub async fn set_policy(name: &str, policy: Policy) -> Result<EngineStatus, String> {
        match tokio::time::timeout(PROBE_TIMEOUT, request(name, ClientMessage::SetPolicy(policy))).await {
            Ok(Ok(PipeFact::Welcome { status, .. })) => Ok(*status),
            Ok(Ok(PipeFact::Refused { message } | PipeFact::Unreachable { message })) => Err(message),
            Ok(Ok(PipeFact::Incompatible { supported })) => Err(format!("the engine speaks protocol {} to {}", supported[0], supported[1])),
            Ok(Err(message)) => Err(message),
            Err(_) => Err(format!("no answer in {} s", PROBE_TIMEOUT.as_secs())),
        }
    }

    /// One subscription: Hello, Status; while the engine routes, Subscribe
    /// and apply every batch until the engine ends the stream (its routes
    /// went down) or the pipe breaks.
    pub async fn subscribe_once(name: &str, flows: &EngineFlows, log: &EngineLog) -> Result<(), String> {
        let (mut pipe, _, _) = hello(name).await?.map_err(|f| format!("{f:?}"))?;
        write_frame(&mut pipe, &ClientMessage::Status).await.map_err(|e| e.to_string())?;
        match read_frame(&mut pipe).await.map_err(|e| e.to_string())? {
            EngineMessage::Status(s) if s.routes_up => {}
            _ => return Ok(()),
        }
        write_frame(&mut pipe, &ClientMessage::Subscribe).await.map_err(|e| e.to_string())?;
        flows.set_live(true);
        let result = loop {
            match read_frame::<_, EngineMessage>(&mut pipe).await {
                Ok(EngineMessage::Flows { flows: batch }) => flows.apply(batch),
                Ok(EngineMessage::Log { rows }) => log.push(rows),
                Ok(EngineMessage::Welcome { .. } | EngineMessage::Incompatible { .. } | EngineMessage::Status(_) | EngineMessage::Error { .. }) => {}
                Err(sieve_ipc::FrameError::Closed) => break Ok(()),
                Err(e) => break Err(e.to_string()),
            }
        };
        flows.set_live(false);
        result
    }
}

/// A service's state (connect and query access only).
#[cfg(windows)]
pub fn service_fact(name: &str) -> Result<ServiceFact, String> {
    imp::service_fact(name)
}

/// Keeps the subscription to the engine's flows and log for the app's
/// lifetime: connect, follow while the engine routes, retry every
/// [`SUBSCRIBE_RETRY`].
#[cfg(windows)]
pub async fn follow_flows(flows: std::sync::Arc<EngineFlows>, log: std::sync::Arc<EngineLog>) {
    loop {
        let _ = imp::subscribe_once(PIPE_NAME, &flows, &log).await;
        tokio::time::sleep(SUBSCRIBE_RETRY).await;
    }
}

/// Command: the log rows after `since`, from the ring the subscription feeds.
#[tauri::command]
pub async fn engine_log_tail(since: u64, log: tauri::State<'_, std::sync::Arc<EngineLog>>) -> Result<LogTail, String> {
    Ok(log.tail(since))
}

/// Command: what the engine is, from facts. Fails only when the service
/// manager cannot be read at all.
#[cfg(windows)]
#[tauri::command]
pub async fn engine_probe() -> Result<EngineProbe, String> {
    let (service, adguard) = tauri::async_runtime::spawn_blocking(|| {
        Ok::<_, String>((imp::service_fact(SERVICE_NAME)?, imp::service_fact(crate::adguard::ADGUARD_SERVICE)?))
    })
    .await
    .map_err(|e| e.to_string())??;
    let pipe = if service == ServiceFact::Running { Some(imp::pipe_fact(PIPE_NAME).await) } else { None };
    Ok(probe_of(service, adguard, pipe))
}

#[cfg(not(windows))]
#[tauri::command]
pub async fn engine_probe() -> Result<EngineProbe, String> {
    Ok(probe_of(ServiceFact::Missing, ServiceFact::Missing, None))
}

/// Command: the user's switch to the engine (the engine controller sends it
/// whenever the engine holds another value). The engine's Status after it.
#[cfg(windows)]
#[tauri::command]
pub async fn engine_set_policy(policy: Policy) -> Result<EngineStatus, String> {
    imp::set_policy(PIPE_NAME, policy).await
}

#[cfg(not(windows))]
#[tauri::command]
pub async fn engine_set_policy(_policy: Policy) -> Result<EngineStatus, String> {
    Err("the engine runs on Windows only".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const FIXTURE: &str = include_str!("../../src/data/fixtures/engine-probe-v2.json");
    const IPC_FIXTURE: &str = include_str!("../../src/data/fixtures/engine-ipc-v2.json");
    const LOG_FIXTURE: &str = include_str!("../../src/data/fixtures/engine-log-v1.json");

    fn row(id: u64) -> LogRow {
        LogRow {
            id,
            t: 1_760_000_000_000,
            flow_id: id,
            pid: Some(4),
            exe: None,
            session: Some(1),
            kind: sieve_ipc::FlowKind::Tls,
            host: "example.com".into(),
            remote: "192.0.2.1:443".into(),
            url: None,
            request_type: None,
            outcome: sieve_ipc::LogOutcome::Blocked,
            rule: Some("||example.com^".into()),
            list: Some("adguard-base".into()),
        }
    }

    #[test]
    fn the_log_fixture_round_trips_unchanged() {
        let f: Value = serde_json::from_str(LOG_FIXTURE).unwrap();
        let tail: LogTail = serde_json::from_value(f.clone()).unwrap();
        assert_eq!(tail.v, LOG_TAIL_VERSION);
        assert_eq!(serde_json::to_value(&tail).unwrap(), f);
    }

    #[test]
    fn the_log_tail_answers_rows_after_the_cursor() {
        let log = EngineLog::default();
        assert_eq!(log.tail(0), LogTail { v: LOG_TAIL_VERSION, next: 0, dropped: 0, rows: vec![] });
        log.push(vec![row(1), row(2), row(3)]);
        let all = log.tail(0);
        assert_eq!(all.rows.iter().map(|e| e.seq).collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!((all.next, all.dropped), (3, 0));
        let rest = log.tail(2);
        assert_eq!(rest.rows.iter().map(|e| e.row.id).collect::<Vec<_>>(), [3]);
        let none = log.tail(3);
        assert_eq!((none.next, none.dropped, none.rows.len()), (3, 0, 0));
    }

    #[test]
    fn the_log_ring_drops_the_oldest_at_the_cap_and_counts_it() {
        let log = EngineLog::default();
        log.push((0..ENGINE_LOG_CAP as u64 + 5).map(row).collect());
        let tail = log.tail(0);
        assert_eq!(tail.rows.len(), ENGINE_LOG_CAP);
        assert_eq!(tail.rows[0].seq, 6);
        assert_eq!(tail.dropped, 5);
        assert_eq!(log.tail(3).dropped, 2, "a reader partway through lost only what it had not read");
        assert_eq!(log.tail(tail.next).dropped, 0);
    }

    /// The window's cursor never strands: `seq` is the app's, and an engine
    /// restart (row ids from 1 again) or a new subscription keeps it rising.
    #[test]
    fn seq_keeps_rising_when_the_engines_row_ids_restart() {
        let log = EngineLog::default();
        log.push(vec![row(1), row(2)]);
        let cursor = log.tail(0).next;
        log.push(vec![row(1)]);
        let tail = log.tail(cursor);
        assert_eq!(tail.rows.iter().map(|e| (e.seq, e.row.id)).collect::<Vec<_>>(), [(3, 1)]);
    }

    #[test]
    fn every_fixture_example_round_trips_unchanged() {
        let f: Value = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(f["v"], ENGINE_PROBE_VERSION);
        let examples = f["examples"].as_object().unwrap();
        assert!(examples.len() >= 12);
        for (name, example) in examples {
            let probe: EngineProbe = serde_json::from_value(example.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(&serde_json::to_value(&probe).unwrap(), example, "{name}");
        }
    }

    #[test]
    fn the_service_name_is_the_engines() {
        let engine = include_str!("../../engine/crates/sieve-engine/src/service/mod.rs");
        assert!(engine.contains(&format!("pub const SERVICE_NAME: &str = \"{SERVICE_NAME}\";")));
    }

    fn fixture_flows() -> Vec<FlowEvent> {
        let f: Value = serde_json::from_str(IPC_FIXTURE).unwrap();
        let msg = f["engine"].as_array().unwrap().iter().find(|m| m["type"] == "flows").unwrap().clone();
        serde_json::from_value(msg["flows"].clone()).unwrap()
    }

    /// The fixture's flows as snapshot rows: TCP open flows are established
    /// with their remote end, UDP has none, and a flow with no process is
    /// left out (as connection-table rows of no app would be).
    #[test]
    fn engine_flows_become_snapshot_rows_with_the_tables_meaning() {
        let rows: Vec<Flow> = fixture_flows().iter().filter_map(snapshot_flow).collect();
        assert_eq!(rows.len(), 4, "the unattributed QUIC flow is left out");
        assert_eq!(rows[0].pid, 4242);
        assert_eq!((rows[0].proto, rows[0].family, rows[0].state), (Proto::Tcp, Family::V4, FlowState::Established));
        assert_eq!(rows[0].local, Endpoint { addr: "198.18.0.1".into(), port: 50112 });
        assert_eq!(rows[0].remote, Some(Endpoint { addr: "93.184.215.14".into(), port: 443 }));
        assert_eq!((rows[1].proto, rows[1].remote.clone(), rows[1].state), (Proto::Udp, None, FlowState::None));
    }

    #[test]
    fn the_subscription_keeps_open_flows_and_nothing_while_not_live() {
        let flows = EngineFlows::default();
        assert_eq!(flows.flows(), None, "not live: the app reads the connection tables");
        flows.set_live(true);
        flows.apply(fixture_flows());
        // Open in the fixture: ids 7, 9 (no pid) and 11; 8 and 10 are closed.
        assert_eq!(flows.flows().unwrap().iter().map(|f| f.pid).collect::<Vec<_>>(), [4242, 912]);
        let mut close = fixture_flows()[0].clone();
        close.open = false;
        flows.apply(vec![close]);
        assert_eq!(flows.flows().unwrap().len(), 1);
        flows.set_live(false);
        assert_eq!(flows.flows(), None);
        flows.set_live(true);
        assert_eq!(flows.flows(), Some(vec![]), "a new subscription starts from the engine's open flows");
    }

    /// Read only, no admin: the service manager answers this test's account
    /// with one of the known facts (missing on a machine without Sieve).
    #[cfg(windows)]
    #[test]
    fn the_service_state_is_readable_without_admin() {
        assert!(imp::service_fact(SERVICE_NAME).is_ok());
        assert!(imp::service_fact(crate::adguard::ADGUARD_SERVICE).is_ok());
    }

    /// A stand-in engine on a test pipe: answers Hello with `hello`, then
    /// the next request with `then`.
    #[cfg(windows)]
    async fn fake_engine(name: &str, hello: sieve_ipc::EngineMessage, then: sieve_ipc::EngineMessage, ask: ClientAsk) -> Result<PipeFact, String> {
        use sieve_ipc::nonblocking::{read_frame, write_frame};
        use sieve_ipc::{ClientMessage, EngineMessage};
        use tokio::net::windows::named_pipe::ServerOptions;

        let mut server = ServerOptions::new().first_pipe_instance(true).create(name).unwrap();
        let engine = tokio::spawn(async move {
            server.connect().await.unwrap();
            let first: ClientMessage = read_frame(&mut server).await.unwrap();
            assert!(matches!(first, ClientMessage::Hello { protocol: PROTOCOL, .. }));
            let welcomed = matches!(hello, EngineMessage::Welcome { .. });
            write_frame(&mut server, &hello).await.unwrap();
            if welcomed {
                let next: ClientMessage = read_frame(&mut server).await.unwrap();
                write_frame(&mut server, &then).await.unwrap();
                Some(next)
            } else {
                None
            }
        });
        let fact = match ask {
            ClientAsk::Status => Ok(imp::pipe_fact(name).await),
            ClientAsk::Policy(p) => imp::set_policy(name, p).await.map(|status| PipeFact::Welcome { engine_version: String::new(), session_id: 0, status: Box::new(status) }),
        };
        let asked = engine.await.unwrap();
        if let (Some(asked), ClientAsk::Policy(p)) = (asked, ask) {
            assert_eq!(asked, ClientMessage::SetPolicy(p));
        }
        fact
    }

    #[cfg(windows)]
    #[derive(Clone, Copy)]
    enum ClientAsk {
        Status,
        Policy(Policy),
    }

    #[cfg(windows)]
    fn test_pipe(tag: &str) -> String {
        format!(r"\\.\pipe\sieve-app-test-{tag}-{}", std::process::id())
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn the_probe_reads_welcome_and_status_incompatible_and_refusal() {
        use sieve_ipc::EngineMessage;
        let status = || EngineMessage::Status(EngineStatus::default());
        let welcome = EngineMessage::Welcome { protocol: PROTOCOL, engine_version: "9.9.9".into(), session_id: 4 };
        assert_eq!(
            fake_engine(&test_pipe("welcome"), welcome, status(), ClientAsk::Status).await,
            Ok(PipeFact::Welcome { engine_version: "9.9.9".into(), session_id: 4, status: Box::default() })
        );
        let old = EngineMessage::Incompatible { supported: [3, 3] };
        assert_eq!(fake_engine(&test_pipe("old"), old, status(), ClientAsk::Status).await, Ok(PipeFact::Incompatible { supported: [3, 3] }));
        let refused = EngineMessage::Error { message: "only the installed Sieve app may connect".into() };
        assert_eq!(
            fake_engine(&test_pipe("refused"), refused, status(), ClientAsk::Status).await,
            Ok(PipeFact::Refused { message: "only the installed Sieve app may connect".into() })
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn set_policy_sends_the_switch_and_returns_the_engines_status_or_its_refusal() {
        use sieve_ipc::EngineMessage;
        let on = Policy { revision: 2, engine: true };
        let welcome = || EngineMessage::Welcome { protocol: PROTOCOL, engine_version: "0.1.0".into(), session_id: 1 };
        let after = EngineStatus { policy: on, ..EngineStatus::default() };
        let got = fake_engine(&test_pipe("policy"), welcome(), EngineMessage::Status(after.clone()), ClientAsk::Policy(on)).await;
        assert!(matches!(got, Ok(PipeFact::Welcome { status, .. }) if *status == after));
        let stale = EngineMessage::Error { message: "stale policy revision 2 (the engine holds 5)".into() };
        let got = fake_engine(&test_pipe("stale"), welcome(), stale, ClientAsk::Policy(on)).await;
        assert_eq!(got, Err("stale policy revision 2 (the engine holds 5)".into()));
    }

    /// A stand-in engine on a test pipe: routes, takes the subscription, sends
    /// a flows frame and a log frame, then closes. The rows reach the tail with
    /// a `seq`, and a second subscription keeps counting.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_log_frame_on_the_subscription_reaches_the_tail() {
        use sieve_ipc::nonblocking::{read_frame, write_frame};
        use sieve_ipc::{ClientMessage, EngineMessage};
        use tokio::net::windows::named_pipe::ServerOptions;

        let name = test_pipe("log");
        let flows = EngineFlows::default();
        let log = EngineLog::default();
        for round in 0..2u64 {
            let mut server = if round == 0 {
                ServerOptions::new().first_pipe_instance(true).create(&name).unwrap()
            } else {
                ServerOptions::new().create(&name).unwrap()
            };
            let engine = tokio::spawn(async move {
                server.connect().await.unwrap();
                let _: ClientMessage = read_frame(&mut server).await.unwrap();
                write_frame(&mut server, &EngineMessage::Welcome { protocol: PROTOCOL, engine_version: "0.1.0".into(), session_id: 1 }).await.unwrap();
                let _: ClientMessage = read_frame(&mut server).await.unwrap();
                let status = EngineStatus { routes_up: true, ..EngineStatus::default() };
                write_frame(&mut server, &EngineMessage::Status(status)).await.unwrap();
                let asked: ClientMessage = read_frame(&mut server).await.unwrap();
                assert_eq!(asked, ClientMessage::Subscribe);
                write_frame(&mut server, &EngineMessage::Flows { flows: vec![] }).await.unwrap();
                write_frame(&mut server, &EngineMessage::Log { rows: vec![row(1), row(2)] }).await.unwrap();
            });
            imp::subscribe_once(&name, &flows, &log).await.unwrap();
            engine.await.unwrap();
        }
        let tail = log.tail(0);
        assert_eq!(tail.rows.iter().map(|e| (e.seq, e.row.id)).collect::<Vec<_>>(), [(1, 1), (2, 2), (3, 1), (4, 2)]);
        assert_eq!(tail.next, 4);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn no_engine_on_the_pipe_is_unreachable_with_the_reason() {
        assert!(matches!(imp::pipe_fact(&test_pipe("nobody")).await, PipeFact::Unreachable { .. }));
    }
}
