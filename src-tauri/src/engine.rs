//! The filtering engine as the app sees it (plan 1.3, 1.6, 8), no admin:
//! - `engine_probe() -> EngineProbe`, facts only, read only:
//!   - `service`: the `sieve-engine` service's state from the service manager
//!     (connect and query access only), `missing` when not installed;
//!   - `adguard`: AdGuard for Windows' service state, read the same way (the
//!     pause offer reads it beside the engine's blocker, which alone says
//!     whether AdGuard intercepts);
//!   - `pipe` (only while the service runs): the engine's own answer over
//!     `\\.\pipe\sieve-engine` (protocol `sieve-ipc` v3): Welcome with its
//!     Status, Incompatible, the engine's refusal (only the installed app may
//!     connect), or unreachable with the reason.
//! - `engine_set_policy(policy) -> EngineStatus`: sends the user's switches
//!   (the engine controller's whole policy) to the engine.
//! - `engine_lists() -> EngineLists`, `engine_lists_refresh() -> EngineLists`:
//!   the per-list report; the second also asks for a download of every list.
//! - [`EngineFlows`]: while the engine routes, a subscription to its `Flows`
//!   events; `net_snapshot` then builds the snapshot from them instead of
//!   the connection tables (whose rows would show every flow twice: the
//!   app's and the engine's own upstream socket).
//!
//! The app never starts, stops or installs the engine: the installer and the
//! user do. Wire shape in `src/data/fixtures/engine-probe-v2.json`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sieve_ipc::{EngineStatus, FlowEvent, FlowProto, ListStatus, PIPE_NAME, PROTOCOL, Policy};

use crate::protocol::{Endpoint, Family, Flow, FlowState, Proto};

pub const ENGINE_PROBE_VERSION: u32 = 2;
/// The engine's service name (sieve-engine `service::SERVICE_NAME`).
pub const SERVICE_NAME: &str = "sieve-engine";
/// A probe that gets no answer in this time reports the pipe unreachable.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// The flow subscription retries this often while it is not connected.
pub const SUBSCRIBE_RETRY: Duration = Duration::from_secs(2);

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

/// The engine's per-list report (its `Lists` message).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineLists {
    pub lists: Vec<ListStatus>,
    pub compile_ms: Option<u64>,
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

    /// Asks for the list report on pipe `name` (`msg` is Lists or ListsRefresh).
    pub async fn lists(name: &str, msg: ClientMessage) -> Result<EngineLists, String> {
        let exchange = async {
            let mut pipe = match hello(name).await? {
                Ok((pipe, _, _)) => pipe,
                Err(PipeFact::Incompatible { supported }) => return Err(format!("the engine speaks protocol {} to {}", supported[0], supported[1])),
                Err(PipeFact::Refused { message } | PipeFact::Unreachable { message }) => return Err(message),
                Err(other) => return Err(format!("unexpected answer to hello: {other:?}")),
            };
            write_frame(&mut pipe, &msg).await.map_err(|e| e.to_string())?;
            match read_frame(&mut pipe).await.map_err(|e| e.to_string())? {
                EngineMessage::Lists { lists, compile_ms } => Ok(EngineLists { lists, compile_ms }),
                EngineMessage::Error { message } => Err(message),
                other => Err(format!("unexpected answer: {other:?}")),
            }
        };
        match tokio::time::timeout(PROBE_TIMEOUT, exchange).await {
            Ok(answer) => answer,
            Err(_) => Err(format!("no answer in {} s", PROBE_TIMEOUT.as_secs())),
        }
    }

    /// One subscription: Hello, Status; while the engine routes, Subscribe
    /// and apply every batch until the engine ends the stream (its routes
    /// went down) or the pipe breaks.
    pub async fn subscribe_once(name: &str, flows: &EngineFlows) -> Result<(), String> {
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
                Ok(_) => {}
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

/// Keeps the subscription to the engine's flows for the app's lifetime:
/// connect, follow while the engine routes, retry every [`SUBSCRIBE_RETRY`].
#[cfg(windows)]
pub async fn follow_flows(flows: std::sync::Arc<EngineFlows>) {
    loop {
        let _ = imp::subscribe_once(PIPE_NAME, &flows).await;
        tokio::time::sleep(SUBSCRIBE_RETRY).await;
    }
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

/// Command: the engine's per-list report.
#[cfg(windows)]
#[tauri::command]
pub async fn engine_lists() -> Result<EngineLists, String> {
    imp::lists(PIPE_NAME, sieve_ipc::ClientMessage::Lists).await
}

/// Command: asks the engine to download every selected list now.
#[cfg(windows)]
#[tauri::command]
pub async fn engine_lists_refresh() -> Result<EngineLists, String> {
    imp::lists(PIPE_NAME, sieve_ipc::ClientMessage::ListsRefresh).await
}

#[cfg(not(windows))]
#[tauri::command]
pub async fn engine_lists() -> Result<EngineLists, String> {
    Err("the engine runs on Windows only".into())
}

#[cfg(not(windows))]
#[tauri::command]
pub async fn engine_lists_refresh() -> Result<EngineLists, String> {
    Err("the engine runs on Windows only".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const FIXTURE: &str = include_str!("../../src/data/fixtures/engine-probe-v2.json");
    const IPC_FIXTURE: &str = include_str!("../../src/data/fixtures/engine-ipc-v3.json");

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
        assert_eq!(rows.len(), 5, "the unattributed QUIC flow and both forwarded flows are left out");
        assert!(fixture_flows().iter().filter(|f| f.forwarded.is_some()).count() == 2);
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
        // Open in the fixture: ids 7, 9 (no pid), 11, and 13 and 14 (forwarded, no pid); 8, 10 and 12 are closed.
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
        let fact = match ask.clone() {
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
    #[derive(Clone)]
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
        let on = Policy { revision: 2, engine: true, sieving: true, off_apps: vec!["firefox".into()], ..Policy::default() };
        let welcome = || EngineMessage::Welcome { protocol: PROTOCOL, engine_version: "0.1.0".into(), session_id: 1 };
        let after = EngineStatus { policy: on.clone(), ..EngineStatus::default() };
        let got = fake_engine(&test_pipe("policy"), welcome(), EngineMessage::Status(after.clone()), ClientAsk::Policy(on.clone())).await;
        assert!(matches!(got, Ok(PipeFact::Welcome { status, .. }) if *status == after));
        let stale = EngineMessage::Error { message: "stale policy revision 2 (the engine holds 5)".into() };
        let got = fake_engine(&test_pipe("stale"), welcome(), stale, ClientAsk::Policy(on)).await;
        assert_eq!(got, Err("stale policy revision 2 (the engine holds 5)".into()));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn the_list_report_comes_from_the_engine_or_says_why_not() {
        use sieve_ipc::nonblocking::{read_frame, write_frame};
        use sieve_ipc::{ClientMessage, EngineMessage};
        use tokio::net::windows::named_pipe::ServerOptions;

        let name = test_pipe("lists");
        let mut server = ServerOptions::new().first_pipe_instance(true).create(&name).unwrap();
        let report = vec![ListStatus { id: "adguard-dns".into(), network: 3, ..ListStatus::default() }];
        let answer = EngineMessage::Lists { lists: report.clone(), compile_ms: Some(9) };
        let engine = tokio::spawn(async move {
            server.connect().await.unwrap();
            let _: ClientMessage = read_frame(&mut server).await.unwrap();
            write_frame(&mut server, &EngineMessage::Welcome { protocol: PROTOCOL, engine_version: "0.1.0".into(), session_id: 1 }).await.unwrap();
            let asked: ClientMessage = read_frame(&mut server).await.unwrap();
            write_frame(&mut server, &answer).await.unwrap();
            asked
        });
        let got = imp::lists(&name, ClientMessage::ListsRefresh).await.unwrap();
        assert_eq!(got, EngineLists { lists: report, compile_ms: Some(9) });
        assert_eq!(engine.await.unwrap(), ClientMessage::ListsRefresh);
        assert!(imp::lists(&test_pipe("lists-nobody"), ClientMessage::Lists).await.is_err());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn no_engine_on_the_pipe_is_unreachable_with_the_reason() {
        assert!(matches!(imp::pipe_fact(&test_pipe("nobody")).await, PipeFact::Unreachable { .. }));
    }
}
