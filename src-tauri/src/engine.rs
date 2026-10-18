//! The filtering engine as the app sees it (plan 1.3, 1.6, 8): facts only,
//! read only, no admin. One command, `engine_probe() -> EngineProbe`:
//! - `service`: the state of the `sieve-engine` service from the service
//!   manager (connect and query access only), `missing` when not installed;
//! - `pipe` (only while the service runs): the engine's own answer over
//!   `\\.\pipe\sieve-engine` (protocol `sieve-ipc`): Welcome with its Status,
//!   Incompatible, the engine's refusal (only the installed app may connect),
//!   or unreachable with the reason.
//!
//! The app never starts, stops or installs the engine: the installer and the
//! user do. Wire shape in `src/data/fixtures/engine-probe-v1.json`.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sieve_ipc::{EngineStatus, PIPE_NAME, PROTOCOL};

pub const ENGINE_PROBE_VERSION: u32 = 1;
/// The engine's service name (sieve-engine `service::SERVICE_NAME`).
pub const SERVICE_NAME: &str = "sieve-engine";
/// A probe that gets no answer in this time reports the pipe unreachable.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

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
    Welcome { engine_version: String, session_id: u32, status: EngineStatus },
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
    /// None while the service is not running (the pipe is not asked).
    pub pipe: Option<PipeFact>,
}

/// The probe from its two facts.
pub fn probe_of(service: ServiceFact, pipe: Option<PipeFact>) -> EngineProbe {
    EngineProbe { v: ENGINE_PROBE_VERSION, service, pipe }
}

#[cfg(windows)]
mod imp {
    use sieve_ipc::nonblocking::{read_frame, write_frame};
    use sieve_ipc::{ClientMessage, EngineMessage};
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT, SERVICE_CONTINUE_PENDING,
        SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOP_PENDING,
        SERVICE_STOPPED,
    };
    use windows::core::{HSTRING, PCWSTR};

    use super::*;

    /// The service's state, read with connect and query access only.
    pub fn service_fact() -> Result<ServiceFact, String> {
        // SAFETY: plain SCM calls; every handle is closed below.
        unsafe {
            let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT).map_err(|e| format!("service manager: {e}"))?;
            let service = OpenServiceW(scm, &HSTRING::from(SERVICE_NAME), SERVICE_QUERY_STATUS);
            let fact = match service {
                Err(e) if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => Ok(ServiceFact::Missing),
                Err(e) => Err(format!("{SERVICE_NAME}: {e}")),
                Ok(handle) => {
                    let mut status = SERVICE_STATUS::default();
                    let read = QueryServiceStatus(handle, &mut status).map_err(|e| format!("{SERVICE_NAME} status: {e}"));
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

    async fn ask(name: &str) -> Result<PipeFact, String> {
        let mut pipe = ClientOptions::new().open(name).map_err(|e| e.to_string())?;
        let hello = ClientMessage::Hello { protocol: PROTOCOL, app_version: env!("CARGO_PKG_VERSION").to_string() };
        write_frame(&mut pipe, &hello).await.map_err(|e| e.to_string())?;
        let (engine_version, session_id) = match read_frame(&mut pipe).await.map_err(|e| e.to_string())? {
            EngineMessage::Welcome { engine_version, session_id, .. } => (engine_version, session_id),
            EngineMessage::Incompatible { supported } => return Ok(PipeFact::Incompatible { supported }),
            EngineMessage::Error { message } => return Ok(PipeFact::Refused { message }),
            other => return Err(format!("unexpected answer to hello: {other:?}")),
        };
        write_frame(&mut pipe, &ClientMessage::Status).await.map_err(|e| e.to_string())?;
        match read_frame(&mut pipe).await.map_err(|e| e.to_string())? {
            EngineMessage::Status(status) => Ok(PipeFact::Welcome { engine_version, session_id, status }),
            EngineMessage::Error { message } => Ok(PipeFact::Refused { message }),
            other => Err(format!("unexpected answer to status: {other:?}")),
        }
    }

    /// The engine's own answer on pipe `name`, or why there is none.
    pub async fn pipe_fact(name: &str) -> PipeFact {
        match tokio::time::timeout(PROBE_TIMEOUT, ask(name)).await {
            Ok(Ok(fact)) => fact,
            Ok(Err(message)) => PipeFact::Unreachable { message },
            Err(_) => PipeFact::Unreachable { message: format!("no answer in {} s", PROBE_TIMEOUT.as_secs()) },
        }
    }
}

/// Command: what the engine is, from facts. Fails only when the service
/// manager cannot be read at all.
#[cfg(windows)]
#[tauri::command]
pub async fn engine_probe() -> Result<EngineProbe, String> {
    let service = tauri::async_runtime::spawn_blocking(imp::service_fact).await.map_err(|e| e.to_string())??;
    let pipe = if service == ServiceFact::Running { Some(imp::pipe_fact(PIPE_NAME).await) } else { None };
    Ok(probe_of(service, pipe))
}

#[cfg(not(windows))]
#[tauri::command]
pub async fn engine_probe() -> Result<EngineProbe, String> {
    Ok(probe_of(ServiceFact::Missing, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const FIXTURE: &str = include_str!("../../src/data/fixtures/engine-probe-v1.json");

    #[test]
    fn every_fixture_example_round_trips_unchanged() {
        let f: Value = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(f["v"], ENGINE_PROBE_VERSION);
        let examples = f["examples"].as_object().unwrap();
        assert!(examples.len() >= 6);
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

    /// Read only, no admin: the service manager answers this test's account
    /// with one of the known facts (missing on a machine without Sieve).
    #[cfg(windows)]
    #[test]
    fn the_service_state_is_readable_without_admin() {
        assert!(imp::service_fact().is_ok());
    }

    /// A stand-in engine on a test pipe: answers Hello with `hello`, then
    /// Status with an idle status.
    #[cfg(windows)]
    async fn fake_engine(name: &str, hello: sieve_ipc::EngineMessage) -> PipeFact {
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
                assert_eq!(next, ClientMessage::Status);
                write_frame(&mut server, &EngineMessage::Status(EngineStatus::default())).await.unwrap();
            }
        });
        let fact = imp::pipe_fact(name).await;
        engine.await.unwrap();
        fact
    }

    #[cfg(windows)]
    fn test_pipe(tag: &str) -> String {
        format!(r"\\.\pipe\sieve-app-test-{tag}-{}", std::process::id())
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn the_probe_reads_welcome_and_status_incompatible_and_refusal() {
        use sieve_ipc::EngineMessage;
        let welcome = EngineMessage::Welcome { protocol: PROTOCOL, engine_version: "9.9.9".into(), session_id: 4 };
        assert_eq!(
            fake_engine(&test_pipe("welcome"), welcome).await,
            PipeFact::Welcome { engine_version: "9.9.9".into(), session_id: 4, status: EngineStatus::default() }
        );
        let old = EngineMessage::Incompatible { supported: [2, 3] };
        assert_eq!(fake_engine(&test_pipe("old"), old).await, PipeFact::Incompatible { supported: [2, 3] });
        let refused = EngineMessage::Error { message: "only the installed Sieve app may connect".into() };
        assert_eq!(
            fake_engine(&test_pipe("refused"), refused).await,
            PipeFact::Refused { message: "only the installed Sieve app may connect".into() }
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn no_engine_on_the_pipe_is_unreachable_with_the_reason() {
        assert!(matches!(imp::pipe_fact(&test_pipe("nobody")).await, PipeFact::Unreachable { .. }));
    }
}
