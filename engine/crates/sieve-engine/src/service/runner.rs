//! The service process (started by the SCM only). It reports Running, serves
//! the pipe until Windows asks it to stop or shut down, then reports Stopped.
//! In slice 2 it changes nothing about traffic: no adapter, no routes.

use std::ffi::OsString;
use std::time::Duration;

use sieve_ipc::EngineStatus;
use tokio::sync::watch;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use super::acl::pipe_sddl;
use super::{SERVICE_NAME, state};
use crate::ipc::server;

/// Bound for the runtime's own shutdown after the pipe stops.
const SHUTDOWN_BOUND: Duration = Duration::from_secs(3);
/// Service-specific exit code when the engine could not run.
const FAILED: u32 = 1;

define_windows_service!(ffi_service_main, service_main);

/// Hands the process to the SCM. Fails (at once) when the process was not
/// started by the SCM.
pub fn run() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

/// Slice 2: nothing filters, so every fact is false or zero.
fn status() -> EngineStatus {
    EngineStatus::default()
}

fn service_main(_args: Vec<OsString>) {
    let (stop_tx, stop_rx) = watch::channel(false);
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(SERVICE_NAME, handler) else { return };
    let report = |state, accept, code| {
        let _ = handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: code,
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        });
    };
    report(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, ServiceExitCode::Win32(0));
    let code = match serve(stop_rx) {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(_) => ServiceExitCode::ServiceSpecific(FAILED),
    };
    report(ServiceState::Stopped, ServiceControlAccept::empty(), code);
}

/// The pipe, with the DACL for the recorded owner, until the stop signal.
/// An error ends the process with a failure code, so the SCM's recovery
/// restarts it.
fn serve(stop: watch::Receiver<bool>) -> Result<(), String> {
    let owner = state::read(&state::engine_dir(&state::program_data()?))?.owner_sid;
    let sddl = pipe_sddl(owner.as_deref())?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    let result = rt.block_on(server::serve(&sddl, status, stop));
    rt.shutdown_timeout(SHUTDOWN_BOUND);
    result
}
