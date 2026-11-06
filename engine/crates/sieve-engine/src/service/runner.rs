//! The service process (started by the SCM only). In order:
//! 1. DLLs load from System32 only (`SetDefaultDllDirectories`); wintun.dll
//!    is later loaded by absolute path after its hash check (`tun`).
//! 2. It checks who can change its files (`image`, the same check as
//!    `install`) and refuses to run when users can.
//! 3. Before anything else touches the network: every route on an interface
//!    named "Sieve" and every journalled route is deleted (plan 1.6.3).
//! 4. The run is recorded (`runs.json`); the third restart within an hour is
//!    a crash loop and routes nothing (plan 1.6.4).
//! 5. It reports Running, starts the watchdog thread, the routing loop and
//!    the pipe, until Windows asks it to stop or shut down; then it takes the
//!    routes down, records a clean stop and reports Stopped.
//!
//! A panic on any thread but a flow worker deletes Sieve's routes and stops
//! the ETW session before the process dies (plan 1.6.6); a flow task's panic
//! ends that flow only.

use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use super::acl::pipe_sddl;
use super::image::check_this_exe;
use super::{EXIT_UNSAFE_FOLDER, EXIT_WATCHDOG, SERVICE_NAME, state};
use crate::control::{Engine, routing};
use crate::flow::etw::os::stop_stale;
use crate::ipc::server;
use crate::policy::{self, crash_loop};
use crate::route::apply::clear_stale;
use crate::route::journal::Journal;
use crate::watchdog::{self, Stall, Trip, monotonic_ms};

/// Bound for the runtime's own shutdown after the pipe stops.
const SHUTDOWN_BOUND: Duration = Duration::from_secs(3);
/// The routing loop gets this long to take the routes down at a stop.
const TAKE_DOWN_BOUND: Duration = Duration::from_secs(10);
/// Service-specific exit code when the engine could not run.
const FAILED: u32 = 1;
/// Service-specific exit code when it refused to run from a folder users can
/// change (`sc query` shows it as SERVICE_EXIT_CODE).
const UNSAFE_FOLDER: u32 = EXIT_UNSAFE_FOLDER as u32;
/// Flow workers: a panic there is caught by its task (the flow ends).
const FLOW_THREAD: &str = "sieve-flow";

define_windows_service!(ffi_service_main, service_main);

/// Hands the process to the SCM. Fails (at once) when the process was not
/// started by the SCM.
pub fn run() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn system32_only() {
    use windows::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories};
    // SAFETY: a process-wide setting with a valid flag.
    let _ = unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) };
}

fn service_main(_args: Vec<OsString>) {
    system32_only();
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
    // Every start, before anything runs: a LocalSystem service whose files
    // users can change must not run (the ACL may have changed since install).
    if let Err(why) = check_this_exe() {
        record_failure(&why);
        report(ServiceState::Stopped, ServiceControlAccept::empty(), ServiceExitCode::ServiceSpecific(UNSAFE_FOLDER));
        return;
    }
    report(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, ServiceExitCode::Win32(0));
    let code = match serve(stop_rx) {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(why) => {
            record_failure(&why);
            ServiceExitCode::ServiceSpecific(FAILED)
        }
    };
    report(ServiceState::Stopped, ServiceControlAccept::empty(), code);
}

/// A service has no console: why it stopped goes to
/// `ProgramData\Sieve\engine\last-error.txt` (admin-only, like the folder),
/// for the live check and for a person reading it after a failure. Writing
/// it is best effort: the exit code already tells the SCM it failed.
fn record_failure(why: &str) {
    if let Ok(pd) = state::program_data() {
        let _ = std::fs::write(state::engine_dir(&pd).join(LAST_ERROR_FILE), why);
    }
}

const LAST_ERROR_FILE: &str = "last-error.txt";

/// An emergency exit waits this long for the ETW session to stop: the process
/// must still end, or the SCM's recovery never runs.
const SESSION_STOP_BOUND: Duration = Duration::from_secs(2);

/// What both emergency exits do. Routes first, so a hang stopping the session
/// cannot hold a route. The session goes too: if the SCM's recovery has run
/// out, no later start stops it, and routing off means no session.
fn emergency_cleanup(routes: impl FnOnce() -> String, session: impl FnOnce() -> Result<String, String> + Send + 'static) -> String {
    let routes = routes();
    format!("{routes}; {}", stop_session_within(session, SESSION_STOP_BOUND))
}

fn stop_session_within(stop: impl FnOnce() -> Result<String, String> + Send + 'static, bound: Duration) -> String {
    let (done, wait) = std::sync::mpsc::sync_channel(1);
    let stopper = std::thread::Builder::new().name("sieve-etw-stop".into()).spawn(move || {
        let _ = done.send(stop());
    });
    if let Err(e) = stopper {
        return format!("attribution session: FAILED, no thread to stop it: {e}");
    }
    match wait.recv_timeout(bound) {
        Ok(Ok(what)) => format!("attribution session: {what}"),
        Ok(Err(why)) => format!("attribution session: FAILED, {why}"),
        Err(_) => format!("attribution session: FAILED, no answer within {} s", bound.as_secs()),
    }
}

/// The watchdog's trip: routes first (named and journalled), then the ETW
/// session, the reason on disk, then the process ends with [`EXIT_WATCHDOG`]
/// (the SCM restarts it).
struct ServiceTrip {
    journal: Journal,
}

impl Trip for ServiceTrip {
    fn delete_routes(&self) -> String {
        emergency_cleanup(|| clear_stale(&self.journal), stop_stale)
    }

    fn exit(&self, stall: &Stall, routes: &str) {
        record_failure(&format!("{}; {routes}", stall.reason()));
        std::process::exit(EXIT_WATCHDOG);
    }
}

/// Deletes Sieve's routes and stops the ETW session when anything but a flow
/// worker panics, before the default hook prints the panic (the process then
/// unwinds or aborts).
fn install_panic_cleanup(journal_dir: std::path::PathBuf) {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let flow = std::thread::current().name().is_some_and(|n| n == FLOW_THREAD);
        if !flow {
            let cleaned = emergency_cleanup(|| clear_stale(&Journal::new(&journal_dir)), stop_stale);
            record_failure(&format!("panic: {info}; {cleaned}"));
        }
        default_hook(info);
    }));
}

/// Adds what start-up found to what the engine already reports (a bad `dns.json`).
fn report_start_problems(engine: &Engine, policy_error: Option<String>, cleaned: &str) {
    let cleanup = cleaned.contains("FAILED").then(|| format!("start-up cleanup: {cleaned}"));
    for problem in [policy_error, cleanup].into_iter().flatten() {
        engine.add_error(problem);
    }
}

/// The engine until the stop signal. An error ends the process with a
/// failure code, so the SCM's recovery restarts it.
fn serve(stop: watch::Receiver<bool>) -> Result<(), String> {
    let dir = state::engine_dir(&state::program_data()?);
    let journal = Journal::new(&dir);
    let cleaned = clear_stale(&journal);
    // A real-time session outlives a killed controller; nothing routes yet.
    let _ = stop_stale();
    install_panic_cleanup(dir.clone());

    let mut runs = policy::load_runs(&dir);
    let crash = crash_loop(runs.start(policy::wall_ms()));
    policy::save_runs(&dir, &runs)?;
    let (policy, policy_error) = policy::load(&dir);

    let owner = state::read(&dir)?.owner_sid;
    let sddl = pipe_sddl(owner.as_deref())?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let engine = Arc::new(Engine::new(Some(dir.clone()), exe, policy, runs, crash));
    report_start_problems(&engine, policy_error, &cleaned);

    // The watchdog: a plain thread, armed only while routes are up.
    let (ping_tx, ping_rx) = mpsc::unbounded_channel();
    {
        let (arm, beats) = (engine.arm.clone(), engine.beats.clone());
        let trip = ServiceTrip { journal: Journal::new(&dir) };
        std::thread::Builder::new()
            .name("sieve-watchdog".into())
            .spawn(move || watchdog::run(&arm, &beats, &monotonic_ms, &|| {
                let _ = ping_tx.send(());
            }, &trip))
            .map_err(|e| format!("watchdog thread: {e}"))?;
    }

    #[cfg(feature = "relay-experiments")]
    let rt = {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        if let Some(workers) = engine.experiments.settings.worker_threads {
            builder.worker_threads(workers);
        }
        builder.enable_all().thread_name(FLOW_THREAD).build().map_err(|e| e.to_string())?
    };
    #[cfg(not(feature = "relay-experiments"))]
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name(FLOW_THREAD)
        .build()
        .map_err(|e| e.to_string())?;
    #[cfg(feature = "relay-experiments")]
    {
        engine.runtime_workers.store(rt.metrics().num_workers(), std::sync::atomic::Ordering::Relaxed);
        engine.write_status_file();
    }
    let result = rt.block_on(async {
        tokio::spawn(routing::answer_pings(engine.clone(), ping_rx));
        let (halt_tx, halt_rx) = watch::channel(false);
        let routing = tokio::spawn(routing::run(engine.clone(), halt_rx));
        let served = server::serve(&sddl, engine.clone(), stop).await;
        // The pipe ended (a stop, or a pipe error): the routes go down either way.
        let _ = halt_tx.send(true);
        let _ = tokio::time::timeout(TAKE_DOWN_BOUND, routing).await;
        served
    });
    rt.shutdown_timeout(SHUTDOWN_BOUND);
    // Whatever the loop managed, nothing of Sieve's stays routed or tracing.
    clear_stale(&journal);
    let _ = stop_stale();
    if result.is_ok() {
        engine.stop_clean();
    }
    result
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use super::*;
    use crate::control::STATUS_FILE;
    use crate::dns::config::DNS_FILE;

    #[test]
    fn an_emergency_exit_deletes_the_routes_first_then_stops_the_session() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let (routes, session) = (order.clone(), order.clone());
        let said = emergency_cleanup(
            move || {
                routes.lock().unwrap().push("routes");
                "3 routes deleted".into()
            },
            move || {
                session.lock().unwrap().push("session");
                Ok("a leftover session was stopped".into())
            },
        );
        assert_eq!(*order.lock().unwrap(), ["routes", "session"]);
        assert_eq!(said, "3 routes deleted; attribution session: a leftover session was stopped");
    }

    #[test]
    fn a_failed_session_stop_is_on_the_record() {
        let said = emergency_cleanup(|| "3 routes deleted".into(), || Err("Win32 error 5".into()));
        assert_eq!(said, "3 routes deleted; attribution session: FAILED, Win32 error 5");
    }

    #[test]
    fn a_hung_session_stop_cannot_keep_the_process_alive() {
        let (release, hung) = std::sync::mpsc::channel::<()>();
        let said = stop_session_within(
            move || {
                let _ = hung.recv();
                Ok("too late".into())
            },
            Duration::from_millis(20),
        );
        assert!(said.starts_with("attribution session: FAILED, no answer"), "{said}");
        drop(release);
    }

    /// `last_error` as `status.json` says it, after a start with a bad `dns.json`.
    fn reported_after_start(dir: &Path, policy_error: Option<String>, cleaned: &str) -> Option<String> {
        std::fs::write(dir.join(DNS_FILE), b"{\"revision\":1,\"upstreams\":[\"udp://1.1.1.1\"]}").unwrap();
        let engine = Engine::new(Some(dir.to_path_buf()), PathBuf::new(), Default::default(), Default::default(), None);
        report_start_problems(&engine, policy_error, cleaned);
        engine.write_status_file();
        let status: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join(STATUS_FILE)).unwrap()).unwrap();
        status["last_error"].as_str().map(str::to_string)
    }

    #[test]
    fn a_bad_dns_file_is_still_reported_after_a_healthy_start() {
        let dir = tempfile::tempdir().unwrap();
        let reported = reported_after_start(dir.path(), None, "removed 0 routes").unwrap();
        assert!(reported.contains("read as the defaults"), "{reported}");
    }

    #[test]
    fn every_start_problem_is_reported_beside_a_bad_dns_file() {
        let dir = tempfile::tempdir().unwrap();
        let reported = reported_after_start(dir.path(), Some("policy.json: broken".into()), "route delete FAILED").unwrap();
        for reason in ["read as the defaults", "policy.json: broken", "start-up cleanup: route delete FAILED"] {
            assert!(reported.contains(reason), "{reason} in {reported}");
        }
    }
}
