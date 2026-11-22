//! The service process (started by the SCM only). In order:
//! 1. DLLs load from System32 only (`SetDefaultDllDirectories`); wintun.dll
//!    is later loaded by absolute path after its hash check (`tun`).
//! 2. It checks who can change its files (`image`, the same check as
//!    `install`) and refuses to run when users can.
//! 3. It settles a signed update in flight (`update::state::on_service_start`).
//! 4. Before anything else touches the network: every route on an interface
//!    named "Sieve" and every journalled route is deleted (plan 1.6.3).
//! 5. The run is recorded (`runs.json`); the third restart within an hour is
//!    a crash loop and routes nothing (plan 1.6.4).
//! 6. It reports Running, starts the watchdog thread, the updater's thread, the
//!    routing loop and the pipe, until Windows asks it to stop or shut down; then
//!    it takes the routes down, records a clean stop and reports Stopped.
//!    StopPending goes to the SCM as the stop arrives; a stop that has not
//!    finished within [`STOP_BOUND`] cleans up by itself and ends the process
//!    (`guard_stop`), so a part of shutdown that hangs cannot keep the engine,
//!    or its file, alive.
//!
//! A panic on any thread but a flow worker deletes Sieve's routes and stops
//! the ETW session before the process dies (plan 1.6.6); a flow task's panic
//! ends that flow only.
//!
//! Started with [`PURGE_ARG`] (by `uninstall` only, as SYSTEM is the one
//! account the key's DACL admits), after the same folder check it deletes the
//! recorded CA keys and stops: no routing, no pipe.

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use sieve_ipc::PIPE_NAME;
use tokio::sync::{mpsc, watch};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle};
use windows_service::{define_windows_service, service_dispatcher};

use super::acl::pipe_sddl;
use super::image::check_this_exe;
use super::{EXIT_UNSAFE_FOLDER, EXIT_WATCHDOG, SERVICE_NAME, state};
use crate::ca::removal::{PURGE_ARG, purge_keys};
use crate::ca::win::{CngKeyStore, RegistryFirefoxPolicy, WindowsRootStore};
use crate::ca::{Ca, Seams};
use crate::control::{Engine, certs, routing};
use crate::flow::etw::os::stop_stale;
use crate::ipc::server;
use crate::policy::{self, crash_loop};
use crate::route::apply::clear_stale;
use crate::route::journal::Journal;
use crate::update;
use crate::update::state::{FileLog, Log};
use crate::update::trust::OWN_RELEASE;
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

/// Also for the `update-finish` verb, which runs from the staging folder.
pub fn system32_only() {
    use windows::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories};
    // SAFETY: a process-wide setting with a valid flag.
    let _ = unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) };
}

/// The CA over the real system. A failure here means no root and no
/// interception; the engine still runs.
fn real_ca(dir: &std::path::Path) -> Result<Arc<Ca>, crate::ca::CaError> {
    let seams = Seams { keys: Arc::new(CngKeyStore), store: Arc::new(WindowsRootStore), firefox: Arc::new(RegistryFirefoxPolicy) };
    let machine = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "this computer".to_string());
    Ca::new(dir.to_path_buf(), machine, seams).map(Arc::new)
}

/// `uninstall`'s key step. The verb reads back its outcome from `ca.json` and a
/// failure's reason from `last-error.txt`.
fn purge_ca_keys() {
    let purged = state::program_data().and_then(|pd| purge_keys(&state::engine_dir(&pd), &CngKeyStore));
    if let Err(why) = purged {
        record_failure(&why);
    }
}

/// From the stop's start (the SCM's request, or the pipe ending by itself) to
/// Stopped, at most this long. Past it the process cleans up by itself and ends
/// ([`stop_overran`]). Under `restore`'s wait ([`super::STOP_WAIT`]), so an
/// installer never meets an engine that still holds its file.
const STOP_BOUND: Duration = Duration::from_secs(15);
/// What Windows is told the stop may take (the SCM's `WaitHint`).
const STOP_HINT: Duration = Duration::from_secs(20);
/// The cleanup past [`STOP_BOUND`] waits this long for the routes; a hang there
/// must not keep the process alive.
const ROUTES_BOUND: Duration = Duration::from_secs(3);

/// The stop is under way: set by the control handler, or by `serve` when the
/// pipe ended by itself.
static STOPPING: AtomicBool = AtomicBool::new(false);
/// Windows asked for the stop (not the pipe ending by itself).
static ASKED: AtomicBool = AtomicBool::new(false);
/// Everything is down: [`guard_stop`] has nothing more to watch.
static DONE: AtomicBool = AtomicBool::new(false);
/// The thread that runs [`guard_stop`], woken by [`begin_stop`] and [`DONE`].
static GUARD: OnceLock<std::thread::Thread> = OnceLock::new();
/// The SCM status handle, and whether Stopped was reported (nothing is
/// reported after it).
static STATUS: Mutex<Option<(ServiceStatusHandle, bool)>> = Mutex::new(None);

/// Reports `state` to the SCM, unless Stopped was reported already.
fn report(state: ServiceState, accept: ServiceControlAccept, code: ServiceExitCode) {
    let mut status = STATUS.lock().unwrap_or_else(|p| p.into_inner());
    let Some((handle, stopped)) = status.as_mut() else { return };
    if *stopped {
        return;
    }
    let pending = state == ServiceState::StopPending;
    let _ = handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: code,
        checkpoint: u32::from(pending),
        wait_hint: if pending { STOP_HINT } else { Duration::ZERO },
        process_id: None,
    });
    *stopped = state == ServiceState::Stopped;
}

/// Starts the stop once: StopPending to the SCM at once, then the guard thread
/// takes it from there. Never waits on the engine: only an atomic, the status
/// report and a wake.
fn begin_stop() {
    if STOPPING.swap(true, Ordering::SeqCst) {
        return;
    }
    report(ServiceState::StopPending, ServiceControlAccept::empty(), ServiceExitCode::Win32(0));
    if let Some(guard) = GUARD.get() {
        guard.unpark();
    }
}

/// The SCM's control handler, on its dispatcher thread. A plain function, so of
/// size zero: windows-service frees the handler after the first Stop and still
/// calls it for every later control, harmless only when there is nothing to
/// free. It hands the stop on and returns; a second Stop is answered too.
fn on_control(control: ServiceControl) -> ServiceControlHandlerResult {
    match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            ASKED.store(true, Ordering::SeqCst);
            begin_stop();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}

/// The guard thread's whole job: wait for the stop (`stopping`), pass it on to
/// the engine (`pass_on`, which may wait on the engine's locks, so it runs here
/// and not on the dispatcher thread), then give the stop `bound` to finish
/// (`done`); past it, `overran` runs. Woken by `unpark`; a spurious wake only
/// looks again.
fn guard_stop(stopping: &AtomicBool, done: &AtomicBool, bound: Duration, pass_on: impl FnOnce(), overran: impl FnOnce()) {
    while !stopping.load(Ordering::SeqCst) {
        if done.load(Ordering::SeqCst) {
            return;
        }
        std::thread::park();
    }
    pass_on();
    let deadline = Instant::now() + bound;
    while !done.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now >= deadline {
            overran();
            return;
        }
        std::thread::park_timeout(deadline - now);
    }
}

/// The stop did not finish within [`STOP_BOUND`]: the same cleanup as an
/// emergency exit (routes, then the ETW session, each bounded), the reason on
/// disk, Stopped to the SCM, and the process ends at once, whatever its other
/// threads hold. The code is 0 when Windows asked for the stop, so the SCM's
/// recovery does not start the engine again in the middle of an install; a pipe
/// that ended by itself is a failure, and recovery restarts the engine.
fn stop_overran() {
    let routes = || {
        let journal = state::program_data().map(|pd| Journal::new(&state::engine_dir(&pd)));
        match journal {
            Ok(journal) => within(ROUTES_BOUND, move || clear_stale(&journal)).unwrap_or_else(|why| format!("routes: FAILED, {why}")),
            Err(why) => format!("routes: FAILED, {why}"),
        }
    };
    let cleaned = emergency_cleanup(routes, stop_stale);
    record_failure(&format!("the stop did not finish within {} s; {cleaned}", STOP_BOUND.as_secs()));
    let code = if ASKED.load(Ordering::SeqCst) { ServiceExitCode::Win32(0) } else { ServiceExitCode::ServiceSpecific(FAILED) };
    report(ServiceState::Stopped, ServiceControlAccept::empty(), code);
    use windows::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};
    // SAFETY: ends this process; the pseudo handle needs no closing.
    let _ = unsafe { TerminateProcess(GetCurrentProcess(), 0) };
    std::process::abort();
}

fn service_main(args: Vec<OsString>) {
    system32_only();
    let (stop_tx, stop_rx) = watch::channel(false);
    let Ok(handle) = service_control_handler::register(SERVICE_NAME, on_control) else { return };
    *STATUS.lock().unwrap_or_else(|p| p.into_inner()) = Some((handle, false));
    // Every start, before anything runs: a LocalSystem service whose files
    // users can change must not run (the ACL may have changed since install).
    if let Err(why) = check_this_exe() {
        record_failure(&why);
        report(ServiceState::Stopped, ServiceControlAccept::empty(), ServiceExitCode::ServiceSpecific(UNSAFE_FOLDER));
        return;
    }
    if args.iter().any(|a| a == PURGE_ARG) {
        report(ServiceState::Running, ServiceControlAccept::empty(), ServiceExitCode::Win32(0));
        purge_ca_keys();
        // Exit code 0 even after a failure: a failure code would make the
        // SCM's recovery start the engine again in the middle of uninstall.
        report(ServiceState::Stopped, ServiceControlAccept::empty(), ServiceExitCode::Win32(0));
        return;
    }
    let guard = std::thread::Builder::new().name("sieve-stop-guard".into()).spawn(move || {
        guard_stop(&STOPPING, &DONE, STOP_BOUND, move || {
            let _ = stop_tx.send(true);
        }, stop_overran);
    });
    match guard {
        Ok(guard) => {
            let _ = GUARD.set(guard.thread().clone());
        }
        Err(e) => {
            // No guard, no bounded stop: refuse to run rather than risk a hung one.
            record_failure(&format!("stop guard thread: {e}"));
            report(ServiceState::Stopped, ServiceControlAccept::empty(), ServiceExitCode::ServiceSpecific(FAILED));
            return;
        }
    }
    report(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, ServiceExitCode::Win32(0));
    let code = match serve(stop_rx) {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(why) => {
            record_failure(&why);
            ServiceExitCode::ServiceSpecific(FAILED)
        }
    };
    DONE.store(true, Ordering::SeqCst);
    if let Some(guard) = GUARD.get() {
        guard.unpark();
    }
    report(ServiceState::Stopped, ServiceControlAccept::empty(), code);
}

/// A service has no console: why it stopped goes to
/// `ProgramData\Sieve\engine\last-error.txt` (admin-only, like the folder),
/// for the live check and for a person reading it after a failure. Writing
/// it is best effort: the exit code already tells the SCM it failed.
fn record_failure(why: &str) {
    if let Ok(pd) = state::program_data() {
        let _ = std::fs::write(state::engine_dir(&pd).join(state::LAST_ERROR_FILE), why);
    }
}

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
    match within(bound, stop) {
        Ok(Ok(what)) => format!("attribution session: {what}"),
        Ok(Err(why)) | Err(why) => format!("attribution session: FAILED, {why}"),
    }
}

/// `work` on a thread of its own, waited for up to `bound`; one that hangs is
/// left behind, so it cannot hold the caller.
fn within<T: Send + 'static>(bound: Duration, work: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    let (done, wait) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("sieve-bounded".into())
        .spawn(move || {
            let _ = done.send(work());
        })
        .map_err(|e| format!("no thread to run it: {e}"))?;
    wait.recv_timeout(bound).map_err(|_| format!("no answer within {bound:?}"))
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
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let install = exe.parent().ok_or_else(|| format!("{} has no folder", exe.display()))?;
    let release = update::state::on_service_start(&dir, install, OWN_RELEASE, &FileLog::new(&dir));
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
    update::win::start_worker(&engine.updates, &dir, &engine.exe);
    report_start_problems(&engine, policy_error, &cleaned);
    let ca = match real_ca(&dir) {
        Ok(ca) => {
            engine.attach_ca(ca.clone());
            Some(ca)
        }
        Err(why) => {
            engine.add_error(format!("certificate: {why}"));
            None
        }
    };

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
        if let Some(ca) = ca {
            tokio::spawn(certs::run(engine.clone(), ca, halt_rx.clone()));
        }
        let routing = tokio::spawn(routing::run(engine.clone(), halt_rx));
        if let Some(pending) = release {
            let dir = dir.clone();
            tokio::spawn(async move {
                // No report: the supervisor's deadline decides, and rolls back.
                if let Err(why) = update::health::report(PIPE_NAME, &dir, &pending).await {
                    FileLog::new(&dir).line(&format!("no health report: {why}"));
                }
            });
        }
        let served = server::serve(&sddl, engine.clone(), stop).await;
        // The pipe ended (a stop, or a pipe error): the routes go down either way,
        // within the stop's bound.
        begin_stop();
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

    /// windows-service frees the handler after the first Stop and calls it again
    /// for later controls: only a handler of size zero survives that.
    #[test]
    fn the_control_handler_has_nothing_to_free_and_answers_every_stop() {
        assert_eq!(std::mem::size_of_val(&on_control), 0);
        for control in [ServiceControl::Stop, ServiceControl::Stop, ServiceControl::Interrogate, ServiceControl::Shutdown] {
            assert_eq!(on_control(control).to_raw(), ServiceControlHandlerResult::NoError.to_raw(), "{control:?}");
        }
        assert!(STOPPING.load(Ordering::SeqCst) && ASKED.load(Ordering::SeqCst));
    }

    /// Runs `guard_stop` on a thread, as the service does; returns what it did.
    fn guard(stopping: Arc<AtomicBool>, done: Arc<AtomicBool>, bound: Duration) -> (std::thread::JoinHandle<()>, std::sync::mpsc::Receiver<&'static str>) {
        let (said, heard) = std::sync::mpsc::channel();
        let passed = said.clone();
        let thread = std::thread::spawn(move || {
            guard_stop(&stopping, &done, bound, move || passed.send("passed on").unwrap(), move || said.send("overran").unwrap());
        });
        (thread, heard)
    }

    #[test]
    fn a_stop_that_finishes_in_time_is_only_passed_on() {
        let (stopping, done) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let (thread, heard) = guard(stopping.clone(), done.clone(), Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(20));
        assert!(heard.try_recv().is_err(), "nothing before the stop");
        stopping.store(true, Ordering::SeqCst);
        thread.thread().unpark();
        assert_eq!(heard.recv_timeout(Duration::from_secs(5)), Ok("passed on"));
        done.store(true, Ordering::SeqCst);
        thread.thread().unpark();
        thread.join().unwrap();
        assert!(heard.try_recv().is_err(), "no overrun");
    }

    #[test]
    fn a_stop_that_hangs_overruns_at_its_bound() {
        let (stopping, done) = (Arc::new(AtomicBool::new(true)), Arc::new(AtomicBool::new(false)));
        let started = Instant::now();
        let (thread, heard) = guard(stopping, done, Duration::from_millis(200));
        assert_eq!(heard.recv_timeout(Duration::from_secs(5)), Ok("passed on"));
        assert_eq!(heard.recv_timeout(Duration::from_secs(5)), Ok("overran"));
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(200) && took < Duration::from_secs(3), "{took:?}");
        thread.join().unwrap();
    }

    #[test]
    fn a_run_that_ends_without_a_stop_passes_nothing_on() {
        let (stopping, done) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let (thread, heard) = guard(stopping, done.clone(), Duration::from_millis(50));
        done.store(true, Ordering::SeqCst);
        thread.thread().unpark();
        thread.join().unwrap();
        assert!(heard.try_recv().is_err());
    }

    #[test]
    fn a_hung_task_is_left_behind_within_its_bound() {
        let (release, hung) = std::sync::mpsc::channel::<()>();
        let started = Instant::now();
        let got = within(Duration::from_millis(50), move || hung.recv());
        assert_eq!(got.err().as_deref(), Some("no answer within 50ms"));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(release);
        assert_eq!(within(Duration::from_secs(5), || 7), Ok(7));
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
