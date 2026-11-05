//! The real seams on Windows: the service manager, the process spawns and the
//! worker thread. Compiled, never run by a test: their proof is the user's
//! (docs/live/updates.md). This is the only product code that starts a process.

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sieve_ipc::UpdateStatus;
use windows::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, DETACHED_PROCESS};

use super::cycle::{ReleaseStarter, UpdateControl, Updater, run_worker};
use super::finish::{Clock, Installer, Outcome, ServiceControl, Supervisor, install_of, installer_arguments};
use super::https::HttpsFetcher;
use super::state::{FileLog, Log};
use super::swap::{RealFs, STAGING_DIR, SUPERVISOR_EXE};
use super::trust::{OWN_RELEASE, PUBLIC_KEY, UPDATE_BASE_URL, configured};
use crate::policy::wall_ms;
use crate::service::{FINISH_VERB, scm, state as service_state};
use crate::watchdog::monotonic_ms;

/// A silent install that takes longer than this has hung; it is rolled back.
const INSTALLER_DEADLINE: Duration = Duration::from_secs(10 * 60);
const INSTALLER_POLL: Duration = Duration::from_millis(500);
const MS_PER_SECOND: u64 = 1_000;
const EXIT_FAILED: i32 = 1;
const EXIT_ROLLED_BACK: i32 = 4;

struct Scm;

impl ServiceControl for Scm {
    fn stop(&self) -> Result<(), String> {
        scm::stop().map(|_| ())
    }

    fn start(&self) -> Result<(), String> {
        scm::start().map(|_| ())
    }
}

struct NsisInstaller;

impl Installer for NsisInstaller {
    /// NSIS unpacks plugin DLLs under TEMP, and SYSTEM's default temp is a folder
    /// users can write into, so TEMP is the locked staging folder.
    fn run(&self, staged: &Path, install: &Path, temp: &Path) -> Result<(), String> {
        let mut child = Command::new(staged)
            .raw_arg(installer_arguments(install))
            .env("TEMP", temp)
            .env("TMP", temp)
            .current_dir(temp)
            .creation_flags(CREATE_NO_WINDOW.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("{}: {e}", staged.display()))?;
        let deadline = Instant::now() + INSTALLER_DEADLINE;
        loop {
            match child.try_wait().map_err(|e| e.to_string())? {
                Some(status) if status.success() => return Ok(()),
                Some(status) => return Err(format!("the installer ended with {status}")),
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    return Err("the installer did not finish in time".into());
                }
                None => std::thread::sleep(INSTALLER_POLL),
            }
        }
    }
}

struct RealClock;

impl Clock for RealClock {
    fn now_ms(&self) -> u64 {
        monotonic_ms()
    }

    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

/// Copies this exe into staging and starts it detached, so it survives the
/// service stopping. The copy stays until the next check: it is running.
struct SpawnSupervisor;

impl ReleaseStarter for SpawnSupervisor {
    fn start(&self, install_dir: &Path) -> Result<(), String> {
        let staging = install_dir.join(STAGING_DIR);
        let copy = staging.join(SUPERVISOR_EXE);
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        std::fs::copy(&exe, &copy).map_err(|e| format!("{}: {e}", copy.display()))?;
        Command::new(&copy)
            .arg(FINISH_VERB)
            .current_dir(&staging)
            .creation_flags(DETACHED_PROCESS.0 | CREATE_NEW_PROCESS_GROUP.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("{}: {e}", copy.display()))
    }
}

/// Starts the updater's thread, or leaves `not_configured` when this build has
/// no key or host: then the fetcher does not exist at all. A failure here never
/// stops the engine: updates are reported as failed and filtering goes on.
pub fn start_worker(control: &Arc<UpdateControl>, engine_dir: &Path, exe: &Path) {
    let Some(anchor) = configured(PUBLIC_KEY, UPDATE_BASE_URL) else { return };
    let Some(install_dir) = exe.parent().map(Path::to_path_buf) else {
        control.set_status(UpdateStatus::Failed { message: format!("{} has no folder", exe.display()) });
        return;
    };
    let fetcher = match HttpsFetcher::new(UPDATE_BASE_URL) {
        Ok(f) => f,
        Err(message) => return control.set_status(UpdateStatus::Failed { message }),
    };
    let updater = Updater {
        control: control.clone(),
        anchor: Some(anchor),
        fetcher: Box::new(fetcher),
        log: Box::new(FileLog::new(engine_dir)),
        starter: Box::new(SpawnSupervisor),
        engine_dir: engine_dir.to_path_buf(),
        install_dir,
        own: OWN_RELEASE,
    };
    control.set_status(updater.initial_status());
    let (tx, rx) = mpsc::channel();
    control.attach(tx);
    let spawned = std::thread::Builder::new().name("sieve-update".into()).spawn(move || {
        run_worker(&updater, &rx, &monotonic_ms, &|| wall_ms() / MS_PER_SECOND);
    });
    if let Err(e) = spawned {
        control.set_status(UpdateStatus::Failed { message: format!("update thread: {e}") });
    }
}

/// `sieve-engine.exe update-finish`: the exit code of the supervisor.
pub fn finish_verb() -> i32 {
    match finish() {
        Ok(Outcome::NothingPending | Outcome::Healthy) => 0,
        Ok(Outcome::RolledBack) => EXIT_ROLLED_BACK,
        Ok(Outcome::NotStarted(why)) => {
            eprintln!("sieve-engine: {why}");
            EXIT_FAILED
        }
        Err(why) => {
            eprintln!("sieve-engine: {why}");
            EXIT_FAILED
        }
    }
}

fn finish() -> Result<Outcome, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let install_dir: PathBuf = install_of(&exe)?;
    let engine_dir = service_state::engine_dir(&service_state::program_data()?);
    let log = FileLog::new(&engine_dir);
    let outcome = Supervisor {
        fs: &RealFs,
        service: &Scm,
        installer: &NsisInstaller,
        clock: &RealClock,
        log: &log as &dyn Log,
        engine_dir,
        install_dir,
    }
    .finish();
    if let Err(why) = &outcome {
        log.line(why);
    }
    outcome
}
