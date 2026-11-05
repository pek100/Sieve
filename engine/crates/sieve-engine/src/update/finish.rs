//! The supervisor, the `update-finish` verb. A process cannot replace its own
//! image, and rollback needs a process that survives the new engine failing at
//! start, so this runs from a copy of the current exe in the staging folder. It
//! takes no arguments: every input comes from `update-pending.json`, which only
//! an admin can read, so for anyone else the verb does nothing.
//!
//! It stops the service (a clean SCM stop, so an update never counts toward the
//! crash loop), sets the current files aside, swaps or runs the installer,
//! starts the service, and waits for the new engine's report ([`super::health`]).
//! Healthy: `.old` goes. Anything else: rollback, version record unchanged.
//! Filtering fails open throughout: the routes go with the stopped service.

use std::path::{Path, PathBuf};

use super::Kind;
use super::state::{self, Log, Pending};
use super::swap::{self, ENGINE_EXE, Fs, STAGING_DIR};

/// How long a started engine has to report healthy.
pub const HEALTH_DEADLINE_MS: u64 = 90_000;
const HEALTH_POLL_MS: u64 = 500;
/// A rollback that hits a locked file gets this many tries, this far apart.
const ROLLBACK_TRIES: u32 = 3;
const ROLLBACK_RETRY_MS: u64 = 2_000;

pub trait ServiceControl {
    fn stop(&self) -> Result<(), String>;
    fn start(&self) -> Result<(), String>;
}

pub trait Installer {
    /// Runs the verified installer into `install`, with `temp` as its temp folder.
    fn run(&self, staged: &Path, install: &Path, temp: &Path) -> Result<(), String>;
}

pub trait Clock {
    fn now_ms(&self) -> u64;
    fn sleep_ms(&self, ms: u64);
}

/// The installer's command line: silent, update mode, and the same folder even
/// when the registry disagrees. `/D=` goes last and unquoted, as NSIS requires.
/// Never `/R`, which would relaunch the app from session 0.
pub fn installer_arguments(install: &Path) -> String {
    format!("/S /UPDATE /D={}", install.display())
}

/// The install folder of a supervisor running from its staging copy; any other
/// location is not a supervisor, and nothing runs.
pub fn install_of(exe: &Path) -> Result<PathBuf, String> {
    let staging = exe.parent().filter(|p| p.file_name().is_some_and(|n| n.eq_ignore_ascii_case(STAGING_DIR)));
    staging.and_then(Path::parent).map(Path::to_path_buf).ok_or_else(|| format!("{} is not in an update's staging folder", exe.display()))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// No release in flight: nothing was touched.
    NothingPending,
    /// The new set is in place and reported healthy.
    Healthy,
    /// The new set failed; the old one is back and the record did not rise.
    RolledBack,
    /// It stopped before any real file changed.
    NotStarted(String),
}

pub struct Supervisor<'a> {
    pub fs: &'a dyn Fs,
    pub service: &'a dyn ServiceControl,
    pub installer: &'a dyn Installer,
    pub clock: &'a dyn Clock,
    pub log: &'a dyn Log,
    pub engine_dir: PathBuf,
    pub install_dir: PathBuf,
}

impl Supervisor<'_> {
    pub fn finish(&self) -> Result<Outcome, String> {
        let Some(pending) = state::load_pending(&self.engine_dir)? else {
            return Ok(Outcome::NothingPending);
        };
        let kind = Kind::parse(&pending.kind).filter(Kind::is_release).ok_or_else(|| format!("not a release: {}", pending.kind))?;
        if let Err(why) = self.service.stop() {
            return self.give_up(format!("the service would not stop: {why}"));
        }
        if let Err(why) = swap::set_aside(self.fs, &self.install_dir, &pending.aside) {
            return self.give_up(format!("could not set the current files aside: {why}"));
        }
        if let Err(why) = self.replace_set(&kind, &pending) {
            return self.roll_back(&kind, &pending, &format!("the swap failed: {why}"));
        }
        if let Err(why) = self.service.start() {
            return self.roll_back(&kind, &pending, &format!("the new version did not start: {why}"));
        }
        match self.wait_healthy(&pending)? {
            Health::Healthy => {
                self.log.line(&format!("{} {} is healthy", pending.kind, pending.to_version));
                // A file still in use stays until the next check; this is not a failure.
                let _ = swap::clear_leftovers(self.fs, &self.install_dir);
                Ok(Outcome::Healthy)
            }
            Health::Refused => self.roll_back(&kind, &pending, "the new version is not the one that was signed"),
            Health::Timeout => self.roll_back(&kind, &pending, "the new version did not report healthy in time"),
        }
    }

    /// Nothing real changed: the pending record goes, and the service is asked to
    /// run (it may never have stopped).
    fn give_up(&self, why: String) -> Result<Outcome, String> {
        self.log.line(&why);
        state::clear_pending(&self.engine_dir)?;
        let _ = self.service.start();
        Ok(Outcome::NotStarted(why))
    }

    fn replace_set(&self, kind: &Kind, pending: &Pending) -> Result<(), String> {
        let staging = self.install_dir.join(STAGING_DIR);
        let staged = staging.join(&pending.staged);
        if *kind == Kind::Engine {
            swap::replace(self.fs, &staged, &self.install_dir.join(ENGINE_EXE))
        } else {
            self.installer.run(&staged, &self.install_dir, &staging)
        }
    }

    fn wait_healthy(&self, pending: &Pending) -> Result<Health, String> {
        let deadline = self.clock.now_ms() + HEALTH_DEADLINE_MS;
        loop {
            if state::load_pending(&self.engine_dir)?.is_none() {
                let raised = state::is_committed(&self.engine_dir, pending)?;
                return Ok(if raised { Health::Healthy } else { Health::Refused });
            }
            if self.clock.now_ms() >= deadline {
                return Ok(Health::Timeout);
            }
            self.clock.sleep_ms(HEALTH_POLL_MS);
        }
    }

    fn roll_back(&self, kind: &Kind, pending: &Pending, why: &str) -> Result<Outcome, String> {
        self.log.line(&format!("rolling back {} {}: {why}", pending.kind, pending.to_version));
        if let Err(e) = self.service.stop() {
            self.log.line(&format!("stopping the failed version: {e}"));
        }
        let mut restored = swap::rollback(self.fs, &self.install_dir, kind, &pending.aside);
        for _ in 1..ROLLBACK_TRIES {
            if restored.is_ok() {
                break;
            }
            self.clock.sleep_ms(ROLLBACK_RETRY_MS);
            restored = swap::rollback(self.fs, &self.install_dir, kind, &pending.aside);
        }
        let recorded = state::record_rollback(&self.engine_dir, pending);
        // A file still in use stays until the next check; this is not a failure.
        let _ = swap::clear_leftovers(self.fs, &self.install_dir);
        if let Err(e) = self.service.start() {
            self.log.line(&format!("starting the restored version: {e}"));
        }
        restored.and(recorded)?;
        Ok(Outcome::RolledBack)
    }
}

enum Health {
    Healthy,
    /// The pending record went without the version record rising: the started
    /// engine found it is not the release (a mislabelled build).
    Refused,
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::super::state::tests::MemLog;
    use super::super::state::{Record, Recovery, load_record, recover};
    use super::super::swap::tests::{FailingFs, NEW_ENGINE, OLD_ENGINE};
    use super::super::swap::{OLD_SUFFIX, RealFs};
    use super::super::testing::listing;
    use super::super::trust::release_number;
    use super::*;
    use std::cell::{Cell, RefCell};

    const FROM: u64 = release_number(0, 1, 0);
    const TO: u64 = release_number(0, 2, 0);
    const WRONG: u64 = release_number(0, 3, 0);
    const STAGED: &str = "new.exe";

    /// What a started engine does: `Report` answers its own pipe with this number.
    #[derive(Clone, Copy)]
    enum Engine {
        Report(u64),
        /// `start` fails: the engine exited at once.
        ExitsAtStart,
        /// It runs and never reports.
        Silent,
    }

    struct FakeService<'a> {
        engine_dir: &'a Path,
        install_dir: &'a Path,
        engine: Engine,
        refuses_stop: bool,
        stops: Cell<u32>,
        starts: Cell<u32>,
        /// Whether `.old` existed at each transition after the first stop.
        old_seen: RefCell<Vec<bool>>,
    }

    impl<'a> FakeService<'a> {
        fn new(world: &'a World, engine: Engine) -> Self {
            Self {
                engine_dir: &world.engine,
                install_dir: &world.install,
                engine,
                refuses_stop: false,
                stops: Cell::new(0),
                starts: Cell::new(0),
                old_seen: RefCell::default(),
            }
        }

        fn note(&self) {
            self.old_seen.borrow_mut().push(self.install_dir.join(format!("{ENGINE_EXE}{OLD_SUFFIX}")).exists());
        }
    }

    impl ServiceControl for FakeService<'_> {
        fn stop(&self) -> Result<(), String> {
            self.stops.set(self.stops.get() + 1);
            self.note();
            if self.refuses_stop { Err("still StopPending".into()) } else { Ok(()) }
        }

        /// Runs the real start-up decision against the real files.
        fn start(&self) -> Result<(), String> {
            self.starts.set(self.starts.get() + 1);
            self.note();
            let own = match self.engine {
                Engine::ExitsAtStart => return Err("exited at start".into()),
                Engine::Silent => return Ok(()),
                Engine::Report(own) => own,
            };
            if let Some(p) = state::load_pending(self.engine_dir).unwrap() {
                match recover(&p, own) {
                    Recovery::Probe => state::commit_healthy(self.engine_dir, &p).unwrap(),
                    Recovery::NotSwapped | Recovery::Mislabelled => state::clear_pending(self.engine_dir).unwrap(),
                }
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeInstaller {
        calls: RefCell<Vec<(PathBuf, PathBuf, PathBuf)>>,
        fails: bool,
    }

    impl Installer for FakeInstaller {
        fn run(&self, staged: &Path, install: &Path, temp: &Path) -> Result<(), String> {
            self.calls.borrow_mut().push((staged.into(), install.into(), temp.into()));
            std::fs::write(install.join(ENGINE_EXE), NEW_ENGINE).unwrap();
            std::fs::write(install.join("sieve.exe"), b"new app").unwrap();
            std::fs::write(install.join("added.dll"), b"new").unwrap();
            if self.fails { Err("exit code 2".into()) } else { Ok(()) }
        }
    }

    #[derive(Default)]
    struct FakeClock {
        now: Cell<u64>,
    }

    impl Clock for FakeClock {
        fn now_ms(&self) -> u64 {
            self.now.get()
        }
        fn sleep_ms(&self, ms: u64) {
            self.now.set(self.now.get() + ms);
        }
    }

    struct World {
        _dir: tempfile::TempDir,
        engine: PathBuf,
        install: PathBuf,
        pending: Pending,
    }

    impl World {
        fn new(kind: &str, aside: &[&str]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let (engine, install) = (dir.path().join("engine"), dir.path().join("install"));
            let staging = install.join(STAGING_DIR);
            std::fs::create_dir_all(&engine).unwrap();
            std::fs::create_dir_all(&staging).unwrap();
            std::fs::write(install.join(ENGINE_EXE), OLD_ENGINE).unwrap();
            std::fs::write(install.join("sieve.exe"), b"old app").unwrap();
            std::fs::write(staging.join(STAGED), NEW_ENGINE).unwrap();
            let pending = Pending {
                kind: kind.into(),
                from_version: FROM,
                to_version: TO,
                staged: STAGED.into(),
                aside: aside.iter().map(ToString::to_string).collect(),
            };
            state::save_pending(&engine, &pending).unwrap();
            Self { _dir: dir, engine, install, pending }
        }

        fn engine_only() -> Self {
            Self::new("engine", &[ENGINE_EXE])
        }

        fn exe(&self) -> Vec<u8> {
            std::fs::read(self.install.join(ENGINE_EXE)).unwrap()
        }

        fn record(&self) -> Record {
            load_record(&self.engine).unwrap()
        }

        fn run_with(&self, fs: &dyn Fs, service: &dyn ServiceControl, installer: &dyn Installer) -> (Result<Outcome, String>, MemLog) {
            let log = MemLog::default();
            let clock = FakeClock::default();
            let out = Supervisor {
                fs,
                service,
                installer,
                clock: &clock,
                log: &log,
                engine_dir: self.engine.clone(),
                install_dir: self.install.clone(),
            }
            .finish();
            (out, log)
        }

        fn run(&self, service: &dyn ServiceControl) -> Result<Outcome, String> {
            self.run_with(&RealFs, service, &FakeInstaller::default()).0
        }

        fn assert_rolled_back(&self) {
            assert_eq!(self.exe(), OLD_ENGINE);
            let r = self.record();
            assert_eq!(r.versions.get(&self.pending.kind), None, "the record did not rise");
            assert_eq!(r.rolled_back.get(&self.pending.kind), Some(&TO));
            assert_eq!(state::load_pending(&self.engine).unwrap(), None);
            assert!(!self.install.join(format!("{ENGINE_EXE}{OLD_SUFFIX}")).exists());
        }
    }

    #[test]
    fn a_healthy_new_engine_keeps_the_new_set_and_deletes_old() {
        let w = World::engine_only();
        let service = FakeService::new(&w, Engine::Report(TO));
        assert_eq!(w.run(&service), Ok(Outcome::Healthy));
        assert_eq!(w.exe(), NEW_ENGINE);
        assert!(!w.install.join(format!("{ENGINE_EXE}{OLD_SUFFIX}")).exists());
        assert_eq!(w.record().versions["engine"], TO);
        assert_eq!((service.stops.get(), service.starts.get()), (1, 1));
    }

    #[test]
    fn old_set_exists_until_the_new_engine_reports_healthy() {
        let w = World::engine_only();
        let service = FakeService::new(&w, Engine::Report(TO));
        w.run(&service).unwrap();
        // At the stop nothing was set aside yet; at the start of the new engine
        // the old set must still be on disk.
        assert_eq!(*service.old_seen.borrow(), [false, true]);

        let w = World::engine_only();
        let service = FakeService::new(&w, Engine::Silent);
        assert_eq!(w.run(&service), Ok(Outcome::RolledBack));
        assert_eq!(*service.old_seen.borrow(), [false, true, true, false], "stop, start, the rollback's stop, the old engine's start");
    }

    #[test]
    fn a_new_engine_that_exits_at_start_rolls_back_with_the_record_unchanged() {
        let w = World::engine_only();
        let service = FakeService::new(&w, Engine::ExitsAtStart);
        assert_eq!(w.run(&service), Ok(Outcome::RolledBack));
        w.assert_rolled_back();
        assert_eq!(service.starts.get(), 2, "and the old engine is started again");
    }

    #[test]
    fn a_new_engine_that_never_reports_rolls_back_after_the_deadline() {
        let w = World::engine_only();
        let service = FakeService::new(&w, Engine::Silent);
        let clock = FakeClock::default();
        let log = MemLog::default();
        let out = Supervisor {
            fs: &RealFs,
            service: &service,
            installer: &FakeInstaller::default(),
            clock: &clock,
            log: &log,
            engine_dir: w.engine.clone(),
            install_dir: w.install.clone(),
        }
        .finish();
        assert_eq!(out, Ok(Outcome::RolledBack));
        assert!(clock.now.get() >= HEALTH_DEADLINE_MS, "not before the deadline");
        assert!(clock.now.get() < HEALTH_DEADLINE_MS + 2 * HEALTH_POLL_MS);
        w.assert_rolled_back();
        assert!(log.0.lock().unwrap().iter().any(|l| l.contains("did not report healthy")));
    }

    #[test]
    fn a_mislabelled_release_rolls_back() {
        for own in [WRONG, FROM] {
            let w = World::engine_only();
            let service = FakeService::new(&w, Engine::Report(own));
            assert_eq!(w.run(&service), Ok(Outcome::RolledBack), "{own}");
            w.assert_rolled_back();
        }
    }

    #[test]
    fn a_service_that_will_not_stop_changes_no_file() {
        let w = World::engine_only();
        let before = listing(&w.install);
        let mut service = FakeService::new(&w, Engine::Report(FROM));
        service.refuses_stop = true;
        let out = w.run(&service);
        assert!(matches!(out, Ok(Outcome::NotStarted(_))), "{out:?}");
        assert_eq!(listing(&w.install), before);
        assert_eq!(state::load_pending(&w.engine).unwrap(), None);
    }

    #[test]
    fn a_failed_set_aside_changes_no_real_file() {
        let w = World::engine_only();
        let service = FakeService::new(&w, Engine::Report(FROM));
        let (out, _) = w.run_with(&FailingFs::at(0), &service, &FakeInstaller::default());
        assert!(matches!(out, Ok(Outcome::NotStarted(_))), "{out:?}");
        assert_eq!(w.exe(), OLD_ENGINE);
        assert_eq!(service.starts.get(), 1, "the old engine runs again");
    }

    #[test]
    fn a_swap_that_fails_rolls_back_to_the_old_set() {
        let w = World::engine_only();
        let service = FakeService::new(&w, Engine::Report(TO));
        // Step 0 is the copy aside, step 1 the rename into place.
        let (out, _) = w.run_with(&FailingFs::at(1), &service, &FakeInstaller::default());
        assert_eq!(out, Ok(Outcome::RolledBack));
        w.assert_rolled_back();
    }

    #[test]
    fn every_interrupted_supervisor_step_ends_on_a_whole_set() {
        for k in 0..12 {
            for engine in [Engine::Report(TO), Engine::ExitsAtStart] {
                let w = World::engine_only();
                let service = FakeService::new(&w, engine);
                let (out, _) = w.run_with(&FailingFs::at(k), &service, &FakeInstaller::default());
                let exe = w.exe();
                match out {
                    Ok(Outcome::Healthy) => assert_eq!(exe, NEW_ENGINE, "{k}"),
                    Ok(Outcome::RolledBack | Outcome::NotStarted(_)) => assert_eq!(exe, OLD_ENGINE, "{k}"),
                    other => panic!("step {k}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn a_failed_installer_rolls_back() {
        let w = World::new("app", &[ENGINE_EXE, "sieve.exe"]);
        let service = FakeService::new(&w, Engine::Report(TO));
        let installer = FakeInstaller { fails: true, ..FakeInstaller::default() };
        let (out, log) = w.run_with(&RealFs, &service, &installer);
        assert_eq!(out, Ok(Outcome::RolledBack));
        w.assert_rolled_back();
        assert_eq!(std::fs::read(w.install.join("sieve.exe")).unwrap(), b"old app");
        assert!(!w.install.join("added.dll").exists(), "what it added goes too");
        assert!(log.0.lock().unwrap().iter().any(|l| l.contains("exit code 2")));
    }

    #[test]
    fn the_installer_gets_exactly_these_arguments() {
        assert_eq!(installer_arguments(Path::new(r"E:\My Apps\Sieve")), r"/S /UPDATE /D=E:\My Apps\Sieve");
        assert!(!installer_arguments(Path::new(r"E:\Sieve")).contains("/R"));

        let w = World::new("app", &[ENGINE_EXE, "sieve.exe"]);
        let service = FakeService::new(&w, Engine::Report(TO));
        let installer = FakeInstaller::default();
        let (out, _) = w.run_with(&RealFs, &service, &installer);
        assert_eq!(out, Ok(Outcome::Healthy));
        let staging = w.install.join(STAGING_DIR);
        assert_eq!(*installer.calls.borrow(), [(staging.join(STAGED), w.install.clone(), staging)], "TEMP is the locked staging folder");
    }

    #[test]
    fn the_finish_verb_with_no_pending_record_does_nothing() {
        let w = World::engine_only();
        state::clear_pending(&w.engine).unwrap();
        let (install, engine) = (listing(&w.install), listing(&w.engine));
        let service = FakeService::new(&w, Engine::Report(TO));
        assert_eq!(w.run(&service), Ok(Outcome::NothingPending));
        assert_eq!((service.stops.get(), service.starts.get()), (0, 0));
        assert_eq!((listing(&w.install), listing(&w.engine)), (install, engine));
    }

    #[test]
    fn a_pending_record_naming_no_release_stops_the_verb() {
        let w = World::new("resources", &[]);
        let service = FakeService::new(&w, Engine::Report(TO));
        assert!(w.run(&service).is_err());
        assert_eq!(service.stops.get(), 0);
    }

    #[test]
    fn the_supervisor_only_runs_from_a_staging_folder() {
        assert_eq!(install_of(Path::new(r"E:\Sieve\update-staging\update-finish.exe")).unwrap(), Path::new(r"E:\Sieve"));
        assert!(install_of(Path::new(r"E:\Sieve\sieve-engine.exe")).is_err());
        assert!(install_of(Path::new("update-finish.exe")).is_err());
    }
}
