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
//! A rollback that cannot finish keeps every `.old` and the release in flight,
//! marked, so the next process to run carries it on (`Updater::settle`).
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
/// With no engine that starts, this process is the only one left to finish the
/// rollback: it keeps at it this long, this far apart, then leaves it marked.
const ROLLBACK_PATIENCE_MS: u64 = 60 * 60 * 1_000;
const ROLLBACK_PATIENCE_POLL_MS: u64 = 30_000;

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
        if pending.rolling_back {
            return self.roll_back(&kind, &pending, "an earlier rollback did not finish");
        }
        if let Err(why) = self.service.stop() {
            return self.give_up(format!("the service would not stop: {why}"));
        }
        if let Err(why) = swap::set_aside(self.fs, &self.install_dir, &pending.aside) {
            return self.give_up(format!("could not set the current files aside: {why}"));
        }
        // From here a reboot can leave the old engine beside new files, and only
        // this mark tells a whole `.old` from a copy that was cut short.
        let pending = Pending { swap_started: true, ..pending };
        if let Err(why) = state::save_pending(&self.engine_dir, &pending) {
            let _ = swap::clear_leftovers(self.fs, &self.install_dir);
            return self.give_up(format!("could not record the swap: {why}"));
        }
        if let Err(why) = self.replace_set(&kind, &pending) {
            return self.roll_back(&kind, &pending, &format!("the swap failed: {why}"));
        }
        if let Err(why) = self.service.start() {
            return self.roll_back(&kind, &pending, &format!("the new version did not start: {why}"));
        }
        match self.wait_healthy(&pending) {
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

    /// A state file that cannot be read proves nothing either way: the new set
    /// stays unproven, so the wait goes on, and the deadline rolls it back.
    fn wait_healthy(&self, pending: &Pending) -> Health {
        let deadline = self.clock.now_ms() + HEALTH_DEADLINE_MS;
        let mut reported = None;
        loop {
            match self.read_health(pending) {
                Ok(Some(health)) => return health,
                Ok(None) => {}
                Err(why) if reported.as_ref() != Some(&why) => {
                    self.log.line(&why);
                    reported = Some(why);
                }
                Err(_) => {}
            }
            if self.clock.now_ms() >= deadline {
                return Health::Timeout;
            }
            self.clock.sleep_ms(HEALTH_POLL_MS);
        }
    }

    /// The new engine's verdict, or None while the release is still in flight.
    fn read_health(&self, pending: &Pending) -> Result<Option<Health>, String> {
        if state::load_pending(&self.engine_dir)?.is_some() {
            return Ok(None);
        }
        let raised = state::is_committed(&self.engine_dir, pending)?;
        Ok(Some(if raised { Health::Healthy } else { Health::Refused }))
    }

    /// The verdict is written first: from there on the `.old` files are the only
    /// copy of the set that works, and no process may treat them as leftovers. The
    /// pending file may already be gone when the new engine reported in time.
    fn roll_back(&self, kind: &Kind, pending: &Pending, why: &str) -> Result<Outcome, String> {
        self.log.line(&format!("rolling back {} {}: {why}", pending.kind, pending.to_version));
        let verdict = Pending { rolling_back: true, ..pending.clone() };
        if let Err(e) = state::save_pending(&self.engine_dir, &verdict) {
            self.log.line(&format!("recording the rollback: {e}"));
        }
        if let Err(e) = self.service.stop() {
            self.log.line(&format!("stopping the failed version: {e}"));
        }
        let deadline = self.clock.now_ms() + ROLLBACK_PATIENCE_MS;
        loop {
            let Err(locked) = self.restore(kind, &verdict) else {
                return self.finish_rollback(&verdict);
            };
            self.log.line(&format!("the old version is not back yet: {locked}"));
            // A running engine carries the rollback on; with none, only this process can.
            if self.service.start().is_ok() || self.clock.now_ms() >= deadline {
                return Err(format!("the rollback did not finish, the old files stay: {locked}"));
            }
            self.clock.sleep_ms(ROLLBACK_PATIENCE_POLL_MS);
        }
    }

    fn restore(&self, kind: &Kind, pending: &Pending) -> Result<(), String> {
        let mut restored = swap::rollback(self.fs, &self.install_dir, kind, &pending.aside);
        for _ in 1..ROLLBACK_TRIES {
            if restored.is_ok() {
                break;
            }
            self.clock.sleep_ms(ROLLBACK_RETRY_MS);
            restored = swap::rollback(self.fs, &self.install_dir, kind, &pending.aside);
        }
        restored
    }

    /// The old set is whole again: only now do the leftovers go and the record say so.
    fn finish_rollback(&self, pending: &Pending) -> Result<Outcome, String> {
        let recorded = state::record_rollback(&self.engine_dir, pending);
        // A file still in use stays until the next check; this is not a failure.
        let _ = swap::clear_leftovers(self.fs, &self.install_dir);
        if let Err(e) = self.service.start() {
            self.log.line(&format!("starting the restored version: {e}"));
        }
        recorded?;
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
    use super::super::state::{Record, installed, load_record};
    use super::super::swap::tests::{FailingFs, NEW_ENGINE, OLD_ENGINE};
    use super::super::swap::{FAILED_SUFFIX, OLD_SUFFIX, RealFs};
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
        /// It reports after the deadline, while the rollback's stop is under way.
        ReportsDuringStop,
        /// It reports, while the service manager's wait for it times out.
        ReportsButStartTimesOut,
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

    /// The new engine's report, when one is still in flight.
    fn report(engine_dir: &Path) {
        if let Some(p) = state::load_pending(engine_dir).unwrap() {
            state::commit_healthy(engine_dir, &p).unwrap();
        }
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
            if matches!(self.engine, Engine::ReportsDuringStop) && self.starts.get() > 0 {
                report(self.engine_dir);
            }
            if self.refuses_stop { Err("still StopPending".into()) } else { Ok(()) }
        }

        /// Runs the real start-up decision against the real files.
        fn start(&self) -> Result<(), String> {
            self.starts.set(self.starts.get() + 1);
            self.note();
            let own = match self.engine {
                Engine::ExitsAtStart => return Err("exited at start".into()),
                Engine::Silent | Engine::ReportsDuringStop => return Ok(()),
                Engine::ReportsButStartTimesOut => {
                    report(self.engine_dir);
                    return Err("still StartPending".into());
                }
                Engine::Report(own) => own,
            };
            if let Some(p) = state::on_service_start(self.engine_dir, self.install_dir, own, &MemLog::default()) {
                state::commit_healthy(self.engine_dir, &p).unwrap();
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeInstaller {
        calls: RefCell<Vec<(PathBuf, PathBuf, PathBuf)>>,
        fails: bool,
        /// Its post-install hook started the new engine, which reported here.
        hook_engine_reports_to: Option<PathBuf>,
    }

    impl Installer for FakeInstaller {
        fn run(&self, staged: &Path, install: &Path, temp: &Path) -> Result<(), String> {
            self.calls.borrow_mut().push((staged.into(), install.into(), temp.into()));
            std::fs::write(install.join(ENGINE_EXE), NEW_ENGINE).unwrap();
            std::fs::write(install.join("sieve.exe"), b"new app").unwrap();
            std::fs::write(install.join("added.dll"), b"new").unwrap();
            if let Some(dir) = &self.hook_engine_reports_to {
                report(dir);
            }
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

    /// A fake clock that also lets the world change on each poll.
    struct ChangingClock<'a> {
        clock: FakeClock,
        polls: Cell<u32>,
        on_poll: &'a dyn Fn(u32),
    }

    impl Clock for ChangingClock<'_> {
        fn now_ms(&self) -> u64 {
            self.clock.now_ms()
        }
        fn sleep_ms(&self, ms: u64) {
            self.clock.sleep_ms(ms);
            self.polls.set(self.polls.get() + 1);
            (self.on_poll)(self.polls.get());
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
                rolling_back: false,
                swap_started: false,
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

        fn run_changing(&self, service: &dyn ServiceControl, on_poll: &dyn Fn(u32)) -> (Result<Outcome, String>, MemLog) {
            let log = MemLog::default();
            let clock = ChangingClock { clock: FakeClock::default(), polls: Cell::new(0), on_poll };
            let out = Supervisor {
                fs: &RealFs,
                service,
                installer: &FakeInstaller::default(),
                clock: &clock,
                log: &log,
                engine_dir: self.engine.clone(),
                install_dir: self.install.clone(),
            }
            .finish();
            (out, log)
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

    /// A commit can land first when the report and the verdict race. The old
    /// files come back, so the record must say so.
    #[test]
    fn a_commit_that_lands_before_the_rollback_does_not_stay_in_the_record() {
        for engine in [Engine::ReportsDuringStop, Engine::ReportsButStartTimesOut] {
            let w = World::engine_only();
            let service = FakeService::new(&w, engine);
            assert_eq!(w.run(&service), Ok(Outcome::RolledBack));
            w.assert_rolled_back();
            assert_eq!(installed(&Kind::Engine, &w.record(), FROM), FROM);
        }

        let w = World::new("app", &[ENGINE_EXE, "sieve.exe"]);
        let service = FakeService::new(&w, Engine::Silent);
        let installer = FakeInstaller { fails: true, hook_engine_reports_to: Some(w.engine.clone()), ..FakeInstaller::default() };
        let (out, _) = w.run_with(&RealFs, &service, &installer);
        assert_eq!(out, Ok(Outcome::RolledBack));
        w.assert_rolled_back();
    }

    #[test]
    fn a_pending_file_damaged_during_the_wait_rolls_back_at_the_deadline() {
        let w = World::engine_only();
        let service = FakeService::new(&w, Engine::Silent);
        let pending_file = w.engine.join(state::PENDING_FILE);
        let (out, log) = w.run_changing(&service, &|_| std::fs::write(&pending_file, b"not json").unwrap());
        assert_eq!(out, Ok(Outcome::RolledBack));
        w.assert_rolled_back();
        let lines = log.0.lock().unwrap();
        assert_eq!(lines.iter().filter(|l| l.contains(state::PENDING_FILE)).count(), 1, "said once, not every poll: {lines:?}");
    }

    #[test]
    fn a_record_damaged_during_the_wait_restores_the_files_and_reports_the_damage() {
        let w = World::engine_only();
        let service = FakeService::new(&w, Engine::Silent);
        let (out, _) = w.run_changing(&service, &|poll| {
            if poll == 1 {
                state::clear_pending(&w.engine).unwrap();
                std::fs::write(w.engine.join(state::STATE_FILE), b"not json").unwrap();
            }
        });
        assert!(out.as_ref().is_err_and(|why| why.contains(state::STATE_FILE)), "{out:?}");
        assert_eq!(w.exe(), OLD_ENGINE);
        assert_eq!(state::load_pending(&w.engine).unwrap(), None);
        assert_eq!(service.starts.get(), 2, "and the old engine runs again");
    }

    #[test]
    fn a_read_error_that_clears_does_not_end_the_wait() {
        let w = World::engine_only();
        let service = FakeService::new(&w, Engine::Silent);
        let pending_file = w.engine.join(state::PENDING_FILE);
        let good = std::fs::read(&pending_file).unwrap();
        let (out, _) = w.run_changing(&service, &|poll| match poll {
            1 => std::fs::write(&pending_file, b"not json").unwrap(),
            2 => std::fs::write(&pending_file, &good).unwrap(),
            3 => report(&w.engine),
            _ => {}
        });
        assert_eq!(out, Ok(Outcome::Healthy));
        assert_eq!(w.exe(), NEW_ENGINE);
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

    /// Real files, except that this many renames to `.failed` fail first: a file
    /// held open without delete sharing, as an antivirus scan of a new exe does.
    struct LockedFs {
        locked_tries: Cell<u32>,
    }

    impl LockedFs {
        const FOREVER: u32 = u32::MAX;

        fn new(locked_tries: u32) -> Self {
            Self { locked_tries: Cell::new(locked_tries) }
        }
    }

    impl Fs for LockedFs {
        fn copy(&self, from: &Path, to: &Path) -> std::io::Result<()> {
            RealFs.copy(from, to)
        }

        fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
            let held = self.locked_tries.get();
            if held > 0 && to.to_string_lossy().ends_with(FAILED_SUFFIX) {
                self.locked_tries.set(held - 1);
                return Err(std::io::Error::other("sharing violation"));
            }
            RealFs.rename(from, to)
        }

        fn remove_file(&self, path: &Path) -> std::io::Result<()> {
            RealFs.remove_file(path)
        }

        fn exists(&self, path: &Path) -> bool {
            RealFs.exists(path)
        }

        fn files(&self, dir: &Path) -> std::io::Result<Vec<String>> {
            RealFs.files(dir)
        }
    }

    /// The only copy of the old set stays, and nothing says it is back.
    #[test]
    fn a_rollback_that_stays_locked_keeps_the_old_set_and_the_flight() {
        let w = World::engine_only();
        let service = FakeService::new(&w, Engine::ExitsAtStart);
        let (out, _) = w.run_with(&LockedFs::new(LockedFs::FOREVER), &service, &FakeInstaller::default());
        assert!(out.as_ref().is_err_and(|why| why.contains("sharing violation")), "{out:?}");
        assert_eq!(std::fs::read(w.install.join(format!("{ENGINE_EXE}{OLD_SUFFIX}"))).unwrap(), OLD_ENGINE);
        assert!(state::load_pending(&w.engine).unwrap().is_some_and(|p| p.rolling_back), "still in flight, marked");
        assert_eq!(w.record().rolled_back.get("engine"), None, "not rolled back yet");
        assert!(service.starts.get() > 2, "with no engine running it kept trying");
    }

    /// No engine runs, so the supervisor outlasts a scan far longer than its quick tries.
    #[test]
    fn with_no_engine_running_the_supervisor_outlasts_the_lock() {
        let w = World::engine_only();
        let service = FakeService::new(&w, Engine::ExitsAtStart);
        let (out, _) = w.run_with(&LockedFs::new(4 * ROLLBACK_TRIES), &service, &FakeInstaller::default());
        assert_eq!(out, Ok(Outcome::RolledBack));
        w.assert_rolled_back();
    }

    /// An engine that starts ends this supervisor; a later one finishes the job.
    #[test]
    fn a_later_supervisor_finishes_a_rollback_left_marked() {
        let w = World::engine_only();
        let service = FakeService::new(&w, Engine::Silent);
        let (out, _) = w.run_with(&LockedFs::new(LockedFs::FOREVER), &service, &FakeInstaller::default());
        assert!(out.is_err(), "{out:?}");
        assert_eq!(w.exe(), NEW_ENGINE);

        let starts = service.starts.get();
        assert_eq!(w.run(&service), Ok(Outcome::RolledBack));
        w.assert_rolled_back();
        assert_eq!(service.starts.get(), starts + 1, "it went straight to the rollback");
    }

    /// The report the verdict beat cannot keep a release the supervisor refused.
    #[test]
    fn a_mislabelled_release_that_stays_locked_is_back_in_flight() {
        let w = World::engine_only();
        let service = FakeService::new(&w, Engine::Report(WRONG));
        let (out, _) = w.run_with(&LockedFs::new(LockedFs::FOREVER), &service, &FakeInstaller::default());
        assert!(out.is_err(), "{out:?}");
        assert!(state::load_pending(&w.engine).unwrap().is_some_and(|p| p.rolling_back), "the start had cleared it");
        assert_eq!(std::fs::read(w.install.join(format!("{ENGINE_EXE}{OLD_SUFFIX}"))).unwrap(), OLD_ENGINE);
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

    /// The installer's first file must find the mark on disk and every `.old` whole.
    #[test]
    fn the_swap_is_marked_once_the_set_aside_is_whole_and_before_the_installer() {
        /// The mark, then the bytes of both `.old` files, as the installer found them.
        type Seen = (bool, Vec<u8>, Vec<u8>);
        struct Watching<'a>(&'a World, RefCell<Option<Seen>>);
        impl Installer for Watching<'_> {
            fn run(&self, _: &Path, install: &Path, _: &Path) -> Result<(), String> {
                let marked = state::load_pending(&self.0.engine).unwrap().unwrap().swap_started;
                let read = |name: &str| std::fs::read(install.join(format!("{name}{OLD_SUFFIX}"))).unwrap();
                *self.1.borrow_mut() = Some((marked, read(ENGINE_EXE), read("sieve.exe")));
                std::fs::write(install.join(ENGINE_EXE), NEW_ENGINE).unwrap();
                Ok(())
            }
        }
        let w = World::new("app", &[ENGINE_EXE, "sieve.exe"]);
        let installer = Watching(&w, RefCell::default());
        let service = FakeService::new(&w, Engine::Report(TO));
        let (out, _) = w.run_with(&RealFs, &service, &installer);
        assert_eq!(out, Ok(Outcome::Healthy));
        assert_eq!(installer.1.into_inner(), Some((true, OLD_ENGINE.to_vec(), b"old app".to_vec())));
    }

    #[test]
    fn a_set_aside_that_fails_never_marks_the_swap() {
        let w = World::new("app", &[ENGINE_EXE, "sieve.exe"]);
        let seen = RefCell::new(None);
        let (out, _) = {
            let probe = FailingFsWatching { inner: FailingFs::at(1), engine: &w.engine, seen: &seen };
            let service = FakeService::new(&w, Engine::Report(FROM));
            w.run_with(&probe, &service, &FakeInstaller::default())
        };
        assert!(matches!(out, Ok(Outcome::NotStarted(_))), "{out:?}");
        assert_eq!(seen.into_inner(), Some(false));
    }

    /// Reads the pending file at the moment the failing step fires.
    struct FailingFsWatching<'a> {
        inner: FailingFs,
        engine: &'a Path,
        seen: &'a RefCell<Option<bool>>,
    }

    impl Fs for FailingFsWatching<'_> {
        fn copy(&self, from: &Path, to: &Path) -> std::io::Result<()> {
            let out = self.inner.copy(from, to);
            if out.is_err() {
                *self.seen.borrow_mut() = state::load_pending(self.engine).unwrap().map(|p| p.swap_started);
            }
            out
        }
        fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
            self.inner.rename(from, to)
        }
        fn remove_file(&self, path: &Path) -> std::io::Result<()> {
            self.inner.remove_file(path)
        }
        fn exists(&self, path: &Path) -> bool {
            self.inner.exists(path)
        }
        fn files(&self, dir: &Path) -> std::io::Result<Vec<String>> {
            self.inner.files(dir)
        }
    }

    /// Without the mark a reboot could not be told from no swap at all, so no
    /// real file may change.
    #[test]
    fn a_mark_that_cannot_be_written_changes_no_real_file() {
        let w = World::new("app", &[ENGINE_EXE, "sieve.exe"]);
        std::fs::create_dir(w.engine.join(state::PENDING_FILE).with_extension("tmp")).unwrap();
        let service = FakeService::new(&w, Engine::Report(FROM));
        let installer = FakeInstaller::default();
        let (out, _) = w.run_with(&RealFs, &service, &installer);
        assert!(matches!(&out, Ok(Outcome::NotStarted(why)) if why.contains("record the swap")), "{out:?}");
        assert!(installer.calls.borrow().is_empty());
        assert_eq!(w.exe(), OLD_ENGINE);
        assert!(!w.install.join(format!("{ENGINE_EXE}{OLD_SUFFIX}")).exists());
        assert_eq!(state::load_pending(&w.engine).unwrap(), None);
        assert_eq!(service.starts.get(), 1, "the old engine runs again");
    }

    /// An installer that finished but left the old engine: the started old build
    /// marks it, and the supervisor still ends on the whole old set.
    #[test]
    fn an_installer_that_leaves_the_old_engine_rolls_back() {
        struct AppOnly;
        impl Installer for AppOnly {
            fn run(&self, _: &Path, install: &Path, _: &Path) -> Result<(), String> {
                std::fs::write(install.join("sieve.exe"), b"new app").unwrap();
                Ok(())
            }
        }
        let w = World::new("app", &[ENGINE_EXE, "sieve.exe"]);
        let service = FakeService::new(&w, Engine::Report(FROM));
        let (out, _) = w.run_with(&RealFs, &service, &AppOnly);
        assert_eq!(out, Ok(Outcome::RolledBack));
        w.assert_rolled_back();
        assert_eq!(std::fs::read(w.install.join("sieve.exe")).unwrap(), b"old app");
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
