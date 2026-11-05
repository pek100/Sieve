//! One check or apply over the seams, and when they run.
//!
//! The daily check applies data kinds and only reports a release. `RequestUpdate`
//! carries no field and takes its meaning from the state: while a release is
//! `available` it applies that one, otherwise it runs a check, so neither "check
//! again" nor a host publishing between the check and the click can install
//! something the user was not shown.
//!
//! Every refusal leaves both trees as they were: staged files go, and nothing is
//! recorded, the accepted index version included, until a cycle had no refusal.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sieve_ipc::UpdateStatus;

use super::fetch::{FetchError, Fetcher};
use super::finish::HEALTH_DEADLINE_MS;
use super::index::{Entry, INDEX_FILE, Index, MAX_INDEX_BYTES, SIGNATURE_SUFFIX, parse_index, require_listed};
use super::state::{self, Log, Pending, Record, installed};
use super::swap::{self, DATA_DIR, DATA_STAGING_DIR, RealFs, STAGING_DIR};
use super::trust::{TrustAnchor, display_version};
use super::verify::{MAX_SIGNATURE_BYTES, require_newer, verify_artefact};
use super::{Kind, Refusal};
use crate::service::STOP_WAIT;

/// At most one asked-for check in this long; over that the answer is an error.
pub const REQUEST_COOLDOWN_MS: u64 = 5 * 60 * 1_000;
/// Boot stays quiet: the first check runs this long after the service starts.
pub const FIRST_CHECK_DELAY_MS: u64 = 10 * 60 * 1_000;
pub const CHECK_EVERY_MS: u64 = 24 * 60 * 60 * 1_000;
/// After a network failure the next check comes this soon.
pub const FAILED_RETRY_MS: u64 = 60 * 60 * 1_000;
/// How often an `applying` state is compared with the pending file.
const SETTLE_POLL_MS: u64 = 30_000;
/// A supervisor stops this service and watches the new engine within this long.
/// An engine still running with the release unresolved after it has no supervisor.
const SUPERVISOR_WAIT_MS: u64 = STOP_WAIT.as_secs() * 1_000 + HEALTH_DEADLINE_MS;

pub const COOLDOWN_MESSAGE: &str = "an update check ran moments ago; try again in a few minutes";
pub const NOT_RUNNING_MESSAGE: &str = "the updater is not running";
pub const UNFINISHED_MESSAGE: &str = "the update did not finish; the current version keeps running";
pub const ROLLBACK_UNFINISHED_MESSAGE: &str = "the update failed and the previous version could not be restored yet; Sieve keeps trying";

/// A worker's job; the pipe only ever queues one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Job {
    Check,
    /// Installs the release the user was shown, and only that one.
    Apply { shown: String },
}

/// What the pipe sees: the status, and the one way to queue work.
#[derive(Default)]
pub struct UpdateControl {
    status: Mutex<UpdateStatus>,
    last_request_ms: Mutex<Option<u64>>,
    jobs: Mutex<Option<mpsc::Sender<Job>>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl UpdateControl {
    pub fn status(&self) -> UpdateStatus {
        lock(&self.status).clone()
    }

    pub fn set_status(&self, status: UpdateStatus) {
        *lock(&self.status) = status;
    }

    /// Connects the worker; until then nothing can be queued.
    pub fn attach(&self, jobs: mpsc::Sender<Job>) {
        *lock(&self.jobs) = Some(jobs);
    }

    /// `RequestUpdate`: decided from the state alone.
    pub fn request(&self, now_ms: u64) -> Result<(), String> {
        let mut status = lock(&self.status);
        let (job, next) = match &*status {
            UpdateStatus::NotConfigured | UpdateStatus::Checking | UpdateStatus::Applying { .. } => return Ok(()),
            UpdateStatus::Available { version } => (Job::Apply { shown: version.clone() }, UpdateStatus::Applying { version: version.clone() }),
            _ => {
                let mut last = lock(&self.last_request_ms);
                if last.is_some_and(|at| now_ms.saturating_sub(at) < REQUEST_COOLDOWN_MS) {
                    return Err(COOLDOWN_MESSAGE.to_string());
                }
                *last = Some(now_ms);
                (Job::Check, UpdateStatus::Checking)
            }
        };
        let jobs = lock(&self.jobs);
        jobs.as_ref().and_then(|tx| tx.send(job).ok()).ok_or_else(|| NOT_RUNNING_MESSAGE.to_string())?;
        *status = next;
        Ok(())
    }
}

/// Starts the supervisor once the pending record and the staged file are in place.
pub trait ReleaseStarter: Send {
    fn start(&self, install_dir: &Path) -> Result<(), String>;
}

/// A cycle that stopped.
#[derive(Debug, PartialEq, Eq)]
enum Stop {
    Refused(Refusal),
    Failed(String),
}

impl From<Refusal> for Stop {
    fn from(r: Refusal) -> Self {
        Self::Refused(r)
    }
}

impl From<String> for Stop {
    fn from(why: String) -> Self {
        Self::Failed(why)
    }
}

impl From<Stop> for UpdateStatus {
    fn from(stop: Stop) -> Self {
        match stop {
            Stop::Refused(Refusal::IndexExpired) => Self::Stale,
            Stop::Refused(r) => Self::Refused { message: r.to_string() },
            Stop::Failed(message) => Self::Failed { message },
        }
    }
}

/// A staging folder that is gone again unless kept: a refusal leaves nothing.
struct Staging {
    dir: PathBuf,
    keep: bool,
}

impl Staging {
    fn new(dir: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        Ok(Self { dir, keep: false })
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        let _ = std::fs::remove_dir_all(&self.dir);
        // The data folder, only when this cycle made it for nothing (a folder
        // with files in it is not removed by this call).
        if let Some(parent) = self.dir.parent().filter(|p| p.ends_with(DATA_DIR)) {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

fn signature_name(file: &str) -> String {
    format!("{file}{SIGNATURE_SUFFIX}")
}

/// The release the index offers, app first: its installer carries the engine too.
fn offer<'a>(index: &'a Index, record: &Record, own: u64) -> Option<(Kind, &'a Entry)> {
    [Kind::App, Kind::Engine].into_iter().find_map(|kind| {
        let entry = index.artefacts.get(&kind)?;
        let failed = record.rolled_back.get(&kind.to_string()).copied().unwrap_or(0);
        (entry.version > installed(&kind, record, own) && entry.version > failed).then_some((kind, entry))
    })
}

/// The newest release that failed and was not since passed by another.
fn rolled_back(record: &Record, own: u64) -> Option<u64> {
    record.rolled_back.values().copied().filter(|n| *n > installed(&Kind::Engine, record, own)).max()
}

pub struct Updater {
    pub control: Arc<UpdateControl>,
    pub anchor: Option<TrustAnchor>,
    pub fetcher: Box<dyn Fetcher>,
    pub log: Box<dyn Log>,
    pub starter: Box<dyn ReleaseStarter>,
    pub engine_dir: PathBuf,
    pub install_dir: PathBuf,
    pub own: u64,
    /// When `settle` started this wait for a supervisor (monotonic).
    pub supervisor_wait_from_ms: Cell<Option<u64>>,
}

impl Updater {
    /// The status before any check of this run: a release that failed stays
    /// shown until a newer one passes it.
    pub fn initial_status(&self) -> UpdateStatus {
        if self.anchor.is_none() {
            return UpdateStatus::NotConfigured;
        }
        match state::load_record(&self.engine_dir).map(|r| rolled_back(&r, self.own)) {
            Ok(Some(n)) => UpdateStatus::RolledBack { version: display_version(n) },
            Ok(None) => UpdateStatus::Idle,
            Err(message) => UpdateStatus::Failed { message },
        }
    }

    /// Runs one job and publishes its result. True when the network failed, for
    /// the schedule.
    pub fn run(&self, job: Job, now_unix: u64) -> bool {
        let status = self.cycle(job, now_unix);
        let network_failed = matches!(status, UpdateStatus::Failed { .. });
        self.control.set_status(status);
        network_failed
    }

    fn cycle(&self, job: Job, now_unix: u64) -> UpdateStatus {
        let Some(anchor) = &self.anchor else { return UpdateStatus::NotConfigured };
        match state::load_pending(&self.engine_dir) {
            Ok(Some(p)) if p.rolling_back => return UpdateStatus::Failed { message: ROLLBACK_UNFINISHED_MESSAGE.to_string() },
            Ok(Some(p)) => return UpdateStatus::Applying { version: display_version(p.to_version) },
            Ok(None) => self.clear_leftovers(),
            Err(message) => return UpdateStatus::Failed { message },
        }
        let done = match &job {
            Job::Check => self.check(anchor, now_unix),
            Job::Apply { shown } => self.apply(anchor, now_unix, shown),
        };
        done.unwrap_or_else(|stop| {
            let status = UpdateStatus::from(stop);
            self.log.line(&format!("{job:?}: {status:?}"));
            status
        })
    }

    /// Compares what the status says with the release actually in flight. An
    /// `applying` state ends here when the supervisor gave up (the pending file is
    /// gone) or never took over; an unfinished rollback is carried on.
    pub fn settle(&self, now_ms: u64) {
        let waiting = matches!(self.control.status(), UpdateStatus::Applying { .. });
        match state::load_pending(&self.engine_dir) {
            Ok(None) => {
                self.supervisor_wait_from_ms.set(None);
                if waiting {
                    self.control.set_status(UpdateStatus::Failed { message: UNFINISHED_MESSAGE.to_string() });
                }
            }
            Ok(Some(p)) if p.rolling_back => self.carry_on_rollback(&p, now_ms),
            Ok(Some(p)) if waiting && self.supervisor_wait_over(now_ms) => self.supervisor_never_finished(p),
            Ok(Some(_)) => {}
            Err(message) if waiting => self.control.set_status(UpdateStatus::Failed { message }),
            Err(_) => {}
        }
    }

    /// True once per [`SUPERVISOR_WAIT_MS`] of the same release in flight.
    fn supervisor_wait_over(&self, now_ms: u64) -> bool {
        let from = self.supervisor_wait_from_ms.get().unwrap_or(now_ms);
        let over = now_ms.saturating_sub(from) >= SUPERVISOR_WAIT_MS;
        self.supervisor_wait_from_ms.set(Some(if over { now_ms } else { from }));
        over
    }

    /// The old build still runs, so nothing was stopped and no file changed: the
    /// release ends here. The new build runs unwatched and unproven, which is a
    /// health timeout with no one to act on it: it becomes a rollback.
    fn supervisor_never_finished(&self, pending: Pending) {
        self.log.line(&format!("{} {}: no supervisor took over", pending.kind, pending.to_version));
        if self.own != pending.from_version {
            if let Err(why) = state::save_pending(&self.engine_dir, &Pending { rolling_back: true, ..pending }) {
                self.log.line(&why);
            }
            return;
        }
        self.supervisor_wait_from_ms.set(None);
        let message = state::clear_pending(&self.engine_dir).err().unwrap_or_else(|| UNFINISHED_MESSAGE.to_string());
        self.control.set_status(UpdateStatus::Failed { message });
    }

    /// The old build restores the rest in place. Any other build needs to be
    /// replaced while stopped, which takes a supervisor, one per wait.
    fn carry_on_rollback(&self, pending: &Pending, now_ms: u64) {
        if self.own != pending.from_version {
            self.rollback_unfinished("a failed release is still the running one");
            if self.supervisor_wait_over(now_ms)
                && let Err(why) = self.starter.start(&self.install_dir)
            {
                self.log.line(&why);
            }
            return;
        }
        let restored = Kind::parse(&pending.kind)
            .ok_or_else(|| format!("not a release: {}", pending.kind))
            .and_then(|kind| swap::rollback(&RealFs, &self.install_dir, &kind, &pending.aside));
        if let Err(why) = restored {
            return self.rollback_unfinished(&why);
        }
        self.supervisor_wait_from_ms.set(None);
        let status = match state::record_rollback(&self.engine_dir, pending) {
            Ok(()) => UpdateStatus::RolledBack { version: display_version(pending.to_version) },
            Err(message) => UpdateStatus::Failed { message },
        };
        self.control.set_status(status);
    }

    /// Said once, not on every poll.
    fn rollback_unfinished(&self, why: &str) {
        let status = UpdateStatus::Failed { message: ROLLBACK_UNFINISHED_MESSAGE.to_string() };
        if self.control.status() != status {
            self.log.line(&format!("rollback unfinished: {why}"));
            self.control.set_status(status);
        }
    }

    /// With no release in flight, whatever an earlier one left is of no use.
    fn clear_leftovers(&self) {
        let _ = swap::clear_leftovers(&RealFs, &self.install_dir);
        let _ = std::fs::remove_dir_all(self.install_dir.join(STAGING_DIR));
    }

    fn data_staging(&self) -> Result<Staging, String> {
        Staging::new(self.engine_dir.join(DATA_DIR).join(DATA_STAGING_DIR))
    }

    fn fetch(&self, file: &str, max_bytes: u64, dest: &Path) -> Result<(), Stop> {
        self.fetcher.get(file, max_bytes, dest).map_err(|e| match e {
            FetchError::OverCap(file) => Stop::Refused(Refusal::WrongSize(file)),
            other => Stop::Failed(other.to_string()),
        })
    }

    fn fetch_signature(&self, file: &str, staging: &Path) -> Result<Vec<u8>, Stop> {
        let name = signature_name(file);
        let dest = staging.join(&name);
        match self.fetcher.get(&name, MAX_SIGNATURE_BYTES, &dest) {
            Ok(()) => std::fs::read(&dest).map_err(|e| Stop::Failed(format!("{}: {e}", dest.display()))),
            Err(FetchError::NotFound(_)) => Err(Stop::Refused(Refusal::NoSignature)),
            Err(FetchError::OverCap(_)) => Err(Stop::Refused(Refusal::BadSignature)),
            Err(other) => Err(Stop::Failed(other.to_string())),
        }
    }

    fn read_index(&self, anchor: &TrustAnchor, record: &Record, now_unix: u64) -> Result<Index, Stop> {
        let staging = self.data_staging()?;
        let dest = staging.dir.join(INDEX_FILE);
        self.fetch(INDEX_FILE, MAX_INDEX_BYTES, &dest)?;
        let body = std::fs::read(&dest).map_err(|e| format!("{}: {e}", dest.display()))?;
        let signature = self.fetch_signature(INDEX_FILE, &staging.dir)?;
        Ok(parse_index(anchor, &body, &signature, now_unix, record.index_version)?)
    }

    /// Fetches into `staging` and verifies over the exact staged bytes: size,
    /// signature, kind, the index's version, and a version above the installed one.
    fn fetch_verified(&self, anchor: &TrustAnchor, kind: &Kind, entry: &Entry, baseline: u64, staging: &Path) -> Result<PathBuf, Stop> {
        let dest = staging.join(&entry.file);
        self.fetch(&entry.file, entry.size, &dest)?;
        let bytes = std::fs::read(&dest).map_err(|e| format!("{}: {e}", dest.display()))?;
        if bytes.len() as u64 != entry.size {
            return Err(Refusal::WrongSize(entry.file.clone()).into());
        }
        let signature = self.fetch_signature(&entry.file, staging)?;
        let signed = verify_artefact(anchor, &bytes, &signature, kind)?;
        require_listed(kind, signed, entry)?;
        require_newer(signed, baseline)?;
        Ok(dest)
    }

    /// Data kinds apply here: one atomic rename, then the record.
    fn apply_data(&self, anchor: &TrustAnchor, record: &mut Record, kind: &Kind, entry: &Entry) -> Result<(), Stop> {
        let name = kind.data_file().ok_or_else(|| format!("{kind} is not a data kind"))?;
        let staging = self.data_staging()?;
        let staged = self.fetch_verified(anchor, kind, entry, installed(kind, record, self.own), &staging.dir)?;
        swap::replace(&RealFs, &staged, &self.engine_dir.join(DATA_DIR).join(name))?;
        record.versions.insert(kind.to_string(), entry.version);
        state::save_record(&self.engine_dir, record)?;
        Ok(())
    }

    fn check(&self, anchor: &TrustAnchor, now_unix: u64) -> Result<UpdateStatus, Stop> {
        let mut record = state::load_record(&self.engine_dir)?;
        let index = self.read_index(anchor, &record, now_unix)?;
        let mut first_stop = None;
        for (kind, entry) in index.data() {
            if entry.version > installed(kind, &record, self.own)
                && let Err(stop) = self.apply_data(anchor, &mut record, kind, entry)
            {
                first_stop.get_or_insert(stop);
            }
        }
        if let Some(stop) = first_stop {
            return Err(stop);
        }
        record.index_version = index.version;
        state::save_record(&self.engine_dir, &record)?;
        Ok(self.outcome(&index, &record))
    }

    fn outcome(&self, index: &Index, record: &Record) -> UpdateStatus {
        if let Some((_, entry)) = offer(index, record, self.own) {
            return UpdateStatus::Available { version: display_version(entry.version) };
        }
        rolled_back(record, self.own).map_or(UpdateStatus::Current, |n| UpdateStatus::RolledBack { version: display_version(n) })
    }

    /// The index may have moved since the check: anything but the release on the
    /// user's screen is shown to them instead, never installed.
    fn apply(&self, anchor: &TrustAnchor, now_unix: u64, shown: &str) -> Result<UpdateStatus, Stop> {
        let record = state::load_record(&self.engine_dir)?;
        let index = self.read_index(anchor, &record, now_unix)?;
        let Some((kind, entry)) = offer(&index, &record, self.own).filter(|(_, entry)| display_version(entry.version) == shown) else {
            return Ok(self.outcome(&index, &record));
        };
        let mut staging = Staging::new(self.install_dir.join(STAGING_DIR))?;
        self.fetch_verified(anchor, &kind, entry, installed(&kind, &record, self.own), &staging.dir)?;
        let pending = Pending {
            kind: kind.to_string(),
            from_version: self.own,
            to_version: entry.version,
            staged: entry.file.clone(),
            aside: swap::release_set(&RealFs, &self.install_dir, &kind)?,
            rolling_back: false,
        };
        state::save_pending(&self.engine_dir, &pending)?;
        if let Err(why) = self.starter.start(&self.install_dir) {
            state::clear_pending(&self.engine_dir)?;
            return Err(why.into());
        }
        staging.keep = true;
        Ok(UpdateStatus::Applying { version: display_version(entry.version) })
    }
}

/// When the next scheduled check runs: `first_delay` after the start, then
/// daily, or sooner after a network failure. Not persisted: a restart costs at
/// most one extra fetch.
pub fn next_check(started_ms: u64, last: Option<(u64, bool)>) -> u64 {
    match last {
        None => started_ms + FIRST_CHECK_DELAY_MS,
        Some((at, true)) => at + FAILED_RETRY_MS,
        Some((at, false)) => at + CHECK_EVERY_MS,
    }
}

/// The worker: scheduled checks and asked-for jobs, one at a time, until the
/// sender goes away. A blocking thread of its own: fetches and verification
/// never hold the pipe.
pub fn run_worker(updater: &Updater, jobs: &mpsc::Receiver<Job>, monotonic_ms: &dyn Fn() -> u64, unix_now: &dyn Fn() -> u64) {
    let started = monotonic_ms();
    let mut last = None;
    loop {
        let now = monotonic_ms();
        let due = next_check(started, last);
        let wait = due.saturating_sub(now).min(SETTLE_POLL_MS);
        let job = match jobs.recv_timeout(Duration::from_millis(wait)) {
            Ok(job) => Some(job),
            Err(RecvTimeoutError::Timeout) if monotonic_ms() >= due => Some(Job::Check),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        if let Some(job) = job {
            let failed = updater.run(job, unix_now());
            last = Some((monotonic_ms(), failed));
        }
        updater.settle(monotonic_ms());
    }
}

#[cfg(test)]
mod tests {
    use super::super::fetch::tests::FakeHost;
    use super::super::state::tests::MemLog;
    use super::super::swap::ENGINE_EXE;
    use super::super::testing::{TestKey, comment, listing};
    use super::super::trust::release_number;
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NOW: u64 = 1_800_000_000;
    const FUTURE: u64 = NOW + 86_400;
    const OWN: u64 = release_number(0, 1, 0);
    const NEXT: u64 = release_number(0, 2, 0);
    const MARKER: &str = "sieve-install.marker";

    #[derive(Clone, Default)]
    struct FakeStarter {
        calls: Arc<AtomicUsize>,
        fail: bool,
    }

    impl ReleaseStarter for FakeStarter {
        fn start(&self, _: &Path) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail { Err("cannot start".into()) } else { Ok(()) }
        }
    }

    /// A temp install folder and ProgramData, a catalogue, and a signing key.
    struct World {
        _dir: tempfile::TempDir,
        key: TestKey,
        host: FakeHost,
        log: MemLog,
        starter: FakeStarter,
        updater: Updater,
    }

    impl World {
        fn with_anchor(configured: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let (install, engine) = (dir.path().join("install"), dir.path().join("engine"));
            std::fs::create_dir_all(&install).unwrap();
            std::fs::create_dir_all(&engine).unwrap();
            for (name, bytes) in [(ENGINE_EXE, &b"engine"[..]), ("sieve.exe", b"app"), (MARKER, b"")] {
                std::fs::write(install.join(name), bytes).unwrap();
            }
            let key = TestKey::new();
            let (host, log, starter) = (FakeHost::default(), MemLog::default(), FakeStarter::default());
            let updater = Updater {
                control: Arc::default(),
                anchor: configured.then(|| key.anchor()),
                fetcher: Box::new(host.clone()),
                log: Box::new(log.clone()),
                starter: Box::new(starter.clone()),
                engine_dir: engine,
                install_dir: install,
                own: OWN,
                supervisor_wait_from_ms: Cell::default(),
            };
            Self { _dir: dir, key, host, log, starter, updater }
        }

        fn new() -> Self {
            Self::with_anchor(true)
        }

        fn sign_put(&self, name: &str, bytes: &[u8], kind: &Kind, version: u64) {
            self.host.put(name, bytes);
            self.host.put(&signature_name(name), self.key.sign(bytes, &comment(kind, version)));
        }

        /// Publishes an index of these artefacts (kind, version, file, bytes).
        fn publish(&self, index_version: u64, artefacts: &[(Kind, u64, &str, &[u8])]) {
            for (kind, version, file, bytes) in artefacts {
                self.sign_put(file, bytes, kind, *version);
            }
            let entries: serde_json::Map<String, serde_json::Value> = artefacts
                .iter()
                .map(|(k, v, f, b)| (k.to_string(), serde_json::json!({"version": v, "file": f, "size": b.len()})))
                .collect();
            let body = serde_json::json!({"schema": 1, "version": index_version, "expires_unix": FUTURE, "artefacts": entries});
            self.sign_put(INDEX_FILE, body.to_string().as_bytes(), &Kind::Index, index_version);
        }

        fn engine_dir(&self) -> &Path {
            &self.updater.engine_dir
        }

        fn install_dir(&self) -> &Path {
            &self.updater.install_dir
        }

        fn trees(&self) -> [std::collections::BTreeMap<String, (u64, [u8; 32])>; 2] {
            [listing(self.install_dir()), listing(self.engine_dir())]
        }

        fn run(&self, job: Job) -> UpdateStatus {
            self.updater.run(job, NOW);
            self.updater.control.status()
        }

        fn record(&self) -> Record {
            state::load_record(self.engine_dir()).unwrap()
        }

        fn seed_record(&self, f: impl FnOnce(&mut Record)) {
            let mut r = self.record();
            f(&mut r);
            state::save_record(self.engine_dir(), &r).unwrap();
        }
    }

    const NEW_BYTES: &[u8] = b"new release bytes";
    const DATA_BYTES: &[u8] = b"resource bundle";

    fn resources() -> Kind {
        Kind::Resources
    }

    /// Applying what a check of the usual catalogue showed.
    fn apply_next() -> Job {
        Job::Apply { shown: "0.2.0".into() }
    }

    fn engine_release() -> Pending {
        Pending { kind: "engine".into(), from_version: OWN, to_version: NEXT, staged: "new.exe".into(), aside: vec![ENGINE_EXE.into()], rolling_back: false }
    }

    fn unfinished_rollback() -> UpdateStatus {
        UpdateStatus::Failed { message: ROLLBACK_UNFINISHED_MESSAGE.to_string() }
    }

    /// Every way the host can serve bad bytes, each from a world holding a
    /// valid catalogue for a data kind and a release: a mutation and whether it
    /// is seen by a check (data, index) or only by applying the release.
    #[test]
    fn after_each_refusal_both_trees_are_identical() {
        type Mutation = fn(&World);
        let cases: &[(&str, Job, Mutation)] = &[
            ("index: byte changed", Job::Check, |w| {
                let mut b = w.host.files.lock().unwrap()[INDEX_FILE].clone();
                b[0] ^= 1;
                w.host.put(INDEX_FILE, b);
            }),
            ("index: no signature", Job::Check, |w| {
                w.host.files.lock().unwrap().remove(&signature_name(INDEX_FILE));
            }),
            ("index: another key", Job::Check, |w| {
                let body = w.host.files.lock().unwrap()[INDEX_FILE].clone();
                w.host.put(&signature_name(INDEX_FILE), TestKey::new().sign(&body, &comment(&Kind::Index, 7)));
            }),
            ("index: signed as a list", Job::Check, |w| {
                let body = w.host.files.lock().unwrap()[INDEX_FILE].clone();
                w.host.put(&signature_name(INDEX_FILE), w.key.sign(&body, &comment(&Kind::List("x".into()), 7)));
            }),
            ("index: expired", Job::Check, |w| {
                let body = serde_json::json!({"schema": 1, "version": 7, "expires_unix": NOW, "artefacts": {}});
                w.sign_put(INDEX_FILE, body.to_string().as_bytes(), &Kind::Index, 7);
            }),
            ("index: older", Job::Check, |w| {
                let body = serde_json::json!({"schema": 1, "version": 4, "expires_unix": FUTURE, "artefacts": {}});
                w.sign_put(INDEX_FILE, body.to_string().as_bytes(), &Kind::Index, 4);
            }),
            ("index: bad file name", Job::Check, |w| {
                let body = serde_json::json!({"schema": 1, "version": 7, "expires_unix": FUTURE,
                    "artefacts": {"resources": {"version": 9, "file": "..\\x", "size": 1}}});
                w.sign_put(INDEX_FILE, body.to_string().as_bytes(), &Kind::Index, 7);
            }),
            ("index: unknown field", Job::Check, |w| {
                let body = serde_json::json!({"schema": 1, "version": 7, "expires_unix": FUTURE, "artefacts": {}, "url": "x"});
                w.sign_put(INDEX_FILE, body.to_string().as_bytes(), &Kind::Index, 7);
            }),
            ("data: byte changed", Job::Check, |w| {
                let mut b = DATA_BYTES.to_vec();
                b[3] ^= 1;
                w.host.put("res.bin", b);
            }),
            ("data: no signature", Job::Check, |w| {
                w.host.files.lock().unwrap().remove(&signature_name("res.bin"));
            }),
            ("data: another key", Job::Check, |w| {
                w.host.put(&signature_name("res.bin"), TestKey::new().sign(DATA_BYTES, &comment(&resources(), 3)));
            }),
            ("data: signed as engine", Job::Check, |w| {
                w.host.put(&signature_name("res.bin"), w.key.sign(DATA_BYTES, &comment(&Kind::Engine, 3)));
            }),
            ("data: signed for another version", Job::Check, |w| {
                w.host.put(&signature_name("res.bin"), w.key.sign(DATA_BYTES, &comment(&resources(), 2)));
            }),
            ("data: default minisign comment", Job::Check, |w| {
                w.host.put(&signature_name("res.bin"), w.key.sign_default(DATA_BYTES));
            }),
            ("data: garbled signature", Job::Check, |w| {
                w.host.put(&signature_name("res.bin"), "garbage");
            }),
            ("data: longer than signed", Job::Check, |w| {
                let mut b = DATA_BYTES.to_vec();
                b.push(0);
                w.host.put("res.bin", b);
            }),
            ("data: shorter than signed", Job::Check, |w| {
                w.host.put("res.bin", &DATA_BYTES[..3]);
            }),
            ("release: byte changed", apply_next(), |w| {
                let mut b = NEW_BYTES.to_vec();
                b[0] ^= 1;
                w.host.put("new.exe", b);
            }),
            ("release: no signature", apply_next(), |w| {
                w.host.files.lock().unwrap().remove(&signature_name("new.exe"));
            }),
            ("release: another key", apply_next(), |w| {
                w.host.put(&signature_name("new.exe"), TestKey::new().sign(NEW_BYTES, &comment(&Kind::Engine, NEXT)));
            }),
            ("release: a signed list served as engine", apply_next(), |w| {
                w.host.put(&signature_name("new.exe"), w.key.sign(NEW_BYTES, &comment(&Kind::List("x".into()), NEXT)));
            }),
            ("release: the old version re-served", apply_next(), |w| {
                w.host.put(&signature_name("new.exe"), w.key.sign(NEW_BYTES, &comment(&Kind::Engine, OWN)));
            }),
            ("release: longer than signed", apply_next(), |w| {
                let mut b = NEW_BYTES.to_vec();
                b.push(0);
                w.host.put("new.exe", b);
            }),
        ];
        for (name, job, mutate) in cases {
            let w = World::new();
            w.seed_record(|r| {
                r.index_version = 5;
                r.versions.insert("resources".into(), 2);
            });
            std::fs::create_dir_all(w.engine_dir().join(DATA_DIR)).unwrap();
            std::fs::write(w.engine_dir().join(DATA_DIR).join("resources"), b"the previous bundle").unwrap();
            w.publish(7, &[(resources(), 3, "res.bin", DATA_BYTES), (Kind::Engine, NEXT, "new.exe", NEW_BYTES)]);
            mutate(&w);
            if matches!(job, Job::Apply { .. }) {
                // The data applies first, so this compares only what the release could change.
                assert!(matches!(w.run(Job::Check), UpdateStatus::Available { .. }), "{name}");
            }
            let before = w.trees();
            let status = w.run(job.clone());
            let refused = matches!(status, UpdateStatus::Refused { .. } | UpdateStatus::Stale);
            assert!(refused, "{name}: {status:?}");
            assert_eq!(w.trees(), before, "{name}");
            assert_eq!(w.starter.calls.load(Ordering::Relaxed), 0, "{name}");
            assert!(!w.log.0.lock().unwrap().is_empty(), "{name}: the reason is logged");
            assert!(!w.engine_dir().join(DATA_DIR).join(DATA_STAGING_DIR).exists(), "{name}");
            assert!(!w.install_dir().join(STAGING_DIR).exists(), "{name}");
        }
    }

    #[test]
    fn a_refused_cycle_on_a_fresh_machine_leaves_no_folder_behind() {
        let w = World::new();
        w.publish(7, &[(resources(), 3, "res.bin", DATA_BYTES)]);
        w.host.put("res.bin", b"tampered".to_vec());
        assert!(matches!(w.run(Job::Check), UpdateStatus::Refused { .. }));
        assert!(!w.engine_dir().join(DATA_DIR).exists());
    }

    #[test]
    fn an_expired_index_reads_as_stale() {
        let w = World::new();
        let body = serde_json::json!({"schema": 1, "version": 1, "expires_unix": NOW, "artefacts": {}});
        w.sign_put(INDEX_FILE, body.to_string().as_bytes(), &Kind::Index, 1);
        assert_eq!(w.run(Job::Check), UpdateStatus::Stale);
    }

    #[test]
    fn a_body_longer_than_its_signed_size_is_cut_and_refused() {
        let w = World::new();
        w.publish(7, &[(resources(), 3, "res.bin", DATA_BYTES)]);
        w.host.put("res.bin", vec![b'x'; 10_000]);
        let UpdateStatus::Refused { message } = w.run(Job::Check) else { panic!("refused") };
        assert!(message.contains("res.bin"), "{message}");
        assert!(!w.engine_dir().join(DATA_DIR).join("resources").exists());
    }

    #[test]
    fn not_configured_never_calls_the_fetcher() {
        let w = World::with_anchor(false);
        w.publish(7, &[(Kind::Engine, NEXT, "new.exe", NEW_BYTES)]);
        assert_eq!(w.updater.initial_status(), UpdateStatus::NotConfigured);
        for job in [Job::Check, apply_next()] {
            assert_eq!(w.run(job), UpdateStatus::NotConfigured);
        }
        assert_eq!(w.host.call_count(), 0);
        w.updater.control.set_status(UpdateStatus::NotConfigured);
        w.updater.control.request(0).unwrap();
        assert_eq!(w.updater.control.status(), UpdateStatus::NotConfigured, "and a request queues nothing");
    }

    #[test]
    fn a_data_kind_applies_on_the_daily_check_and_raises_its_record() {
        let w = World::new();
        let list = Kind::List("sensitive".into());
        w.publish(7, &[(resources(), 3, "res.bin", DATA_BYTES), (list.clone(), 2, "l.txt", b"list")]);
        assert_eq!(w.run(Job::Check), UpdateStatus::Current);
        assert_eq!(std::fs::read(w.engine_dir().join(DATA_DIR).join("resources")).unwrap(), DATA_BYTES);
        assert_eq!(std::fs::read(w.engine_dir().join(DATA_DIR).join("list-sensitive")).unwrap(), b"list");
        let r = w.record();
        assert_eq!((r.versions["resources"], r.versions["list:sensitive"], r.index_version), (3, 2, 7));
        assert!(!w.engine_dir().join(DATA_DIR).join(DATA_STAGING_DIR).exists());

        let calls = w.host.call_count();
        assert_eq!(w.run(Job::Check), UpdateStatus::Current);
        assert_eq!(w.host.call_count(), calls + 2, "the same version is not fetched again: only the index and its signature");
    }

    #[test]
    fn a_release_is_only_reported_on_the_daily_check() {
        let w = World::new();
        w.publish(7, &[(Kind::Engine, NEXT, "new.exe", NEW_BYTES)]);
        let before = listing(w.install_dir());
        assert_eq!(w.run(Job::Check), UpdateStatus::Available { version: "0.2.0".into() });
        assert_eq!(listing(w.install_dir()), before);
        assert_eq!(w.starter.calls.load(Ordering::Relaxed), 0);
        assert_eq!(state::load_pending(w.engine_dir()).unwrap(), None);
    }

    #[test]
    fn request_while_available_applies_and_otherwise_only_checks() {
        let w = World::new();
        let (tx, rx) = mpsc::channel();
        w.updater.control.attach(tx);
        w.updater.control.set_status(UpdateStatus::Idle);
        w.publish(7, &[(Kind::Engine, NEXT, "new.exe", NEW_BYTES)]);

        w.updater.control.request(0).unwrap();
        assert_eq!(w.updater.control.status(), UpdateStatus::Checking);
        assert_eq!(rx.try_recv(), Ok(Job::Check), "not available yet: a check");
        w.updater.run(Job::Check, NOW);
        assert_eq!(state::load_pending(w.engine_dir()).unwrap(), None, "a check installs nothing");

        w.updater.control.request(1).unwrap();
        assert_eq!(w.updater.control.status(), UpdateStatus::Applying { version: "0.2.0".into() });
        assert_eq!(rx.try_recv(), Ok(apply_next()), "available and inside the cooldown: applying is not a check");
        w.updater.run(apply_next(), NOW);

        assert_eq!(w.updater.control.status(), UpdateStatus::Applying { version: "0.2.0".into() });
        let pending = state::load_pending(w.engine_dir()).unwrap().unwrap();
        assert_eq!((pending.from_version, pending.to_version, pending.kind.as_str()), (OWN, NEXT, "engine"));
        assert_eq!(pending.aside, [ENGINE_EXE]);
        assert_eq!(std::fs::read(w.install_dir().join(STAGING_DIR).join("new.exe")).unwrap(), NEW_BYTES);
        assert_eq!(w.starter.calls.load(Ordering::Relaxed), 1);
        assert_eq!(std::fs::read(w.install_dir().join(ENGINE_EXE)).unwrap(), b"engine", "the swap is the supervisor's");

        w.updater.control.request(2).unwrap();
        assert!(rx.try_recv().is_err(), "while applying a request queues nothing");
    }

    /// The host published again between the check and the click.
    #[test]
    fn apply_never_installs_a_release_the_user_was_not_shown() {
        let w = World::new();
        w.publish(7, &[(Kind::Engine, NEXT, "new.exe", NEW_BYTES)]);
        assert_eq!(w.run(Job::Check), UpdateStatus::Available { version: "0.2.0".into() });
        w.publish(8, &[(Kind::Engine, NEXT + 1, "newer.exe", NEW_BYTES)]);
        let before = w.trees();
        assert_eq!(w.run(apply_next()), UpdateStatus::Available { version: "0.2.1".into() }, "shown first, not applied");
        assert_eq!(w.trees(), before);
        assert_eq!(state::load_pending(w.engine_dir()).unwrap(), None);
        assert_eq!(w.starter.calls.load(Ordering::Relaxed), 0);

        assert_eq!(w.run(Job::Apply { shown: "0.2.1".into() }), UpdateStatus::Applying { version: "0.2.1".into() });
        assert_eq!(state::load_pending(w.engine_dir()).unwrap().unwrap().to_version, NEXT + 1);
    }

    /// A scheduled check may overwrite `applying` before the queued job runs;
    /// the job still carries what was on screen when the user clicked.
    #[test]
    fn the_queued_apply_carries_the_version_on_screen() {
        let c = UpdateControl::default();
        let (tx, rx) = mpsc::channel();
        c.attach(tx);
        c.set_status(UpdateStatus::Available { version: "0.2.0".into() });
        c.request(0).unwrap();
        c.set_status(UpdateStatus::Available { version: "0.2.1".into() });
        assert_eq!(rx.try_recv(), Ok(apply_next()));
    }

    #[test]
    fn a_commit_that_lost_to_a_rollback_is_still_shown_as_rolled_back() {
        let w = World::new();
        let p = engine_release();
        state::save_pending(w.engine_dir(), &p).unwrap();
        state::commit_healthy(w.engine_dir(), &p).unwrap();
        state::save_pending(w.engine_dir(), &p).unwrap();
        state::record_rollback(w.engine_dir(), &p).unwrap();
        assert_eq!(w.updater.initial_status(), UpdateStatus::RolledBack { version: "0.2.0".into() });
        w.publish(7, &[(Kind::Engine, NEXT, "new.exe", NEW_BYTES)]);
        assert_eq!(w.run(Job::Check), UpdateStatus::RolledBack { version: "0.2.0".into() }, "and it is not offered again");
    }

    #[test]
    fn a_second_request_inside_the_cooldown_is_an_error() {
        let c = UpdateControl::default();
        let (tx, rx) = mpsc::channel();
        c.attach(tx);
        c.set_status(UpdateStatus::Current);
        c.request(1_000).unwrap();
        c.set_status(UpdateStatus::Current);
        assert_eq!(c.request(1_000 + REQUEST_COOLDOWN_MS - 1), Err(COOLDOWN_MESSAGE.to_string()));
        assert_eq!(c.status(), UpdateStatus::Current, "refused: nothing changed");
        c.request(1_000 + REQUEST_COOLDOWN_MS).unwrap();
        assert_eq!(rx.try_iter().count(), 2);
    }

    #[test]
    fn a_request_with_no_worker_says_so() {
        let c = UpdateControl::default();
        c.set_status(UpdateStatus::Idle);
        assert_eq!(c.request(0), Err(NOT_RUNNING_MESSAGE.to_string()));
        assert_eq!(c.status(), UpdateStatus::Idle);
    }

    #[test]
    fn an_app_release_is_preferred_when_both_are_offered() {
        let w = World::new();
        w.publish(7, &[(Kind::App, NEXT, "setup.exe", b"installer"), (Kind::Engine, NEXT + 1, "new.exe", NEW_BYTES)]);
        assert_eq!(w.run(Job::Check), UpdateStatus::Available { version: "0.2.0".into() });
        w.run(apply_next());
        let pending = state::load_pending(w.engine_dir()).unwrap().unwrap();
        assert_eq!((pending.kind.as_str(), pending.staged.as_str()), ("app", "setup.exe"));
        assert_eq!(pending.aside, [ENGINE_EXE, "sieve.exe"], "derived from the listing, without the marker");
    }

    #[test]
    fn a_lower_app_release_cannot_downgrade_a_newer_engine() {
        let w = World::new();
        w.seed_record(|r| {
            r.versions.insert("engine".into(), release_number(0, 3, 0));
        });
        w.publish(7, &[(Kind::App, NEXT, "setup.exe", b"installer")]);
        assert_eq!(w.run(Job::Check), UpdateStatus::Current);
        assert_eq!(w.run(apply_next()), UpdateStatus::Current);
        assert_eq!(state::load_pending(w.engine_dir()).unwrap(), None);
    }

    #[test]
    fn a_rolled_back_version_is_not_offered_again_and_a_higher_one_is() {
        let w = World::new();
        w.seed_record(|r| {
            r.rolled_back.insert("engine".into(), NEXT);
        });
        assert_eq!(w.updater.initial_status(), UpdateStatus::RolledBack { version: "0.2.0".into() });
        w.publish(7, &[(Kind::Engine, NEXT, "new.exe", NEW_BYTES)]);
        assert_eq!(w.run(Job::Check), UpdateStatus::RolledBack { version: "0.2.0".into() }, "still shown, still not offered");
        assert_eq!(w.run(apply_next()), UpdateStatus::RolledBack { version: "0.2.0".into() });
        assert_eq!(state::load_pending(w.engine_dir()).unwrap(), None);
        w.publish(8, &[(Kind::Engine, NEXT + 1, "new.exe", NEW_BYTES)]);
        assert_eq!(w.run(Job::Check), UpdateStatus::Available { version: "0.2.1".into() });
    }

    #[test]
    fn a_host_that_is_down_is_a_failure_not_a_refusal_and_retries_sooner() {
        let w = World::new();
        *w.host.down.lock().unwrap() = true;
        assert!(w.updater.run(Job::Check, NOW));
        assert!(matches!(w.updater.control.status(), UpdateStatus::Failed { .. }));
        assert_eq!(next_check(0, Some((5, true))), 5 + FAILED_RETRY_MS);
        assert_eq!(next_check(0, Some((5, false))), 5 + CHECK_EVERY_MS);
        assert_eq!(next_check(100, None), 100 + FIRST_CHECK_DELAY_MS);
    }

    #[test]
    fn a_supervisor_that_cannot_start_leaves_nothing_in_flight() {
        let mut w = World::new();
        w.updater.starter = Box::new(FakeStarter { fail: true, ..FakeStarter::default() });
        w.publish(7, &[(Kind::Engine, NEXT, "new.exe", NEW_BYTES)]);
        let before = w.trees();
        assert!(matches!(w.run(apply_next()), UpdateStatus::Failed { .. }));
        assert_eq!(state::load_pending(w.engine_dir()).unwrap(), None);
        assert!(!w.install_dir().join(STAGING_DIR).exists());
        assert_eq!(w.trees(), before);
    }

    #[test]
    fn while_a_release_is_in_flight_nothing_else_runs_and_a_vanished_one_is_reported() {
        let w = World::new();
        w.publish(7, &[(Kind::Engine, NEXT, "new.exe", NEW_BYTES)]);
        w.run(apply_next());
        let calls = w.host.call_count();
        assert_eq!(w.run(Job::Check), UpdateStatus::Applying { version: "0.2.0".into() });
        assert_eq!(w.host.call_count(), calls);
        w.updater.settle(0);
        assert_eq!(w.updater.control.status(), UpdateStatus::Applying { version: "0.2.0".into() });
        state::clear_pending(w.engine_dir()).unwrap();
        w.updater.settle(1);
        assert_eq!(w.updater.control.status(), UpdateStatus::Failed { message: UNFINISHED_MESSAGE.to_string() });
    }

    /// The supervisor died before it stopped this service: the pending file stays
    /// and this process runs on. The wait ends, and updates work again.
    #[test]
    fn a_supervisor_that_never_takes_over_ends_the_wait() {
        const START: u64 = 5_000;
        let w = World::new();
        w.publish(7, &[(Kind::Engine, NEXT, "new.exe", NEW_BYTES)]);
        w.run(apply_next());
        w.updater.settle(START);
        w.updater.settle(START + SUPERVISOR_WAIT_MS - 1);
        assert_eq!(w.updater.control.status(), UpdateStatus::Applying { version: "0.2.0".into() }, "a slow stop still has time");
        assert!(state::load_pending(w.engine_dir()).unwrap().is_some());

        w.updater.settle(START + SUPERVISOR_WAIT_MS);
        assert_eq!(w.updater.control.status(), UpdateStatus::Failed { message: UNFINISHED_MESSAGE.to_string() });
        assert_eq!(state::load_pending(w.engine_dir()).unwrap(), None);

        let (tx, rx) = mpsc::channel();
        w.updater.control.attach(tx);
        w.updater.control.request(0).unwrap();
        assert_eq!(rx.try_recv(), Ok(Job::Check), "a request queues work again");
        assert_eq!(w.run(Job::Check), UpdateStatus::Available { version: "0.2.0".into() });
        assert!(!w.install_dir().join(STAGING_DIR).exists());
    }

    /// The new build is running with nobody watching: past the wait the release is
    /// not dropped, which would keep it unproven, but rolled back.
    #[test]
    fn a_new_build_left_unwatched_turns_the_release_into_a_rollback() {
        let mut w = World::new();
        w.updater.own = NEXT;
        state::save_pending(w.engine_dir(), &engine_release()).unwrap();
        w.updater.control.set_status(UpdateStatus::Applying { version: "0.2.0".into() });
        w.updater.settle(0);
        w.updater.settle(SUPERVISOR_WAIT_MS);
        assert_eq!(state::load_pending(w.engine_dir()).unwrap(), Some(Pending { rolling_back: true, ..engine_release() }));
        assert_eq!(w.starter.calls.load(Ordering::Relaxed), 0);
    }

    /// The old engine is back but a later file of an app release was locked. The
    /// next check must not take its `.old` for a leftover.
    #[test]
    fn the_old_build_finishes_a_rollback_in_place_and_only_then_the_old_files_go() {
        let w = World::new();
        let aside = vec![ENGINE_EXE.to_string(), "sieve.exe".to_string()];
        state::save_pending(w.engine_dir(), &Pending { kind: "app".into(), aside, rolling_back: true, ..engine_release() }).unwrap();
        std::fs::write(w.install_dir().join("sieve.exe"), b"new app").unwrap();
        std::fs::write(w.install_dir().join("sieve.exe.old"), b"old app").unwrap();
        w.publish(7, &[]);

        let calls = w.host.call_count();
        assert_eq!(w.run(Job::Check), unfinished_rollback());
        assert_eq!(w.host.call_count(), calls, "nothing is fetched");
        assert_eq!(std::fs::read(w.install_dir().join("sieve.exe.old")).unwrap(), b"old app");

        w.updater.settle(0);
        assert_eq!(w.updater.control.status(), UpdateStatus::RolledBack { version: "0.2.0".into() });
        assert_eq!(std::fs::read(w.install_dir().join("sieve.exe")).unwrap(), b"old app");
        assert_eq!(std::fs::read(w.install_dir().join(ENGINE_EXE)).unwrap(), b"engine", "already restored, left alone");
        assert_eq!(state::load_pending(w.engine_dir()).unwrap(), None);
        assert_eq!(w.record().rolled_back["app"], NEXT);
        assert_eq!(w.starter.calls.load(Ordering::Relaxed), 0, "no restart");

        assert_eq!(w.run(Job::Check), UpdateStatus::RolledBack { version: "0.2.0".into() });
        assert!(!w.install_dir().join("sieve.exe.failed").exists(), "now they are leftovers");
    }

    /// The failed build itself is running: a supervisor replaces it, spaced out.
    #[test]
    fn a_running_failed_build_hands_the_rollback_to_a_supervisor_one_per_wait() {
        let mut w = World::new();
        w.updater.own = NEXT;
        let marked = Pending { rolling_back: true, ..engine_release() };
        state::save_pending(w.engine_dir(), &marked).unwrap();
        std::fs::write(w.install_dir().join("sieve-engine.exe.old"), b"old").unwrap();
        for at in [0, 1, SUPERVISOR_WAIT_MS - 1] {
            w.updater.settle(at);
            assert_eq!(w.starter.calls.load(Ordering::Relaxed), 0, "{at}");
        }
        assert_eq!(w.updater.control.status(), unfinished_rollback());
        w.updater.settle(SUPERVISOR_WAIT_MS);
        w.updater.settle(SUPERVISOR_WAIT_MS + 1);
        assert_eq!(w.starter.calls.load(Ordering::Relaxed), 1);
        assert_eq!(state::load_pending(w.engine_dir()).unwrap(), Some(marked), "the supervisor ends it, not this");
        assert_eq!(std::fs::read(w.install_dir().join("sieve-engine.exe.old")).unwrap(), b"old");
        assert_eq!(w.log.0.lock().unwrap().iter().filter(|l| l.contains("rollback unfinished")).count(), 1);
    }

    #[test]
    fn leftovers_of_a_finished_release_go_at_the_next_check() {
        let w = World::new();
        w.publish(7, &[]);
        std::fs::write(w.install_dir().join("sieve-engine.exe.old"), b"x").unwrap();
        std::fs::create_dir(w.install_dir().join(STAGING_DIR)).unwrap();
        std::fs::write(w.install_dir().join(STAGING_DIR).join("update-finish.exe"), b"x").unwrap();
        assert_eq!(w.run(Job::Check), UpdateStatus::Current);
        assert!(!w.install_dir().join("sieve-engine.exe.old").exists());
        assert!(!w.install_dir().join(STAGING_DIR).exists());
        assert_eq!(std::fs::read(w.install_dir().join(ENGINE_EXE)).unwrap(), b"engine");
    }

    #[test]
    fn the_worker_runs_a_queued_job_and_ends_with_its_sender() {
        let w = World::new();
        w.publish(7, &[(Kind::Engine, NEXT, "new.exe", NEW_BYTES)]);
        let (tx, rx) = mpsc::channel();
        tx.send(Job::Check).unwrap();
        drop(tx);
        run_worker(&w.updater, &rx, &|| 0, &|| NOW);
        assert_eq!(w.updater.control.status(), UpdateStatus::Available { version: "0.2.0".into() });
    }
}
