//! What the updater keeps in admin-only `ProgramData\Sieve\engine`:
//! `update-state.json` (the versions it accepted), `update-pending.json` (a
//! release in flight, the supervisor's only input) and `update.log`. Both JSON
//! files use the atomic write; a malformed one is an error, never read as
//! empty, which would quietly reset the rollback protection.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::Kind;
use crate::policy::write_atomic;

pub const STATE_FILE: &str = "update-state.json";
pub const PENDING_FILE: &str = "update-pending.json";
pub const LOG_FILE: &str = "update.log";
/// A hostile host can provoke a refusal every check, so the log is capped.
pub const LOG_MAX_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// The installed version per kind, once one was accepted.
    pub versions: BTreeMap<String, u64>,
    /// The highest index version accepted.
    pub index_version: u64,
    /// The release version per kind that failed; it and anything lower is not
    /// offered again, a higher one is.
    pub rolled_back: BTreeMap<String, u64>,
}

/// A release in flight, written before the supervisor starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    /// `app` or `engine`.
    pub kind: String,
    pub from_version: u64,
    pub to_version: u64,
    /// The verified file's bare name inside the staging folder.
    pub staged: String,
    /// The install folder's files this release replaces, as listed before it.
    pub aside: Vec<String>,
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    write_atomic(path, &serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?)
}

pub fn load_record(dir: &Path) -> Result<Record, String> {
    Ok(read_json(&dir.join(STATE_FILE))?.unwrap_or_default())
}

pub fn save_record(dir: &Path, record: &Record) -> Result<(), String> {
    write_json(&dir.join(STATE_FILE), record)
}

pub fn load_pending(dir: &Path) -> Result<Option<Pending>, String> {
    read_json(&dir.join(PENDING_FILE))
}

pub fn save_pending(dir: &Path, pending: &Pending) -> Result<(), String> {
    write_json(&dir.join(PENDING_FILE), pending)
}

pub fn clear_pending(dir: &Path) -> Result<(), String> {
    let path = dir.join(PENDING_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// The version a new artefact of `kind` must beat. The installer carries app
/// and engine both, so a lower `app` release would downgrade the engine: a
/// release beats the highest of both records and this build's own number.
pub fn installed(kind: &Kind, record: &Record, own: u64) -> u64 {
    let of = |k: &Kind| record.versions.get(&k.to_string()).copied().unwrap_or(0);
    if kind.is_release() { of(&Kind::App).max(of(&Kind::Engine)).max(own) } else { of(kind) }
}

/// What a starting service does about a pending release, whatever came before
/// it (a live supervisor or a reboot in the middle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    /// This build is the release: run the health probe.
    Probe,
    /// This build is the old one: the swap never happened.
    NotSwapped,
    /// This build is neither: a mislabelled release. Never raised.
    Mislabelled,
}

pub fn recover(pending: &Pending, own: u64) -> Recovery {
    if own == pending.to_version {
        Recovery::Probe
    } else if own == pending.from_version {
        Recovery::NotSwapped
    } else {
        Recovery::Mislabelled
    }
}

/// Runs before anything else when the service starts, and handles a reboot in
/// the middle, when no supervisor exists any more. The release to report healthy
/// for, if this build is it. `.old` files stay for the next check: a live
/// supervisor may still need them for its rollback.
pub fn on_service_start(dir: &Path, own: u64, log: &dyn Log) -> Option<Pending> {
    let pending = match load_pending(dir) {
        Ok(p) => p?,
        Err(why) => {
            log.line(&why);
            return None;
        }
    };
    let recovery = recover(&pending, own);
    if recovery == Recovery::Probe {
        return Some(pending);
    }
    log.line(&format!("{} {} in flight, this build is {own}: {recovery:?}", pending.kind, pending.to_version));
    if let Err(why) = clear_pending(dir) {
        log.line(&why);
    }
    None
}

/// The new engine answered its own pipe: the record rises, then the pending
/// file goes. The supervisor reads both, in that order.
pub fn commit_healthy(dir: &Path, pending: &Pending) -> Result<(), String> {
    let mut record = load_record(dir)?;
    record.versions.insert(pending.kind.clone(), pending.to_version);
    save_record(dir, &record)?;
    clear_pending(dir)
}

/// True once the record holds this release (the supervisor's view of a healthy
/// report; a pending file cleared without it is no such report).
pub fn is_committed(dir: &Path, pending: &Pending) -> Result<bool, String> {
    Ok(load_record(dir)?.versions.get(&pending.kind) == Some(&pending.to_version))
}

/// Rollback: the version record stays where it was, the failed version is
/// remembered, and the pending file goes.
pub fn record_rollback(dir: &Path, pending: &Pending) -> Result<(), String> {
    let mut record = load_record(dir)?;
    record.rolled_back.insert(pending.kind.clone(), pending.to_version);
    save_record(dir, &record)?;
    clear_pending(dir)
}

/// Where refusal reasons go.
pub trait Log: Send {
    fn line(&self, text: &str);
}

/// `update.log`, capped: at [`LOG_MAX_BYTES`] it keeps the newer half. Best
/// effort: a log that cannot be written never stops an update check.
pub struct FileLog {
    path: PathBuf,
    max: u64,
    guard: Mutex<()>,
}

impl FileLog {
    pub fn new(dir: &Path) -> Self {
        Self::capped(dir, LOG_MAX_BYTES)
    }

    fn capped(dir: &Path, max: u64) -> Self {
        Self { path: dir.join(LOG_FILE), max, guard: Mutex::new(()) }
    }

    fn trim(&self) {
        let Ok(bytes) = std::fs::read(&self.path) else { return };
        if (bytes.len() as u64) < self.max {
            return;
        }
        let half = bytes.len() - usize::try_from(self.max / 2).unwrap_or(bytes.len());
        let after_newline = bytes[half..].iter().position(|b| *b == b'\n').map_or(half, |i| half + i + 1);
        let _ = write_atomic(&self.path, &bytes[after_newline..]);
    }
}

impl Log for FileLog {
    fn line(&self, text: &str) {
        let _held = self.guard.lock().unwrap_or_else(|p| p.into_inner());
        self.trim();
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = writeln!(file, "{} {text}", crate::policy::wall_ms());
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A memory sink, so a refusal test can compare trees and read the reason.
    #[derive(Default, Clone)]
    pub struct MemLog(pub std::sync::Arc<Mutex<Vec<String>>>);

    impl Log for MemLog {
        fn line(&self, text: &str) {
            self.0.lock().unwrap().push(text.to_string());
        }
    }

    fn pending(from: u64, to: u64) -> Pending {
        Pending { kind: "engine".into(), from_version: from, to_version: to, staged: "s.exe".into(), aside: vec!["sieve-engine.exe".into()] }
    }

    #[test]
    fn a_release_beats_both_records_and_this_build_and_data_only_its_own() {
        let mut r = Record::default();
        assert_eq!(installed(&Kind::App, &r, 5), 5, "no record: this build is the baseline");
        assert_eq!(installed(&Kind::Resources, &r, 5), 0);
        r.versions.insert("engine".into(), 9);
        r.versions.insert("resources".into(), 3);
        assert_eq!(installed(&Kind::App, &r, 5), 9, "an app release must not downgrade the engine");
        r.versions.insert("app".into(), 11);
        assert_eq!(installed(&Kind::Engine, &r, 5), 11);
        assert_eq!(installed(&Kind::Resources, &r, 5), 3);
        assert_eq!(installed(&Kind::List("a".into()), &r, 5), 0);
    }

    #[test]
    fn recover_after_a_reboot_in_each_phase() {
        // A reboot before or during the swap leaves the old build running; after
        // it the new one; a release that names another number is neither.
        for (own, want) in [(1, Recovery::NotSwapped), (2, Recovery::Probe), (3, Recovery::Mislabelled), (0, Recovery::Mislabelled)] {
            assert_eq!(recover(&pending(1, 2), own), want, "{own}");
        }
    }

    #[test]
    fn a_start_with_a_release_in_flight_probes_or_clears_and_never_raises() {
        let dir = tempfile::tempdir().unwrap();
        let log = MemLog::default();
        assert_eq!(on_service_start(dir.path(), 2, &log), None, "nothing in flight");
        assert!(log.0.lock().unwrap().is_empty());

        let p = pending(1, 2);
        save_pending(dir.path(), &p).unwrap();
        assert_eq!(on_service_start(dir.path(), 2, &log), Some(p.clone()));
        assert_eq!(load_pending(dir.path()).unwrap(), Some(p.clone()), "the probe clears it, not the start");

        for own in [1, 3] {
            save_pending(dir.path(), &p).unwrap();
            assert_eq!(on_service_start(dir.path(), own, &log), None, "{own}");
            assert_eq!(load_pending(dir.path()).unwrap(), None, "{own}");
            assert_eq!(load_record(dir.path()).unwrap(), Record::default(), "{own}: never raised");
        }
        assert_eq!(log.0.lock().unwrap().len(), 2, "each reported");

        std::fs::write(dir.path().join(PENDING_FILE), b"not json").unwrap();
        assert_eq!(on_service_start(dir.path(), 2, &log), None, "a damaged record starts the engine anyway");
    }

    #[test]
    fn the_record_and_pending_round_trip_and_a_malformed_one_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_record(dir.path()).unwrap(), Record::default());
        assert_eq!(load_pending(dir.path()).unwrap(), None);
        let p = pending(1, 2);
        save_pending(dir.path(), &p).unwrap();
        assert_eq!(load_pending(dir.path()).unwrap(), Some(p));
        clear_pending(dir.path()).unwrap();
        clear_pending(dir.path()).unwrap();
        std::fs::write(dir.path().join(STATE_FILE), b"{}").unwrap();
        assert!(load_record(dir.path()).is_err(), "a damaged record never resets the protection");
    }

    #[test]
    fn a_healthy_commit_raises_the_record_and_a_rollback_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let p = pending(1, 2);
        save_pending(dir.path(), &p).unwrap();
        assert!(!is_committed(dir.path(), &p).unwrap());
        record_rollback(dir.path(), &p).unwrap();
        let r = load_record(dir.path()).unwrap();
        assert_eq!((r.versions.get("engine"), r.rolled_back.get("engine")), (None, Some(&2)));
        assert_eq!(load_pending(dir.path()).unwrap(), None);
        save_pending(dir.path(), &p).unwrap();
        commit_healthy(dir.path(), &p).unwrap();
        assert!(is_committed(dir.path(), &p).unwrap());
        assert_eq!(load_pending(dir.path()).unwrap(), None);
    }

    #[test]
    fn the_log_appends_and_at_its_cap_keeps_the_newer_half() {
        let dir = tempfile::tempdir().unwrap();
        let log = FileLog::capped(dir.path(), 200);
        for i in 0..100 {
            log.line(&format!("line {i}"));
        }
        let text = std::fs::read_to_string(dir.path().join(LOG_FILE)).unwrap();
        assert!(text.len() < 240, "{}", text.len());
        assert!(text.contains("line 99"));
        assert!(!text.contains("line 0\n"));
        assert!(text.lines().all(|l| l.contains("line ")), "cut at a line boundary");
    }
}
