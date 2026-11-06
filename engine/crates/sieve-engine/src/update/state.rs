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
use super::swap::{self, RealFs};
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
    /// The supervisor gave its verdict: this release failed. Set before any file
    /// moves back, so `.old` stays and the set is restored whoever runs next.
    #[serde(default)]
    pub rolling_back: bool,
    /// Every `.old` is whole and on disk, and the swap or installer may have
    /// begun. Before this nothing real changed, and a partial `.old` means nothing.
    #[serde(default)]
    pub swap_started: bool,
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

/// On disk before it returns: recovery after a power loss reads the marks in it.
pub fn save_pending(dir: &Path, pending: &Pending) -> Result<(), String> {
    let path = dir.join(PENDING_FILE);
    write_json(&path, pending)?;
    std::fs::OpenOptions::new().write(true).open(&path).and_then(|file| file.sync_all()).map_err(|e| format!("{}: {e}", path.display()))
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
    /// This build is the old one and the files are its own: the swap never happened.
    NotSwapped,
    /// This build is the old one but the files around it moved on: an `app`
    /// install stopped part way, since the installer copies the engine last. The
    /// `.old` files are the only whole set, so this becomes a rollback.
    Interrupted,
    /// This build is neither: a mislabelled release. Never raised.
    Mislabelled,
    /// A rollback did not finish: whichever build this is, the release stays in
    /// flight and the updater's `settle` carries it on.
    FinishRollback,
}

/// `set_changed`: the real files are no longer the set that was set aside.
pub fn recover(pending: &Pending, own: u64, set_changed: bool) -> Recovery {
    if pending.rolling_back {
        Recovery::FinishRollback
    } else if own == pending.to_version {
        Recovery::Probe
    } else if own != pending.from_version {
        Recovery::Mislabelled
    } else if set_changed {
        Recovery::Interrupted
    } else {
        Recovery::NotSwapped
    }
}

/// Runs before anything else when the service starts, and handles a reboot in
/// the middle, when no supervisor exists any more. The release to report healthy
/// for, if this build is it. `.old` files stay for the next check: a live
/// supervisor may still need them for its rollback.
pub fn on_service_start(dir: &Path, install: &Path, own: u64, log: &dyn Log) -> Option<Pending> {
    let pending = match load_pending(dir) {
        Ok(p) => p?,
        Err(why) => {
            log.line(&why);
            return None;
        }
    };
    let set_changed = pending.swap_started
        && own == pending.from_version
        && Kind::parse(&pending.kind).is_some_and(|kind| swap::set_changed(&RealFs, install, &kind, &pending.aside));
    let recovery = recover(&pending, own, set_changed);
    if recovery == Recovery::Probe {
        return Some(pending);
    }
    log.line(&format!("{} {} in flight, this build is {own}: {recovery:?}", pending.kind, pending.to_version));
    let settled = match recovery {
        Recovery::Probe | Recovery::FinishRollback => Ok(()),
        Recovery::Interrupted => save_pending(dir, &Pending { rolling_back: true, ..pending }),
        Recovery::NotSwapped | Recovery::Mislabelled => clear_pending(dir),
    };
    if let Err(why) = settled {
        log.line(&why);
    }
    None
}

/// The new engine answered its own pipe: the record rises, then the pending
/// file goes. The supervisor reads both, in that order. With the release no
/// longer in flight, or marked as rolling back, the supervisor has already
/// decided, and nothing rises.
pub fn commit_healthy(dir: &Path, pending: &Pending) -> Result<(), String> {
    if load_pending(dir)?.as_ref() != Some(pending) {
        return Ok(());
    }
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

/// Rollback: the failed version is remembered and the pending file goes. The
/// version record says what is installed, and that is not this release: if its
/// report landed before the verdict, the raise is undone. The entry goes rather
/// than falling to an older number, since [`installed`] already has the restored
/// build's own as its baseline. A damaged record is reported, never reset, and
/// the release is over all the same.
pub fn record_rollback(dir: &Path, pending: &Pending) -> Result<(), String> {
    let recorded = load_record(dir).and_then(|mut record| {
        if record.versions.get(&pending.kind) == Some(&pending.to_version) {
            record.versions.remove(&pending.kind);
        }
        record.rolled_back.insert(pending.kind.clone(), pending.to_version);
        save_record(dir, &record)
    });
    let cleared = clear_pending(dir);
    recorded.and(cleared)
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
        Pending {
            kind: "engine".into(),
            from_version: from,
            to_version: to,
            staged: "s.exe".into(),
            aside: vec!["sieve-engine.exe".into()],
            rolling_back: false,
            swap_started: false,
        }
    }

    /// Whichever build starts, an unfinished rollback stays in flight, so the
    /// next check cannot delete the `.old` files it still needs.
    #[test]
    fn a_start_during_an_unfinished_rollback_keeps_it_in_flight() {
        let dir = tempfile::tempdir().unwrap();
        let log = MemLog::default();
        let p = Pending { rolling_back: true, ..pending(1, 2) };
        save_pending(dir.path(), &p).unwrap();
        for own in [1, 2, 3] {
            for set_changed in [false, true] {
                assert_eq!(recover(&p, own, set_changed), Recovery::FinishRollback, "{own}");
            }
            assert_eq!(on_service_start(dir.path(), dir.path(), own, &log), None, "{own}: no probe");
            assert_eq!(load_pending(dir.path()).unwrap().as_ref(), Some(&p), "{own}");
        }
    }

    /// Where an `app` release can stand when a build starts with no supervisor
    /// left, and what that start must do. The installer copies `sieve.exe` first
    /// and the engine last, so the old engine can start beside new app files.
    #[test]
    fn an_app_release_through_recover_and_on_service_start() {
        use super::super::swap::{ENGINE_EXE, OLD_SUFFIX, set_aside};

        #[derive(Debug, PartialEq, Eq)]
        enum After {
            Cleared,
            MarkedRollingBack,
            ProbeWithRecordKept,
        }
        const OLD: &[u8] = b"old";
        const NEW: &[u8] = b"new";
        const FROM: u64 = 1;
        const TO: u64 = 2;
        const WRONG: u64 = 3;
        let write = |i: &Path, name: &str, bytes: &[u8]| std::fs::write(i.join(name), bytes).unwrap();
        let aside_all = |i: &Path| set_aside(&RealFs, i, &[ENGINE_EXE.to_string(), "sieve.exe".to_string(), "uninstall.exe".to_string()]).unwrap();

        type Setup<'a> = &'a dyn Fn(&Path);
        let table: &[(&str, bool, Setup, u64, Recovery, After)] = &[
            ("before the set-aside", false, &|_| {}, FROM, Recovery::NotSwapped, After::Cleared),
            // A copy cut short differs from its real file, and proves nothing.
            ("during the set-aside", false, &|i| write(i, "sieve.exe.old", b"ol"), FROM, Recovery::NotSwapped, After::Cleared),
            ("set aside, installer not yet at a file", true, &aside_all, FROM, Recovery::NotSwapped, After::Cleared),
            (
                "new app files, old engine",
                true,
                &|i| {
                    aside_all(i);
                    write(i, "sieve.exe", NEW);
                },
                FROM,
                Recovery::Interrupted,
                After::MarkedRollingBack,
            ),
            (
                "a file the installer removed",
                true,
                &|i| {
                    aside_all(i);
                    std::fs::remove_file(i.join("uninstall.exe")).unwrap();
                },
                FROM,
                Recovery::Interrupted,
                After::MarkedRollingBack,
            ),
            (
                "only a file the installer added",
                true,
                &|i| {
                    aside_all(i);
                    write(i, "added.dll", NEW);
                },
                FROM,
                Recovery::Interrupted,
                After::MarkedRollingBack,
            ),
            (
                "the whole new set",
                true,
                &|i| {
                    aside_all(i);
                    write(i, "sieve.exe", NEW);
                    write(i, ENGINE_EXE, NEW);
                },
                TO,
                Recovery::Probe,
                After::ProbeWithRecordKept,
            ),
            (
                "another build reinstalled by hand",
                true,
                &|i| {
                    aside_all(i);
                    write(i, "sieve.exe", NEW);
                    write(i, ENGINE_EXE, NEW);
                },
                WRONG,
                Recovery::Mislabelled,
                After::Cleared,
            ),
        ];

        for (case, swap_started, setup, own, recovery, after) in table {
            let (dir, install) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            for name in [ENGINE_EXE, "sieve.exe", "uninstall.exe"] {
                write(install.path(), name, OLD);
            }
            setup(install.path());
            let p = Pending {
                kind: "app".into(),
                from_version: FROM,
                to_version: TO,
                staged: "setup.exe".into(),
                aside: vec![ENGINE_EXE.into(), "sieve.exe".into(), "uninstall.exe".into()],
                rolling_back: false,
                swap_started: *swap_started,
            };
            save_pending(dir.path(), &p).unwrap();
            let olds: Vec<_> = p.aside.iter().map(|n| std::fs::read(install.path().join(format!("{n}{OLD_SUFFIX}"))).ok()).collect();

            let changed = *swap_started && *own == FROM && swap::set_changed(&RealFs, install.path(), &Kind::App, &p.aside);
            assert_eq!(recover(&p, *own, changed), *recovery, "{case}");

            let log = MemLog::default();
            let probe = on_service_start(dir.path(), install.path(), *own, &log);
            let left = load_pending(dir.path()).unwrap();
            let got = match (&probe, &left) {
                (None, None) => After::Cleared,
                (None, Some(l)) if *l == (Pending { rolling_back: true, ..p.clone() }) => After::MarkedRollingBack,
                (Some(q), Some(l)) if *q == p && *l == p => After::ProbeWithRecordKept,
                other => panic!("{case}: {other:?}"),
            };
            assert_eq!(got, *after, "{case}");
            assert_eq!(load_record(dir.path()).unwrap(), Record::default(), "{case}: never raised, never marked failed by a start");
            let kept: Vec<_> = p.aside.iter().map(|n| std::fs::read(install.path().join(format!("{n}{OLD_SUFFIX}"))).ok()).collect();
            assert_eq!(kept, olds, "{case}: a start deletes no .old");
        }
    }

    /// A pending file that cannot be rewritten stays as it was, and is reported.
    #[test]
    fn an_interrupted_install_whose_mark_cannot_be_written_stays_in_flight() {
        let (dir, install) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let name = "sieve-engine.exe";
        std::fs::write(install.path().join(name), b"new").unwrap();
        std::fs::write(install.path().join(format!("{name}.old")), b"old").unwrap();
        let p = Pending { swap_started: true, ..pending(1, 2) };
        save_pending(dir.path(), &p).unwrap();
        std::fs::create_dir(dir.path().join(PENDING_FILE).with_extension("tmp")).unwrap();
        let log = MemLog::default();
        assert_eq!(on_service_start(dir.path(), install.path(), 1, &log), None);
        assert_eq!(load_pending(dir.path()).unwrap(), Some(p));
        assert_eq!(log.0.lock().unwrap().len(), 2, "what it found, and the failure");
    }

    /// The new engine holds the record as it was read at its start.
    #[test]
    fn a_report_after_the_verdict_raises_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let read_at_start = pending(1, 2);
        save_pending(dir.path(), &Pending { rolling_back: true, ..read_at_start.clone() }).unwrap();
        commit_healthy(dir.path(), &read_at_start).unwrap();
        assert!(!is_committed(dir.path(), &read_at_start).unwrap());
        assert!(load_pending(dir.path()).unwrap().is_some());
    }

    #[test]
    fn a_pending_record_from_before_the_rolling_back_field_reads_as_not_rolling_back() {
        let dir = tempfile::tempdir().unwrap();
        let old = r#"{"kind":"engine","from_version":1,"to_version":2,"staged":"s.exe","aside":["sieve-engine.exe"]}"#;
        std::fs::write(dir.path().join(PENDING_FILE), old).unwrap();
        assert_eq!(load_pending(dir.path()).unwrap(), Some(pending(1, 2)));
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
            assert_eq!(recover(&pending(1, 2), own, false), want, "{own}");
        }
        // Only the old build beside changed files is an interrupted swap.
        for (own, want) in [(1, Recovery::Interrupted), (2, Recovery::Probe), (3, Recovery::Mislabelled), (0, Recovery::Mislabelled)] {
            assert_eq!(recover(&pending(1, 2), own, true), want, "{own}");
        }
    }

    #[test]
    fn a_start_with_a_release_in_flight_probes_or_clears_and_never_raises() {
        let dir = tempfile::tempdir().unwrap();
        let log = MemLog::default();
        assert_eq!(on_service_start(dir.path(), dir.path(), 2, &log), None, "nothing in flight");
        assert!(log.0.lock().unwrap().is_empty());

        let p = pending(1, 2);
        save_pending(dir.path(), &p).unwrap();
        assert_eq!(on_service_start(dir.path(), dir.path(), 2, &log), Some(p.clone()));
        assert_eq!(load_pending(dir.path()).unwrap(), Some(p.clone()), "the probe clears it, not the start");

        for own in [1, 3] {
            save_pending(dir.path(), &p).unwrap();
            assert_eq!(on_service_start(dir.path(), dir.path(), own, &log), None, "{own}");
            assert_eq!(load_pending(dir.path()).unwrap(), None, "{own}");
            assert_eq!(load_record(dir.path()).unwrap(), Record::default(), "{own}: never raised");
        }
        assert_eq!(log.0.lock().unwrap().len(), 2, "each reported");

        std::fs::write(dir.path().join(PENDING_FILE), b"not json").unwrap();
        assert_eq!(on_service_start(dir.path(), dir.path(), 2, &log), None, "a damaged record starts the engine anyway");
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
    fn a_rollback_takes_back_a_commit_that_landed_first() {
        let dir = tempfile::tempdir().unwrap();
        let p = pending(1, 2);
        save_pending(dir.path(), &p).unwrap();
        commit_healthy(dir.path(), &p).unwrap();
        save_pending(dir.path(), &p).unwrap();
        record_rollback(dir.path(), &p).unwrap();
        let r = load_record(dir.path()).unwrap();
        assert_eq!((r.versions.get("engine"), r.rolled_back.get("engine")), (None, Some(&2)));
        assert_eq!(installed(&Kind::Engine, &r, 1), 1);

        let mut kept = Record::default();
        kept.versions.insert("engine".into(), 1);
        kept.versions.insert("app".into(), 2);
        save_record(dir.path(), &kept).unwrap();
        record_rollback(dir.path(), &p).unwrap();
        let r = load_record(dir.path()).unwrap();
        assert_eq!(r.versions, kept.versions, "only this release's own raise is undone");
    }

    #[test]
    fn a_report_after_the_rollback_raises_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let p = pending(1, 2);
        save_pending(dir.path(), &p).unwrap();
        record_rollback(dir.path(), &p).unwrap();
        commit_healthy(dir.path(), &p).unwrap();
        assert!(!is_committed(dir.path(), &p).unwrap());
    }

    #[test]
    fn a_rollback_over_a_damaged_record_still_ends_the_flight_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let p = pending(1, 2);
        save_pending(dir.path(), &p).unwrap();
        std::fs::write(dir.path().join(STATE_FILE), b"not json").unwrap();
        assert!(record_rollback(dir.path(), &p).is_err());
        assert_eq!(load_pending(dir.path()).unwrap(), None);
        assert_eq!(std::fs::read(dir.path().join(STATE_FILE)).unwrap(), b"not json", "never reset");
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
