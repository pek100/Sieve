//! Uninstall's half of removal (plan 1.5, 2.4). The verb runs as an admin:
//! admin rights reach the store and HKLM, so [`remove_trust`] runs in the
//! verb, first. The key's DACL is SYSTEM only, so [`purge_keys`] runs in the
//! service, which the verb starts with [`PURGE_ARG`]. Each records what it
//! did in `ca.json`; [`remaining`] says what is still on the machine, and
//! while it says anything the service and `ca.json` stay for the rerun.

use std::path::Path;

use super::key::KeyStore;
use super::state::{self, CaState, Retiring};
use super::trust::{FIREFOX_POLICY_ON, FirefoxPolicy, RootStore};

/// The service start argument: delete the recorded keys and stop.
pub const PURGE_ARG: &str = "purge-ca-keys";

fn everything_retiring(state: &mut CaState) {
    if let Some(active) = state.active.take() {
        state.retiring.push(Retiring { key_name: active.key_name, thumbprint: Some(active.thumbprint), remove_at: 0 });
    }
}

/// Removes every recorded root (by thumbprint, never by name) and the Firefox
/// value if Sieve set it. Every entry is tried; an entry keeps its thumbprint
/// until its root is gone, so rerunning uninstall still knows it.
pub fn remove_trust(dir: &Path, store: &dyn RootStore, firefox: &dyn FirefoxPolicy) -> Result<String, String> {
    let mut state = state::load(dir)?;
    everything_retiring(&mut state);
    let (mut removed, mut errors) = (0, Vec::new());
    for entry in &mut state.retiring {
        let Some(thumbprint) = entry.thumbprint.clone() else { continue };
        match store.remove(&thumbprint) {
            Ok(()) => {
                entry.thumbprint = None;
                removed += 1;
            }
            Err(why) => errors.push(why),
        }
    }
    if state.firefox_policy_set {
        let done = firefox.read().and_then(|value| if value == Some(FIREFOX_POLICY_ON) { firefox.delete() } else { Ok(()) });
        match done {
            Ok(()) => state.firefox_policy_set = false,
            Err(why) => errors.push(why),
        }
    }
    let record = dir.join(state::CA_FILE);
    if state.is_clear() && !record.exists() {
        return Ok("no certificate was installed".into());
    }
    state::save(dir, &state)?;
    if errors.is_empty() { Ok(format!("{removed} roots removed")) } else { Err(errors.join("; ")) }
}

/// Deletes every recorded key. An entry goes only when its root is gone too.
pub fn purge_keys(dir: &Path, keys: &dyn KeyStore) -> Result<String, String> {
    let mut state = state::load(dir)?;
    everything_retiring(&mut state);
    let (mut deleted, mut errors) = (0, Vec::new());
    let mut kept = Vec::new();
    for entry in std::mem::take(&mut state.retiring) {
        match keys.delete(&entry.key_name) {
            Ok(()) => {
                deleted += 1;
                if entry.thumbprint.is_some() {
                    kept.push(entry);
                }
            }
            Err(why) => {
                errors.push(why);
                kept.push(entry);
            }
        }
    }
    state.retiring = kept;
    state::save(dir, &state)?;
    if errors.is_empty() { Ok(format!("{deleted} keys deleted")) } else { Err(errors.join("; ")) }
}

/// Why `ca.json` must outlive uninstall's folder deletion, if it must: a
/// record of something not yet removed, or a record that cannot be read.
pub fn remaining(dir: &Path) -> Option<String> {
    match state::load(dir) {
        Ok(state) if state.is_clear() => None,
        Ok(state) => {
            let roots = usize::from(state.active.is_some()) + state.retiring.len();
            Some(format!("{roots} recorded certificates or keys were not removed"))
        }
        Err(why) => Some(why),
    }
}

/// `ca keys`: asks the service to purge when anything is recorded, then reads
/// the outcome from `ca.json`.
pub fn purge_through_service(dir: &Path, purge: impl FnOnce() -> Result<(), String>) -> Result<String, String> {
    if remaining(dir).is_none() {
        return Ok("no key recorded".into());
    }
    purge()?;
    remaining(dir).map_or_else(|| Ok("keys deleted".into()), Err)
}

/// `delete service`: runs `delete` once [`remaining`] is clear. Until then the
/// service is the rerun's only way to the keys, so it runs `hold` instead and
/// reports the step failed.
pub fn delete_service_once_clear(
    dir: &Path,
    hold: impl FnOnce() -> Result<(), String>,
    delete: impl FnOnce() -> Result<String, String>,
) -> Result<String, String> {
    let Some(why) = remaining(dir) else { return delete() };
    let kept = format!("service kept so that rerunning uninstall can reach the keys: {why}");
    Err(match hold() {
        Ok(()) => kept,
        Err(held) => format!("{kept}; {held}"),
    })
}

/// Deletes `sieve_dir`, except `engine\ca.json` while it still records
/// something, so rerunning uninstall knows the thumbprints.
pub fn remove_program_data(sieve_dir: &Path, engine_dir: &Path) -> Result<String, String> {
    let shown = sieve_dir.display();
    let Some(why) = remaining(engine_dir) else {
        return match std::fs::remove_dir_all(sieve_dir) {
            Ok(()) => Ok(format!("{shown} deleted")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(format!("{shown} not there")),
            Err(e) => Err(format!("{shown}: {e}")),
        };
    };
    let keep = engine_dir.join(state::CA_FILE);
    let mut errors = vec![format!("{} kept: {why}", keep.display())];
    remove_all_but(sieve_dir, &keep, &mut errors);
    Err(errors.join("; "))
}

fn remove_all_but(dir: &Path, keep: &Path, errors: &mut Vec<String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => return errors.push(format!("{}: {e}", dir.display())),
    };
    for path in entries.flatten().map(|e| e.path()) {
        let done = if path == keep {
            Ok(())
        } else if keep.starts_with(&path) {
            remove_all_but(&path, keep, errors);
            Ok(())
        } else if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        if let Err(e) = done {
            errors.push(format!("{}: {e}", path.display()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::key::{KeyStore, MemoryKeyStore};
    use super::super::state::ActiveRoot;
    use super::super::trust::{FakeFirefox, FakeRootStore};
    use super::*;

    fn recorded(dir: &Path) -> CaState {
        let state = CaState {
            active: Some(ActiveRoot { key_name: "new".into(), thumbprint: "aa".into() }),
            retiring: vec![Retiring { key_name: "old".into(), thumbprint: Some("bb".into()), remove_at: 99 }],
            firefox_policy_set: true,
            last_rotation_ms: None,
            withdrawn: false,
        };
        state::save(dir, &state).unwrap();
        state
    }

    fn store() -> FakeRootStore {
        let store = FakeRootStore::default();
        for (t, der) in [("aa", b"a"), ("bb", b"b"), ("cc", b"c")] {
            store.roots.lock().unwrap().insert(t.to_string(), der.to_vec());
        }
        store
    }

    #[test]
    fn trust_goes_by_recorded_thumbprint_and_the_policy_only_if_sieve_set_it() {
        let dir = tempfile::tempdir().unwrap();
        recorded(dir.path());
        let (store, firefox) = (store(), FakeFirefox::default());
        *firefox.value.lock().unwrap() = Some(FIREFOX_POLICY_ON);
        assert_eq!(remove_trust(dir.path(), &store, &firefox).unwrap(), "2 roots removed");
        assert_eq!(store.thumbprints(), ["cc"], "the foreign root stays");
        assert_eq!(*firefox.value.lock().unwrap(), None);
        let after = state::load(dir.path()).unwrap();
        assert!(after.active.is_none() && !after.firefox_policy_set);
        assert!(after.retiring.iter().all(|e| e.thumbprint.is_none()), "the keys are still to go");
        assert!(remaining(dir.path()).is_some());
    }

    #[test]
    fn a_failed_root_removal_keeps_its_thumbprint_for_the_rerun() {
        let dir = tempfile::tempdir().unwrap();
        recorded(dir.path());
        let (store, firefox) = (store(), FakeFirefox::default());
        store.faults.fail_named.lock().unwrap().insert("store remove");
        assert!(remove_trust(dir.path(), &store, &firefox).unwrap_err().contains("store remove"));
        assert_eq!(state::load(dir.path()).unwrap().retiring.iter().filter(|e| e.thumbprint.is_some()).count(), 2);
        store.faults.clear();
        remove_trust(dir.path(), &store, &firefox).unwrap();
        assert_eq!(store.thumbprints(), ["cc"]);
    }

    #[test]
    fn nothing_recorded_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (store, firefox) = (store(), FakeFirefox::default());
        assert_eq!(remove_trust(dir.path(), &store, &firefox).unwrap(), "no certificate was installed");
        assert_eq!(store.thumbprints().len(), 3);
        assert!(!dir.path().join(state::CA_FILE).exists());
    }

    #[test]
    fn purging_keys_clears_the_record_once_roots_are_gone() {
        let dir = tempfile::tempdir().unwrap();
        recorded(dir.path());
        let keys = MemoryKeyStore::default();
        for name in ["new", "old", "foreign"] {
            keys.create(name).unwrap();
        }
        let (store, firefox) = (store(), FakeFirefox::default());
        *firefox.value.lock().unwrap() = Some(FIREFOX_POLICY_ON);
        remove_trust(dir.path(), &store, &firefox).unwrap();
        assert_eq!(purge_keys(dir.path(), &keys).unwrap(), "2 keys deleted");
        assert_eq!(keys.names(), ["foreign"]);
        assert!(state::load(dir.path()).unwrap().is_clear());
        assert_eq!(remaining(dir.path()), None);
    }

    #[test]
    fn a_key_purged_before_its_root_went_keeps_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        recorded(dir.path());
        purge_keys(dir.path(), &MemoryKeyStore::default()).unwrap();
        assert_eq!(state::load(dir.path()).unwrap().retiring.len(), 2);
        assert!(remaining(dir.path()).is_some());
    }

    #[test]
    fn a_failed_key_delete_is_reported_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        state::save(dir.path(), &CaState { retiring: vec![Retiring { key_name: "k".into(), thumbprint: None, remove_at: 0 }], ..CaState::default() }).unwrap();
        let keys = MemoryKeyStore::default();
        keys.faults.fail_named.lock().unwrap().insert("key delete");
        assert!(purge_keys(dir.path(), &keys).is_err());
        assert_eq!(state::load(dir.path()).unwrap().retiring.len(), 1);
    }

    fn laid_out(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let sieve = root.join("Sieve");
        let engine = sieve.join("engine");
        std::fs::create_dir_all(engine.join("sub")).unwrap();
        std::fs::write(engine.join("policy.json"), b"{}").unwrap();
        std::fs::write(engine.join("sub").join("x"), b"x").unwrap();
        std::fs::write(sieve.join("other"), b"x").unwrap();
        (sieve, engine)
    }

    #[test]
    fn a_remaining_entry_keeps_ca_json_and_reports_failed() {
        let root = tempfile::tempdir().unwrap();
        let (sieve, engine) = laid_out(root.path());
        recorded(&engine);
        let why = remove_program_data(&sieve, &engine).unwrap_err();
        assert!(why.contains("kept") && why.contains("not removed"), "{why}");
        assert!(engine.join(state::CA_FILE).exists(), "rerunning uninstall still knows the thumbprints");
        assert!(!engine.join("policy.json").exists() && !engine.join("sub").exists() && !sieve.join("other").exists(), "the rest went");
    }

    #[test]
    fn a_malformed_record_is_kept_and_reported_too() {
        let root = tempfile::tempdir().unwrap();
        let (sieve, engine) = laid_out(root.path());
        std::fs::write(engine.join(state::CA_FILE), b"garbage").unwrap();
        assert!(remove_program_data(&sieve, &engine).is_err());
        assert!(engine.join(state::CA_FILE).exists());
        assert!(remove_trust(&engine, &store(), &FakeFirefox::default()).is_err(), "never guessed around");
    }

    #[test]
    fn with_nothing_remaining_the_whole_folder_goes() {
        let root = tempfile::tempdir().unwrap();
        let (sieve, engine) = laid_out(root.path());
        state::save(&engine, &CaState::default()).unwrap();
        assert!(remove_program_data(&sieve, &engine).unwrap().ends_with("deleted"));
        assert!(!sieve.exists());
        assert!(remove_program_data(&sieve, &engine).unwrap().ends_with("not there"), "rerun is safe");
    }

    /// The machine as uninstall's steps see it. The service purges as the real
    /// one does: a failed purge still stops cleanly and leaves its outcome in
    /// `ca.json` alone.
    struct Machine {
        root: tempfile::TempDir,
        store: FakeRootStore,
        firefox: FakeFirefox,
        keys: MemoryKeyStore,
        service_installed: std::cell::Cell<bool>,
        service_held: std::cell::Cell<bool>,
        service_start: std::cell::RefCell<Result<(), String>>,
    }

    impl Machine {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let (_, engine) = laid_out(root.path());
            recorded(&engine);
            let keys = MemoryKeyStore::default();
            for name in ["new", "old", "foreign"] {
                keys.create(name).unwrap();
            }
            Self {
                root,
                store: store(),
                firefox: FakeFirefox::default(),
                keys,
                service_installed: true.into(),
                service_held: false.into(),
                service_start: Ok(()).into(),
            }
        }

        fn sieve(&self) -> std::path::PathBuf {
            self.root.path().join("Sieve")
        }

        fn engine(&self) -> std::path::PathBuf {
            self.sieve().join("engine")
        }

        /// The verb's CA steps in the verb's order, each running whatever the
        /// last one did. Returns (trust, ca keys, delete service, program data).
        fn uninstall(&self) -> [Result<String, String>; 4] {
            let engine = self.engine();
            let trust = remove_trust(&engine, &self.store, &self.firefox);
            let keys = purge_through_service(&engine, || {
                if !self.service_installed.get() {
                    return Err("the service is not installed".into());
                }
                self.service_start.borrow().clone()?;
                let _ = purge_keys(&engine, &self.keys);
                Ok(())
            });
            let delete = delete_service_once_clear(
                &engine,
                || {
                    self.service_held.set(true);
                    Ok(())
                },
                || {
                    self.service_installed.set(false);
                    Ok("deleted".into())
                },
            );
            let data = remove_program_data(&self.sieve(), &engine);
            [trust, keys, delete, data]
        }

        fn assert_finished(&self) {
            assert_eq!(self.store.thumbprints(), ["cc"]);
            assert_eq!(self.keys.names(), ["foreign"]);
            assert!(!self.service_installed.get());
            assert!(!self.sieve().exists());
        }
    }

    #[test]
    fn a_clean_uninstall_deletes_the_service_and_never_holds_it() {
        let machine = Machine::new();
        assert!(machine.uninstall().iter().all(Result::is_ok));
        assert!(!machine.service_held.get());
        machine.assert_finished();
    }

    #[test]
    fn a_failed_key_delete_keeps_the_service_and_the_rerun_finishes() {
        let machine = Machine::new();
        machine.keys.faults.fail_named.lock().unwrap().insert("key delete");
        let [trust, keys, delete, data] = machine.uninstall();
        assert!(trust.is_ok(), "the root does not wait for the key");
        assert!(keys.is_err() && data.is_err());
        assert!(delete.unwrap_err().contains("kept"), "keeping the service is reported, not silent");
        assert!(machine.service_installed.get() && machine.service_held.get());
        assert_eq!(machine.store.thumbprints(), ["cc"]);
        assert!(machine.engine().join(state::CA_FILE).exists());

        machine.keys.faults.clear();
        assert!(machine.uninstall().iter().all(Result::is_ok));
        machine.assert_finished();
    }

    #[test]
    fn a_service_that_would_not_start_is_kept_and_the_rerun_finishes() {
        let machine = Machine::new();
        *machine.service_start.borrow_mut() = Err("start: refused".into());
        let [_, keys, delete, _] = machine.uninstall();
        assert_eq!(keys.unwrap_err(), "start: refused");
        assert!(delete.is_err() && machine.service_installed.get());

        *machine.service_start.borrow_mut() = Ok(());
        assert!(machine.uninstall().iter().all(Result::is_ok));
        machine.assert_finished();
    }

    /// The key went on the first run, but its entry stays while the root is
    /// there, and the rerun still has to clear that entry through the service.
    #[test]
    fn a_failed_root_removal_keeps_the_service_too() {
        let machine = Machine::new();
        machine.store.faults.fail_named.lock().unwrap().insert("store remove");
        let [trust, keys, delete, _] = machine.uninstall();
        assert!(trust.is_err() && keys.is_err() && delete.is_err());
        assert_eq!(machine.keys.names(), ["foreign"]);
        assert!(machine.service_installed.get());

        machine.store.faults.clear();
        assert!(machine.uninstall().iter().all(Result::is_ok));
        machine.assert_finished();
    }

    #[test]
    fn a_failed_hold_is_reported_with_the_reason_the_service_stayed() {
        let dir = tempfile::tempdir().unwrap();
        recorded(dir.path());
        let why = delete_service_once_clear(dir.path(), || Err("change config: denied".into()), || panic!("must not delete")).unwrap_err();
        assert!(why.contains("not removed") && why.contains("change config: denied"), "{why}");
    }
}
