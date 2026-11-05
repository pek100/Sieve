//! `Ca::reconcile` with a fake clock and fake system seams: no key, store or
//! registry on this machine is ever touched here.

use std::collections::BTreeSet;
use std::sync::Arc;

use sieve_ipc::{CertState, FirefoxTrust};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::key::MemoryKeyStore;
use super::trust::{FIREFOX_POLICY_ON, Faults, FakeFirefox, FakeRootStore};
use super::*;

const T0: u64 = 1_793_000_000_000;
const WINDOW: u64 = T0 + ROOT_LIFETIME_MS - ROTATE_BEFORE_MS;
const FOREIGN: &str = "f00d";
const MIN: u64 = 60_000;

/// The checks of `scripts/live/engine-ca.ps1` that `live_root_ca_trust_and_removal` requires.
const LIVE_CA_CHECKS: &[&str] = &[
    "the root is in LocalMachine Root with its thumbprint",
    "the root has CA true and path length 0",
    "the root has Server Authentication only",
    "the store property is Server Authentication",
    "the key is a machine CNG key of the software provider",
    "the key is not exportable and its DACL lists SYSTEM only",
    "no file in ProgramData holds key material",
    "the Firefox policy follows the record",
    "the root stays through a restart",
    "turning HTTPS off removes root, key and policy",
    "uninstall removes root, key, policy, service and ProgramData",
];

/// Which required checks did not pass: the last line about each decides.
fn live_ca_failures(results: &str) -> Vec<&'static str> {
    LIVE_CA_CHECKS
        .iter()
        .copied()
        .filter(|name| {
            let last = results.lines().rfind(|l| l.get(6..).is_some_and(|rest| rest.starts_with(name)));
            !last.is_some_and(|l| l.starts_with("PASS  "))
        })
        .collect()
}

struct Rig {
    dir: tempfile::TempDir,
    faults: Arc<Faults>,
    keys: Arc<MemoryKeyStore>,
    store: Arc<FakeRootStore>,
    firefox: Arc<FakeFirefox>,
}

impl Rig {
    fn new() -> Self {
        let faults = Arc::new(Faults::default());
        Self {
            dir: tempfile::tempdir().unwrap(),
            faults: faults.clone(),
            keys: Arc::new(MemoryKeyStore { faults: faults.clone(), ..MemoryKeyStore::default() }),
            store: Arc::new(FakeRootStore { faults: faults.clone(), ..FakeRootStore::default() }),
            firefox: Arc::new(FakeFirefox { faults, ..FakeFirefox::default() }),
        }
    }

    /// A fresh `Ca` over the saved file: what a restart of the engine sees.
    fn ca(&self) -> Ca {
        let seams = Seams { keys: self.keys.clone(), store: self.store.clone(), firefox: self.firefox.clone() };
        Ca::new(self.dir.path().to_path_buf(), "BOX".into(), seams).unwrap()
    }

    fn on(&self) -> Ca {
        let ca = self.ca();
        ca.reconcile(true, T0).unwrap();
        ca
    }

    fn roots(&self) -> Vec<String> {
        self.store.thumbprints()
    }

    fn saved(&self) -> CaState {
        state::load(self.dir.path()).unwrap()
    }

    fn active_thumbprint(&self) -> String {
        self.saved().active.unwrap().thumbprint
    }

    fn fail(&self, op: &'static str) {
        self.faults.fail_named.lock().unwrap().insert(op);
    }

    fn firefox_installed(&self, value: Option<u32>) {
        *self.firefox.installed.lock().unwrap() = true;
        *self.firefox.value.lock().unwrap() = value;
    }

    fn firefox_value(&self) -> Option<u32> {
        *self.firefox.value.lock().unwrap()
    }
}

fn issuer_of(der: &[u8]) -> String {
    X509Certificate::from_der(der).unwrap().1.issuer().to_string()
}

fn subject_of(der: &[u8]) -> String {
    X509Certificate::from_der(der).unwrap().1.subject().to_string()
}

fn leaf(ca: &Ca, host: &str, now: u64) -> Arc<Leaf> {
    ca.minter().unwrap().leaf(LeafRequest { host, upstream_not_after_ms: u64::MAX }, now).unwrap()
}

// Turning on.

#[test]
fn on_makes_one_root_and_key_and_reports_them() {
    let rig = Rig::new();
    let ca = rig.on();
    assert_eq!(rig.roots().len(), 1);
    assert_eq!(rig.keys.names().len(), 1);
    assert!(rig.keys.names()[0].starts_with(KEY_NAME_PREFIX) && rig.keys.names()[0].len() == KEY_NAME_PREFIX.len() + 16);
    let s = ca.status(T0);
    assert_eq!(s.state, CertState::Installed);
    assert_eq!(s.valid_until_ms, Some(T0 + ROOT_LIFETIME_MS));
    assert_eq!(s.thumbprint.as_deref(), Some(rig.roots()[0].as_str()));
    assert_eq!(s.last_rotation_ms, None);
    assert_eq!(s.last_error, None);
    assert!(ca.minter().is_some() && ca.holding());
    let again = rig.roots();
    ca.reconcile(true, T0 + MIN).unwrap();
    assert_eq!(rig.roots(), again, "a second reconcile changes nothing");
}

#[test]
fn off_with_nothing_recorded_touches_nothing() {
    let rig = Rig::new();
    let ca = rig.ca();
    ca.reconcile(false, T0).unwrap();
    assert!(rig.faults.log.lock().unwrap().is_empty(), "{:?}", rig.faults.log.lock().unwrap());
    assert!(!ca.holding());
    assert_eq!(ca.status(T0), CertStatus::default());
}

// Rotation.

#[test]
fn does_not_rotate_one_ms_before_the_window() {
    let rig = Rig::new();
    let ca = rig.on();
    let root = rig.active_thumbprint();
    ca.reconcile(true, WINDOW - 1).unwrap();
    assert_eq!(rig.active_thumbprint(), root);
    assert_eq!(rig.roots().len(), 1);
    assert_eq!(ca.status(WINDOW - 1).state, CertState::Installed);
    assert_eq!(ca.status(WINDOW).state, CertState::ExpiresSoon, "overdue from this point, until the rotation ran");
}

#[test]
fn rotates_exactly_at_the_window() {
    let rig = Rig::new();
    let ca = rig.on();
    let root = rig.active_thumbprint();
    ca.reconcile(true, WINDOW).unwrap();
    assert_ne!(rig.active_thumbprint(), root);
    assert_eq!(rig.roots().len(), 2, "both, while the old root's leaves live");
    let s = ca.status(WINDOW);
    assert_eq!(s.state, CertState::Installed);
    assert_eq!(s.last_rotation_ms, Some(WINDOW));
    assert_eq!(s.valid_until_ms, Some(WINDOW + ROOT_LIFETIME_MS));
}

#[test]
fn new_leaves_come_from_the_new_root_at_once() {
    let rig = Rig::new();
    // Subjects carry the date, so the two roots differ by name as well.
    let ca = rig.on();
    let before = leaf(&ca, "a.example", WINDOW - MIN);
    ca.reconcile(true, WINDOW).unwrap();
    let after = leaf(&ca, "a.example", WINDOW);
    assert!(!Arc::ptr_eq(&before, &after), "the new minter has its own cache");
    let root = ca.minter().unwrap().root_der().to_vec();
    assert_eq!(root::thumbprint(&root), rig.active_thumbprint());
    assert_eq!(issuer_of(&after.der), subject_of(&root));
    assert_ne!(issuer_of(&before.der), issuer_of(&after.der));
}

#[test]
fn old_root_stays_until_remove_at_and_goes_at_it() {
    let rig = Rig::new();
    let ca = rig.on();
    let old = rig.active_thumbprint();
    ca.reconcile(true, WINDOW).unwrap();
    let remove_at = WINDOW + LEAF_MAX_LIFETIME_MS + CLOCK_SKEW_MS;
    assert_eq!(rig.saved().retiring.iter().map(|e| e.remove_at).collect::<Vec<_>>(), [remove_at]);
    ca.reconcile(true, remove_at - 1).unwrap();
    assert!(rig.roots().contains(&old));
    assert_eq!(rig.keys.names().len(), 2);
    ca.reconcile(true, remove_at).unwrap();
    assert_eq!(rig.roots(), [rig.active_thumbprint()]);
    assert_eq!(rig.keys.names().len(), 1);
    assert!(rig.saved().retiring.is_empty());
}

#[test]
fn no_leaf_outlives_the_old_roots_removal() {
    let rig = Rig::new();
    let ca = rig.on();
    let last = leaf(&ca, "a.example", WINDOW - 1);
    ca.reconcile(true, WINDOW).unwrap();
    assert!(last.not_after_ms <= rig.saved().retiring[0].remove_at);

    // A machine that first wakes close to expiry: the root's own end caps
    // both the leaves and the removal.
    let rig = Rig::new();
    let ca = rig.on();
    let end = T0 + ROOT_LIFETIME_MS;
    let late = end - 2 * CLOCK_SKEW_MS;
    let last = leaf(&ca, "a.example", late - 1);
    ca.reconcile(true, late).unwrap();
    assert_eq!(rig.saved().retiring[0].remove_at, end);
    assert!(last.not_after_ms <= end);
}

#[test]
fn a_machine_asleep_past_expiry_rotates_and_removes_at_once() {
    let rig = Rig::new();
    let ca = rig.on();
    let old = rig.active_thumbprint();
    let later = T0 + ROOT_LIFETIME_MS + 10 * ROTATE_BEFORE_MS;
    ca.reconcile(true, later).unwrap();
    assert_ne!(rig.active_thumbprint(), old);
    assert_eq!(rig.roots(), [rig.active_thumbprint()], "the expired root went at once");
    assert!(rig.saved().retiring.is_empty());
    assert_eq!(ca.status(later).state, CertState::Installed);
    assert!(leaf(&ca, "a.example", later).not_after_ms > later);
}

#[test]
fn a_failed_rotation_keeps_the_active_root_and_retries() {
    for op in ["key create", "store add"] {
        let rig = Rig::new();
        let ca = rig.on();
        let old = rig.active_thumbprint();
        rig.fail(op);
        assert!(ca.reconcile(true, WINDOW).is_err(), "{op}");
        assert_eq!(rig.active_thumbprint(), old, "{op}");
        assert!(ca.minter().is_some(), "{op}: the old root is still in date");
        let s = ca.status(WINDOW);
        assert_eq!(s.state, CertState::ExpiresSoon);
        assert!(s.last_error.unwrap().contains(op));
        rig.faults.clear();
        ca.reconcile(true, WINDOW + MIN).unwrap();
        assert_ne!(rig.active_thumbprint(), old, "{op}: the retry rotated");
        assert_eq!(rig.keys.names().len(), 2, "{op}: the failed attempt's key went");
        assert_eq!(rig.roots().len(), 2);
        assert_eq!(ca.status(WINDOW + MIN).last_error, None);
    }
}

#[test]
fn a_failed_rotation_past_expiry_gives_no_minter() {
    let rig = Rig::new();
    let ca = rig.on();
    rig.fail("key create");
    let later = T0 + ROOT_LIFETIME_MS;
    assert!(ca.reconcile(true, later).is_err());
    assert!(ca.minter().is_none(), "no in-date root: pass through");
    assert_eq!(ca.status(later).state, CertState::ExpiresSoon);
}

#[test]
fn rotation_uses_a_new_key() {
    let rig = Rig::new();
    let ca = rig.on();
    let old = rig.saved().active.unwrap().key_name;
    ca.reconcile(true, WINDOW).unwrap();
    assert_ne!(rig.saved().active.unwrap().key_name, old);
    let created: BTreeSet<String> = rig.keys.created.lock().unwrap().iter().cloned().collect();
    assert_eq!(created.len(), rig.keys.created.lock().unwrap().len());
}

// Removal.

#[test]
fn off_removes_roots_keys_and_policy() {
    let rig = Rig::new();
    rig.firefox_installed(None);
    let ca = rig.on();
    assert_eq!(rig.firefox_value(), Some(FIREFOX_POLICY_ON));
    ca.reconcile(true, WINDOW).unwrap();
    assert_eq!(rig.roots().len(), 2);
    ca.reconcile(false, WINDOW + MIN).unwrap();
    assert!(rig.roots().is_empty());
    assert!(rig.keys.names().is_empty());
    assert_eq!(rig.firefox_value(), None);
    assert!(rig.saved().is_clear());
    assert!(ca.minter().is_none() && !ca.holding());
    assert_eq!(ca.status(WINDOW + MIN).state, CertState::NotInstalled);
}

#[test]
fn off_then_on_makes_a_new_key_and_thumbprint() {
    let rig = Rig::new();
    let ca = rig.on();
    let old = rig.saved().active.unwrap();
    ca.reconcile(false, T0 + MIN).unwrap();
    ca.reconcile(true, T0 + 2 * MIN).unwrap();
    let new = rig.saved().active.unwrap();
    assert_ne!(new.key_name, old.key_name);
    assert_ne!(new.thumbprint, old.thumbprint);
    assert_eq!(rig.roots(), [new.thumbprint]);
}

#[test]
fn a_failed_removal_keeps_its_record_and_retries() {
    for op in ["store remove", "key delete"] {
        let rig = Rig::new();
        let ca = rig.on();
        rig.fail(op);
        assert!(ca.reconcile(false, T0 + MIN).is_err(), "{op}");
        assert_eq!(rig.saved().retiring.len(), 1, "{op}");
        assert!(ca.minter().is_none(), "{op}: off stops the minter whatever else fails");
        assert!(ca.holding(), "{op}: the loop keeps its timer for the retry");
        assert!(ca.status(T0 + MIN).last_error.unwrap().contains(op));
        rig.faults.clear();
        rig.ca().reconcile(false, T0 + 2 * MIN).unwrap();
        assert!(rig.roots().is_empty() && rig.keys.names().is_empty(), "{op}");
        assert!(rig.saved().is_clear());
    }
}

#[test]
fn removal_goes_by_recorded_thumbprint_and_leaves_foreign_roots() {
    let rig = Rig::new();
    rig.store.roots.lock().unwrap().insert(FOREIGN.into(), b"not ours".to_vec());
    let ca = rig.on();
    ca.reconcile(false, T0 + MIN).unwrap();
    assert_eq!(rig.roots(), [FOREIGN]);
}

#[test]
fn removal_comes_before_the_policy() {
    let rig = Rig::new();
    rig.firefox_installed(None);
    let ca = rig.on();
    rig.faults.clear();
    ca.reconcile(false, T0 + MIN).unwrap();
    let log = rig.faults.log.lock().unwrap().clone();
    let at = |op: &str| log.iter().position(|l| *l == op).unwrap_or_else(|| panic!("{op}: {log:?}"));
    assert!(at("store remove") < at("key delete") && at("key delete") < at("firefox delete"), "{log:?}");
}

// Crash.

/// Every operation of a turn on, a rotation and an off, failed in both ways
/// (refused, and a crash right behind the write): a fresh `Ca` from the saved
/// file ends clean each time.
#[test]
fn a_failure_at_every_step_ends_clean_after_restart() {
    for behind_the_write in [false, true] {
        let mut step = 0;
        loop {
            let rig = Rig::new();
            rig.firefox_installed(None);
            let slot = if behind_the_write { &rig.faults.fail_after } else { &rig.faults.fail_before };
            *slot.lock().unwrap() = Some(step);
            let ca = rig.ca();
            let results = [ca.reconcile(true, T0), ca.reconcile(true, WINDOW), ca.reconcile(false, WINDOW + MIN)];
            let fired = results.iter().any(Result::is_err);
            if !fired {
                assert!(rig.roots().is_empty(), "the last step was reached: step {step}");
                break;
            }
            rig.faults.clear();
            // Restart with the switch on: exactly the active root is left once
            // the old ones' time has come.
            let restarted = rig.ca();
            let soon = WINDOW + 2 * MIN;
            restarted.reconcile(true, soon).unwrap_or_else(|e| panic!("step {step}, {behind_the_write}: {e}"));
            restarted.reconcile(true, soon + LEAF_MAX_LIFETIME_MS + CLOCK_SKEW_MS).unwrap();
            let state = rig.saved();
            let context = format!("step {step}, behind the write {behind_the_write}: {state:?}");
            assert!(state.retiring.is_empty(), "{context}");
            assert_eq!(rig.roots(), [state.active.clone().unwrap().thumbprint], "{context}");
            assert_eq!(rig.keys.names(), [state.active.clone().unwrap().key_name], "{context}");
            assert!(restarted.minter().is_some(), "{context}");
            // And the switch off then leaves nothing at all.
            let again = rig.ca();
            again.reconcile(false, soon + LEAF_MAX_LIFETIME_MS + 2 * CLOCK_SKEW_MS).unwrap();
            assert!(rig.roots().is_empty() && rig.keys.names().is_empty(), "{context}");
            assert!(rig.saved().is_clear(), "{context}");
            assert_eq!(rig.firefox_value(), None, "{context}");
            step += 1;
        }
        assert!(step > 10, "the sweep covered the operations: {step}");
    }
}

#[test]
fn a_record_that_cannot_be_written_makes_nothing() {
    let rig = Rig::new();
    // `write_atomic` writes `ca.tmp` first; a folder there makes that fail.
    std::fs::create_dir(rig.dir.path().join("ca.tmp")).unwrap();
    let ca = rig.ca();
    assert!(ca.reconcile(true, T0).is_err());
    assert!(rig.roots().is_empty() && rig.keys.names().is_empty(), "the record comes first");
    assert!(ca.minter().is_none());
}

#[test]
fn a_malformed_ca_json_is_reported_and_makes_no_root() {
    let rig = Rig::new();
    std::fs::write(rig.dir.path().join(state::CA_FILE), b"{\"active\":").unwrap();
    let ca = rig.ca();
    assert!(ca.status(T0).last_error.is_some(), "before the first reconcile too");
    for wanted in [true, false] {
        assert!(matches!(ca.reconcile(wanted, T0), Err(CaError::State(_))), "{wanted}");
        assert!(rig.roots().is_empty() && rig.keys.names().is_empty());
        assert!(rig.faults.log.lock().unwrap().is_empty(), "nothing guessed");
        let s = ca.status(T0);
        assert_eq!(s.state, CertState::NotInstalled);
        assert!(s.last_error.unwrap().contains(state::CA_FILE));
        assert!(ca.minter().is_none());
        assert!(ca.holding(), "the file may record something: keep looking");
    }
    assert!(ca.reinstall(T0).is_err(), "Reinstall makes no root over it either");
    assert!(rig.roots().is_empty());
    std::fs::remove_file(rig.dir.path().join(state::CA_FILE)).unwrap();
    ca.reconcile(true, T0).unwrap();
    assert_eq!(rig.roots().len(), 1, "a readable record clears the error");
}

// Withdrawal.

#[test]
fn a_root_missing_from_the_store_is_not_replaced_silently() {
    let rig = Rig::new();
    rig.firefox_installed(None);
    let ca = rig.on();
    rig.store.roots.lock().unwrap().clear();
    assert!(ca.reconcile(true, T0 + MIN).is_err());
    assert!(rig.roots().is_empty(), "no new root");
    assert!(rig.keys.names().is_empty(), "the leftover key went");
    assert_eq!(rig.firefox_value(), None, "the policy went with it");
    let saved = rig.saved();
    assert!(saved.withdrawn && saved.active.is_none());
    assert!(ca.minter().is_none());
    let s = ca.status(T0 + MIN);
    assert_eq!(s.state, CertState::NotInstalled);
    assert_eq!(s.last_error.as_deref(), Some(ROOT_GONE));
    // A later tick and an engine restart do not undo the removal either.
    ca.reconcile(true, T0 + 2 * MIN).unwrap();
    assert!(rig.roots().is_empty());
    assert_eq!(ca.status(T0 + 2 * MIN).last_error.as_deref(), Some(WITHDRAWN), "the reason stays on show");
    let restarted = rig.ca();
    restarted.reconcile(true, T0 + 3 * MIN).unwrap();
    assert!(rig.roots().is_empty());
}

#[test]
fn reinstall_clears_the_withdrawal() {
    let rig = Rig::new();
    let ca = rig.on();
    rig.store.roots.lock().unwrap().clear();
    let _ = ca.reconcile(true, T0 + MIN);
    assert!(rig.saved().withdrawn);
    ca.reinstall(T0 + 2 * MIN).unwrap();
    assert!(!rig.saved().withdrawn);
    assert_eq!(rig.roots(), [rig.active_thumbprint()]);
    assert_eq!(ca.status(T0 + 2 * MIN).state, CertState::Installed);
    assert!(ca.minter().is_some());

    // The switch off and on clears it as well.
    let rig = Rig::new();
    let ca = rig.on();
    rig.store.roots.lock().unwrap().clear();
    let _ = ca.reconcile(true, T0 + MIN);
    ca.reconcile(false, T0 + 2 * MIN).unwrap();
    ca.reconcile(true, T0 + 3 * MIN).unwrap();
    assert_eq!(rig.roots().len(), 1);
}

#[test]
fn reinstall_removes_the_old_root_at_once_and_reads_as_a_rotation() {
    let rig = Rig::new();
    let ca = rig.on();
    let old = rig.saved().active.unwrap();
    ca.reinstall(T0 + MIN).unwrap();
    let new = rig.saved().active.unwrap();
    assert_ne!(new, old);
    assert_eq!(rig.roots(), [new.thumbprint]);
    assert_eq!(rig.keys.names(), [new.key_name]);
    assert_eq!(ca.status(T0 + MIN).last_rotation_ms, Some(T0 + MIN));
}

#[test]
fn a_failed_reinstall_keeps_the_root_it_has() {
    let rig = Rig::new();
    let ca = rig.on();
    let old = rig.active_thumbprint();
    rig.fail("store add");
    assert!(ca.reinstall(T0 + MIN).is_err());
    assert_eq!(rig.active_thumbprint(), old);
    assert!(rig.roots().contains(&old) && ca.minter().is_some());
}

#[test]
fn a_key_that_will_not_open_removes_the_root_and_gives_no_minter() {
    let rig = Rig::new();
    let ca = rig.on();
    let name = rig.saved().active.unwrap().key_name;
    rig.keys.broken.lock().unwrap().insert(name);
    let why = ca.reconcile(true, T0 + MIN).unwrap_err();
    assert!(why.to_string().contains("will not open"), "{why}");
    assert!(rig.roots().is_empty());
    assert!(ca.minter().is_none());
    assert!(rig.saved().withdrawn);
    assert_eq!(ca.status(T0 + MIN).state, CertState::NotInstalled);
}

#[test]
fn a_store_that_cannot_answer_concludes_nothing() {
    let rig = Rig::new();
    let ca = rig.on();
    let root = rig.active_thumbprint();
    rig.fail("store read");
    assert!(ca.reconcile(true, T0 + MIN).is_err());
    let saved = rig.saved();
    assert!(!saved.withdrawn, "not a removal");
    assert_eq!(saved.active.unwrap().thumbprint, root);
    assert!(ca.minter().is_some());
    assert_eq!(ca.status(T0 + MIN).state, CertState::Installed);
}

// Firefox.

#[test]
fn firefox_policy_is_set_only_when_installed_and_absent() {
    let rig = Rig::new();
    let ca = rig.on();
    assert_eq!(rig.firefox_value(), None, "not installed: nothing written");
    assert!(!rig.saved().firefox_policy_set);
    assert_eq!(ca.status(T0).firefox, FirefoxTrust::NotInstalled);

    let rig = Rig::new();
    rig.firefox_installed(None);
    let ca = rig.on();
    assert_eq!(rig.firefox_value(), Some(FIREFOX_POLICY_ON));
    assert!(rig.saved().firefox_policy_set);
    assert_eq!(ca.status(T0).firefox, FirefoxTrust::UsesWindows);
}

#[test]
fn a_preexisting_firefox_value_is_never_touched() {
    for value in [FIREFOX_POLICY_ON, 0] {
        let rig = Rig::new();
        rig.firefox_installed(Some(value));
        let ca = rig.on();
        assert!(!rig.saved().firefox_policy_set, "{value}");
        ca.reconcile(false, T0 + MIN).unwrap();
        assert_eq!(rig.firefox_value(), Some(value), "off leaves a value Sieve did not set");
    }
}

#[test]
fn a_value_changed_after_sieve_set_it_is_left_alone() {
    let rig = Rig::new();
    rig.firefox_installed(None);
    let ca = rig.on();
    *rig.firefox.value.lock().unwrap() = Some(0);
    ca.reconcile(false, T0 + MIN).unwrap();
    assert_eq!(rig.firefox_value(), Some(0));
    assert!(!rig.saved().firefox_policy_set);
}

#[test]
fn firefox_installed_later_is_covered_on_the_next_tick() {
    let rig = Rig::new();
    let ca = rig.on();
    assert_eq!(ca.status(T0).firefox, FirefoxTrust::NotInstalled);
    rig.firefox_installed(None);
    ca.reconcile(true, T0 + MIN).unwrap();
    assert_eq!(rig.firefox_value(), Some(FIREFOX_POLICY_ON));
    assert_eq!(ca.status(T0 + MIN).firefox, FirefoxTrust::UsesWindows);
}

#[test]
fn not_using_windows_is_reported_for_a_foreign_zero() {
    let rig = Rig::new();
    rig.firefox_installed(Some(0));
    let ca = rig.on();
    assert_eq!(ca.status(T0).firefox, FirefoxTrust::NotUsingWindows);
    assert_eq!(rig.firefox_value(), Some(0));
}

#[test]
fn a_firefox_failure_is_reported_and_leaves_the_root() {
    let rig = Rig::new();
    rig.firefox_installed(None);
    rig.fail("firefox set");
    let ca = rig.ca();
    assert!(ca.reconcile(true, T0).is_err());
    assert_eq!(rig.roots().len(), 1);
    assert!(ca.minter().is_some());
    assert!(ca.status(T0).last_error.unwrap().contains("firefox set"));
    rig.faults.clear();
    ca.reconcile(true, T0 + MIN).unwrap();
    assert_eq!(rig.firefox_value(), Some(FIREFOX_POLICY_ON));
}

// The live checks, run by the user only (docs/live/engine-slice-5.md).

/// Reads the evidence of `scripts/live/engine-ca.ps1` (`SIEVE_LIVE_DIR`,
/// default `C:\Users\Public\sieve-engine-live`) and passes when every
/// required check passed. It changes nothing.
#[test]
#[ignore = "live: reads the user's evidence of scripts/live/engine-ca.ps1"]
fn live_root_ca_trust_and_removal() {
    let dir = std::env::var("SIEVE_LIVE_DIR").unwrap_or_else(|_| r"C:\Users\Public\sieve-engine-live".into());
    let path = std::path::Path::new(&dir).join("results-ca.txt");
    let results = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e} (run the live check first)", path.display()));
    assert_eq!(live_ca_failures(&results), Vec::<&str>::new(), "required checks without a PASS");
}

/// The registry's `liveCheck` of `filtering.https`. Interception does not
/// exist yet, so this cannot pass and claims nothing.
#[test]
#[ignore = "live: slice 6 builds what this checks"]
fn live_https_intercepts_public_and_passes_floor() {
    panic!("slice 6 is not built");
}

#[test]
fn every_required_live_check_is_one_the_script_makes() {
    let script = include_str!("../../../../../scripts/live/engine-ca.ps1");
    for name in LIVE_CA_CHECKS {
        assert!(script.contains(&format!("Check \"{name}\"")), "{name}");
    }
}

#[test]
fn the_last_line_about_a_live_check_decides() {
    let mut results = String::new();
    for name in LIVE_CA_CHECKS {
        results.push_str(&format!("FAIL  {name}\nPASS  {name}\n"));
    }
    assert!(live_ca_failures(&results).is_empty());
    results.push_str(&format!("FAIL  {}\n", LIVE_CA_CHECKS[0]));
    assert_eq!(live_ca_failures(&results), [LIVE_CA_CHECKS[0]]);
    assert_eq!(live_ca_failures("").len(), LIVE_CA_CHECKS.len());
}

// No key material.

#[test]
fn ca_json_holds_no_certificate_or_key_bytes() {
    let rig = Rig::new();
    rig.firefox_installed(None);
    let ca = rig.on();
    ca.reconcile(true, WINDOW).unwrap();
    let text = std::fs::read_to_string(rig.dir.path().join(state::CA_FILE)).unwrap();
    assert!(text.len() < 1024, "names and thumbprints only: {} bytes", text.len());
    for pattern in ["BEGIN", "PRIVATE", "MII", "der"] {
        assert!(!text.contains(pattern), "{pattern}: {text}");
    }
    let minter = ca.minter().unwrap();
    let as_hex: String = minter.root_der().iter().map(|b| format!("{b:02x}")).collect();
    assert!(!text.contains(&as_hex));
    // Every file the engine wrote in the folder is this one file.
    let files: Vec<_> = std::fs::read_dir(rig.dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(files, [std::ffi::OsString::from(state::CA_FILE)]);
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let keys: BTreeSet<&str> = value.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, BTreeSet::from(["active", "retiring", "firefox_policy_set", "last_rotation_ms", "withdrawn"]));
}
