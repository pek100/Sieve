//! The per-install root CA (plan 2.1 to 2.5, slice 5): a key the engine
//! cannot export, a root with the 2.1 limits, trusted by the machine and by
//! Firefox, rotated silently before expiry, removed on every off path.
//! `tls::intercept` asks [`Ca::minter`] for each flow it decrypts.
//!
//! [`Ca::reconcile`] is the only path that changes trust: turn on, turn off,
//! rotate, retire and retry are all one function, so no path can forget a
//! step. It takes the time as a number (S15); only the service loop reads the
//! clock. It blocks: the loop runs it on a blocking thread.
//!
//! `ca.json` ([`state`]) is written before each external write, so a crash at
//! any step leaves a record the next run finishes. Every system write sits
//! behind a seam ([`KeyStore`], [`RootStore`], [`FirefoxPolicy`]); tests use
//! fakes, and only `service::runner` and `service::scm` build the real ones
//! (`win`, law 13).

pub mod cng_blob;
pub mod key;
pub mod leaf;
pub mod removal;
pub mod root;
pub mod state;
pub mod trust;
#[cfg(windows)]
pub mod win;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use sieve_ipc::{CertState, CertStatus, FirefoxTrust};

pub use key::{KeyStore, RootKey, RootSigner};
pub use leaf::{Leaf, LeafRequest, Minter};
use root::RootFacts;
use state::{ActiveRoot, CaState, Retiring};
pub use trust::{FirefoxPolicy, RootStore};

const DAY_MS: u64 = 86_400_000;
const HOUR_MS: u64 = 3_600_000;

/// Plan 2.1.
pub const ROOT_LIFETIME_MS: u64 = 365 * DAY_MS;
/// Plan 2.1. Also what status calls "expires soon": from this point on the
/// rotation is overdue.
pub const ROTATE_BEFORE_MS: u64 = 30 * DAY_MS;
/// Plan 2.5.
pub const LEAF_MAX_LIFETIME_MS: u64 = 7 * DAY_MS;
/// Plan 2.5; also on the root's notBefore, so a leaf's backdating never
/// predates its root.
pub const CLOCK_SKEW_MS: u64 = HOUR_MS;
/// Plan 2.5 (`tls.leafCacheSize`).
pub const LEAF_CACHE_SIZE: usize = 4096;

/// Random bytes of a key's name.
const KEY_NAME_BYTES: usize = 8;
const KEY_NAME_PREFIX: &str = "Sieve root ";

/// Why a removal outside Sieve stops the certificate until the user acts.
pub const ROOT_GONE: &str = "the certificate is no longer in the Windows store";
pub const WITHDRAWN: &str = "the certificate was removed outside Sieve; reinstall it to go on";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaError {
    /// A certificate could not be built or read.
    #[error("{0}")]
    Cert(String),
    /// A host no leaf may name; the flow passes through.
    #[error("{0}")]
    Host(String),
    /// No validity is left for a leaf; the flow passes through.
    #[error("{0}")]
    Expired(String),
    /// `ca.json` cannot be read: nothing is guessed, no root is made.
    #[error("{0}")]
    State(String),
    /// One or more steps of a reconcile failed; it retries on the next tick.
    #[error("{0}")]
    Reconcile(String),
}

/// The three seams onto the system.
pub struct Seams {
    pub keys: Arc<dyn KeyStore>,
    pub store: Arc<dyn RootStore>,
    pub firefox: Arc<dyn FirefoxPolicy>,
}

/// What status and the minter read between reconciles. `root` is a copy of
/// what the store said at the last reconcile, not a second owner.
struct Held {
    state: Option<CaState>,
    root: Option<RootFacts>,
    firefox: FirefoxTrust,
    minter: Option<Arc<Minter>>,
    last_error: Option<String>,
}

/// The active root as the system holds it.
enum Verified {
    Held { der: Vec<u8>, facts: RootFacts, key: RootKey },
    /// No active root (now).
    Absent,
    /// The store could not answer: nothing is concluded this time.
    Unreadable,
}

pub struct Ca {
    dir: PathBuf,
    machine: String,
    seams: Seams,
    /// One P-256 key per engine run, memory only (plan 2.2).
    leaf_key: Arc<KeyPair>,
    held: Mutex<Held>,
}

fn new_key_name() -> Result<String, String> {
    let mut bytes = [0u8; KEY_NAME_BYTES];
    SystemRandom::new().fill(&mut bytes).map_err(|_| "no random bytes for a key name".to_string())?;
    Ok(format!("{KEY_NAME_PREFIX}{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()))
}

impl Ca {
    pub fn new(dir: PathBuf, machine: String, seams: Seams) -> Result<Self, CaError> {
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| CaError::Cert(format!("leaf key: {e}")))?;
        let (state, last_error) = match state::load(&dir) {
            Ok(s) => (Some(s), None),
            Err(why) => (None, Some(why)),
        };
        let held = Held { state, root: None, firefox: FirefoxTrust::NotInstalled, minter: None, last_error };
        Ok(Self { dir, machine, seams, leaf_key: Arc::new(leaf_key), held: Mutex::new(held) })
    }

    fn held(&self) -> MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Makes the machine match `wanted`. Every step that can run does; the
    /// failures are in status and in the error, and the next call retries.
    pub fn reconcile(&self, wanted: bool, now_ms: u64) -> Result<(), CaError> {
        self.run(wanted, false, now_ms)
    }

    /// The user's act: a new root and key now, the old root removed at once
    /// instead of retired. It also clears a withdrawal.
    pub fn reinstall(&self, now_ms: u64) -> Result<(), CaError> {
        self.run(true, true, now_ms)
    }

    fn run(&self, wanted: bool, replace: bool, now_ms: u64) -> Result<(), CaError> {
        let mut held = self.held();
        let mut state = match state::load(&self.dir) {
            Ok(s) => s,
            Err(why) => {
                *held = Held { state: None, root: None, firefox: FirefoxTrust::NotInstalled, minter: None, last_error: Some(why.clone()) };
                return Err(CaError::State(why));
            }
        };
        let loaded = state.clone();
        let mut errors = Vec::new();
        if wanted {
            self.hold(&mut held, &mut state, replace, now_ms, &mut errors);
        } else {
            self.release(&mut held, &mut state, &mut errors);
        }
        if state != loaded {
            self.save(&state, &mut errors);
        }
        held.state = Some(state);
        held.last_error = (!errors.is_empty()).then(|| errors.join("; "));
        match &held.last_error {
            Some(why) => Err(CaError::Reconcile(why.clone())),
            None => Ok(()),
        }
    }

    fn save(&self, state: &CaState, errors: &mut Vec<String>) -> bool {
        match state::save(&self.dir, state) {
            Ok(()) => true,
            Err(why) => {
                errors.push(why);
                false
            }
        }
    }

    /// Off: the minter stops first, then every root, key and the policy go.
    /// With nothing recorded, nothing on the system is touched.
    fn release(&self, held: &mut Held, state: &mut CaState, errors: &mut Vec<String>) {
        held.minter = None;
        held.root = None;
        held.firefox = FirefoxTrust::NotInstalled;
        state.withdrawn = false;
        if let Some(active) = state.active.take() {
            state.retiring.push(Retiring { key_name: active.key_name, thumbprint: Some(active.thumbprint), remove_at: 0 });
            self.save(state, errors);
        }
        self.retire(state, u64::MAX, errors);
        self.sync_firefox(held, state, false, errors);
    }

    fn hold(&self, held: &mut Held, state: &mut CaState, replace: bool, now_ms: u64, errors: &mut Vec<String>) {
        self.retire(state, now_ms, errors);
        let mut verified = self.verify(state, now_ms, errors);
        if replace {
            state.withdrawn = false;
        }
        let previous_not_after = match &verified {
            Verified::Held { facts, .. } => Some(facts.not_after_ms),
            _ => None,
        };
        let overdue = previous_not_after.is_some_and(|end| now_ms >= end.saturating_sub(ROTATE_BEFORE_MS));
        let missing = state.active.is_none() && !state.withdrawn;
        if overdue || missing || replace {
            let old_root_goes_at = if replace { 0 } else { retire_at(now_ms, previous_not_after) };
            match self.make_root(state, old_root_goes_at, now_ms) {
                Ok(()) => {
                    self.retire(state, now_ms, errors);
                    verified = self.verify(state, now_ms, errors);
                }
                Err(why) => errors.push(why),
            }
        }
        self.sync_firefox(held, state, state.active.is_some(), errors);
        match verified {
            Verified::Held { der, facts, key } => {
                held.minter = self.minter_for(held.minter.take(), der, &facts, key, now_ms, errors);
                held.root = Some(facts);
            }
            Verified::Absent => {
                held.minter = None;
                held.root = None;
            }
            Verified::Unreadable => {
                if held.root.as_ref().is_some_and(|r| now_ms >= r.not_after_ms) {
                    held.minter = None;
                }
            }
        }
    }

    /// What the store and the key store say about the active root. A root
    /// that vanished is not replaced silently (plan 7.3): what is left of it
    /// is removed and `withdrawn` waits for the user's act.
    fn verify(&self, state: &mut CaState, now_ms: u64, errors: &mut Vec<String>) -> Verified {
        let Some(active) = state.active.clone() else { return Verified::Absent };
        let read = self.seams.store.read(&active.thumbprint);
        let gone = match read {
            Err(why) => {
                errors.push(why);
                return Verified::Unreadable;
            }
            Ok(None) => ROOT_GONE.to_string(),
            Ok(Some(der)) => match (self.seams.keys.open(&active.key_name), root::facts(&der)) {
                (Ok(key), Ok(facts)) => return Verified::Held { der, facts, key },
                (Err(why), _) => format!("the certificate's key will not open: {why}"),
                (_, Err(why)) => format!("the stored certificate cannot be read: {why}"),
            },
        };
        errors.push(gone);
        state.active = None;
        state.withdrawn = true;
        state.retiring.push(Retiring { key_name: active.key_name, thumbprint: Some(active.thumbprint), remove_at: 0 });
        self.save(state, errors);
        self.retire(state, now_ms, errors);
        Verified::Absent
    }

    /// A new key and root, record first at each step:
    /// 1. an entry due now, then the key;
    /// 2. the DER and its thumbprint in the entry, then the store;
    /// 3. the entry becomes `active`; the previous root retires.
    fn make_root(&self, state: &mut CaState, old_root_goes_at: u64, now_ms: u64) -> Result<(), String> {
        let key_name = new_key_name()?;
        state.retiring.push(Retiring { key_name: key_name.clone(), thumbprint: None, remove_at: 0 });
        state::save(&self.dir, state)?;
        let key = self.seams.keys.create(&key_name)?;
        let der = root::build(&key, &self.machine, now_ms).map_err(|e| e.to_string())?;
        let thumbprint = root::thumbprint(&der);
        if let Some(entry) = state.retiring.last_mut() {
            entry.thumbprint = Some(thumbprint.clone());
        }
        state::save(&self.dir, state)?;
        self.seams.store.add(&der)?;
        state.retiring.pop();
        if let Some(previous) = state.active.replace(ActiveRoot { key_name, thumbprint }) {
            state.retiring.push(Retiring {
                key_name: previous.key_name,
                thumbprint: Some(previous.thumbprint),
                remove_at: old_root_goes_at,
            });
            state.last_rotation_ms = Some(now_ms);
        }
        state::save(&self.dir, state)
    }

    /// Removes each retiring root whose time came (root, then key), by its
    /// recorded thumbprint only. An entry stays until its removal succeeded.
    fn retire(&self, state: &mut CaState, now_ms: u64, errors: &mut Vec<String>) {
        let before = state.retiring.len();
        let mut changed = false;
        let mut kept = Vec::with_capacity(before);
        for mut entry in std::mem::take(&mut state.retiring) {
            if entry.remove_at > now_ms {
                kept.push(entry);
                continue;
            }
            if let Some(thumbprint) = entry.thumbprint.clone() {
                if let Err(why) = self.seams.store.remove(&thumbprint) {
                    errors.push(why);
                    kept.push(entry);
                    continue;
                }
                entry.thumbprint = None;
                changed = true;
            }
            if let Err(why) = self.seams.keys.delete(&entry.key_name) {
                errors.push(why);
                kept.push(entry);
            }
        }
        state.retiring = kept;
        if changed || state.retiring.len() != before {
            self.save(state, errors);
        }
    }

    /// The policy follows whether a root is held. It is set only when Firefox
    /// is installed and the value is absent; it is removed only if Sieve set
    /// it and only while it still says what Sieve wrote.
    fn sync_firefox(&self, held: &mut Held, state: &mut CaState, want: bool, errors: &mut Vec<String>) {
        let result = if want { self.firefox_on(state, errors) } else { self.firefox_off(state, errors) };
        match result {
            Ok(trust) => held.firefox = trust,
            Err(why) => errors.push(why),
        }
    }

    fn firefox_on(&self, state: &mut CaState, errors: &mut Vec<String>) -> Result<FirefoxTrust, String> {
        if !self.seams.firefox.installed()? {
            return Ok(FirefoxTrust::NotInstalled);
        }
        match self.seams.firefox.read()? {
            Some(trust::FIREFOX_POLICY_ON) => Ok(FirefoxTrust::UsesWindows),
            Some(_) => Ok(FirefoxTrust::NotUsingWindows),
            None => {
                state.firefox_policy_set = true;
                if !self.save(state, errors) {
                    return Ok(FirefoxTrust::NotUsingWindows);
                }
                self.seams.firefox.set()?;
                Ok(FirefoxTrust::UsesWindows)
            }
        }
    }

    fn firefox_off(&self, state: &mut CaState, errors: &mut Vec<String>) -> Result<FirefoxTrust, String> {
        if !state.firefox_policy_set {
            return Ok(FirefoxTrust::NotInstalled);
        }
        if self.seams.firefox.read()? == Some(trust::FIREFOX_POLICY_ON) {
            self.seams.firefox.delete()?;
        }
        state.firefox_policy_set = false;
        self.save(state, errors);
        Ok(FirefoxTrust::NotInstalled)
    }

    /// One minter per root: the same root keeps its minter and its cache.
    fn minter_for(
        &self,
        current: Option<Arc<Minter>>,
        der: Vec<u8>,
        facts: &RootFacts,
        key: RootKey,
        now_ms: u64,
        errors: &mut Vec<String>,
    ) -> Option<Arc<Minter>> {
        if now_ms >= facts.not_after_ms {
            return None;
        }
        if let Some(m) = current.filter(|m| m.thumbprint() == facts.thumbprint) {
            return Some(m);
        }
        match Minter::new(der, facts.thumbprint.clone(), facts.not_after_ms, key, self.leaf_key.clone()) {
            Ok(m) => Some(Arc::new(m)),
            Err(e) => {
                errors.push(e.to_string());
                None
            }
        }
    }

    /// None: no installed, in-date root; `tls::intercept` passes through.
    pub fn minter(&self) -> Option<Arc<Minter>> {
        self.held().minter.clone()
    }

    /// The engine's facts for the app; the app never recomputes `state`.
    pub fn status(&self, now_ms: u64) -> CertStatus {
        let held = self.held();
        let recorded = held.state.as_ref();
        let last_rotation_ms = recorded.and_then(|s| s.last_rotation_ms);
        let withdrawn = recorded.is_some_and(|s| s.withdrawn).then(|| WITHDRAWN.to_string());
        let last_error = held.last_error.clone().or(withdrawn);
        let Some(root) = &held.root else {
            return CertStatus { last_rotation_ms, last_error, ..CertStatus::default() };
        };
        let state = if now_ms >= root.not_after_ms.saturating_sub(ROTATE_BEFORE_MS) {
            CertState::ExpiresSoon
        } else {
            CertState::Installed
        };
        CertStatus {
            state,
            valid_until_ms: Some(root.not_after_ms),
            thumbprint: Some(root.thumbprint.clone()),
            firefox: held.firefox,
            last_rotation_ms,
            last_error,
        }
    }

    /// Something is recorded (or the record cannot be read), so the hourly
    /// tick has work; with nothing to hold the loop waits with no timer.
    pub fn holding(&self) -> bool {
        self.held().state.as_ref().is_none_or(|s| !s.is_clear())
    }
}

/// When a rotated-out root goes: once its last leaf has expired. A leaf lives
/// at most [`LEAF_MAX_LIFETIME_MS`] and never past its root, so the removal
/// is the earlier of the two; a root already expired goes at once.
fn retire_at(now_ms: u64, not_after_ms: Option<u64>) -> u64 {
    let last_leaf = now_ms + LEAF_MAX_LIFETIME_MS + CLOCK_SKEW_MS;
    not_after_ms.map_or(0, |end| last_leaf.min(end))
}

#[cfg(test)]
mod tests;
