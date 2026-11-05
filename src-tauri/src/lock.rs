//! The settings password (plan D8, D9): a gate in the UI, kept here so the hash
//! never reaches the webview. `<app data>/settings-lock.json` holds
//! `{v: 1, phc: "$argon2id$..."}`, written atomically. It is not a settings
//! key, so export, import and reset can neither carry nor clear it.
//!
//! What it stands up to: a person at the open app. Anyone who can edit files in
//! this Windows account can delete the file (that is also the documented way
//! out of a forgotten password). It touches settings only, never the network.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use tauri::State;

/// The file's name in the app data dir.
pub const LOCK_FILE: &str = "settings-lock.json";
/// Agrees with MIN_PASSWORD_CHARS in src/core/lock.ts (law 14).
pub const MIN_PASSWORD_CHARS: usize = 8;
/// Wrong answers allowed before the wait.
pub const MAX_TRIES: u32 = 5;
/// The wait after MAX_TRIES wrong answers.
pub const RETRY_AFTER_SECS: u64 = 30;

const FILE_VERSION: u32 = 1;
const HASH_PREFIX: &str = "$argon2id$";
/// OWASP's minimum Argon2id profile. The PHC string carries salt and
/// parameters, so a later build can raise them and still verify an old hash.
const ARGON2_M_KIB: u32 = 19_456;
const ARGON2_T: u32 = 2;
const ARGON2_P: u32 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LockError {
    #[error("Use at least {MIN_PASSWORD_CHARS} characters.")]
    TooShort,
    #[error("That is not the current password.")]
    Wrong,
    #[error("Too many tries. Try again in {0} s.")]
    Throttled(u64),
    #[error("The password file could not be read, so it was left as it is.")]
    Unreadable,
    #[error("Could not hash the password: {0}")]
    Hash(String),
    #[error("Could not save the password: {0}")]
    Write(String),
}

/// `MAX_TRIES` wrong answers earn a `RETRY_AFTER_SECS` wait. Time is an
/// argument, so tests need no sleeping.
#[derive(Debug, Default)]
pub struct Throttle {
    failures: u32,
    until: u64,
}

impl Throttle {
    /// Seconds left to wait, or None when an attempt may run.
    pub fn wait(&self, now: u64) -> Option<u64> {
        (now < self.until).then(|| self.until - now)
    }

    pub fn failed(&mut self, now: u64) {
        self.failures += 1;
        if self.failures >= MAX_TRIES {
            self.failures = 0;
            self.until = now + RETRY_AFTER_SECS;
        }
    }

    pub fn passed(&mut self) {
        *self = Self::default();
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct LockFile {
    v: u32,
    phc: String,
}

/// What the file says. An unreadable file is never treated as "no password".
#[derive(Debug, PartialEq, Eq)]
enum Stored {
    None,
    Set(String),
    Unreadable,
}

fn read_stored(path: &Path) -> Stored {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Stored::None,
        Err(_) => return Stored::Unreadable,
    };
    match serde_json::from_str::<LockFile>(&text) {
        Ok(f) if f.v == FILE_VERSION && f.phc.starts_with(HASH_PREFIX) && PasswordHash::new(&f.phc).is_ok() => Stored::Set(f.phc),
        _ => Stored::Unreadable,
    }
}

/// Temp file then rename, so a failed write leaves the old file whole.
fn write_stored(path: &Path, phc: &str) -> Result<(), LockError> {
    let fail = |e: std::io::Error| LockError::Write(e.to_string());
    let text = serde_json::to_string(&LockFile { v: FILE_VERSION, phc: phc.to_string() }).map_err(|e| LockError::Write(e.to_string()))?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(fail)?;
    }
    let tmp = path.with_extension("json.tmp");
    let mut file = fs::File::create(&tmp).map_err(fail)?;
    file.write_all(text.as_bytes()).map_err(fail)?;
    file.sync_all().map_err(fail)?;
    drop(file);
    fs::rename(&tmp, path).map_err(fail)
}

/// The salt comes from the OS random source, inside `hash_password`.
fn hash(password: &str) -> Result<String, LockError> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, None).map_err(|e| LockError::Hash(e.to_string()))?;
    let hashed = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(password.as_bytes())
        .map_err(|e| LockError::Hash(e.to_string()))?;
    Ok(hashed.to_string())
}

fn verify(password: &str, phc: &str) -> bool {
    // Parameters come from the PHC string, never from this build's constants.
    PasswordHash::new(phc).is_ok_and(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

/// `lock_status`: no hash field, by construction.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct LockStatus {
    pub v: u32,
    /// `none`, `set` or `unreadable`.
    pub state: &'static str,
    pub retry_after_secs: u64,
}

/// `lock_verify`: no hash field, by construction.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct LockVerdict {
    pub ok: bool,
    pub retry_after_secs: u64,
}

/// The file and its throttle. Every method takes the time, as `now` in seconds.
#[derive(Debug)]
pub struct LockStore {
    path: PathBuf,
    throttle: Mutex<Throttle>,
}

impl LockStore {
    pub fn open_at(dir: &Path) -> Self {
        Self { path: dir.join(LOCK_FILE), throttle: Mutex::new(Throttle::default()) }
    }

    fn throttle(&self) -> std::sync::MutexGuard<'_, Throttle> {
        self.throttle.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn status(&self, now: u64) -> LockStatus {
        let state = match read_stored(&self.path) {
            Stored::None => "none",
            Stored::Set(_) => "set",
            Stored::Unreadable => "unreadable",
        };
        LockStatus { v: FILE_VERSION, state, retry_after_secs: self.throttle().wait(now).unwrap_or(0) }
    }

    /// Checks `password` against the hash in `phc`, under the throttle.
    fn answer(&self, password: &str, phc: &str, now: u64) -> Result<(), LockError> {
        if let Some(secs) = self.throttle().wait(now) {
            return Err(LockError::Throttled(secs));
        }
        if verify(password, phc) {
            self.throttle().passed();
            return Ok(());
        }
        self.throttle().failed(now);
        Err(self.throttle().wait(now).map_or(LockError::Wrong, LockError::Throttled))
    }

    pub fn verify(&self, password: &str, now: u64) -> Result<LockVerdict, LockError> {
        let Stored::Set(phc) = read_stored(&self.path) else {
            return Err(LockError::Unreadable);
        };
        Ok(match self.answer(password, &phc, now) {
            Ok(()) => LockVerdict { ok: true, retry_after_secs: 0 },
            Err(LockError::Throttled(secs)) => LockVerdict { ok: false, retry_after_secs: secs },
            Err(_) => LockVerdict { ok: false, retry_after_secs: 0 },
        })
    }

    /// Set or change. `current` must match when a password exists; an
    /// unreadable file is refused and left as it is.
    pub fn set(&self, current: Option<&str>, next: &str, now: u64) -> Result<(), LockError> {
        if next.chars().count() < MIN_PASSWORD_CHARS {
            return Err(LockError::TooShort);
        }
        match read_stored(&self.path) {
            Stored::Unreadable => return Err(LockError::Unreadable),
            Stored::Set(phc) => self.answer(current.unwrap_or(""), &phc, now)?,
            Stored::None => {}
        }
        write_stored(&self.path, &hash(next)?)
    }

    pub fn clear(&self, current: &str, now: u64) -> Result<(), LockError> {
        match read_stored(&self.path) {
            Stored::Unreadable => Err(LockError::Unreadable),
            Stored::None => Ok(()),
            Stored::Set(phc) => {
                self.answer(current, &phc, now)?;
                fs::remove_file(&self.path).map_err(|e| LockError::Write(e.to_string()))
            }
        }
    }
}

/// Managed state: the store and the clock its throttle reads.
#[derive(Debug, Clone)]
pub struct LockState {
    store: Arc<LockStore>,
    started: Instant,
}

impl LockState {
    pub fn open_at(dir: &Path) -> Self {
        Self { store: Arc::new(LockStore::open_at(dir)), started: Instant::now() }
    }

    fn now(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

async fn blocking<T: Send + 'static>(run: impl FnOnce() -> Result<T, LockError> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(run).await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn lock_status(state: State<'_, LockState>) -> Result<LockStatus, String> {
    let (store, now) = (state.store.clone(), state.now());
    blocking(move || Ok(store.status(now))).await
}

#[tauri::command]
pub async fn lock_verify(state: State<'_, LockState>, password: String) -> Result<LockVerdict, String> {
    let (store, now) = (state.store.clone(), state.now());
    blocking(move || store.verify(&password, now)).await
}

#[tauri::command]
pub async fn lock_set(state: State<'_, LockState>, current: Option<String>, next: String) -> Result<(), String> {
    let (store, now) = (state.store.clone(), state.now());
    blocking(move || store.set(current.as_deref(), &next, now)).await
}

#[tauri::command]
pub async fn lock_clear(state: State<'_, LockState>, current: String) -> Result<(), String> {
    let (store, now) = (state.store.clone(), state.now());
    blocking(move || store.clear(&current, now)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "correct horse";

    fn store() -> (tempfile::TempDir, LockStore) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = LockStore::open_at(dir.path());
        (dir, store)
    }

    fn file_text(dir: &tempfile::TempDir) -> String {
        fs::read_to_string(dir.path().join(LOCK_FILE)).expect("lock file")
    }

    #[test]
    fn set_writes_an_argon2id_hash_and_never_the_password() {
        let (dir, s) = store();
        assert_eq!(s.status(0).state, "none");
        s.set(None, PASSWORD, 0).expect("set");
        let text = file_text(&dir);
        let parsed: LockFile = serde_json::from_str(&text).expect("json");
        assert!(parsed.phc.starts_with("$argon2id$"), "{}", parsed.phc);
        assert!(parsed.phc.contains("m=19456,t=2,p=1"), "{}", parsed.phc);
        assert!(!text.contains(PASSWORD));
        assert_eq!(s.status(0).state, "set");
    }

    #[test]
    fn two_sets_of_one_password_give_two_salts() {
        let (dir, s) = store();
        s.set(None, PASSWORD, 0).expect("first");
        let first = file_text(&dir);
        s.set(Some(PASSWORD), PASSWORD, 0).expect("second");
        assert_ne!(first, file_text(&dir));
    }

    #[test]
    fn verify_answers_right_and_wrong() {
        let (_dir, s) = store();
        s.set(None, PASSWORD, 0).expect("set");
        assert_eq!(s.verify(PASSWORD, 0), Ok(LockVerdict { ok: true, retry_after_secs: 0 }));
        assert_eq!(s.verify("not the one", 0), Ok(LockVerdict { ok: false, retry_after_secs: 0 }));
    }

    #[test]
    fn a_wrong_current_password_refuses_set_and_clear() {
        let (dir, s) = store();
        s.set(None, PASSWORD, 0).expect("set");
        let before = file_text(&dir);
        assert_eq!(s.set(Some("wrong one"), "a new password", 0), Err(LockError::Wrong));
        assert_eq!(s.set(None, "a new password", 0), Err(LockError::Wrong));
        assert_eq!(s.clear("wrong one", 0), Err(LockError::Wrong));
        assert_eq!(file_text(&dir), before);
        s.clear(PASSWORD, 0).expect("clear");
        assert_eq!(s.status(0).state, "none");
    }

    #[test]
    fn a_short_password_is_refused_in_rust_too() {
        let (dir, s) = store();
        assert_eq!(s.set(None, "1234567", 0), Err(LockError::TooShort));
        assert!(!dir.path().join(LOCK_FILE).exists());
    }

    #[test]
    fn a_corrupt_file_reads_unreadable_and_is_never_overwritten() {
        for corrupt in ["not json", r#"{"v":1,"phc":"plain text"}"#, r#"{"v":9,"phc":"$argon2id$x"}"#, r#"{"v":1}"#] {
            let (dir, s) = store();
            fs::write(dir.path().join(LOCK_FILE), corrupt).expect("write");
            assert_eq!(s.status(0).state, "unreadable", "{corrupt}");
            assert_eq!(s.set(None, PASSWORD, 0), Err(LockError::Unreadable), "{corrupt}");
            assert_eq!(s.clear(PASSWORD, 0), Err(LockError::Unreadable), "{corrupt}");
            assert_eq!(s.verify(PASSWORD, 0), Err(LockError::Unreadable), "{corrupt}");
            assert_eq!(file_text(&dir), corrupt);
        }
    }

    #[test]
    fn a_failed_write_leaves_the_old_file() {
        let (dir, s) = store();
        s.set(None, PASSWORD, 0).expect("set");
        let before = file_text(&dir);
        // The temp file's name is taken by a folder, so the write cannot start.
        fs::create_dir(dir.path().join(LOCK_FILE).with_extension("json.tmp")).expect("dir");
        assert!(matches!(s.set(Some(PASSWORD), "a new password", 0), Err(LockError::Write(_))));
        assert_eq!(file_text(&dir), before);
        assert_eq!(s.verify(PASSWORD, 0), Ok(LockVerdict { ok: true, retry_after_secs: 0 }));
    }

    #[test]
    fn the_throttle_refuses_after_five_and_allows_again_after_thirty_seconds() {
        let mut t = Throttle::default();
        for _ in 0..MAX_TRIES - 1 {
            t.failed(100);
            assert_eq!(t.wait(100), None);
        }
        t.failed(100);
        assert_eq!(t.wait(100), Some(RETRY_AFTER_SECS));
        assert_eq!(t.wait(100 + RETRY_AFTER_SECS - 1), Some(1));
        assert_eq!(t.wait(100 + RETRY_AFTER_SECS), None);
        // A right answer clears the count.
        t.failed(200);
        t.passed();
        for _ in 0..MAX_TRIES - 1 {
            t.failed(200);
        }
        assert_eq!(t.wait(200), None);
    }

    #[test]
    fn the_store_applies_the_throttle_to_every_way_of_asking() {
        let (_dir, s) = store();
        s.set(None, PASSWORD, 0).expect("set");
        for _ in 0..MAX_TRIES - 1 {
            assert_eq!(s.verify("wrong one", 10), Ok(LockVerdict { ok: false, retry_after_secs: 0 }));
        }
        assert_eq!(s.clear("wrong one", 10), Err(LockError::Throttled(RETRY_AFTER_SECS)));
        // Even the right password waits.
        assert_eq!(s.verify(PASSWORD, 11), Ok(LockVerdict { ok: false, retry_after_secs: RETRY_AFTER_SECS - 1 }));
        assert_eq!(s.status(11).retry_after_secs, RETRY_AFTER_SECS - 1);
        assert_eq!(s.verify(PASSWORD, 10 + RETRY_AFTER_SECS), Ok(LockVerdict { ok: true, retry_after_secs: 0 }));
    }

    #[test]
    fn the_wire_answers_carry_no_hash() {
        let (_dir, s) = store();
        s.set(None, PASSWORD, 0).expect("set");
        for text in [
            serde_json::to_string(&s.status(0)).expect("status"),
            serde_json::to_string(&s.verify(PASSWORD, 0).expect("verify")).expect("verdict"),
        ] {
            assert!(!text.contains("argon2"), "{text}");
            assert!(!text.contains("phc"), "{text}");
        }
    }
}
