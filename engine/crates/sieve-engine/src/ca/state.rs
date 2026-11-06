//! `ca.json` in `ProgramData\Sieve\engine\` (admin-only): the one record of
//! which keys and roots are Sieve's, written before each external write, like
//! the route journal. Names, thumbprints and dates only: the certificate is
//! read back from the store (S51), and no key or certificate byte is on disk.
//!
//! It is not `state.json`: `record_owner` overwrites that on every install,
//! so an update would erase the thumbprints and strand the root.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::policy::write_atomic;

pub const CA_FILE: &str = "ca.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveRoot {
    pub key_name: String,
    pub thumbprint: String,
}

/// A root on its way out, or one being made. `remove_at` 0 is due now, so a
/// crash at any step of making a root leaves an entry the next run cleans up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retiring {
    pub key_name: String,
    /// None before the root exists, and after it left the store.
    pub thumbprint: Option<String>,
    pub remove_at: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaState {
    pub active: Option<ActiveRoot>,
    pub retiring: Vec<Retiring>,
    /// Sieve set the Firefox policy value, so Sieve may remove it.
    pub firefox_policy_set: bool,
    pub last_rotation_ms: Option<u64>,
    /// The active root vanished: no new one without the user's act (plan 7.3).
    pub withdrawn: bool,
}

impl CaState {
    /// Nothing of Sieve's is recorded as still on the machine.
    pub fn is_clear(&self) -> bool {
        self.active.is_none() && self.retiring.is_empty() && !self.firefox_policy_set
    }
}

/// A missing file is the empty record; a malformed one is an error, never
/// guessed around (a guess could strand a root or touch a foreign one).
pub fn load(dir: &Path) -> Result<CaState, String> {
    let path = dir.join(CA_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CaState::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

pub fn save(dir: &Path, state: &CaState) -> Result<(), String> {
    write_atomic(&dir.join(CA_FILE), &serde_json::to_vec_pretty(state).map_err(|e| e.to_string())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_round_trips_and_missing_is_empty_and_malformed_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path()).unwrap(), CaState::default());
        assert!(CaState::default().is_clear());
        let s = CaState {
            active: Some(ActiveRoot { key_name: "k".into(), thumbprint: "t".into() }),
            retiring: vec![Retiring { key_name: "o".into(), thumbprint: None, remove_at: 5 }],
            firefox_policy_set: true,
            last_rotation_ms: Some(9),
            withdrawn: false,
        };
        save(dir.path(), &s).unwrap();
        assert_eq!(load(dir.path()).unwrap(), s);
        assert!(!s.is_clear());
        std::fs::write(dir.path().join(CA_FILE), b"{\"active\":1}").unwrap();
        assert!(load(dir.path()).is_err());
    }
}
