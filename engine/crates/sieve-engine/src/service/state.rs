//! Where the engine keeps its state: `%ProgramData%\Sieve\engine\` (plan
//! 1.5), admin-only by its ACL. `state.json` records the user who installed
//! Sieve, the one non-admin account the pipe admits (plan 1.3).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const SIEVE_DIR: &str = "Sieve";
const ENGINE_DIR: &str = "engine";
const STATE_FILE: &str = "state.json";
/// Why the service last stopped by itself. It has no console, so this file is
/// how the reason reaches a person or the verb that started it.
pub const LAST_ERROR_FILE: &str = "last-error.txt";

/// `%ProgramData%`, which Windows sets for every account, SYSTEM included.
pub fn program_data() -> Result<PathBuf, String> {
    std::env::var_os("ProgramData").map(PathBuf::from).ok_or_else(|| "ProgramData is not set".to_string())
}

/// `<ProgramData>\Sieve`, the folder uninstall deletes.
pub fn sieve_dir(program_data: &Path) -> PathBuf {
    program_data.join(SIEVE_DIR)
}

/// `<ProgramData>\Sieve\engine`.
pub fn engine_dir(program_data: &Path) -> PathBuf {
    sieve_dir(program_data).join(ENGINE_DIR)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// String SID of the user who installed Sieve.
    pub owner_sid: Option<String>,
}

/// The recorded state; a missing file is the empty state, a malformed one an
/// error (never guessed).
pub fn read(engine_dir: &Path) -> Result<State, String> {
    let path = engine_dir.join(STATE_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Writes the state (the folder exists and carries its ACL already).
pub fn write(engine_dir: &Path, state: &State) -> Result<(), String> {
    let path = engine_dir.join(STATE_FILE);
    let text = serde_json::to_vec_pretty(state).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_program_data_sieve_engine() {
        let pd = Path::new(r"C:\ProgramData");
        assert_eq!(sieve_dir(pd), Path::new(r"C:\ProgramData\Sieve"));
        assert_eq!(engine_dir(pd), Path::new(r"C:\ProgramData\Sieve\engine"));
    }

    #[test]
    fn state_round_trips_and_missing_is_empty_and_malformed_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read(dir.path()).unwrap(), State::default());
        let s = State { owner_sid: Some("S-1-5-21-1-2-3-1001".into()) };
        write(dir.path(), &s).unwrap();
        assert_eq!(read(dir.path()).unwrap(), s);
        std::fs::write(dir.path().join(STATE_FILE), b"{\"owner\":1}").unwrap();
        assert!(read(dir.path()).is_err());
    }
}
