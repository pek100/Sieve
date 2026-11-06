//! The lists on disk, in `ProgramData\Sieve\engine\lists\` (admin-only, and
//! removed with `ProgramData\Sieve`): `<id>.txt` is the last good copy,
//! `<id>.json` what is known about it. Writes are atomic. A file that cannot
//! be read as what it should be is treated as absent, so a corrupt cache means
//! fewer blocks and one more download, never a failed connection.

use std::io::Read;
use std::path::{Path, PathBuf};

use sieve_filter::lists::{FetchState, MAX_LIST_BYTES};
use sieve_filter::rules::has_a_rule;

use crate::policy::write_atomic;

pub const FOLDER: &str = "lists";
/// `! Expires:` sits in a list's first kilobyte; only that much is read to
/// know a copy's refresh, so a start does not load every list.
const HEAD_BYTES: u64 = 4 * 1024;

#[derive(Debug, Clone)]
pub struct Cache {
    dir: PathBuf,
}

impl Cache {
    /// The cache under the engine's state folder (created on first write).
    pub fn new(engine_dir: &Path) -> Self {
        Self { dir: engine_dir.join(FOLDER) }
    }

    fn text_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.txt"))
    }

    fn state_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// The whole copy, or None when it is missing, too large, not UTF-8 or
    /// holds no rule.
    pub fn read_text(&self, id: &str) -> Option<String> {
        let bytes = std::fs::read(self.text_path(id)).ok().filter(|b| b.len() <= MAX_LIST_BYTES)?;
        String::from_utf8(bytes).ok().filter(|t| has_a_rule(t))
    }

    fn read_head(&self, id: &str) -> Option<String> {
        let file = std::fs::File::open(self.text_path(id)).ok()?;
        let mut head = Vec::new();
        file.take(HEAD_BYTES).read_to_end(&mut head).ok()?;
        Some(String::from_utf8_lossy(&head).into_owned())
    }

    /// The saved state joined with its copy's header. A cut or corrupt body is
    /// found when the copy is read to compile.
    pub fn read_state(&self, id: &str) -> FetchState {
        let saved: FetchState = std::fs::read(self.state_path(id)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        saved.restored(self.read_head(id).as_deref())
    }

    pub fn write_text(&self, id: &str, text: &str) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        write_atomic(&self.text_path(id), text.as_bytes())
    }

    pub fn write_state(&self, id: &str, state: &FetchState) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        write_atomic(&self.state_path(id), &serde_json::to_vec_pretty(state).map_err(|e| e.to_string())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "! Expires: 2 days\n||ads.example^\n";

    fn cache() -> (tempfile::TempDir, Cache) {
        let dir = tempfile::tempdir().unwrap();
        let c = Cache::new(dir.path());
        (dir, c)
    }

    #[test]
    fn corrupt_cache_reads_as_absent() {
        let (_dir, c) = cache();
        assert_eq!(c.read_text("x"), None, "nothing there");
        assert_eq!(c.read_state("x"), FetchState::default());
        c.write_text("x", LIST).unwrap();
        c.write_state("x", &FetchState { etag: Some("\"v\"".into()), ..FetchState::fetched(LIST, None, None, 5) }).unwrap();
        std::fs::write(c.text_path("x"), [0xff, 0xfe, 0x00]).unwrap();
        assert_eq!(c.read_text("x"), None, "not UTF-8");
        std::fs::write(c.text_path("x"), "! only a comment\n").unwrap();
        assert_eq!(c.read_text("x"), None, "no rule");
        std::fs::write(c.state_path("x"), "garbage{").unwrap();
        std::fs::write(c.text_path("x"), LIST).unwrap();
        assert_eq!(c.read_state("x").fetched_at_ms, None, "a broken state file knows nothing");
        assert_eq!(c.read_text("x").as_deref(), Some(LIST), "the copy itself stays good");
    }

    #[test]
    fn state_survives_a_restart() {
        let (dir, c) = cache();
        let state = FetchState::fetched(LIST, Some("\"v1\"".into()), Some("yesterday".into()), 77);
        c.write_text("x", LIST).unwrap();
        c.write_state("x", &state).unwrap();
        let reopened = Cache::new(dir.path());
        assert_eq!(reopened.read_state("x"), state, "the refresh comes back from the copy's header");
        assert_eq!(reopened.read_text("x").as_deref(), Some(LIST));
        std::fs::remove_file(c.text_path("x")).unwrap();
        assert_eq!(reopened.read_state("x"), FetchState::default(), "a state with no copy is not believed");
    }
}
