//! The route journal (plan 1.6.3): before the engine adds a route it appends
//! the route to `routes.journal` and fsyncs it. At every start, before
//! anything else, the engine deletes every route on an interface named
//! "Sieve" and every route in the journal, then truncates it, so a crashed
//! run never carries stale routes into the next one. One JSON object per
//! line; a line that does not parse (a torn write) is skipped and counted.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::prefix::Prefix;

pub const JOURNAL_FILE: &str = "routes.journal";

/// One route the engine added: the prefix and the adapter it sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub prefix: Prefix,
    pub luid: u64,
}

#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
}

/// What a replay did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Replay {
    pub deleted: usize,
    /// Already gone (the adapter took it, or a previous cleanup).
    pub absent: usize,
    pub failed: usize,
    /// Lines that did not parse.
    pub skipped: usize,
}

/// How deleting one journalled route went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deleted {
    Yes,
    NotThere,
    Failed,
}

impl Journal {
    pub fn new(dir: &Path) -> Self {
        Self { path: dir.join(JOURNAL_FILE) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends `entry` and returns only once it is on disk.
    pub fn append(&self, entry: &Entry) -> Result<(), String> {
        let mut line = serde_json::to_string(entry).map_err(|e| e.to_string())?;
        line.push('\n');
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path).map_err(|e| format!("{}: {e}", self.path.display()))?;
        f.write_all(line.as_bytes()).map_err(|e| format!("{}: {e}", self.path.display()))?;
        f.sync_all().map_err(|e| format!("{}: fsync: {e}", self.path.display()))
    }

    /// Every entry in the file (none when it does not exist) and the count of
    /// lines that did not parse.
    pub fn read(&self) -> Result<(Vec<Entry>, usize), String> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
            Err(e) => return Err(format!("{}: {e}", self.path.display())),
        };
        let mut skipped = 0;
        let entries = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).map_err(|_| skipped += 1).ok())
            .collect();
        Ok((entries, skipped))
    }

    /// Deletes every journalled route with `delete`, then empties the
    /// journal. The journal is emptied only when no deletion failed, so a
    /// route that could not go is tried again at the next start.
    pub fn replay(&self, mut delete: impl FnMut(&Entry) -> Deleted) -> Result<Replay, String> {
        let (entries, skipped) = self.read()?;
        let mut r = Replay { skipped, ..Replay::default() };
        for e in &entries {
            match delete(e) {
                Deleted::Yes => r.deleted += 1,
                Deleted::NotThere => r.absent += 1,
                Deleted::Failed => r.failed += 1,
            }
        }
        if r.failed == 0 {
            self.truncate()?;
        }
        Ok(r)
    }

    /// Empties the journal; one that does not exist is already empty (the
    /// folder may not exist either, for example before an install).
    pub fn truncate(&self) -> Result<(), String> {
        if !self.path.exists() {
            return Ok(());
        }
        match std::fs::File::create(&self.path).and_then(|f| f.sync_all()) {
            Ok(()) => Ok(()),
            Err(e) => Err(format!("{}: {e}", self.path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(p: &str) -> Entry {
        Entry { prefix: p.parse().unwrap(), luid: 77 }
    }

    #[test]
    fn a_crashed_run_is_replayed_in_full_then_the_journal_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path());
        let added = [entry("0.0.0.0/5"), entry("8.0.0.0/7"), entry("192.168.7.1/32"), entry("2000::/4")];
        for e in &added {
            j.append(e).unwrap();
        }
        // The run "crashes": nothing removes them. The next start replays.
        let mut seen = Vec::new();
        let r = j
            .replay(|e| {
                seen.push(*e);
                if e.prefix.is_host() { Deleted::NotThere } else { Deleted::Yes }
            })
            .unwrap();
        assert_eq!(seen, added);
        assert_eq!(r, Replay { deleted: 3, absent: 1, failed: 0, skipped: 0 });
        assert_eq!(j.read().unwrap(), (vec![], 0));
        assert_eq!(j.replay(|_| panic!("nothing left to delete")).unwrap(), Replay::default());
    }

    #[test]
    fn a_failed_deletion_keeps_the_journal_for_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path());
        j.append(&entry("0.0.0.0/5")).unwrap();
        let r = j.replay(|_| Deleted::Failed).unwrap();
        assert_eq!(r.failed, 1);
        assert_eq!(j.read().unwrap().0, vec![entry("0.0.0.0/5")]);
    }

    #[test]
    fn a_torn_line_is_skipped_and_counted_never_guessed() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path());
        j.append(&entry("64.0.0.0/2")).unwrap();
        let mut f = OpenOptions::new().append(true).open(j.path()).unwrap();
        f.write_all(b"{\"prefix\":\"128.0.").unwrap();
        drop(f);
        let r = j.replay(|_| Deleted::Yes).unwrap();
        assert_eq!((r.deleted, r.skipped), (1, 1));
    }

    #[test]
    fn no_journal_is_an_empty_replay_even_without_its_folder() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Journal::new(dir.path()).replay(|_| Deleted::Failed).unwrap(), Replay::default());
        let missing = dir.path().join("not-installed");
        assert_eq!(Journal::new(&missing).replay(|_| Deleted::Failed).unwrap(), Replay::default());
        assert!(!missing.exists(), "nothing is created");
    }
}
