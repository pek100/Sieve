//! What the engine keeps between runs in `ProgramData\Sieve\engine\`
//! (admin-only):
//! - `policy.json`: the user's switches ([`Policy`]). Missing means the
//!   default, everything off; a malformed file also reads as off (never
//!   guessed on), and the reason is reported.
//! - `runs.json`: when each recent run started and whether it stopped
//!   cleanly, for the crash-loop stop (plan 1.6.4): at the third restart
//!   within an hour, that is the third start after a run that did not stop
//!   cleanly, the engine routes nothing until the user turns it on again.
//!   The service manager's recovery (restart twice, then stay stopped) is
//!   the other half; this half holds across reboots and manual starts.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sieve_ipc::Policy;

pub const POLICY_FILE: &str = "policy.json";
pub const RUNS_FILE: &str = "runs.json";

/// Restarts within [`CRASH_WINDOW_MS`] that stop routing (plan 1.6.4).
pub const CRASH_LOOP_RESTARTS: u32 = 3;
/// One hour.
pub const CRASH_WINDOW_MS: u64 = 3_600_000;

/// Reads the policy, and the reason when a present file was not used.
pub fn load(dir: &Path) -> (Policy, Option<String>) {
    let path = dir.join(POLICY_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(p) => (p, None),
            Err(e) => (Policy::default(), Some(format!("{}: {e}; read as off", path.display()))),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Policy::default(), None),
        Err(e) => (Policy::default(), Some(format!("{}: {e}; read as off", path.display()))),
    }
}

/// Writes the policy through a temporary file and a rename, so a crash
/// leaves the old or the new file, never half of one.
pub fn save(dir: &Path, policy: &Policy) -> Result<(), String> {
    write_atomic(&dir.join(POLICY_FILE), &serde_json::to_vec_pretty(policy).map_err(|e| e.to_string())?)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The policy a SetPolicy asks for, or why it is refused: an older or equal
/// revision is a stale write (another window, a retry) and changes nothing.
pub fn accept(current: Policy, asked: Policy) -> Result<Policy, String> {
    if asked.revision <= current.revision {
        return Err(format!("stale policy revision {} (the engine holds {})", asked.revision, current.revision));
    }
    Ok(asked)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    /// Start time, ms since the Unix epoch.
    pub start: u64,
    pub clean: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Runs {
    pub runs: Vec<Run>,
}

impl Runs {
    /// Starts within the window after a run that did not stop cleanly.
    pub fn restarts(&self, now: u64) -> u32 {
        let recent = self.runs.iter().filter(|r| now.saturating_sub(r.start) < CRASH_WINDOW_MS);
        u32::try_from(recent.filter(|r| !r.clean).count()).unwrap_or(u32::MAX)
    }

    /// Records this start; returns the restarts that counts as (the earlier
    /// unclean runs in the window), and drops runs older than the window.
    pub fn start(&mut self, now: u64) -> u32 {
        self.runs.retain(|r| now.saturating_sub(r.start) < CRASH_WINDOW_MS);
        let restarts = self.restarts(now);
        self.runs.push(Run { start: now, clean: false });
        restarts
    }

    /// The current run ends cleanly (the service was asked to stop).
    pub fn stop_clean(&mut self) {
        if let Some(last) = self.runs.last_mut() {
            last.clean = true;
        }
    }

    /// The user turned the engine on again: earlier failures no longer count.
    pub fn forgive(&mut self) {
        let current = self.runs.pop();
        self.runs.clear();
        self.runs.extend(current);
    }
}

/// Wall-clock milliseconds since the Unix epoch (run starts must compare
/// across process restarts and reboots; a clock before 1970 reads as 0).
pub fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// A crash loop: the number of restarts when it is one.
pub fn crash_loop(restarts: u32) -> Option<u32> {
    (restarts >= CRASH_LOOP_RESTARTS).then_some(restarts)
}

pub fn load_runs(dir: &Path) -> Runs {
    std::fs::read(dir.join(RUNS_FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn save_runs(dir: &Path, runs: &Runs) -> Result<(), String> {
    write_atomic(&dir.join(RUNS_FILE), &serde_json::to_vec(runs).map_err(|e| e.to_string())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60_000;

    #[test]
    fn the_policy_defaults_off_round_trips_and_a_bad_file_reads_as_off() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path()), (Policy::default(), None));
        let on = Policy { revision: 4, engine: true };
        save(dir.path(), &on).unwrap();
        assert_eq!(load(dir.path()), (on, None));
        std::fs::write(dir.path().join(POLICY_FILE), b"{\"engine\":true}").unwrap();
        let (p, why) = load(dir.path());
        assert_eq!(p, Policy::default());
        assert!(why.unwrap().contains("read as off"));
    }

    #[test]
    fn only_a_newer_revision_is_accepted() {
        let cur = Policy { revision: 4, engine: true };
        assert_eq!(accept(cur, Policy { revision: 5, engine: false }), Ok(Policy { revision: 5, engine: false }));
        assert!(accept(cur, Policy { revision: 4, engine: false }).is_err());
        assert!(accept(cur, Policy { revision: 1, engine: true }).is_err());
    }

    /// A fake clock in minutes: three crashes in an hour stop routing at the
    /// next start; a clean stop or an hour without crashes does not.
    #[test]
    fn the_third_restart_within_an_hour_is_a_crash_loop() {
        let mut runs = Runs::default();
        assert_eq!(crash_loop(runs.start(0)), None); // first start
        assert_eq!(crash_loop(runs.start(MIN)), None); // restart 1 (run 1 crashed)
        assert_eq!(crash_loop(runs.start(2 * MIN)), None); // restart 2
        assert_eq!(crash_loop(runs.start(3 * MIN)), Some(3)); // restart 3: stop routing
    }

    #[test]
    fn clean_stops_and_old_crashes_do_not_count() {
        let mut runs = Runs::default();
        for i in 0..5 {
            assert_eq!(crash_loop(runs.start(i * MIN)), None);
            runs.stop_clean();
        }
        let mut runs = Runs::default();
        runs.start(0);
        runs.start(MIN);
        runs.start(2 * MIN);
        assert_eq!(crash_loop(runs.start(2 * MIN + CRASH_WINDOW_MS)), None, "all three crashes are over an hour old");
        assert_eq!(runs.runs.len(), 1, "old runs are dropped");
    }

    #[test]
    fn turning_the_engine_on_again_forgives_earlier_failures() {
        let mut runs = Runs::default();
        for i in 0..4 {
            runs.start(i * MIN);
        }
        assert_eq!(runs.restarts(4 * MIN), 4);
        runs.forgive();
        assert_eq!(runs.runs.len(), 1);
        runs.stop_clean();
        assert_eq!(crash_loop(runs.start(5 * MIN)), None);
    }

    #[test]
    fn runs_survive_a_restart_of_the_process() {
        let dir = tempfile::tempdir().unwrap();
        let mut runs = load_runs(dir.path());
        runs.start(0);
        save_runs(dir.path(), &runs).unwrap();
        assert_eq!(load_runs(dir.path()), runs);
        std::fs::write(dir.path().join(RUNS_FILE), b"garbage").unwrap();
        assert_eq!(load_runs(dir.path()), Runs::default());
    }
}
