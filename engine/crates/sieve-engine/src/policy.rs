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

use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
pub use sieve_ipc::MAX_POLICY_BYTES;
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

/// A record that outlives a power loss: on disk before it returns, because what
/// comes next may depend on it (`ca.json` guards the trust write that follows).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_durably(path, bytes, &std::fs::File::sync_all)
}

/// The bytes first, then the rename, then the rename itself: a rename reaching
/// the disk ahead of its data would leave a damaged file behind.
fn write_durably(path: &Path, bytes: &[u8], flush: &dyn Fn(&std::fs::File) -> std::io::Result<()>) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let named = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    let mut file = std::fs::File::create(&tmp).map_err(|e| named(&tmp, e))?;
    file.write_all(bytes).and_then(|()| flush(&file)).map_err(|e| named(&tmp, e))?;
    drop(file);
    std::fs::rename(&tmp, path).map_err(|e| named(path, e))?;
    std::fs::OpenOptions::new().write(true).open(path).and_then(|renamed| flush(&renamed)).map_err(|e| named(path, e))
}

/// A report rewritten every few seconds and read by a person: atomic, and not
/// worth a flush.
pub(crate) fn write_report(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The policy a SetPolicy asks for, or why it is refused: an older or equal
/// revision is a stale write (another window, a retry) and changes nothing. A
/// policy is sent back in every Status, so one that could not fit a frame
/// beside the rest of a Status is refused here and not at the next answer.
pub fn accept(current: &Policy, asked: Policy) -> Result<Policy, String> {
    if asked.revision <= current.revision {
        return Err(format!("stale policy revision {} (the engine holds {})", asked.revision, current.revision));
    }
    let size = serde_json::to_vec(&asked).map_err(|e| e.to_string())?.len();
    if size > MAX_POLICY_BYTES {
        return Err(format!("a policy of {size} bytes is over the {MAX_POLICY_BYTES} byte limit"));
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
        let on = Policy { revision: 4, engine: true, sieving: true, off_apps: vec!["app".into()], ..Policy::default() };
        save(dir.path(), &on).unwrap();
        assert_eq!(load(dir.path()), (on, None));
        std::fs::write(dir.path().join(POLICY_FILE), b"{\"engine\":true}").unwrap();
        let (p, why) = load(dir.path());
        assert_eq!(p, Policy::default());
        assert!(why.unwrap().contains("read as off"));
    }

    /// What is on disk at each flush: the old file while the new bytes go down,
    /// the new one when the rename goes down. No power-loss run proves more.
    #[test]
    fn a_durable_write_flushes_the_bytes_before_the_rename_and_the_rename_after() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.json");
        std::fs::write(&path, b"old").unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        write_durably(&path, b"new!", &|file| {
            seen.borrow_mut().push((file.metadata()?.len(), std::fs::read(&path)?));
            Ok(())
        })
        .unwrap();
        assert_eq!(*seen.borrow(), [(4, b"old".to_vec()), (4, b"new!".to_vec())]);

        let failed = write_durably(&path, b"newer", &|_| Err(std::io::Error::other("disk gone")));
        assert!(failed.unwrap_err().contains("disk gone"));
        assert_eq!(std::fs::read(&path).unwrap(), b"new!", "a failed flush renames nothing");

        write_atomic(&path, b"real").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"real");
    }

    /// What `scripts/live/engine-ca-checks.ps1` writes for one call, through this
    /// file's reader. Touches only a temporary folder.
    #[cfg(windows)]
    fn live_script_writes(before: &Policy, call: &str) -> Policy {
        const CHECKS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../scripts/live/engine-ca-checks.ps1");
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.json");
        std::fs::write(&source, serde_json::to_vec(before).unwrap()).unwrap();
        let script = format!("$ErrorActionPreference = 'Stop'; . '{CHECKS}'; $policy = Get-Content -Raw '{}' | ConvertFrom-Json; {call}", source.display());
        let out = std::process::Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        std::fs::write(dir.path().join(POLICY_FILE), &out.stdout).unwrap();
        let (written, refused) = load(dir.path());
        assert_eq!(refused, None, "the engine reads what the script writes");
        written
    }

    /// The slice 6 route must reach interception, or the floor checks pass with
    /// nothing intercepted.
    #[cfg(windows)]
    #[test]
    fn the_policy_the_live_script_writes_is_one_interception_wants() {
        use crate::tls::intercept::wanted;
        let list = sieve_ipc::DomainList { kind: sieve_ipc::DomainListKind::Block, entries: vec!["a.example".into()], enabled: true };
        let before = Policy { revision: 7, off_apps: vec!["chrome".into()], lists: Some(vec!["adguard-dns".into()]), domain_lists: vec![list], user_rules: vec!["||x.example^".into()], ..Policy::default() };
        let written = live_script_writes(&before, "New-InterceptionPolicyJson $policy");
        assert!(wanted(&written) && written.engine, "{written:?}");
        assert_eq!(written, Policy { revision: 8, engine: true, sieving: true, https: true, ..before.clone() }, "nothing else moved");
        // The control: slice 5's route holds a root and intercepts nothing.
        let root_only = live_script_writes(&before, "New-HttpsPolicyJson $policy $true");
        assert!(root_only.https && !wanted(&root_only) && !root_only.engine, "{root_only:?}");
    }

    #[test]
    fn an_old_policy_file_loads_with_sieving_off() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(POLICY_FILE), br#"{"revision":7,"engine":true}"#).unwrap();
        let (p, why) = load(dir.path());
        assert_eq!(why, None);
        assert_eq!((p.revision, p.engine, p.sieving), (7, true, false));
        assert!(p.off_apps.is_empty() && p.lists.is_none() && p.domain_lists.is_empty());
    }

    fn policy(revision: u64, engine: bool) -> Policy {
        Policy { revision, engine, ..Policy::default() }
    }

    #[test]
    fn only_a_newer_revision_is_accepted() {
        let cur = policy(4, true);
        assert_eq!(accept(&cur, policy(5, false)), Ok(policy(5, false)));
        assert!(accept(&cur, policy(4, false)).is_err());
        assert!(accept(&cur, policy(1, true)).is_err());
    }

    #[test]
    fn a_policy_too_large_for_a_status_frame_is_refused() {
        let big = Policy { off_apps: vec!["a".repeat(MAX_POLICY_BYTES)], ..policy(5, true) };
        assert!(accept(&policy(4, true), big).unwrap_err().contains("over the"));
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
