//! `engine\exclusions.json`: the entries the engine wrote itself (plan 4.1's
//! table). Only this layer is persisted here: user entries live in the policy
//! and list entries in their lists. An unreadable file is not an empty store:
//! it reads as `floor:no-exclusion-list` (S24), since an excluded bank must not
//! become decryptable because a file was damaged.
//!
//! A web page can make the engine write here (one host per subdomain of a server
//! that asks for a client certificate), so the layer is bounded by [`cap`] and
//! reaches the disk through [`Writer`], off the flows' threads and in batches.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sieve_filter::exclusions::{AutoReason, Exclusion, Pattern, exe_file_name};

use crate::policy::write_atomic;

pub const FILE: &str = "exclusions.json";
const VERSION: u32 = 1;
/// The evidence rule of `heal::score` that this engine writes `auto:pinning`
/// entries by. A browser's entries of an older rule are dropped once (see
/// [`RULE_FILE`] and `ExclusionSlot::set_browsers`): that rule took what browsers
/// do for a rejection, so they cannot be believed. Raise it whenever that rule
/// starts excluding on less. 0 is an entry from before rules were recorded, whose
/// rule excluded browsers' unused preconnects (2026-11-08).
pub const PINNING_RULE: u32 = 1;
/// Beside [`FILE`]: the newest [`PINNING_RULE`] whose one-time drop has run, so
/// it runs once per rule and not at every start.
///
/// Its own file, not a field of [`FILE`]: an older engine rewrites [`FILE`] in its
/// own shape, losing what it does not know (each entry's `rule` with it) and refusing
/// a file with a field at the top it does not know, but it leaves this file alone.
/// So after a rollback and a roll forward the drop has run and does not run again,
/// and the entries the newer engine wrote survive although their `rule` is gone.
/// The cost, accepted: entries the rolled-back engine wrote by its own older rule
/// are kept too, until "Try decrypting again".
pub const RULE_FILE: &str = "exclusions-rule.json";
/// Entries kept per reason. A budget for each, so a flood of one reason cannot
/// push out the others. An evicted entry costs one more upstream handshake at
/// that host's next visit, which writes it again, so this is a memory and disk
/// bound with room for far more hosts than one person uses, not a tuned value.
pub const MAX_PER_REASON: usize = 1024;
/// The disk sees at most one write in this long. The first write of a quiet
/// spell goes at once, so a kill loses at most this much, and a lost entry comes
/// back at its next sighting.
pub const WRITE_SPACING: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoEntry {
    pub pattern: Pattern,
    /// An exe file name, lower case; None means every app.
    pub app: Option<String>,
    pub reason: AutoReason,
    pub created_ms: u64,
    /// `auto:ev` goes with its certificate; the others stay until [`cap`]
    /// evicts them or "Try decrypting again" takes them back.
    pub expires_ms: Option<u64>,
    /// How many times "Try decrypting again" was used. Defaulted, like `retrying`:
    /// a file from before slice 7 loads, version unchanged (S39).
    #[serde(default)]
    pub retries: u32,
    /// Taken back by the user, so no exclusion; if the client refuses again the
    /// entry returns with its first date and this count (plan 4.3). Counts toward
    /// [`cap`], so the file stays bounded; an evicted one just loses its history.
    #[serde(default)]
    pub retrying: bool,
    /// The [`PINNING_RULE`] it was written by; defaulted to 0, so a file without it
    /// loads, and a rolled-back engine reads it too (S39), though it does not keep it
    /// ([`RULE_FILE`]). Read for `auto:pinning` only.
    #[serde(default)]
    pub rule: u32,
}

impl AutoEntry {
    /// An entry for exactly this host and every app.
    pub fn host(host: &str, reason: AutoReason, created_ms: u64, expires_ms: Option<u64>) -> Self {
        Self { pattern: Pattern::Exact(host.to_ascii_lowercase()), app: None, reason, created_ms, expires_ms, retries: 0, retrying: false, rule: PINNING_RULE }
    }

    /// Written by an evidence rule this engine no longer believes.
    pub fn outdated(&self) -> bool {
        self.reason == AutoReason::Pinning && self.rule < PINNING_RULE
    }

    /// An entry for exactly this host and one app.
    pub fn for_app(host: &str, exe: &str, reason: AutoReason, created_ms: u64) -> Self {
        Self { app: Some(exe_file_name(exe)), ..Self::host(host, reason, created_ms, None) }
    }

    /// Excludes right now: not taken back, not past its end.
    pub fn is_held(&self, now_ms: u64) -> bool {
        !self.retrying && !self.expired(now_ms)
    }

    pub fn expired(&self, now_ms: u64) -> bool {
        self.expires_ms.is_some_and(|end| now_ms >= end)
    }

    pub fn exclusion(&self) -> Exclusion {
        Exclusion { pattern: self.pattern.clone(), apps: self.app.iter().cloned().collect() }
    }
}

/// Keeps the newest [`MAX_PER_REASON`] of each reason. `entries` runs oldest
/// first, in the order they were written.
pub fn cap(entries: &mut Vec<AutoEntry>) {
    let mut counts: Vec<(AutoReason, usize)> = Vec::new();
    let mut keep: Vec<bool> = entries
        .iter()
        .rev()
        .map(|e| {
            let at = counts.iter().position(|(r, _)| *r == e.reason).unwrap_or_else(|| {
                counts.push((e.reason, 0));
                counts.len() - 1
            });
            counts[at].1 += 1;
            counts[at].1 <= MAX_PER_REASON
        })
        .collect();
    keep.reverse();
    let mut flags = keep.into_iter();
    entries.retain(|_| flags.next().unwrap_or(true));
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OnDisk {
    v: u32,
    entries: Vec<AutoEntry>,
}

pub fn path(engine_dir: &Path) -> PathBuf {
    engine_dir.join(FILE)
}

/// The entries, or why the file cannot be believed. A file that is not there
/// holds no entries; that is not a failure.
pub fn load(engine_dir: &Path) -> Result<Vec<AutoEntry>, String> {
    let bytes = match std::fs::read(path(engine_dir)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{FILE}: {e}")),
    };
    let file: OnDisk = serde_json::from_slice(&bytes).map_err(|e| format!("{FILE}: {e}"))?;
    if file.v != VERSION {
        return Err(format!("{FILE}: version {} is not {VERSION}", file.v));
    }
    let mut entries = file.entries;
    cap(&mut entries);
    Ok(entries)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleRecord {
    pinning_rule: u32,
}

/// The newest rule whose drop has run: 0 with no [`RULE_FILE`], or one that cannot
/// be read, so a damaged record runs the drop again, which takes only entries of an
/// older rule.
pub fn rule_applied(engine_dir: &Path) -> u32 {
    let record = std::fs::read(engine_dir.join(RULE_FILE)).ok().and_then(|bytes| serde_json::from_slice::<RuleRecord>(&bytes).ok());
    record.map_or(0, |r| r.pinning_rule)
}

/// Records that the drop for [`PINNING_RULE`] has run.
pub fn record_rule(engine_dir: &Path) -> Result<(), String> {
    let json = serde_json::to_vec(&RuleRecord { pinning_rule: PINNING_RULE }).map_err(|e| format!("{RULE_FILE}: {e}"))?;
    write_atomic(&engine_dir.join(RULE_FILE), &json).map_err(|e| format!("{RULE_FILE}: {e}"))
}

pub fn save(engine_dir: &Path, entries: &[AutoEntry]) -> Result<(), String> {
    let file = OnDisk { v: VERSION, entries: entries.to_vec() };
    let json = serde_json::to_vec_pretty(&file).map_err(|e| format!("{FILE}: {e}"))?;
    write_atomic(&path(engine_dir), &json).map_err(|e| format!("{FILE}: {e}"))
}

type Save = Box<dyn Fn(&[AutoEntry]) -> Result<(), String> + Send + Sync>;

#[derive(Default)]
struct Queue {
    /// The newest state not yet written. A newer one replaces it: that is the batch.
    latest: Option<Vec<AutoEntry>>,
    writing: bool,
    /// Skip the spacing: someone waits in [`Writer::flush`].
    hurry: bool,
    stop: bool,
    failure: Option<String>,
}

struct Shared {
    queue: Mutex<Queue>,
    changed: Condvar,
    save: Save,
    spacing: Duration,
}

impl Shared {
    fn queue(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn run(&self) {
        loop {
            let entries = {
                let mut queue = self.queue();
                loop {
                    if let Some(entries) = queue.latest.take() {
                        queue.writing = true;
                        break entries;
                    }
                    if queue.stop {
                        return;
                    }
                    queue = self.changed.wait(queue).unwrap_or_else(|p| p.into_inner());
                }
            };
            let result = (self.save)(&entries);
            let mut queue = self.queue();
            queue.writing = false;
            queue.failure = result.err();
            self.changed.notify_all();
            let _spaced = self.changed.wait_timeout_while(queue, self.spacing, |q| !q.stop && !q.hurry).unwrap_or_else(|p| p.into_inner());
        }
    }
}

/// Saves the newest state on its own thread, started by the first write, so a
/// slow disk holds up neither a flow nor anyone waiting for the store's lock.
pub struct Writer {
    shared: Arc<Shared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writer").finish_non_exhaustive()
    }
}

impl Writer {
    pub fn new(save: Save, spacing: Duration) -> Self {
        Self { shared: Arc::new(Shared { queue: Mutex::default(), changed: Condvar::new(), save, spacing }), thread: Mutex::new(None) }
    }

    /// For the file in `engine_dir`.
    pub fn for_dir(engine_dir: &Path) -> Self {
        let dir = engine_dir.to_path_buf();
        Self::new(Box::new(move |entries| save(&dir, entries)), WRITE_SPACING)
    }

    /// Returns at once: the state is written soon, unless a newer one comes first.
    pub fn queue(&self, entries: Vec<AutoEntry>) {
        self.shared.queue().latest = Some(entries);
        self.shared.changed.notify_all();
        let mut thread = self.thread.lock().unwrap_or_else(|p| p.into_inner());
        if thread.is_some() {
            return;
        }
        let shared = self.shared.clone();
        match std::thread::Builder::new().name("sieve-exclusions-write".into()).spawn(move || shared.run()) {
            Ok(handle) => *thread = Some(handle),
            Err(e) => {
                let mut queue = self.shared.queue();
                queue.latest = None;
                queue.failure = Some(format!("{FILE}: no writer thread: {e}"));
            }
        }
    }

    /// Waits until everything queued so far has been written or has failed.
    pub fn flush(&self) {
        let mut queue = self.shared.queue();
        queue.hurry = true;
        self.shared.changed.notify_all();
        while queue.latest.is_some() || queue.writing {
            queue = self.shared.changed.wait(queue).unwrap_or_else(|p| p.into_inner());
        }
        queue.hurry = false;
    }

    /// Why the last write failed, until one succeeds.
    pub fn failure(&self) -> Option<String> {
        self.shared.queue().failure.clone()
    }
}

impl Drop for Writer {
    /// Whatever is queued is written first.
    fn drop(&mut self) {
        self.shared.queue().stop = true;
        self.shared.changed.notify_all();
        if let Some(thread) = self.thread.get_mut().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Instant;

    use super::*;

    const NOW: u64 = 1_793_000_000_000;

    fn entries(tag: u64) -> Vec<AutoEntry> {
        vec![AutoEntry::host("a.example", AutoReason::ClientCert, tag, None)]
    }

    #[test]
    fn cap_evicts_the_oldest_of_a_reason_and_leaves_the_others() {
        let mut all: Vec<AutoEntry> = vec![AutoEntry::host("ev.example", AutoReason::Ev, NOW, None)];
        all.extend((0..MAX_PER_REASON + 5).map(|i| AutoEntry::host(&format!("h{i}.example"), AutoReason::ClientCert, NOW, None)));
        cap(&mut all);
        assert_eq!(all.len(), MAX_PER_REASON + 1);
        assert_eq!(all[0].reason, AutoReason::Ev, "another reason's budget is its own");
        assert_eq!(all[1].pattern, Pattern::Exact("h5.example".into()), "the five oldest went");
        assert_eq!(all.last().unwrap().pattern, Pattern::Exact(format!("h{}.example", MAX_PER_REASON + 4)), "the newest stayed");
    }

    #[test]
    fn a_write_in_progress_blocks_nobody_and_what_queues_behind_it_is_one_write() {
        let (started, started_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel::<()>();
        let saved: Arc<Mutex<Vec<u64>>> = Arc::default();
        let record = saved.clone();
        let release_rx = Mutex::new(release_rx);
        let caller = std::thread::current().id();
        let writer = Writer::new(
            Box::new(move |e| {
                assert_ne!(std::thread::current().id(), caller, "off the caller's thread");
                let _ = started.send(());
                let _ = release_rx.lock().unwrap().recv();
                record.lock().unwrap().push(e[0].created_ms);
                Ok(())
            }),
            Duration::ZERO,
        );
        writer.queue(entries(1));
        started_rx.recv().unwrap();
        // The save is stuck, and these return all the same.
        for tag in 2..=5 {
            writer.queue(entries(tag));
        }
        release.send(()).unwrap();
        release.send(()).unwrap();
        writer.flush();
        assert_eq!(*saved.lock().unwrap(), [1, 5], "the newest state, once");
    }

    #[test]
    fn a_burst_writes_at_most_once_per_spacing() {
        const SPACING: Duration = Duration::from_millis(50);
        let saves: Arc<Mutex<usize>> = Arc::default();
        let count = saves.clone();
        let writer = Writer::new(
            Box::new(move |_| {
                *count.lock().unwrap() += 1;
                Ok(())
            }),
            SPACING,
        );
        let began = Instant::now();
        for tag in 0..2000 {
            writer.queue(entries(tag));
            if tag % 100 == 0 {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let elapsed = began.elapsed();
        let during = *saves.lock().unwrap();
        // Bounded by the time that passed, so a paused process cannot fail it.
        let most = elapsed.as_millis() / SPACING.as_millis() + 2;
        assert!(during as u128 <= most, "{during} saves in {elapsed:?}");
        assert!(during >= 1, "the first goes at once, not after the burst");
    }

    #[test]
    fn a_failed_write_is_reported_until_one_succeeds_and_drop_writes_what_is_queued() {
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let saved: Arc<Mutex<Vec<u64>>> = Arc::default();
        let (flag, record) = (fail.clone(), saved.clone());
        let writer = Writer::new(
            Box::new(move |e| {
                if flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err("no disk".into());
                }
                record.lock().unwrap().push(e[0].created_ms);
                Ok(())
            }),
            Duration::from_secs(60),
        );
        writer.queue(entries(1));
        writer.flush();
        assert_eq!(writer.failure().as_deref(), Some("no disk"));
        fail.store(false, std::sync::atomic::Ordering::Relaxed);
        writer.queue(entries(2));
        writer.flush();
        assert_eq!(writer.failure(), None);
        writer.queue(entries(3));
        drop(writer);
        assert_eq!(*saved.lock().unwrap(), [2, 3], "the spacing does not delay a stop");
    }

    #[test]
    fn a_file_over_the_budget_loads_within_it() {
        let dir = tempfile::tempdir().unwrap();
        let all: Vec<AutoEntry> = (0..MAX_PER_REASON + 3).map(|i| AutoEntry::host(&format!("h{i}.example"), AutoReason::ClientCert, NOW, None)).collect();
        save(dir.path(), &all).unwrap();
        assert_eq!(load(dir.path()).unwrap().len(), MAX_PER_REASON);
    }

    /// S39: both ways, so a rollback of the engine reads a new file too. Changed
    /// 2026-11-08: this file's entry was `pinning`, which with no rule is outdated
    /// (the next test); `client-cert` is kept whatever its rule.
    #[test]
    fn a_file_without_the_new_fields_loads() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(path(dir.path()), r#"{"v":1,"entries":[{"pattern":{"Exact":"a.example"},"app":null,"reason":"client-cert","created_ms":5,"expires_ms":null}]}"#).unwrap();
        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded, [AutoEntry { rule: 0, ..AutoEntry::host("a.example", AutoReason::ClientCert, 5, None) }]);
        assert_eq!((loaded[0].retries, loaded[0].retrying), (0, false));
    }

    /// Changed 2026-11-08: the drop of an older rule's entries is the slot's, once
    /// (`exclusions::tests`); load itself drops nothing.
    #[test]
    fn only_pinning_entries_of_an_older_rule_are_outdated_and_load_keeps_them() {
        let dir = tempfile::tempdir().unwrap();
        let old = |host: &str, reason| AutoEntry { rule: PINNING_RULE - 1, ..AutoEntry::for_app(host, "msedge.exe", reason, NOW) };
        let current = AutoEntry::for_app("pinned.example", "client.exe", AutoReason::Pinning, NOW);
        let all = [old("search.example", AutoReason::Pinning), old("cert.example", AutoReason::ClientCert), old("ev.example", AutoReason::Ev), current.clone()];
        assert_eq!(all.iter().map(AutoEntry::outdated).collect::<Vec<_>>(), [true, false, false, false]);
        save(dir.path(), &all).unwrap();
        assert_eq!(load(dir.path()).unwrap(), all);
        assert_eq!(current.rule, PINNING_RULE, "a new entry records the rule");
    }

    #[test]
    fn the_rule_record_reads_back_and_a_missing_or_damaged_one_is_no_record() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(rule_applied(dir.path()), 0, "none");
        record_rule(dir.path()).unwrap();
        assert_eq!(rule_applied(dir.path()), PINNING_RULE);
        for damaged in ["", "not json", r#"{"pinning_rule":1,"x":2}"#, r#"{"pinning_rule":"1"}"#] {
            std::fs::write(dir.path().join(RULE_FILE), damaged).unwrap();
            assert_eq!(rule_applied(dir.path()), 0, "{damaged}");
        }
    }

    #[test]
    fn a_file_with_them_loads_in_the_old_shape() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct OldEntry {
            pattern: Pattern,
            app: Option<String>,
            reason: AutoReason,
            created_ms: u64,
            expires_ms: Option<u64>,
        }
        #[derive(Deserialize)]
        #[allow(dead_code)]
        #[serde(deny_unknown_fields)]
        struct OldFile {
            v: u32,
            entries: Vec<OldEntry>,
        }
        let dir = tempfile::tempdir().unwrap();
        let entry = AutoEntry { retries: 3, retrying: true, ..AutoEntry::for_app("a.example", r"C:\x\Client.exe", AutoReason::Pinning, 5) };
        save(dir.path(), &[entry]).unwrap();
        let old: OldFile = serde_json::from_slice(&std::fs::read(path(dir.path())).unwrap()).unwrap();
        assert_eq!(old.entries.len(), 1);
    }

    #[test]
    fn for_app_names_the_file_in_lower_case() {
        let e = AutoEntry::for_app("A.Example", r"C:\Apps\Client.EXE", AutoReason::Pinning, NOW);
        assert_eq!((e.pattern, e.app.as_deref()), (Pattern::Exact("a.example".into()), Some("client.exe")));
    }
}
