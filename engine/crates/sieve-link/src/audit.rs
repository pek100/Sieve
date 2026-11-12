//! The hub's audit log: one JSON object per line. Who (device fingerprint and
//! name), when, where to, bytes each way, outcome. Never payload, never key
//! material.
//!
//! Bounded on disk:
//!
//! - Unauthenticated refusals (failed handshakes, refused pairings) are
//!   coalesced per source address and event: the first in a minute is
//!   written, the rest are counted and written as one summary row.
//! - Denials of a paired device's requests are rate-limited per device
//!   (`AuditConfig::denials_per_minute`); suppressed ones are counted and the
//!   count is written with the next row that gets through, or by `flush`.
//! - The file is rotated at `max_bytes`: `audit.log` becomes `audit.log.1`,
//!   and so on up to `keep` old files; the oldest is deleted.
//!
//! A write that fails marks the log unhealthy (and says so on stderr); the
//! hub then opens no new streams until a write succeeds again (`check`):
//! nothing is relayed without a record.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::rules::Bucket;

#[derive(Debug, Default, Serialize)]
pub struct AuditRow {
    pub ts_ms: u64,
    pub event: &'static str,
    /// Correlates a `stream_open` row with its closing `stream` row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The link's remote socket address (the device's public address).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// `host:port` as the device asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The address the hub connected to (or the one it refused).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    /// Bytes device -> target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up: Option<u64>,
    /// Bytes target -> device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub down: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ms: Option<u64>,
    /// How many like events this summary row stands for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    /// Denials of this device not written since its last written row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<u64>,
    pub outcome: String,
}

#[derive(Clone, Copy, Debug)]
pub struct AuditConfig {
    /// Rotate when the file would grow past this.
    pub max_bytes: u64,
    /// Old files kept (`audit.log.1` .. `audit.log.N`).
    pub keep: u32,
    /// Denial rows written per device per minute (burst the same).
    pub denials_per_minute: u32,
    /// Unauthenticated refusals: one row per source and event per this window.
    pub refusal_window: Duration,
    /// Most sources tracked at once; beyond, refusals share one counter.
    pub max_sources: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            max_bytes: 10 * 1024 * 1024,
            keep: 5,
            denials_per_minute: 60,
            refusal_window: Duration::from_secs(60),
            max_sources: 4096,
        }
    }
}

struct Coalesce {
    since: Instant,
    more: u64,
}

struct DenialGate {
    bucket: Bucket,
    suppressed: u64,
}

struct State {
    file: Option<File>,
    size: u64,
    refusals: HashMap<(IpAddr, &'static str), Coalesce>,
    denials: HashMap<String, DenialGate>,
}

pub struct Audit {
    path: PathBuf,
    cfg: AuditConfig,
    state: Mutex<State>,
    healthy: AtomicBool,
    /// Test hook: every write fails while set.
    fault: AtomicBool,
}

impl std::fmt::Debug for Audit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Audit").field("path", &self.path).field("healthy", &self.healthy()).finish_non_exhaustive()
    }
}

fn open_append(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

fn rotated(path: &Path, i: u32) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{i}"));
    PathBuf::from(s)
}

impl Audit {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Self::open_with(path, AuditConfig::default())
    }

    pub fn open_with(path: &Path, cfg: AuditConfig) -> std::io::Result<Self> {
        let file = open_append(path)?;
        let size = file.metadata()?.len();
        Ok(Audit {
            path: path.to_path_buf(),
            cfg: AuditConfig { keep: cfg.keep.max(1), max_bytes: cfg.max_bytes.max(4096), ..cfg },
            state: Mutex::new(State { file: Some(file), size, refusals: HashMap::new(), denials: HashMap::new() }),
            healthy: AtomicBool::new(true),
            fault: AtomicBool::new(false),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the last write succeeded.
    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }

    #[doc(hidden)]
    pub fn set_fault(&self, on: bool) {
        self.fault.store(on, Ordering::SeqCst);
    }

    /// Writes one row. Returns whether it is on disk (in the OS's hands).
    pub fn record(&self, row: AuditRow) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.write_locked(&mut st, row)
    }

    /// `true` when the log can be written. While unhealthy, tries a write of
    /// an `audit_resumed` row, which is true if it lands.
    pub fn check(&self) -> bool {
        if self.healthy() {
            return true;
        }
        self.record(AuditRow { event: "audit_resumed", outcome: "the audit log can be written again".into(), ..Default::default() })
    }

    fn write_locked(&self, st: &mut State, mut row: AuditRow) -> bool {
        if row.ts_ms == 0 {
            row.ts_ms = crate::now_ms();
        }
        let Ok(mut line) = serde_json::to_vec(&row) else { return false };
        line.push(b'\n');
        let r = self.append(st, &line);
        let was = self.healthy.swap(r.is_ok(), Ordering::SeqCst);
        match (&r, was) {
            (Err(e), true) => eprintln!(
                "sieve-hub: AUDIT LOG WRITE FAILED ({}: {e}); new streams are refused until it can be written",
                self.path.display()
            ),
            (Ok(()), false) => eprintln!("sieve-hub: the audit log can be written again; new streams are allowed"),
            _ => {}
        }
        r.is_ok()
    }

    fn append(&self, st: &mut State, line: &[u8]) -> std::io::Result<()> {
        if self.fault.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("injected fault"));
        }
        if st.size > 0 && st.size + line.len() as u64 > self.cfg.max_bytes {
            self.rotate(st)?;
        }
        if st.file.is_none() {
            let f = open_append(&self.path)?;
            st.size = f.metadata()?.len();
            st.file = Some(f);
        }
        let f = st.file.as_mut().expect("opened above");
        // One write per row so rows never interleave.
        f.write_all(line)?;
        st.size += line.len() as u64;
        Ok(())
    }

    fn rotate(&self, st: &mut State) -> std::io::Result<()> {
        st.file = None;
        let oldest = rotated(&self.path, self.cfg.keep);
        if oldest.exists() {
            std::fs::remove_file(&oldest)?;
        }
        for i in (1..self.cfg.keep).rev() {
            let from = rotated(&self.path, i);
            if from.exists() {
                std::fs::rename(&from, rotated(&self.path, i + 1))?;
            }
        }
        std::fs::rename(&self.path, rotated(&self.path, 1))?;
        let f = open_append(&self.path)?;
        st.size = 0;
        st.file = Some(f);
        Ok(())
    }

    /// An unauthenticated refusal from `ip`: written once per source and
    /// event per window, the rest counted into one summary row.
    pub fn refusal(&self, event: &'static str, ip: IpAddr, outcome: String) {
        self.refusal_at(event, ip, outcome, Instant::now());
    }

    pub(crate) fn refusal_at(&self, event: &'static str, ip: IpAddr, outcome: String, now: Instant) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut key = (ip, event);
        if !st.refusals.contains_key(&key) && st.refusals.len() >= self.cfg.max_sources {
            // Too many sources at once: they share one counter.
            key = (IpAddr::from([0u8, 0, 0, 0]), event);
        }
        let window = self.cfg.refusal_window;
        let summary = match st.refusals.get_mut(&key) {
            Some(c) if now.saturating_duration_since(c.since) < window => {
                c.more += 1;
                return;
            }
            Some(c) => {
                let more = c.more;
                c.since = now;
                c.more = 0;
                (more > 0).then_some(more)
            }
            None => {
                st.refusals.insert(key, Coalesce { since: now, more: 0 });
                None
            }
        };
        if let Some(more) = summary {
            self.write_locked(&mut st, summary_row(key, more));
        }
        let peer = if key.0.is_unspecified() { "(many sources)".to_string() } else { ip.to_string() };
        self.write_locked(&mut st, AuditRow { event, peer: Some(peer), outcome, ..Default::default() });
    }

    /// A denial of a paired device's request: rate-limited per device.
    pub fn denial(&self, row: AuditRow) {
        self.denial_at(row, Instant::now());
    }

    pub(crate) fn denial_at(&self, mut row: AuditRow, now: Instant) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let per_min = self.cfg.denials_per_minute.max(1) as f64;
        let dev = row.device.clone().unwrap_or_default();
        let gate = st.denials.entry(dev).or_insert_with(|| DenialGate { bucket: Bucket::new_at(per_min, per_min / 60.0, now), suppressed: 0 });
        if !gate.bucket.take(1.0, now) {
            gate.suppressed += 1;
            return;
        }
        if gate.suppressed > 0 {
            row.suppressed = Some(gate.suppressed);
            gate.suppressed = 0;
        }
        self.write_locked(&mut st, row);
    }

    /// Writes the pending summaries: refusal counts whose window has ended,
    /// and suppressed-denial counts. The hub calls this periodically.
    pub fn flush(&self) {
        self.flush_at(Instant::now());
    }

    pub(crate) fn flush_at(&self, now: Instant) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let window = self.cfg.refusal_window;
        let mut rows = Vec::new();
        st.refusals.retain(|key, c| {
            if now.saturating_duration_since(c.since) < window {
                return true;
            }
            if c.more > 0 {
                rows.push(summary_row(*key, c.more));
            }
            false
        });
        for (dev, g) in st.denials.iter_mut() {
            if g.suppressed > 0 {
                rows.push(AuditRow {
                    event: "denials_suppressed",
                    device: Some(dev.clone()),
                    count: Some(g.suppressed),
                    outcome: format!("{} denials of this device were not written one by one", g.suppressed),
                    ..Default::default()
                });
                g.suppressed = 0;
            }
        }
        // Forget devices whose bucket is full again (idle).
        st.denials.retain(|_, g| !g.bucket.is_full(now));
        for r in rows {
            self.write_locked(&mut st, r);
        }
    }
}

fn summary_row(key: (IpAddr, &'static str), more: u64) -> AuditRow {
    let peer = if key.0.is_unspecified() { "(many sources)".to_string() } else { key.0.to_string() };
    AuditRow {
        event: key.1,
        peer: Some(peer),
        count: Some(more),
        outcome: format!("{more} more like this from this source in the last window, not written one by one"),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path).unwrap_or_default().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    #[test]
    fn refusals_from_one_source_are_coalesced() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("audit.log");
        let a = Audit::open(&p).unwrap();
        let t0 = Instant::now();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let other: IpAddr = "198.51.100.1".parse().unwrap();
        for i in 0..1000 {
            a.refusal_at("handshake_refused", ip, "tls".into(), t0 + Duration::from_millis(i));
        }
        a.refusal_at("handshake_refused", other, "tls".into(), t0);
        assert_eq!(rows(&p).len(), 2, "one row per source in the window");
        a.flush_at(t0 + Duration::from_secs(61));
        let r = rows(&p);
        assert_eq!(r.len(), 3);
        assert_eq!(r[2]["count"], 999);
        assert_eq!(r[2]["peer"], "203.0.113.5");
        // A new window starts with a written row again.
        a.refusal_at("handshake_refused", ip, "tls".into(), t0 + Duration::from_secs(62));
        assert_eq!(rows(&p).len(), 4);
    }

    #[test]
    fn many_sources_share_one_counter() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("audit.log");
        let a = Audit::open_with(&p, AuditConfig { max_sources: 10, ..Default::default() }).unwrap();
        let t0 = Instant::now();
        for i in 0..10_000u32 {
            let ip = IpAddr::from((0x0a00_0000u32 + i).to_be_bytes());
            a.refusal_at("handshake_refused", ip, "tls".into(), t0);
        }
        // 10 tracked sources + 1 shared row.
        assert_eq!(rows(&p).len(), 11);
    }

    #[test]
    fn denials_are_rate_limited_per_device_and_counted() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("audit.log");
        let a = Audit::open_with(&p, AuditConfig { denials_per_minute: 5, ..Default::default() }).unwrap();
        let t0 = Instant::now();
        let row = |d: &str| AuditRow { event: "denied", device: Some(d.into()), outcome: "x".into(), ..Default::default() };
        for _ in 0..100 {
            a.denial_at(row("aaaa"), t0);
        }
        a.denial_at(row("bbbb"), t0);
        assert_eq!(rows(&p).len(), 6, "5 for aaaa, 1 for bbbb");
        // The next row that gets through carries the count.
        a.denial_at(row("aaaa"), t0 + Duration::from_secs(13));
        let r = rows(&p);
        assert_eq!(r[6]["suppressed"], 95);
        for _ in 0..10 {
            a.denial_at(row("aaaa"), t0 + Duration::from_secs(13));
        }
        a.flush_at(t0 + Duration::from_secs(14));
        let r = rows(&p);
        assert_eq!(r.last().unwrap()["event"], "denials_suppressed");
        assert_eq!(r.last().unwrap()["count"], 10);
    }

    #[test]
    fn the_log_rotates_and_keeps_n_files() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("audit.log");
        let a = Audit::open_with(&p, AuditConfig { max_bytes: 4096, keep: 3, ..Default::default() }).unwrap();
        for i in 0..2000 {
            assert!(a.record(AuditRow { event: "stream", outcome: format!("row {i}"), ..Default::default() }));
        }
        let mut names: Vec<String> = std::fs::read_dir(t.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names, ["audit.log", "audit.log.1", "audit.log.2", "audit.log.3"]);
        for n in &names {
            assert!(std::fs::metadata(t.path().join(n)).unwrap().len() <= 4096, "{n}");
        }
        // The newest row is in the live file.
        assert_eq!(rows(&p).last().unwrap()["outcome"], "row 1999");
    }

    #[test]
    fn a_failed_write_marks_the_log_unhealthy_until_one_succeeds() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("audit.log");
        let a = Audit::open(&p).unwrap();
        assert!(a.check());
        a.set_fault(true);
        assert!(!a.record(AuditRow { event: "x", ..Default::default() }));
        assert!(!a.healthy());
        assert!(!a.check());
        a.set_fault(false);
        assert!(a.check());
        assert!(a.healthy());
        assert_eq!(rows(&p).last().unwrap()["event"], "audit_resumed");
    }
}
