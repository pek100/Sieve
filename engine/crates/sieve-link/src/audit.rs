//! The hub's audit log: one JSON object per line. Who (device fingerprint and
//! name), when, where to, bytes each way, outcome. Never payload, never key
//! material.
//!
//! Bounded on disk, and not something the parties it records can flush:
//!
//! - Unauthenticated refusals (failed handshakes, refused pairings) are
//!   coalesced per source (an IPv4 address or an IPv6 /64, as the admission
//!   gate counts them) and event: the first in a window is written, the rest
//!   are counted into one summary row. On top, all sources together write at
//!   most `refusals_per_minute` refusal rows; the rest are counted and the
//!   count is written by `flush`.
//! - Denials of a paired device's requests are rate-limited per device
//!   (`denials_per_minute`); suppressed ones are counted and the count is
//!   written with the next row that gets through, or by `flush`.
//! - The live file is rotated at `max_bytes`: it is RENAMED aside first
//!   (`audit.log.N`, a higher N is newer), and only once that worked are old
//!   files beyond `keep` deleted, oldest first. A rename that fails (on
//!   Windows: another program holds `audit.log` open without delete sharing)
//!   deletes nothing: rows keep going to the live file, the rotation is
//!   retried every `rotate_retry`, and only a live file twice `max_bytes`
//!   long stops writes (and with them new streams).
//! - Retention has a floor: a file whose newest row is younger than
//!   `min_retention` (30 days by default) is never deleted to make room. If
//!   the size cap would need that, the hub opens no new streams
//!   (`retention_problem`) and says why, until the owner raises the cap,
//!   lowers the floor or moves old files away, or the rows age past it.
//! - So that one paired device cannot bring that about for everyone by
//!   writing rows fast (streams, denials, relinks), each device's rows are
//!   charged to its own share of the log (`device_budget`: half the rate the
//!   cap and the floor allow together). A device past its share has its new
//!   streams refused and its link and learned-address rows counted instead
//!   of written, until the share refills; other devices are not affected.
//!   Several hostile devices together can still fill the cap: pair only
//!   trusted devices, and revoke one that does this.
//!
//! The default cap is 256 MiB (8 files of 32 MiB). A relayed stream writes
//! two rows (`stream_open`, `stream`), 590 bytes together with IPv6
//! addresses and long names (see the test
//! `the_default_cap_holds_30_days_of_ordinary_use`; IPv4 and short names
//! make it about 470), so the cap holds 30 days of about 15,000 streams a
//! day: above one device in ordinary use (a few thousand a day; a busy
//! browsing day under ten thousand).
//!
//! A write that fails marks the log unhealthy (and says so on stderr); the
//! hub then opens no new streams until a write succeeds again (`check`):
//! nothing is relayed without a record.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
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

/// The default size cap, all files together.
pub const DEFAULT_CAP_MIB: u64 = 256;
/// The default retention floor.
pub const DEFAULT_MIN_DAYS: u32 = 30;
/// Files the cap is split into (the live one and `FILES - 1` rotated ones).
const FILES: u64 = 8;
const MIB: u64 = 1024 * 1024;
const DAY: Duration = Duration::from_secs(86_400);

#[derive(Clone, Copy, Debug)]
pub struct AuditConfig {
    /// Rotate when the live file would grow past this.
    pub max_bytes: u64,
    /// Rotated files kept beyond the live one (`(keep + 1) * max_bytes` in all).
    pub keep: u32,
    /// Rows younger than this are never deleted to make room.
    pub min_retention: Duration,
    /// Denial rows written per device per minute (burst the same).
    pub denials_per_minute: u32,
    /// Unauthenticated refusals: one row per source and event per this window.
    pub refusal_window: Duration,
    /// Most sources tracked at once; beyond, refusals share one counter.
    pub max_sources: usize,
    /// Unauthenticated refusal rows per minute, all sources together.
    pub refusals_per_minute: u32,
    /// After a rotation failed, how long before it is tried again.
    pub rotate_retry: Duration,
}

impl AuditConfig {
    /// A size cap (all files together) and a retention floor in days.
    pub fn with_retention(cap_mib: u64, min_days: u32) -> Self {
        let cap = cap_mib.max(1) * MIB;
        AuditConfig { max_bytes: (cap / FILES).max(4096), keep: (FILES - 1) as u32, min_retention: DAY * min_days, ..Default::default() }
    }

    /// The size cap, all files together.
    pub fn cap_bytes(&self) -> u64 {
        self.max_bytes * (self.keep as u64 + 1)
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            max_bytes: DEFAULT_CAP_MIB * MIB / FILES,
            keep: (FILES - 1) as u32,
            min_retention: DAY * DEFAULT_MIN_DAYS,
            denials_per_minute: 60,
            refusal_window: Duration::from_secs(60),
            max_sources: 4096,
            refusals_per_minute: 120,
            rotate_retry: Duration::from_secs(10),
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

/// One device's share of the log (see `Audit::device_budget`).
struct Share {
    bucket: Bucket,
    /// Rows of this device not written because its share was used up.
    suppressed: u64,
}

struct State {
    file: Option<File>,
    size: u64,
    refusals: HashMap<(IpAddr, &'static str), Coalesce>,
    denials: HashMap<String, DenialGate>,
    shares: HashMap<String, Share>,
    /// All sources' refusal rows together.
    refusal_rate: Bucket,
    /// Refusals neither written nor counted in a per-source summary.
    refusals_dropped: u64,
    /// After a failed rotation: not before this.
    rotate_after: Option<Instant>,
}

pub struct Audit {
    path: PathBuf,
    cfg: AuditConfig,
    state: Mutex<State>,
    healthy: AtomicBool,
    /// Why new streams must wait for the retention floor, if they must.
    blocked: Mutex<Option<String>>,
    /// Test hook: every write fails while set.
    fault: AtomicBool,
    /// Test hook: every rotation's rename fails while set.
    rename_fault: AtomicBool,
}

impl std::fmt::Debug for Audit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Audit").field("path", &self.path).field("healthy", &self.healthy()).finish_non_exhaustive()
    }
}

/// Opens for appending. On Windows the handle shares read, write AND delete,
/// so this process never stands in the way of a rename of the file.
fn open_append(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        o.share_mode(0x1 | 0x2 | 0x4);
    }
    o.open(path)
}

fn rotated(path: &Path, i: u64) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{i}"));
    PathBuf::from(s)
}

/// The rotated files next to `path` (`<name>.<N>`), oldest (lowest N) first.
fn rotated_files(path: &Path) -> std::io::Result<Vec<(u64, PathBuf)>> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let base = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        if let Some(n) = name.strip_prefix(&base).and_then(|r| r.strip_prefix('.')).filter(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit())).and_then(|r| r.parse().ok()) {
            out.push((n, e.path()));
        }
    }
    out.sort();
    Ok(out)
}

/// The time of the newest row in `p`: the last line's `ts_ms`, else the
/// file's modification time, else now (so an unreadable file counts as young
/// and is kept).
fn newest_row_ms(p: &Path) -> u64 {
    let tail = (|| -> std::io::Result<Vec<u8>> {
        let mut f = File::open(p)?;
        let len = f.metadata()?.len();
        f.seek(SeekFrom::Start(len.saturating_sub(64 * 1024)))?;
        let mut b = Vec::new();
        f.read_to_end(&mut b)?;
        Ok(b)
    })();
    if let Ok(b) = tail {
        for line in b.split(|c| *c == b'\n').rev() {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(line)
                && let Some(ts) = v.get("ts_ms").and_then(|t| t.as_u64())
            {
                return ts;
            }
        }
    }
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or_else(crate::now_ms)
}

/// How a refusal's source is keyed and shown: an IPv4 address, an IPv6 /64.
fn source_shown(key: IpAddr) -> String {
    match key {
        IpAddr::V4(v4) if v4.is_unspecified() => "(many sources)".to_string(),
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("{v6}/64"),
    }
}

impl Audit {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Self::open_with(path, AuditConfig::default())
    }

    pub fn open_with(path: &Path, cfg: AuditConfig) -> std::io::Result<Self> {
        let file = open_append(path)?;
        let size = file.metadata()?.len();
        let per_min = cfg.refusals_per_minute.max(1) as f64;
        let a = Audit {
            path: path.to_path_buf(),
            cfg: AuditConfig { keep: cfg.keep.max(1), max_bytes: cfg.max_bytes.max(4096), ..cfg },
            state: Mutex::new(State {
                file: Some(file),
                size,
                refusals: HashMap::new(),
                denials: HashMap::new(),
                shares: HashMap::new(),
                refusal_rate: Bucket::new(per_min, per_min / 60.0),
                refusals_dropped: 0,
                rotate_after: None,
            }),
            healthy: AtomicBool::new(true),
            blocked: Mutex::new(None),
            fault: AtomicBool::new(false),
            rename_fault: AtomicBool::new(false),
        };
        a.prune();
        Ok(a)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn config(&self) -> AuditConfig {
        self.cfg
    }

    /// Whether the last write succeeded.
    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }

    #[doc(hidden)]
    pub fn set_fault(&self, on: bool) {
        self.fault.store(on, Ordering::SeqCst);
    }

    #[doc(hidden)]
    pub fn set_rename_fault(&self, on: bool) {
        self.rename_fault.store(on, Ordering::SeqCst);
    }

    /// Why the retention floor stops new streams, if it does.
    pub fn retention_problem(&self) -> Option<String> {
        self.blocked.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Looks again whether old files may go (rows aged past the floor, or the
    /// owner moved files away). The hub calls this with every `flush`.
    pub fn check_retention(&self) {
        let _st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.prune();
    }

    /// Writes one row. Returns whether it is on disk (in the OS's hands).
    /// A device's row is charged to that device's share, and always written
    /// (a stream's rows must be there, whatever the share).
    pub fn record(&self, row: AuditRow) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.write_locked(&mut st, row)
    }

    /// One device's share of the log, as a rate in bytes per second and a
    /// burst in bytes, or `None` when there is no retention floor (old rows
    /// then make room freely and no device can stop the hub).
    ///
    /// With a floor, rows written faster than `cap / floor` fill the cap with
    /// rows the floor forbids deleting, and the hub then opens no streams for
    /// ANY device. So no one device may write faster than half that rate (a
    /// day's worth of the whole rate as a burst, never more than a quarter of
    /// the cap): a device that tries uses up its own share, and only its new
    /// streams are refused (and its other rows counted instead of written)
    /// until the share refills. With the defaults: about 4.5 MB a day (some
    /// 7,500 streams), bursts up to 9 MB.
    pub fn device_budget(&self) -> Option<(f64, f64)> {
        let floor = self.cfg.min_retention.as_secs_f64();
        if floor <= 0.0 {
            return None;
        }
        let cap = self.cfg.cap_bytes() as f64;
        let whole = cap / floor;
        Some((whole / 2.0, (whole * DAY.as_secs_f64()).min(cap / 4.0)))
    }

    /// Whether `device` has used up its share of the log (its new streams
    /// are then refused).
    pub fn over_budget(&self, device: &str) -> bool {
        self.over_budget_at(device, Instant::now())
    }

    pub(crate) fn over_budget_at(&self, device: &str, now: Instant) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.shares.get_mut(device).is_some_and(|s| s.bucket.level(now) <= 0.0)
    }

    /// A device's row that may be counted instead of written when the
    /// device's share is used up (link up and down, learned addresses).
    /// Returns whether it was written.
    pub fn device_row(&self, row: AuditRow) -> bool {
        self.device_row_at(row, Instant::now())
    }

    pub(crate) fn device_row_at(&self, row: AuditRow, now: Instant) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(dev) = &row.device
            && let Some(s) = st.shares.get_mut(dev)
            && s.bucket.level(now) <= 0.0
        {
            s.suppressed += 1;
            return false;
        }
        self.write_locked_at(&mut st, row, now)
    }

    /// Charges `bytes` to `device`'s share.
    fn charge(&self, st: &mut State, device: &str, bytes: u64, now: Instant) {
        let Some((rate, burst)) = self.device_budget() else { return };
        let s = match st.shares.get_mut(device) {
            Some(s) => s,
            None => st.shares.entry(device.to_string()).or_insert(Share { bucket: Bucket::new_at(burst, rate, now), suppressed: 0 }),
        };
        // Always taken (a debt is paid back by time).
        let _ = s.bucket.debit(bytes as f64, now);
    }

    /// `true` when the log can be written. While unhealthy, tries a write of
    /// an `audit_resumed` row, which is true if it lands.
    pub fn check(&self) -> bool {
        if self.healthy() {
            return true;
        }
        self.record(AuditRow { event: "audit_resumed", outcome: "the audit log can be written again".into(), ..Default::default() })
    }

    fn write_locked(&self, st: &mut State, row: AuditRow) -> bool {
        self.write_locked_at(st, row, Instant::now())
    }

    fn write_locked_at(&self, st: &mut State, mut row: AuditRow, now: Instant) -> bool {
        if row.ts_ms == 0 {
            row.ts_ms = crate::now_ms();
        }
        let Ok(mut line) = serde_json::to_vec(&row) else { return false };
        line.push(b'\n');
        if let Some(dev) = &row.device {
            self.charge(st, dev, line.len() as u64, now);
        }
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
        let len = line.len() as u64;
        let due = st.rotate_after.is_none_or(|t| Instant::now() >= t);
        if st.size > 0 && st.size + len > self.cfg.max_bytes && due {
            match self.rotate(st) {
                Ok(()) => {
                    if st.rotate_after.take().is_some() {
                        eprintln!("sieve-hub: the audit log rotated again");
                    }
                }
                Err(e) => {
                    if st.rotate_after.is_none() {
                        eprintln!(
                            "sieve-hub: cannot rotate the audit log ({}: {e}); nothing was deleted, rows go on into the live file, \
                             retrying every {} s (is another program holding it open?)",
                            self.path.display(),
                            self.cfg.rotate_retry.as_secs()
                        );
                    }
                    st.rotate_after = Some(Instant::now() + self.cfg.rotate_retry);
                }
            }
        }
        if st.size + len > 2 * self.cfg.max_bytes {
            return Err(std::io::Error::other("the live audit log cannot be rotated and has reached twice its size limit"));
        }
        if st.file.is_none() {
            let f = open_append(&self.path)?;
            st.size = f.metadata()?.len();
            st.file = Some(f);
        }
        let f = st.file.as_mut().expect("opened above");
        // One write per row so rows never interleave.
        f.write_all(line)?;
        st.size += len;
        Ok(())
    }

    /// Renames the live file aside, then (and only then) deletes what the
    /// cap and the floor allow. A failed rename changes nothing on disk.
    fn rotate(&self, st: &mut State) -> std::io::Result<()> {
        st.file = None;
        if self.rename_fault.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("injected rename fault"));
        }
        let next = rotated_files(&self.path)?.last().map_or(1, |(n, _)| n + 1);
        std::fs::rename(&self.path, rotated(&self.path, next))?;
        st.size = 0;
        st.file = Some(open_append(&self.path)?);
        self.prune();
        Ok(())
    }

    /// Deletes rotated files beyond `keep`, oldest first, while their newest
    /// row is older than the floor; records why it stopped if it had to.
    fn prune(&self) {
        let files = match rotated_files(&self.path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("sieve-hub: cannot list the old audit files ({e}); none deleted");
                return;
            }
        };
        let excess = files.len().saturating_sub(self.cfg.keep as usize);
        let mut why = None;
        for (_, p) in files.iter().take(excess) {
            let age = Duration::from_millis(crate::now_ms().saturating_sub(newest_row_ms(p)));
            if age < self.cfg.min_retention {
                why = Some(format!(
                    "the audit log is at its size cap ({} MiB) and making room would delete rows from {:.1} days ago, younger than \
                     the {}-day retention floor; new streams are refused until the owner raises the cap or lowers the floor \
                     (`sieve-hub audit`), or moves old audit.log.N files out of the hub directory",
                    self.cfg.cap_bytes() / MIB,
                    age.as_secs_f64() / 86_400.0,
                    self.cfg.min_retention.as_secs() / 86_400
                ));
                break;
            }
            if let Err(e) = std::fs::remove_file(p) {
                eprintln!("sieve-hub: cannot delete the old audit file {} ({e}); kept", p.display());
                break;
            }
        }
        let mut b = self.blocked.lock().unwrap_or_else(|e| e.into_inner());
        match (&*b, &why) {
            (None, Some(w)) => eprintln!("sieve-hub: AUDIT RETENTION: {w}"),
            (Some(_), None) => eprintln!("sieve-hub: the audit log has room again within its retention floor; new streams are allowed"),
            _ => {}
        }
        *b = why;
    }

    /// An unauthenticated refusal from `ip`: written once per source and
    /// event per window, the rest counted into one summary row.
    pub fn refusal(&self, event: &'static str, ip: IpAddr, outcome: String) {
        self.refusal_at(event, ip, outcome, Instant::now());
    }

    pub(crate) fn refusal_at(&self, event: &'static str, ip: IpAddr, outcome: String, now: Instant) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut key = (crate::gate::source_key(ip), event);
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
            self.refusal_row(&mut st, summary_row(key, more), more, now);
        }
        let row = AuditRow { event, peer: Some(source_shown(key.0)), outcome, ..Default::default() };
        self.refusal_row(&mut st, row, 1, now);
    }

    /// Writes a refusal row if the overall refusal rate allows; otherwise
    /// counts the `stands_for` refusals it stood for.
    fn refusal_row(&self, st: &mut State, row: AuditRow, stands_for: u64, now: Instant) {
        if st.refusal_rate.take(1.0, now) {
            self.write_locked(st, row);
        } else {
            st.refusals_dropped += stands_for;
        }
    }

    /// A denial of a paired device's request: rate-limited per device.
    pub fn denial(&self, row: AuditRow) {
        self.denial_at(row, Instant::now());
    }

    pub(crate) fn denial_at(&self, mut row: AuditRow, now: Instant) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let st = &mut *guard;
        let per_min = self.cfg.denials_per_minute.max(1) as f64;
        let dev = row.device.clone().unwrap_or_default();
        let spent = st.shares.get_mut(&dev).is_some_and(|s| s.bucket.level(now) <= 0.0);
        let gate = st.denials.entry(dev).or_insert_with(|| DenialGate { bucket: Bucket::new_at(per_min, per_min / 60.0, now), suppressed: 0 });
        // Over the per-minute rate, or the device's share of the log is used up.
        if spent || !gate.bucket.take(1.0, now) {
            gate.suppressed += 1;
            return;
        }
        if gate.suppressed > 0 {
            row.suppressed = Some(gate.suppressed);
            gate.suppressed = 0;
        }
        self.write_locked_at(st, row, now);
    }

    /// Writes the pending summaries: refusal counts whose window has ended,
    /// refusals over the overall rate, and suppressed-denial counts; and looks
    /// at retention again. The hub calls this periodically.
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
        if st.refusals_dropped > 0 {
            let n = std::mem::take(&mut st.refusals_dropped);
            rows.push(AuditRow {
                event: "refusals_suppressed",
                count: Some(n),
                outcome: format!("{n} unauthenticated refusals over the overall rate were not written one by one"),
                ..Default::default()
            });
        }
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
        for (dev, s) in st.shares.iter_mut() {
            if s.suppressed > 0 {
                rows.push(AuditRow {
                    event: "device_rows_suppressed",
                    device: Some(dev.clone()),
                    count: Some(s.suppressed),
                    outcome: format!(
                        "{} rows of this device were not written one by one: it used up its share of the audit log (its new streams are refused until the share refills)",
                        s.suppressed
                    ),
                    ..Default::default()
                });
                s.suppressed = 0;
            }
        }
        // Forget devices whose bucket is full again (idle).
        st.denials.retain(|_, g| !g.bucket.is_full(now));
        st.shares.retain(|_, s| !s.bucket.is_full(now));
        for r in rows {
            self.write_locked_at(&mut st, r, now);
        }
        self.prune();
    }
}

fn summary_row(key: (IpAddr, &'static str), more: u64) -> AuditRow {
    AuditRow {
        event: key.1,
        peer: Some(source_shown(key.0)),
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

    fn names(dir: &Path) -> Vec<String> {
        let mut n: Vec<String> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        n.sort();
        n
    }

    /// No floor: the size cap alone decides (unit tests of rotation).
    fn no_floor(max_bytes: u64, keep: u32) -> AuditConfig {
        AuditConfig { max_bytes, keep, min_retention: Duration::ZERO, rotate_retry: Duration::ZERO, ..Default::default() }
    }

    fn row(i: usize) -> AuditRow {
        AuditRow { event: "stream", outcome: format!("row {i}"), ..Default::default() }
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
    fn refusals_are_keyed_by_ipv6_slash_64() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("audit.log");
        let a = Audit::open(&p).unwrap();
        let t0 = Instant::now();
        // Every address of one /64 is one source (as the admission gate sees it).
        for i in 1..=500u16 {
            let ip = IpAddr::from([0x2a01, 0x4f8, 1, 2, 0, 0, 0xdead, i]);
            a.refusal_at("handshake_refused", ip, "tls".into(), t0);
        }
        let r = rows(&p);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0]["peer"], "2a01:4f8:1:2::/64");
        a.flush_at(t0 + Duration::from_secs(61));
        assert_eq!(rows(&p)[1]["count"], 499);
    }

    #[test]
    fn refusal_rows_have_an_overall_rate() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("audit.log");
        let a = Audit::open_with(&p, AuditConfig { refusals_per_minute: 5, ..Default::default() }).unwrap();
        let t0 = Instant::now();
        // 100 different sources, one refusal each: 5 written, 95 counted.
        for i in 0..100u32 {
            a.refusal_at("handshake_refused", IpAddr::from((0x0a00_0000u32 + i).to_be_bytes()), "tls".into(), t0);
        }
        assert_eq!(rows(&p).len(), 5);
        a.flush_at(t0 + Duration::from_secs(1));
        let r = rows(&p);
        assert_eq!(r.last().unwrap()["event"], "refusals_suppressed");
        assert_eq!(r.last().unwrap()["count"], 95);
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
        let a = Audit::open_with(&p, no_floor(4096, 3)).unwrap();
        for i in 0..2000 {
            assert!(a.record(row(i)));
        }
        let n = names(t.path());
        assert_eq!(n.len(), 4, "{n:?}");
        assert_eq!(n[0], "audit.log");
        for f in &n {
            assert!(std::fs::metadata(t.path().join(f)).unwrap().len() <= 4096, "{f}");
        }
        // The newest row is in the live file; the highest-numbered rotated
        // file holds the rows just before it.
        assert_eq!(rows(&p).last().unwrap()["outcome"], "row 1999");
        let files = rotated_files(&p).unwrap();
        let newest_rotated = rows(&files.last().unwrap().1);
        let first_live = rows(&p)[0]["outcome"].as_str().unwrap().trim_start_matches("row ").parse::<usize>().unwrap();
        assert_eq!(newest_rotated.last().unwrap()["outcome"], format!("row {}", first_live - 1));
        assert!(a.retention_problem().is_none());
    }

    /// A rotation whose rename fails deletes nothing, keeps every row, and is
    /// retried; a live file at twice its limit stops writes until it rotates.
    #[test]
    fn a_failing_rotation_deletes_nothing() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("audit.log");
        let a = Audit::open_with(&p, no_floor(4096, 2)).unwrap();
        let mut i = 0;
        while rotated_files(&p).unwrap().len() < 2 {
            assert!(a.record(row(i)));
            i += 1;
        }
        let before = names(t.path());
        let old: Vec<String> = before.iter().map(|n| std::fs::read_to_string(t.path().join(n)).unwrap()).collect();
        a.set_rename_fault(true);
        // Up to twice the limit, rows still land in the live file.
        let mut landed = 0;
        while a.record(row(i)) {
            i += 1;
            landed += 1;
            assert_eq!(names(t.path()), before, "a failing rotation must not delete or rename anything");
        }
        assert!(landed > 20, "{landed}");
        assert!(!a.healthy());
        for (n, text) in before.iter().zip(&old) {
            assert!(std::fs::read_to_string(t.path().join(n)).unwrap().starts_with(text.as_str()), "{n} lost rows");
        }
        // The rename works again: the next write rotates and goes through.
        a.set_rename_fault(false);
        assert!(a.check());
        assert!(a.record(row(i)));
        assert_eq!(rotated_files(&p).unwrap().len(), 2, "kept two, deleted the oldest only now");
    }

    /// The real thing on Windows: another program holds audit.log open
    /// without delete sharing (as some log viewers do), so the rename fails.
    #[cfg(windows)]
    #[test]
    fn a_locked_live_file_blocks_rotation_without_losing_history() {
        use std::os::windows::fs::OpenOptionsExt;
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("audit.log");
        let a = Audit::open_with(&p, no_floor(4096, 2)).unwrap();
        let mut i = 0;
        while rotated_files(&p).unwrap().len() < 2 {
            assert!(a.record(row(i)));
            i += 1;
        }
        let before = names(t.path());
        // FILE_SHARE_READ | FILE_SHARE_WRITE, no FILE_SHARE_DELETE.
        let holder = OpenOptions::new().read(true).share_mode(0x1 | 0x2).open(&p).unwrap();
        for _ in 0..100 {
            if !a.record(row(i)) {
                break;
            }
            i += 1;
            assert_eq!(names(t.path()), before, "history wiped while the file was held");
        }
        drop(holder);
        assert!(a.check(), "writable again once the holder lets go");
        assert!(a.record(row(i)));
        assert_eq!(rotated_files(&p).unwrap().len(), 2);
    }

    #[test]
    fn the_retention_floor_stops_streams_instead_of_deleting_young_rows() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("audit.log");
        let cfg = AuditConfig { max_bytes: 4096, keep: 2, min_retention: DAY * 30, ..Default::default() };
        let a = Audit::open_with(&p, cfg).unwrap();
        let now = crate::now_ms();
        let day_ms = 86_400_000;
        // Old rows (40 days) fill the first files; they may go.
        let mut i = 0;
        while rotated_files(&p).unwrap().len() < 2 {
            assert!(a.record(AuditRow { ts_ms: now - 40 * day_ms, ..row(i) }));
            i += 1;
        }
        // Fresh rows: once the cap would delete a file of fresh rows, the
        // log keeps it and says so.
        let mut n = 0;
        while a.retention_problem().is_none() && n < 10_000 {
            a.record(row(i));
            i += 1;
            n += 1;
        }
        let why = a.retention_problem().expect("the floor stops it");
        assert!(why.contains("30-day retention floor"), "{why}");
        // Nothing younger than the floor was deleted: every fresh row is still there.
        let mut all = Vec::new();
        for (_, f) in rotated_files(&p).unwrap() {
            all.extend(rows(&f));
        }
        all.extend(rows(&p));
        let fresh: Vec<_> = all.iter().filter(|r| r["ts_ms"].as_u64().unwrap() > now - day_ms).collect();
        assert_eq!(fresh.len(), n, "every fresh row kept");
        // The owner moves the oldest file away: room again.
        let oldest = rotated_files(&p).unwrap()[0].1.clone();
        std::fs::rename(&oldest, t.path().join("moved-away")).unwrap();
        a.check_retention();
        assert!(a.retention_problem().is_none());
    }

    #[test]
    fn the_default_cap_holds_30_days_of_ordinary_use() {
        // The two rows of one stream, with long-ish fields.
        let open = AuditRow {
            ts_ms: 1_762_992_000_000,
            event: "stream_open",
            sid: Some("a1b2c3d4-1234567".into()),
            device: Some("0123456789ab".into()),
            name: Some("michaels-laptop".into()),
            peer: Some("[2a01:4f8:1:2:abcd:1234:5678:9abc]:54321".into()),
            target: Some("www.some-long-site-name.example.com:443".into()),
            addr: Some("[2606:4700:4700::1111]:443".into()),
            outcome: "connected".into(),
            ..Default::default()
        };
        let done = AuditRow { event: "stream", up: Some(123_456), down: Some(12_345_678), ms: Some(123_456), outcome: "closed".into(), ..open };
        let per_stream = serde_json::to_vec(&done).unwrap().len() + 1 + serde_json::to_vec(&AuditRow { event: "stream_open", up: None, down: None, ms: None, outcome: "connected".into(), ..done }).unwrap().len() + 1;
        assert!(per_stream < 600, "{per_stream}");
        let cap = AuditConfig::default().cap_bytes() as usize;
        assert_eq!(cap, 256 * 1024 * 1024);
        // 15,000 streams a day for 30 days fit.
        assert!(15_000 * 30 * per_stream < cap, "{per_stream} bytes per stream");
        assert_eq!(AuditConfig::default().min_retention, DAY * 30);
        let c = AuditConfig::with_retention(1024, 90);
        assert_eq!(c.cap_bytes(), 1024 * MIB);
        assert_eq!(c.min_retention, DAY * 90);
    }

    /// One device writing fast uses up its own share, not the whole log:
    /// its rows are counted instead of written, others are untouched, and
    /// the share refills with time.
    #[test]
    fn one_device_cannot_spend_the_whole_log() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("audit.log");
        // A 64 KiB cap held for 30 days: about 1 byte per minute per device.
        let a = Audit::open_with(&p, AuditConfig { max_bytes: 8192, keep: 7, min_retention: DAY * 30, ..Default::default() }).unwrap();
        let (rate, burst) = a.device_budget().unwrap();
        assert!(burst <= 64.0 * 1024.0 / 4.0 && burst > 1000.0, "{burst}");
        let t0 = Instant::now();
        let dev = |d: &str, ev: &'static str| AuditRow { event: ev, device: Some(d.into()), outcome: "x".repeat(100), ..Default::default() };
        let mut written = 0;
        while !a.over_budget_at("aaaa", t0) {
            assert!(a.record(dev("aaaa", "stream")), "stream rows are always written");
            written += 1;
            assert!(written < 1000, "the share never ran out");
        }
        // Spent: its link rows and denials are counted, not written...
        let before = rows(&p).len();
        assert!(!a.device_row_at(dev("aaaa", "link_up"), t0));
        a.denial_at(dev("aaaa", "denied"), t0);
        assert_eq!(rows(&p).len(), before);
        // ...another device is not affected...
        assert!(!a.over_budget_at("bbbb", t0));
        assert!(a.device_row_at(dev("bbbb", "link_up"), t0));
        // ...nothing stops the hub, and the count is written by `flush`.
        assert!(a.retention_problem().is_none());
        a.flush_at(t0);
        let last = rows(&p).into_iter().rfind(|r| r["event"] == "device_rows_suppressed").expect("summary row");
        assert_eq!(last["device"], "aaaa");
        assert_eq!(last["count"], 1);
        // The share refills at its rate.
        let debt = 1000.0;
        assert!(!a.over_budget_at("aaaa", t0 + Duration::from_secs_f64(debt / rate)), "refilled");
        // No floor: no share at all.
        let b = Audit::open_with(&t.path().join("b.log"), no_floor(4096, 2)).unwrap();
        assert!(b.device_budget().is_none());
        for _ in 0..200 {
            b.record(dev("aaaa", "stream"));
        }
        assert!(!b.over_budget_at("aaaa", t0));
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
