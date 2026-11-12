//! The small file store. A hub directory holds:
//!
//! - `identity.key`  the hub's private key (PKCS#8)
//! - `hub.json`      name, paired devices with their rules and limits,
//!   outstanding pairing codes (deleted on use or expiry), defaults for new
//!   devices, the owner's manual LAN blocks and LAN / audit settings
//! - `audit.log`     the audit log, rotated by size (`audit.log.N`, `audit`)
//! - `status.json`   what the running hub reports for `sieve-hub status` and
//!   `sieve-hub lan` (rewritten when it changes and at least every 10 s;
//!   read-only for the CLI)
//! - `hub.lock`      an empty file the writers lock
//!
//! A device directory holds `identity.key` and `device.json` (the hub's
//! fingerprint and address, the hub-down setting). Nothing else is persisted.
//! Both directories are owner-only (`perms`); the default places are
//! `default_dir`.
//!
//! Writers (the running hub and the CLI) take an operating-system lock on
//! `hub.lock` (released by the OS if the writer dies, so there is no stale
//! lock to guess about), read, change and replace the file atomically (write
//! a temporary file, sync it, rename it over, and on Unix sync the directory).
//! Taking the lock blocks the calling thread: async callers run store writes
//! on the blocking pool.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::device::OnHubDown;
use crate::error::{LinkError, Result};
use crate::identity::Fingerprint;
use crate::rules::{Cidr, Limits, Rules};

pub const IDENTITY_FILE: &str = "identity.key";
pub const HUB_FILE: &str = "hub.json";
pub const DEVICE_FILE: &str = "device.json";
pub const AUDIT_FILE: &str = "audit.log";
pub const STATUS_FILE: &str = "status.json";
const LOCK_FILE: &str = "hub.lock";

/// Longest device name kept, in characters (a fingerprint-like name gets a
/// 7-character prefix on top).
pub const MAX_NAME_CHARS: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRecord {
    pub fingerprint: Fingerprint,
    pub name: String,
    pub paired_at: u64,
    #[serde(default)]
    pub revoked_at: Option<u64>,
    #[serde(default)]
    pub rules: Rules,
    #[serde(default)]
    pub limits: Limits,
}

impl DeviceRecord {
    pub fn active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// An outstanding pairing code. The secret is on disk only until the code
/// is used or expires (the running hub and the CLI are separate processes).
/// `Debug` never shows it, and our copy is wiped when dropped.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingCode {
    /// Hex.
    pub secret: String,
    pub expires_at: u64,
    #[serde(default)]
    pub label: String,
}

impl std::fmt::Debug for PendingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingCode").field("expires_at", &self.expires_at).field("label", &self.label).finish_non_exhaustive()
    }
}

impl Drop for PendingCode {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl PendingCode {
    /// The secret's bytes, in a buffer the caller should wipe after use.
    pub fn secret_bytes(&self) -> Option<zeroize::Zeroizing<[u8; 16]>> {
        let s = self.secret.as_bytes();
        if s.len() != 32 {
            return None;
        }
        let mut out = zeroize::Zeroizing::new([0u8; 16]);
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(std::str::from_utf8(&s[2 * i..2 * i + 2]).ok()?, 16).ok()?;
        }
        Some(out)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Defaults {
    #[serde(default)]
    pub rules: Rules,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HubFile {
    pub version: u32,
    pub name: String,
    #[serde(default)]
    pub devices: Vec<DeviceRecord>,
    #[serde(default)]
    pub pending: Vec<PendingCode>,
    #[serde(default)]
    pub defaults: Defaults,
    /// The owner's manual blocks, denied on top of the ones the hub detects
    /// from its interfaces and routes and the public addresses it learns
    /// from its links. Denied unless a device's `allow_lan` says otherwise.
    #[serde(default)]
    pub lan_cidrs: Vec<Cidr>,
    /// The IPv6 site prefix denied around each global IPv6 address of the
    /// hub (`netif::DEFAULT_V6_SITE_PREFIX` when unset).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_v6_prefix: Option<u8>,
    /// The audit log's size cap in MiB (`audit::DEFAULT_CAP_MIB` when unset).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_cap_mib: Option<u64>,
    /// The audit log's retention floor in days (`audit::DEFAULT_MIN_DAYS`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_min_days: Option<u32>,
}

impl HubFile {
    pub fn v6_site_prefix(&self) -> u8 {
        self.lan_v6_prefix.unwrap_or(crate::netif::DEFAULT_V6_SITE_PREFIX)
    }

    /// The audit settings this store asks for.
    pub fn audit_config(&self) -> crate::audit::AuditConfig {
        crate::audit::AuditConfig::with_retention(
            self.audit_cap_mib.unwrap_or(crate::audit::DEFAULT_CAP_MIB),
            self.audit_min_days.unwrap_or(crate::audit::DEFAULT_MIN_DAYS),
        )
    }
}

impl HubFile {
    pub fn device(&self, fp: &Fingerprint) -> Option<&DeviceRecord> {
        self.devices.iter().find(|d| d.fingerprint == *fp)
    }

    pub fn device_mut(&mut self, fp: &Fingerprint) -> Option<&mut DeviceRecord> {
        self.devices.iter_mut().find(|d| d.fingerprint == *fp)
    }

    /// Resolves a CLI device name. A fingerprint prefix (8+ hex digits) is
    /// tried first and always wins, so revoking by fingerprint works whatever
    /// the devices are called; otherwise an exact name.
    pub fn find(&self, key: &str) -> Result<Fingerprint> {
        let key = key.trim();
        let by_fp: Vec<&DeviceRecord> = self.devices.iter().filter(|d| d.fingerprint.matches_prefix(key)).collect();
        match by_fp.as_slice() {
            [one] => return Ok(one.fingerprint),
            [] => {}
            _ => return Err(LinkError::Store(format!("{key:?} matches several fingerprints; give more of it"))),
        }
        let by_name: Vec<&DeviceRecord> = self.devices.iter().filter(|d| d.name == key).collect();
        match by_name.as_slice() {
            [one] => Ok(one.fingerprint),
            [] => Err(LinkError::Store(format!("no device matches {key:?}"))),
            _ => Err(LinkError::Store(format!("{key:?} names several devices; give the fingerprint"))),
        }
    }

    /// `name` (already cleaned), made unique among this hub's devices by a
    /// numeric suffix.
    pub fn unique_name(&self, name: &str) -> String {
        let taken = |n: &str| self.devices.iter().any(|d| d.name == n);
        if !taken(name) {
            return name.to_string();
        }
        (2u32..).map(|i| format!("{name}-{i}")).find(|n| !taken(n)).expect("some suffix is free")
    }

    pub fn purge_expired(&mut self, now_secs: u64) {
        self.pending.retain(|p| now_secs < p.expires_at);
    }

    pub fn has_pending(&self, now_secs: u64) -> bool {
        self.pending.iter().any(|p| now_secs < p.expires_at)
    }
}

/// Unicode format characters (category Cf) and line/paragraph separators:
/// invisible, and some reorder text (bidi overrides), so a name could look
/// like another one in a list.
fn is_format_char(c: char) -> bool {
    matches!(c as u32,
        0xAD | 0x600..=0x605 | 0x61C | 0x6DD | 0x70F | 0x890..=0x891 | 0x8E2 | 0x180E
        | 0x200B..=0x200F | 0x2028..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F
        | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

/// Whether `s` could be read as a fingerprint prefix by `HubFile::find`.
fn looks_like_fingerprint(s: &str) -> bool {
    s.len() >= 8 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// A device name as the hub keeps it: no control or format characters,
/// whitespace collapsed to single spaces, at most `MAX_NAME_CHARS`
/// characters, never empty, never something that reads as a fingerprint.
pub fn clean_name(raw: &str) -> String {
    let mut out = String::new();
    let mut chars = 0;
    let mut last_space = true;
    for c in raw.chars() {
        if c.is_control() || is_format_char(c) {
            continue;
        }
        let c = if c.is_whitespace() { ' ' } else { c };
        if c == ' ' && last_space {
            continue;
        }
        last_space = c == ' ';
        out.push(c);
        chars += 1;
        if chars == MAX_NAME_CHARS {
            break;
        }
    }
    let out = out.trim().to_string();
    if out.is_empty() {
        "device".into()
    } else if looks_like_fingerprint(&out) {
        format!("device-{out}")
    } else {
        out
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceFile {
    pub version: u32,
    pub name: String,
    pub hub: Fingerprint,
    #[serde(default)]
    pub hub_name: String,
    /// Where to dial the hub; `None` when the hub dials this device.
    #[serde(default)]
    pub hub_addr: Option<String>,
    #[serde(default)]
    pub on_hub_down: OnHubDown,
}

/// The default directory for a hub (`kind` = "hub") or a device ("device"):
/// `%LOCALAPPDATA%\sieve-link\<kind>` on Windows, `$XDG_STATE_HOME/sieve-link/<kind>`
/// (or `~/.local/state/sieve-link/<kind>`) on Unix. Never relative to the
/// current directory.
pub fn default_dir(kind: &str) -> Result<PathBuf> {
    let base = default_base().ok_or_else(|| LinkError::Store("no per-user data directory is known here; give --dir".into()))?;
    Ok(base.join("sieve-link").join(kind))
}

#[cfg(windows)]
fn default_base() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(PathBuf::from).filter(|p| p.is_absolute())
}

#[cfg(unix)]
fn default_base() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from).filter(|p| p.is_absolute()) {
        return Some(x);
    }
    std::env::var_os("HOME").map(PathBuf::from).filter(|p| p.is_absolute()).map(|h| h.join(".local").join("state"))
}

pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let mut bytes = std::fs::read(path).map_err(|e| LinkError::Store(format!("cannot read {}: {e}", path.display())))?;
    let r = serde_json::from_slice(&bytes).map_err(|e| LinkError::Store(format!("{} is damaged: {e}", path.display())));
    // The store holds pending pairing secrets.
    bytes.zeroize();
    r
}

pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("json.tmp");
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| LinkError::Store(e.to_string()))?;
    let written = (|| -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()
    })();
    bytes.zeroize();
    written?;
    std::fs::rename(&tmp, path)?;
    sync_dir(path)?;
    Ok(())
}

/// Makes a rename in `path`'s directory durable (Unix). Windows has no
/// directory handle to sync; NTFS journals the rename.
#[cfg(unix)]
fn sync_dir(path: &Path) -> std::io::Result<()> {
    match path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(d) => File::open(d)?.sync_all(),
        None => File::open(".")?.sync_all(),
    }
}

#[cfg(windows)]
fn sync_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// What a file looks like from outside: when it changed, how long it is, and
/// which file it is (volume and file index on Windows, device and inode on
/// Unix), so a replaced file is noticed even when the clock or the
/// filesystem's timestamp resolution would hide it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStamp {
    pub modified: Option<SystemTime>,
    pub len: u64,
    pub id: Option<(u64, u64)>,
}

pub fn stamp(path: &Path) -> std::io::Result<FileStamp> {
    let m = std::fs::metadata(path)?;
    Ok(FileStamp { modified: m.modified().ok(), len: m.len(), id: file_id(path, &m) })
}

#[cfg(unix)]
fn file_id(_path: &Path, m: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((m.dev(), m.ino()))
}

#[cfg(windows)]
fn file_id(path: &Path, _m: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};
    let f = File::open(path).ok()?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: a live handle owned by `f`, and a struct of the right type.
    if unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) } == 0 {
        return None;
    }
    Some((info.dwVolumeSerialNumber as u64, ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64))
}

/// The writers' lock: an OS lock on `hub.lock`, released when this is dropped
/// or when the process dies. The file itself is never deleted.
struct StoreLock(File);

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

fn lock(dir: &Path) -> Result<StoreLock> {
    let path = dir.join(LOCK_FILE);
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts.open(&path).map_err(|e| LinkError::Store(format!("cannot open {}: {e}", path.display())))?;
    f.lock().map_err(|e| LinkError::Store(format!("cannot lock {}: {e}", path.display())))?;
    Ok(StoreLock(f))
}

/// The hub's store directory.
#[derive(Clone, Debug)]
pub struct HubStore {
    pub dir: PathBuf,
}

impl HubStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        HubStore { dir: dir.into() }
    }

    pub fn file_path(&self) -> PathBuf {
        self.dir.join(HUB_FILE)
    }

    pub fn exists(&self) -> bool {
        self.file_path().exists()
    }

    pub fn load(&self) -> Result<HubFile> {
        read_json(&self.file_path())
    }

    /// Read, change and replace `hub.json` under the lock. Blocks.
    pub fn update<R>(&self, f: impl FnOnce(&mut HubFile) -> Result<R>) -> Result<R> {
        let _guard = lock(&self.dir)?;
        let mut file = self.load()?;
        let r = f(&mut file)?;
        write_json_atomic(&self.file_path(), &file)?;
        Ok(r)
    }

    pub fn create(&self, name: &str) -> Result<()> {
        crate::perms::create_private_dir(&self.dir)?;
        let _guard = lock(&self.dir)?;
        if self.exists() {
            return Err(LinkError::Store(format!("{} already exists", self.file_path().display())));
        }
        write_json_atomic(&self.file_path(), &HubFile { version: 1, name: name.to_string(), ..Default::default() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(b: u8) -> Fingerprint {
        Fingerprint([b; 32])
    }

    fn rec(b: u8, name: &str) -> DeviceRecord {
        DeviceRecord { fingerprint: fp(b), name: name.into(), paired_at: 0, revoked_at: None, rules: Rules::default(), limits: Limits::default() }
    }

    #[test]
    fn names_are_cleaned_and_bounded() {
        assert_eq!(clean_name("laptop"), "laptop");
        assert_eq!(clean_name("  my \t\n laptop  "), "my laptop");
        assert_eq!(clean_name("evil\u{202E}gnp.exe"), "evilgnp.exe");
        assert_eq!(clean_name("zero\u{200B}width\u{FEFF}"), "zerowidth");
        assert_eq!(clean_name("bell\u{7}\u{1b}[31m"), "bell[31m");
        assert_eq!(clean_name(""), "device");
        assert_eq!(clean_name("\u{200B}\u{7}"), "device");
        assert_eq!(clean_name(&"x".repeat(500)).chars().count(), MAX_NAME_CHARS);
        assert_eq!(clean_name(&"é".repeat(500)).chars().count(), MAX_NAME_CHARS);
        // Fingerprint-like names cannot shadow a fingerprint prefix.
        assert_eq!(clean_name("0123abcd"), "device-0123abcd");
        assert_eq!(clean_name("DEADBEEFDEADBEEF"), "device-DEADBEEFDEADBEEF");
        assert_eq!(clean_name("abc"), "abc");
    }

    #[test]
    fn names_are_unique_per_hub() {
        let mut f = HubFile::default();
        f.devices.push(rec(1, "laptop"));
        assert_eq!(f.unique_name("phone"), "phone");
        assert_eq!(f.unique_name("laptop"), "laptop-2");
        f.devices.push(rec(2, "laptop-2"));
        assert_eq!(f.unique_name("laptop"), "laptop-3");
    }

    #[test]
    fn find_prefers_the_fingerprint_over_names() {
        let mut f = HubFile::default();
        // A device (from an older store) named like another one's fingerprint.
        f.devices.push(rec(0x11, "aaaaaaaa"));
        f.devices.push(rec(0xaa, "phone"));
        assert_eq!(f.find("aaaaaaaa").unwrap(), fp(0xaa));
        assert_eq!(f.find("11111111").unwrap(), fp(0x11));
        assert_eq!(f.find("phone").unwrap(), fp(0xaa));
        assert!(f.find("nobody").is_err());
        f.devices.push(rec(0x22, "phone"));
        assert!(f.find("phone").is_err(), "a duplicated name is ambiguous");
        assert_eq!(f.find(&fp(0x22).to_string()).unwrap(), fp(0x22));
    }

    #[test]
    fn debug_never_shows_pending_secrets() {
        let secret = "00112233445566778899aabbccddeeff".to_string();
        let f = HubFile { pending: vec![PendingCode { secret: secret.clone(), expires_at: 9, label: "x".into() }], ..Default::default() };
        let dbg = format!("{f:?}");
        assert!(!dbg.contains(&secret), "{dbg}");
        assert!(!dbg.contains("00112233"), "{dbg}");
    }

    #[test]
    fn the_lock_serialises_writers_and_survives_a_dead_holder() {
        let t = tempfile::tempdir().unwrap();
        let st = HubStore::new(t.path());
        st.create("h").unwrap();
        // Many threads each add one device under the lock: none is lost.
        let threads: Vec<_> = (0..8u8)
            .map(|i| {
                let st = st.clone();
                std::thread::spawn(move || {
                    st.update(|f| {
                        f.devices.push(rec(i + 1, &format!("d{i}")));
                        Ok(())
                    })
                    .unwrap()
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(st.load().unwrap().devices.len(), 8);
        // A leftover lock file (a writer that died) does not block anyone:
        // only a live OS lock does.
        assert!(t.path().join(LOCK_FILE).exists());
        st.update(|_| Ok(())).unwrap();
    }

    #[test]
    fn stamps_notice_a_replaced_file_of_the_same_size() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("hub.json");
        std::fs::write(&p, b"{\"a\":1}").unwrap();
        let a = stamp(&p).unwrap();
        write_json_atomic(&p, &serde_json::json!({"a": 2})).unwrap();
        let b = stamp(&p).unwrap();
        assert_ne!(a, b);
        assert!(a.id.is_some());
    }

    #[test]
    fn default_dirs_are_absolute() {
        if let Ok(d) = default_dir("hub") {
            assert!(d.is_absolute());
            assert!(d.ends_with(Path::new("sieve-link").join("hub")));
        }
    }
}
