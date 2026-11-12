//! The small file store. A hub directory holds:
//!
//! - `identity.key`  the hub's private key (PKCS#8; mode 0600 on Unix)
//! - `hub.json`      name, paired devices with their rules and limits,
//!   outstanding pairing codes (deleted on use or expiry), defaults for new
//!   devices, the LAN blocks to deny
//! - `audit.log`     the append-only audit log (`audit`)
//!
//! A device directory holds `identity.key` and `device.json` (the hub's
//! fingerprint and address, the hub-down setting). Nothing else is persisted.
//!
//! Writers (the running hub and the CLI) take `hub.lock`, read, change and
//! replace the file atomically (write to a temporary file, then rename).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::device::OnHubDown;
use crate::error::{LinkError, Result};
use crate::identity::Fingerprint;
use crate::rules::{Cidr, Limits, Rules};

pub const IDENTITY_FILE: &str = "identity.key";
pub const HUB_FILE: &str = "hub.json";
pub const DEVICE_FILE: &str = "device.json";
pub const AUDIT_FILE: &str = "audit.log";
const LOCK_FILE: &str = "hub.lock";

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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingCode {
    /// Hex.
    pub secret: String,
    pub expires_at: u64,
    #[serde(default)]
    pub label: String,
}

impl PendingCode {
    pub fn secret_bytes(&self) -> Option<[u8; 16]> {
        let s = self.secret.as_bytes();
        if s.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
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
    /// The hub's own LAN blocks beyond the default private classes (e.g. a
    /// public /29 at home). Always denied unless a device's allow_cidrs says otherwise.
    #[serde(default)]
    pub lan_cidrs: Vec<Cidr>,
}

impl HubFile {
    pub fn device(&self, fp: &Fingerprint) -> Option<&DeviceRecord> {
        self.devices.iter().find(|d| d.fingerprint == *fp)
    }

    pub fn device_mut(&mut self, fp: &Fingerprint) -> Option<&mut DeviceRecord> {
        self.devices.iter_mut().find(|d| d.fingerprint == *fp)
    }

    /// Resolves a CLI device name: a fingerprint prefix (8+ hex digits) or an exact name.
    pub fn find(&self, key: &str) -> Result<Fingerprint> {
        let hits: Vec<&DeviceRecord> = self
            .devices
            .iter()
            .filter(|d| d.fingerprint.matches_prefix(key) || d.name == key)
            .collect();
        match hits.as_slice() {
            [one] => Ok(one.fingerprint),
            [] => Err(LinkError::Store(format!("no device matches {key:?}"))),
            _ => Err(LinkError::Store(format!("{key:?} matches several devices; give more of the fingerprint"))),
        }
    }

    pub fn purge_expired(&mut self, now_secs: u64) {
        self.pending.retain(|p| now_secs < p.expires_at);
    }

    pub fn has_pending(&self, now_secs: u64) -> bool {
        self.pending.iter().any(|p| now_secs < p.expires_at)
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

pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path).map_err(|e| LinkError::Store(format!("cannot read {}: {e}", path.display())))?;
    serde_json::from_slice(&bytes).map_err(|e| LinkError::Store(format!("{} is damaged: {e}", path.display())))
}

pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| LinkError::Store(e.to_string()))?;
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

struct LockGuard(PathBuf);

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn lock(dir: &Path) -> Result<LockGuard> {
    let path = dir.join(LOCK_FILE);
    let start = Instant::now();
    loop {
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(_) => return Ok(LockGuard(path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // A lock older than 30 s belongs to a writer that died.
                let stale = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > Duration::from_secs(30));
                if stale {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                if start.elapsed() > Duration::from_secs(10) {
                    return Err(LinkError::Store(format!("{} is held by another writer", path.display())));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e.into()),
        }
    }
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

    /// Read, change and replace `hub.json` under the lock.
    pub fn update<R>(&self, f: impl FnOnce(&mut HubFile) -> Result<R>) -> Result<R> {
        let _guard = lock(&self.dir)?;
        let mut file = self.load()?;
        let r = f(&mut file)?;
        write_json_atomic(&self.file_path(), &file)?;
        Ok(r)
    }

    pub fn create(&self, name: &str) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let _guard = lock(&self.dir)?;
        if self.exists() {
            return Err(LinkError::Store(format!("{} already exists", self.file_path().display())));
        }
        write_json_atomic(&self.file_path(), &HubFile { version: 1, name: name.to_string(), ..Default::default() })
    }
}
