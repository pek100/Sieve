//! `engine\exclusions.json`: the entries the engine wrote itself (plan 4.1's
//! table). Only this layer is persisted here: user entries live in the policy
//! and list entries in their lists. An unreadable file is not an empty store:
//! it reads as `floor:no-exclusion-list` (S24), since an excluded bank must not
//! become decryptable because a file was damaged.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sieve_filter::exclusions::{AutoReason, Exclusion, Pattern};

use crate::policy::write_atomic;

pub const FILE: &str = "exclusions.json";
const VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoEntry {
    pub pattern: Pattern,
    /// An exe file name, lower case; None means every app.
    pub app: Option<String>,
    pub reason: AutoReason,
    pub created_ms: u64,
    /// `auto:ev` goes with its certificate; the others never expire.
    pub expires_ms: Option<u64>,
}

impl AutoEntry {
    /// An entry for exactly this host and every app.
    pub fn host(host: &str, reason: AutoReason, created_ms: u64, expires_ms: Option<u64>) -> Self {
        Self { pattern: Pattern::Exact(host.to_ascii_lowercase()), app: None, reason, created_ms, expires_ms }
    }

    pub fn expired(&self, now_ms: u64) -> bool {
        self.expires_ms.is_some_and(|end| now_ms >= end)
    }

    pub fn exclusion(&self) -> Exclusion {
        Exclusion { pattern: self.pattern.clone(), apps: self.app.iter().cloned().collect() }
    }
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
    Ok(file.entries)
}

pub fn save(engine_dir: &Path, entries: &[AutoEntry]) -> Result<(), String> {
    let file = OnDisk { v: VERSION, entries: entries.to_vec() };
    let json = serde_json::to_vec_pretty(&file).map_err(|e| format!("{FILE}: {e}"))?;
    write_atomic(&path(engine_dir), &json).map_err(|e| format!("{FILE}: {e}"))
}
