//! The hub's append-only audit log: one JSON object per line. Who (device
//! fingerprint and name), when, where to, bytes each way, outcome. Never
//! payload, never key material.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct AuditRow {
    pub ts_ms: u64,
    pub event: &'static str,
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
    /// The address the hub connected to.
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
    pub outcome: String,
}

#[derive(Debug)]
pub struct Audit {
    file: Mutex<File>,
}

impl Audit {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        // Append-only: never truncated or rewritten by this program.
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Audit { file: Mutex::new(file) })
    }

    pub fn record(&self, mut row: AuditRow) {
        if row.ts_ms == 0 {
            row.ts_ms = crate::now_ms();
        }
        let Ok(mut line) = serde_json::to_vec(&row) else { return };
        line.push(b'\n');
        if let Ok(mut f) = self.file.lock() {
            // One write per row so concurrent rows never interleave.
            if f.write_all(&line).is_err() {
                eprintln!("sieve-hub: audit write failed");
            }
        }
    }
}
