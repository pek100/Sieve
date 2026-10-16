//! Tauri commands: the only entry points the web UI can call.
//! Errors cross the bridge as strings; the UI shows them as an error state.

use crate::netstat;
use crate::protocol::Snapshot;

/// One sample of the machine (protocol v1). Runs off the main thread.
#[tauri::command]
pub async fn net_snapshot() -> Result<Snapshot, String> {
    tauri::async_runtime::spawn_blocking(netstat::snapshot)
        .await
        .map_err(|e| format!("snapshot task failed: {e}"))?
        .map_err(|e| e.to_string())
}
