//! Tauri commands: the only entry points the web UI can call.
//! Errors cross the bridge as strings; the UI shows them as an error state.

use std::sync::Arc;

use tauri::{AppHandle, Manager};

use crate::engine::EngineFlows;
use crate::history::HistoryState;
use crate::netstat;
use crate::protocol::{History, HistoryQuery, HistoryRecord, Snapshot};
use crate::tray::{self, TrayState};

/// One sample of the machine (protocol v1). Runs off the main thread.
/// While the engine routes and this app is subscribed to its flows, the
/// flows are the engine's (`EngineFlows`); otherwise the connection tables.
#[tauri::command]
pub async fn net_snapshot(engine: tauri::State<'_, Arc<EngineFlows>>) -> Result<Snapshot, String> {
    let from_engine = engine.flows();
    tauri::async_runtime::spawn_blocking(move || match from_engine {
        Some(flows) => netstat::snapshot_of(flows),
        None => netstat::snapshot(),
    })
    .await
    .map_err(|e| format!("snapshot task failed: {e}"))?
    .map_err(|e| e.to_string())
}

/// Fold one sample's per-app counts into the persisted history.
#[tauri::command]
pub async fn history_record(app: AppHandle, record: HistoryRecord) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || app.state::<HistoryState>().with(|s| s.record(&record)))
        .await
        .map_err(|e| format!("history task failed: {e}"))?
}

/// Read persisted history buckets.
#[tauri::command]
pub async fn history_buckets(app: AppHandle, query: HistoryQuery) -> Result<History, String> {
    tauri::async_runtime::spawn_blocking(move || app.state::<HistoryState>().with(|s| s.read(&query)))
        .await
        .map_err(|e| format!("history task failed: {e}"))?
}

/// The window reports its sampling phase; the tray shows it.
#[tauri::command]
pub async fn tray_set_state(app: AppHandle, state: TrayState) -> Result<(), String> {
    tray::apply(&app, &state)
}
