//! The icon command. Read only: it reads an exe's icon and the app's own cache dir.

use std::path::PathBuf;

use tauri::{AppHandle, Manager};

use super::{AppIcon, IconStore};

/// The icon of one exe at 32 and 64 px (PNG, base64), or null when there is
/// none to read. The UI asks per app, with the first exe of its group.
#[tauri::command]
pub async fn app_icon(app: AppHandle, exe_path: String) -> Result<Option<AppIcon>, String> {
    tauri::async_runtime::spawn_blocking(move || app.state::<IconStore>().icon(&PathBuf::from(exe_path)).map_err(|e| e.to_string()))
        .await
        .map_err(|e| format!("icon task failed: {e}"))?
}
