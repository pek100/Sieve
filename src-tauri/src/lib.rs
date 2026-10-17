//! Sieve, Rust side. Reads facts about the machine (read only) and hands
//! them to the web UI as protocol v1 snapshots; keeps their per-app counts
//! in a history file in the app's own data dir. No admin rights, no
//! drivers, no writes to system state. Launch at startup (autostart plugin)
//! writes the current user's Run entry, only when the user turns the
//! `startup.launchAtLogin` setting on.

pub mod commands;
pub mod history;
pub mod netstat;
pub mod protocol;
pub mod tray;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::Builder::new().build())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            app.manage(history::HistoryState::open_at(&dir));
            tray::install(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::net_snapshot,
            commands::history_record,
            commands::history_buckets,
            commands::tray_set_state
        ])
        .run(tauri::generate_context!());
    if let Err(e) = result {
        eprintln!("Sieve failed to start: {e}");
        std::process::exit(1);
    }
}
