//! Sieve, Rust side. Reads facts about the machine (read only) and hands
//! them to the web UI as protocol v1 snapshots; keeps their per-app counts
//! in a history file in the app's own data dir; runs a local DNS filter
//! (`dns`). No drivers. Launch at startup (autostart plugin) writes the
//! current user's Run entry, only when the user turns the
//! `startup.launchAtLogin` setting on. The one system write is `sysdns`:
//! pointing Windows DNS at the filter and restoring it, each through one
//! elevated script the user approves at the Windows prompt.

pub mod commands;
pub mod dns;
pub mod history;
pub mod netstat;
pub mod protocol;
pub mod sysdns;
pub mod tray;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::Builder::new().build())
        .manage(dns::commands::DnsState::default())
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
            commands::tray_set_state,
            commands::app_quit,
            dns::commands::dns_start,
            dns::commands::dns_stop,
            dns::commands::dns_status,
            dns::commands::dns_self_check,
            dns::commands::dns_set_pass_through,
            sysdns::commands::system_dns_state,
            sysdns::commands::system_dns_point,
            sysdns::commands::system_dns_restore,
            sysdns::commands::adguard_running,
        ])
        .run(tauri::generate_context!());
    if let Err(e) = result {
        eprintln!("Sieve failed to start: {e}");
        std::process::exit(1);
    }
}
