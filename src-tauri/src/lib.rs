//! Sieve, Rust side. Reads facts about the machine (read only) and hands
//! them to the web UI as protocol v1 snapshots; keeps their per-app counts
//! in a history file in the app's own data dir. No drivers. Launch at startup
//! (autostart plugin) writes the current user's Run entry, only when the user
//! turns the `startup.launchAtLogin` setting on. Asks the filtering engine's
//! service and pipe what it is doing, sends it the user's switch, and reads its
//! flows and log while it routes (`engine`). Stops or starts
//! AdGuard's service only when the user clicks the pause offer, through one
//! command Windows asks the user to approve (`adguard`).
//!
//! Sieve off means a normal network: Sieve never writes persistent system
//! network state (DNS servers, persistent routes, proxy settings, firewall
//! rules that outlive the process). See docs/conventions.md.

pub mod adguard;
pub mod commands;
pub mod engine;
pub mod filters;
pub mod history;
pub mod icons;
pub mod lock;
pub mod netstat;
pub mod protocol;
pub mod tray;
pub mod windns;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::Builder::new().build())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .manage(std::sync::Arc::new(engine::EngineFlows::default()))
        .manage(std::sync::Arc::new(engine::EngineLog::default()))
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            app.manage(history::HistoryState::open_at(&dir));
            app.manage(icons::IconStore::open_at(&dir));
            app.manage(lock::LockState::open_at(&dir));
            tray::install(app)?;
            #[cfg(windows)]
            tauri::async_runtime::spawn(engine::follow_flows(
                app.state::<std::sync::Arc<engine::EngineFlows>>().inner().clone(),
                app.state::<std::sync::Arc<engine::EngineLog>>().inner().clone(),
            ));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::net_snapshot,
            commands::history_record,
            commands::history_buckets,
            commands::tray_set_state,
            icons::commands::app_icon,
            adguard::adguard_stop,
            adguard::adguard_start,
            engine::engine_probe,
            engine::engine_set_policy,
            engine::engine_lists,
            engine::engine_lists_refresh,
            engine::engine_log_tail,
            engine::engine_dns_upstreams,
            engine::engine_set_dns_upstreams,
            engine::engine_cert_status,
            engine::engine_install_root,
            engine::engine_request_update,
            windns::windows_dns,
            filters::filter_catalogue,
            filters::rule_check,
            lock::lock_status,
            lock::lock_verify,
            lock::lock_set,
            lock::lock_clear,
        ])
        .run(tauri::generate_context!());
    if let Err(e) = result {
        eprintln!("Sieve failed to start: {e}");
        std::process::exit(1);
    }
}
