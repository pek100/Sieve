//! Sieve, Rust side. Reads facts about the machine (read only) and hands
//! them to the web UI as protocol v1 snapshots; keeps their per-app counts
//! in a history file in the app's own data dir; runs a local DNS filter
//! (`dns`) that answers only lookups sent to it directly. No drivers. Launch
//! at startup (autostart plugin) writes the current user's Run entry, only
//! when the user turns the `startup.launchAtLogin` setting on. Asks the
//! filtering engine's service and pipe what it is doing, sends it the user's
//! switch, and reads its flows while it routes (`engine`). Stops or starts
//! AdGuard's service only when the user clicks the pause offer, through one
//! command Windows asks the user to approve (`adguard`).
//!
//! Sieve off means a normal network: Sieve never writes persistent system
//! network state (DNS servers, persistent routes, proxy settings, firewall
//! rules that outlive the process). See docs/conventions.md.

pub mod adguard;
pub mod commands;
pub mod dns;
pub mod engine;
pub mod history;
pub mod icons;
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
        .manage(dns::commands::DnsState::default())
        .manage(std::sync::Arc::new(engine::EngineFlows::default()))
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            app.manage(history::HistoryState::open_at(&dir));
            app.manage(icons::IconStore::open_at(&dir));
            tray::install(app)?;
            #[cfg(windows)]
            tauri::async_runtime::spawn(engine::follow_flows(app.state::<std::sync::Arc<engine::EngineFlows>>().inner().clone()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::net_snapshot,
            commands::history_record,
            commands::history_buckets,
            commands::tray_set_state,
            icons::commands::app_icon,
            dns::commands::dns_start,
            dns::commands::dns_stop,
            dns::commands::dns_status,
            dns::commands::dns_self_check,
            dns::commands::dns_set_pass_through,
            adguard::adguard_running,
            adguard::adguard_stop,
            adguard::adguard_start,
            engine::engine_probe,
            engine::engine_set_policy,
            engine::engine_cert_status,
            engine::engine_install_root,
            windns::windows_dns,
        ])
        .run(tauri::generate_context!());
    if let Err(e) = result {
        eprintln!("Sieve failed to start: {e}");
        std::process::exit(1);
    }
}
