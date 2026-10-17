//! Sieve, Rust side. Reads facts about the machine (read only) and hands
//! them to the web UI as protocol v1 snapshots. No admin rights, no drivers,
//! no writes to system state.

pub mod commands;
pub mod dns;
pub mod netstat;
pub mod protocol;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![commands::net_snapshot])
        .run(tauri::generate_context!());
    if let Err(e) = result {
        eprintln!("Sieve failed to start: {e}");
        std::process::exit(1);
    }
}
