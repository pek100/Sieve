//! Tauri commands for Windows DNS. Blocking work runs in spawn_blocking;
//! errors cross the bridge as strings.
//!
//! - `system_dns_state()` -> `SystemDnsState` (read only)
//! - `system_dns_point()` -> `SystemDnsState`: refuses unless the DNS filter
//!   runs on 127.0.0.1:53 and [::1]:53 and passes its self check there; then
//!   writes the backup and `restore-dns.ps1` FIRST, then runs one elevated
//!   script (UAC prompt). Declined: the backup is removed, nothing changed.
//!   Script failure: the backup is kept, so restore can undo a partial change.
//! - `system_dns_restore()` -> `SystemDnsState`: runs the restore script made
//!   from the backup, elevated; on success the backup is gone.
//! - `adguard_running()` -> bool (read only process list)

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use tauri::{AppHandle, Manager, State};

use super::backup::{self, Backup};
use super::{SIEVE_V4, SIEVE_V6, SysDnsError, SystemDnsState, script, state, win};
use crate::dns::commands::DnsState;
use crate::dns::engine::system_clock;

/// The port Windows' DNS client asks on; it cannot be changed.
pub const DNS_PORT: u16 = 53;

/// The two addresses Windows will ask, with the DNS port.
pub fn sieve_addrs() -> [SocketAddr; 2] {
    [SocketAddr::new(IpAddr::V4(SIEVE_V4), DNS_PORT), SocketAddr::new(IpAddr::V6(SIEVE_V6), DNS_PORT)]
}

/// Windows may be pointed here only when the filter listens on both
/// addresses Windows will ask. Says what is missing otherwise.
pub fn point_ready(binds: &[SocketAddr]) -> Result<(), String> {
    let missing: Vec<String> = sieve_addrs().iter().filter(|a| !binds.contains(a)).map(SocketAddr::to_string).collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("the DNS filter does not listen on {}; Windows would ask there", missing.join(" and ")))
    }
}

fn backup_dir(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(backup::dir_in(&app.path().app_data_dir().map_err(|e| format!("no app data dir: {e}"))?))
}

/// The state now: adapters read, backup looked for.
pub fn read_state(dir: &Path) -> Result<SystemDnsState, SysDnsError> {
    Ok(state(win::read_interfaces()?, backup::exists(dir), Some(dir.display().to_string())))
}

/// Backup first, then the elevated point script.
pub fn point(dir: &Path, made_at: u64) -> Result<SystemDnsState, SysDnsError> {
    let interfaces = win::read_interfaces()?;
    if interfaces.is_empty() {
        return Err(SysDnsError::Refused("no active network adapter to point at Sieve".to_owned()));
    }
    let snapshot = Backup { v: backup::BACKUP_VERSION, made_at, interfaces };
    backup::write(dir, &snapshot)?;
    let script_path = backup::point_path(dir);
    backup::write_script(&script_path, &script::point_script(&snapshot.interfaces, &backup::backup_path(dir)))?;
    match win::run_elevated(&script_path) {
        Ok(0) => read_state(dir),
        Ok(code) => Err(SysDnsError::ScriptFailed { code, restore: backup::restore_path(dir).display().to_string() }),
        Err(SysDnsError::Declined) => {
            // Nothing ran: the backup describes no change, so it goes.
            backup::remove(dir)?;
            Err(SysDnsError::Declined)
        }
        Err(e) => Err(e),
    }
}

/// The elevated restore from the backup.
pub fn restore(dir: &Path) -> Result<SystemDnsState, SysDnsError> {
    let Some(saved) = backup::read(dir)? else {
        return Err(SysDnsError::Refused("there is no backup to restore: Sieve did not change Windows DNS".to_owned()));
    };
    // Written again from the backup so the script run is exactly the generated one.
    let script_path = backup::restore_path(dir);
    backup::write_script(&script_path, &script::restore_script(&saved.interfaces, &backup::backup_path(dir)))?;
    match win::run_elevated(&script_path)? {
        0 => {
            backup::remove(dir)?;
            read_state(dir)
        }
        code => Err(SysDnsError::ScriptFailed { code, restore: script_path.display().to_string() }),
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, SysDnsError> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("system DNS task failed: {e}"))?
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn system_dns_state(app: AppHandle) -> Result<SystemDnsState, String> {
    let dir = backup_dir(&app)?;
    blocking(move || read_state(&dir)).await
}

#[tauri::command]
pub async fn system_dns_point(app: AppHandle, dns: State<'_, DnsState>) -> Result<SystemDnsState, String> {
    {
        let slot = dns.lock().await;
        let engine = slot.as_ref().ok_or("start DNS filtering before pointing Windows at it")?;
        point_ready(engine.local_addrs())?;
        let check = engine.self_check().await;
        if !check.pass {
            return Err("the DNS filter's self check failed; Windows was not pointed at it".to_owned());
        }
    }
    let dir = backup_dir(&app)?;
    let now = system_clock()();
    blocking(move || point(&dir, now)).await
}

#[tauri::command]
pub async fn system_dns_restore(app: AppHandle) -> Result<SystemDnsState, String> {
    let dir = backup_dir(&app)?;
    blocking(move || restore(&dir)).await
}

#[tauri::command]
pub async fn adguard_running() -> Result<bool, String> {
    blocking(|| Ok(win::adguard_in(&win::process_names()?))).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointing_needs_the_filter_on_both_loopback_addresses_at_port_53() {
        let v4: SocketAddr = "127.0.0.1:53".parse().expect("a");
        let v6: SocketAddr = "[::1]:53".parse().expect("a");
        assert!(point_ready(&[v4, v6]).is_ok());
        assert!(point_ready(&[v6, v4]).is_ok());
        assert_eq!(point_ready(&[v4]).expect_err("no v6"), "the DNS filter does not listen on [::1]:53; Windows would ask there");
        let test_port: SocketAddr = "127.0.0.1:5353".parse().expect("a");
        assert!(point_ready(&[test_port, v6]).is_err(), "a test port is not where Windows asks");
        assert!(point_ready(&[]).is_err());
    }

    #[test]
    fn restore_without_a_backup_is_refused_before_anything_runs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = backup::dir_in(tmp.path());
        assert!(matches!(restore(&dir), Err(SysDnsError::Refused(_))));
        assert!(!backup::restore_path(&dir).exists(), "no script was written");
    }

    /// Live check for the `filtering.systemDns` data switch. READ ONLY: it
    /// changes nothing. Passes only after the user pointed Windows at Sieve
    /// in the app (Settings > Filtering) with Sieve running: every active
    /// adapter asks 127.0.0.1 / ::1, and both answer a blocked name with the
    /// block answer and example.com with a real address.
    #[tokio::test]
    #[ignore = "live: needs Windows pointed at a running Sieve (done by the user in the app)"]
    async fn live_system_dns_points_at_sieve() {
        let ifaces = win::read_interfaces().expect("adapters readable");
        println!("{}", serde_json::to_string_pretty(&ifaces).expect("json"));
        assert!(!ifaces.is_empty(), "no active adapter");
        for i in &ifaces {
            assert!(super::super::uses_sieve(i), "{} does not use Sieve: {:?} / {:?}", i.alias, i.v4.servers, i.v6.servers);
        }
        use crate::dns::probe;
        // The app's rule count cannot be read from here (1 skips the rules
        // check); a listed name answered with the block answer proves a list.
        let check = probe::self_check(&sieve_addrs(), 1, "example.com").await;
        println!("{}", serde_json::to_string(&check).expect("json"));
        assert!(check.pass);
        for addr in sieve_addrs() {
            let m = probe::query_a(addr, "doubleclick.net").await.expect("answered");
            assert!(probe::is_block_answer(&m), "doubleclick.net on {addr}: {}", probe::describe(&m));
        }
    }
}
