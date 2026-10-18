//! Is AdGuard for Windows running? Read only: the process list (Toolhelp
//! snapshot), no admin. AdGuard intercepts DNS with its own driver, so while
//! it runs Sieve's DNS filter sees nothing; the DNS card says so, and the
//! filtering engine (docs/plans/2026-10-17-https-filtering.md, 1.7) refuses
//! to start beside it.
//!
//! Command: `adguard_running()` -> bool.

/// Process image names (lower case) that mean AdGuard for Windows is running.
pub const ADGUARD_EXES: [&str; 2] = ["adguard.exe", "adguardsvc.exe"];

/// Errors of this module; strings only at the command boundary.
#[derive(Debug, thiserror::Error)]
pub enum AdguardError {
    #[error("{0}")]
    Read(String),
}

/// True when one of `names` is an AdGuard process (case does not matter).
pub fn adguard_in<S: AsRef<str>>(names: &[S]) -> bool {
    names.iter().any(|n| ADGUARD_EXES.contains(&n.as_ref().to_ascii_lowercase().as_str()))
}

#[cfg(windows)]
mod imp {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};

    use super::AdguardError;

    fn from_wide(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    pub fn process_names() -> Result<Vec<String>, AdguardError> {
        // SAFETY: a process snapshot; closed below.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|e| AdguardError::Read(format!("process list: {e}")))?;
        let mut names = Vec::new();
        let mut entry = PROCESSENTRY32W { dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap_or(0), ..Default::default() };
        // SAFETY: `entry.dwSize` is set; the snapshot handle is valid.
        let mut more = unsafe { Process32FirstW(snap, &mut entry) }.is_ok();
        while more {
            names.push(from_wide(&entry.szExeFile));
            // SAFETY: as above.
            more = unsafe { Process32NextW(snap, &mut entry) }.is_ok();
        }
        // SAFETY: the handle came from CreateToolhelp32Snapshot. A failed close leaks one handle; nothing to do.
        let _ = unsafe { CloseHandle(snap) };
        Ok(names)
    }
}

/// Every running process's image name. Read only.
#[cfg(windows)]
pub use imp::process_names;

#[cfg(not(windows))]
pub fn process_names() -> Result<Vec<String>, AdguardError> {
    Err(AdguardError::Read("the process list is read on Windows only".to_owned()))
}

#[tauri::command]
pub async fn adguard_running() -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(|| process_names().map(|names| adguard_in(&names)))
        .await
        .map_err(|e| format!("process list task failed: {e}"))?
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adguard_is_found_by_either_exe_in_any_case() {
        assert!(adguard_in(&["explorer.exe", "Adguard.exe"]));
        assert!(adguard_in(&["ADGUARDSVC.EXE"]));
        assert!(!adguard_in(&["explorer.exe", "adguardvpn.exe", "AdGuard Browser Assistant.exe"]));
        assert!(!adguard_in::<&str>(&[]));
    }

    /// Read only: the process list, without admin.
    #[cfg(windows)]
    #[test]
    fn reading_the_process_list_works_without_admin() {
        let names = process_names().expect("process list is readable");
        assert!(names.iter().any(|n| n.eq_ignore_ascii_case("cargo.exe") || n.to_ascii_lowercase().starts_with("sieve")), "{names:?}");
    }
}
