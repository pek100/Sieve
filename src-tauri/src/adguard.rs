//! AdGuard for Windows beside Sieve (plan 1.7, the user's decision of
//! 2026-10-17: "detect it and offer to pause it").
//!
//! Read only: AdGuard's service state comes with `engine_probe` (`adguard`).
//!
//! The pause offer: AdGuard exposes no supported way to pause its protection
//! from outside (read 2026-10-18 from the install at `E:\AdGuard`: no command
//! line switch in its executables, and its `adguard:` link handler takes only
//! `add_dns_server`, `import_user_configuration`, `license`,
//! `oauth_authorize`, `oauth_register`, `subscribe` and `userscript`; its
//! UI-to-service channel is private). So, and only when the user clicks,
//! `adguard_stop` and `adguard_start` run ONE elevated command each, which
//! Windows asks the user to approve: `sc.exe stop "Adguard Service"` or
//! `sc.exe start "Adguard Service"`, from System32, with fixed arguments (no
//! input from the web side reaches them). This is the app's only elevation,
//! and law 8 holds it to exactly these two commands.

use std::time::{Duration, Instant};

/// AdGuard for Windows' service (the engine's `coexist::ADGUARD_SERVICE`,
/// `ADGUARD_SERVICE` in src/core/engine.ts; law 8 keeps the three equal).
pub const ADGUARD_SERVICE: &str = "Adguard Service";

/// How long a stop or start may take before it is reported as not done.
pub const SERVICE_WAIT: Duration = Duration::from_secs(30);

/// The two things the pause offer does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Stop,
    Start,
}

impl ServiceAction {
    /// sc.exe's arguments: the verb and the quoted service name, nothing else.
    pub fn sc_arguments(self) -> String {
        let verb = match self {
            ServiceAction::Stop => "stop",
            ServiceAction::Start => "start",
        };
        format!("{verb} \"{ADGUARD_SERVICE}\"")
    }
}

/// sc.exe's own "nothing to do" answers: stop of a stopped service (1062),
/// start of a running one (1056).
pub const SC_ALREADY: [u32; 2] = [1062, 1056];
/// ShellExecuteEx's answer when the user declined the Windows prompt.
pub const ERROR_CANCELLED: u32 = 1223;

#[cfg(windows)]
mod imp {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::core::HSTRING;

    use super::{ERROR_CANCELLED, SERVICE_WAIT, ServiceAction};

    /// `%SystemRoot%\System32\sc.exe`, never a name looked up on PATH.
    fn sc_exe() -> Result<String, String> {
        let root = std::env::var("SystemRoot").map_err(|_| "SystemRoot is not set".to_string())?;
        Ok(format!(r"{root}\System32\sc.exe"))
    }

    /// Runs sc.exe with the action's fixed arguments through the Windows
    /// elevation prompt and returns its exit code.
    pub fn run_elevated_sc(action: ServiceAction) -> Result<u32, String> {
        let file = HSTRING::from(sc_exe()?);
        let params = HSTRING::from(action.sc_arguments());
        let verb = HSTRING::from("runas");
        let mut info = SHELLEXECUTEINFOW {
            cbSize: u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>()).unwrap_or(0),
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: windows::core::PCWSTR(verb.as_ptr()),
            lpFile: windows::core::PCWSTR(file.as_ptr()),
            lpParameters: windows::core::PCWSTR(params.as_ptr()),
            // SW_HIDE: sc.exe needs no window.
            nShow: 0,
            ..Default::default()
        };
        // SAFETY: `info` points at strings that outlive the call; Windows
        // fills hProcess, closed below.
        if let Err(e) = unsafe { ShellExecuteExW(&mut info) } {
            let code = (e.code().0 as u32) & 0xffff;
            return Err(if code == ERROR_CANCELLED {
                "you declined the Windows prompt, so nothing changed".to_string()
            } else {
                format!("Windows could not run sc.exe: {e}")
            });
        }
        let process = info.hProcess;
        let ms = u32::try_from(SERVICE_WAIT.as_millis()).unwrap_or(u32::MAX);
        let mut code = 1u32;
        // SAFETY: `process` is the handle ShellExecuteEx returned; closed once.
        unsafe {
            WaitForSingleObject(process, ms);
            let _ = GetExitCodeProcess(process, &mut code);
            let _ = CloseHandle(process);
        }
        Ok(code)
    }
}

/// Runs the action (elevated, the user approves) and waits until the service
/// reached its end state, read only.
#[cfg(windows)]
fn change(action: ServiceAction) -> Result<(), String> {
    use crate::engine::{ServiceFact, service_fact};
    let code = imp::run_elevated_sc(action)?;
    if code != 0 && !SC_ALREADY.contains(&code) {
        return Err(format!("sc.exe {} ended with code {code}", action.sc_arguments()));
    }
    let want = match action {
        ServiceAction::Stop => ServiceFact::Stopped,
        ServiceAction::Start => ServiceFact::Running,
    };
    let deadline = Instant::now() + SERVICE_WAIT;
    loop {
        let now = service_fact(ADGUARD_SERVICE)?;
        if now == want {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("{ADGUARD_SERVICE} is still {now:?} after {} s", SERVICE_WAIT.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[cfg(not(windows))]
fn change(_action: ServiceAction) -> Result<(), String> {
    Err("AdGuard for Windows runs on Windows only".into())
}

/// Command: the pause offer. Stops AdGuard's service after the user approves
/// the Windows prompt; never called except from that button.
#[tauri::command]
pub async fn adguard_stop() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(|| change(ServiceAction::Stop)).await.map_err(|e| e.to_string())?
}

/// Command: "Start AdGuard again", the pause offer's undo.
#[tauri::command]
pub async fn adguard_start() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(|| change(ServiceAction::Start)).await.map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The only elevated commands: exactly these two argument lists.
    #[test]
    fn the_pause_offer_runs_sc_with_fixed_arguments_only() {
        assert_eq!(ServiceAction::Stop.sc_arguments(), r#"stop "Adguard Service""#);
        assert_eq!(ServiceAction::Start.sc_arguments(), r#"start "Adguard Service""#);
    }

    #[test]
    fn the_service_name_is_the_engines() {
        let engine = include_str!("../../engine/crates/sieve-engine/src/coexist.rs");
        assert!(engine.contains(&format!("pub const ADGUARD_SERVICE: &str = \"{ADGUARD_SERVICE}\";")));
        let core = include_str!("../../src/core/engine.ts");
        assert!(core.contains(&format!("export const ADGUARD_SERVICE = \"{ADGUARD_SERVICE}\";")));
    }
}
