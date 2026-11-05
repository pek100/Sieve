//! The verbs' Windows side: the service registration, the ProgramData
//! folder, the routes. Each verb is a list of [`Step`]s that all run; see
//! the module doc of `service` for what each verb does.

use std::ffi::OsString;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, SC_HANDLE, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, SERVICE_REQUIRED_PRIVILEGES_INFOW,
};
use windows::core::PWSTR;
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::acl::{PROGRAM_DATA_SDDL, set_dir_security, token_user_sid};
use super::image::check_this_exe;
use super::state::{self, State};
use super::{
    DESCRIPTION, DISPLAY_NAME, FAILURE_RESET, FOLDER_STEP, REQUIRED_PRIVILEGES, RESTART_DELAY, RESTARTS, SERVICE_NAME,
    STOP_WAIT, Step, image_exe,
};
use crate::ca::removal;
use crate::ca::win::{RegistryFirefoxPolicy, WindowsRootStore};
use crate::route::apply::clear_stale;
use crate::route::journal::Journal;

const POLL: Duration = Duration::from_millis(250);

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager, String> {
    ServiceManager::local_computer(None::<&str>, access).map_err(|e| format!("service manager: {e}"))
}

fn is_missing(e: &windows_service::Error) -> bool {
    matches!(e, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST.0 as i32))
}

/// The service, or None when it is not installed.
fn open(access: ServiceAccess) -> Result<Option<Service>, String> {
    match manager(ServiceManagerAccess::CONNECT)?.open_service(SERVICE_NAME, access) {
        Ok(s) => Ok(Some(s)),
        Err(e) if is_missing(&e) => Ok(None),
        Err(e) => Err(format!("open {SERVICE_NAME}: {e}")),
    }
}

fn info() -> Result<ServiceInfo, String> {
    Ok(ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe().map_err(|e| e.to_string())?,
        launch_arguments: vec![],
        dependencies: vec![],
        // None is LocalSystem.
        account_name: None,
        account_password: None,
    })
}

/// A REG_MULTI_SZ: each name NUL-terminated, then one more NUL.
fn multi_sz(names: &[&str]) -> Vec<u16> {
    names.iter().flat_map(|n| n.encode_utf16().chain(std::iter::once(0))).chain(std::iter::once(0)).collect()
}

fn set_required_privileges(service: &Service) -> Result<(), String> {
    let mut list = multi_sz(REQUIRED_PRIVILEGES);
    let info = SERVICE_REQUIRED_PRIVILEGES_INFOW { pmszRequiredPrivileges: PWSTR(list.as_mut_ptr()) };
    let handle = SC_HANDLE(service.raw_handle() as *mut _);
    // SAFETY: `handle` is the open service; `info` points at `list`, which
    // outlives the call.
    unsafe { ChangeServiceConfig2W(handle, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, Some((&raw const info).cast())) }
        .map_err(|e| format!("required privileges: {e}"))
}

fn recovery() -> ServiceFailureActions {
    let restart = ServiceAction { action_type: ServiceActionType::Restart, delay: RESTART_DELAY };
    let mut actions = vec![restart; RESTARTS];
    actions.push(ServiceAction { action_type: ServiceActionType::None, delay: Duration::ZERO });
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(FAILURE_RESET),
        reboot_msg: None,
        command: None,
        actions: Some(actions),
    }
}

/// The exe the installed service is registered with, from its ImagePath.
fn registered_image(service: &Service) -> Result<std::path::PathBuf, String> {
    let config = service.query_config().map_err(|e| format!("query config: {e}"))?;
    Ok(image_exe(&config.executable_path.to_string_lossy()))
}

/// Before anything is registered: only SYSTEM, Administrators and
/// TrustedInstaller can change this exe, what is beside it, and the folders
/// above (`image`). Nothing is re-ACLed here: the installer's hook locked the
/// folder; this proves it.
fn own_folder() -> Result<String, String> {
    check_this_exe().map_err(|why| format!("{why}. Nothing was installed"))
}

fn register() -> Result<String, String> {
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START;
    let info = info()?;
    let (service, done) = match open(access)? {
        Some(s) => {
            let was = registered_image(&s)?;
            s.change_config(&info).map_err(|e| format!("change config: {e}"))?;
            let done = if was == info.executable_path { "updated".to_string() } else { format!("updated (was {})", was.display()) };
            (s, done)
        }
        None => {
            let m = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
            (m.create_service(&info, access).map_err(|e| format!("create: {e}"))?, "created".to_string())
        }
    };
    service.set_description(DESCRIPTION).map_err(|e| format!("description: {e}"))?;
    service.update_failure_actions(recovery()).map_err(|e| format!("recovery: {e}"))?;
    service.set_failure_actions_on_non_crash_failures(true).map_err(|e| format!("recovery flag: {e}"))?;
    set_required_privileges(&service)?;
    Ok(format!("{done}: LocalSystem, automatic start, restart after 5 s twice, privileges {REQUIRED_PRIVILEGES:?}"))
}

fn program_data() -> Result<String, String> {
    let pd = state::program_data()?;
    let sieve = state::sieve_dir(&pd);
    std::fs::create_dir_all(&sieve).map_err(|e| format!("{}: {e}", sieve.display()))?;
    // Owner and DACL are set before anything is written inside, and again on
    // every install (a folder someone else created first is taken over).
    set_dir_security(&sieve, PROGRAM_DATA_SDDL)?;
    let engine = state::engine_dir(&pd);
    std::fs::create_dir_all(&engine).map_err(|e| format!("{}: {e}", engine.display()))?;
    Ok(format!("{} (SYSTEM and Administrators only)", engine.display()))
}

fn record_owner() -> Result<String, String> {
    let sid = token_user_sid()?;
    let engine = state::engine_dir(&state::program_data()?);
    state::write(&engine, &State { owner_sid: Some(sid.clone()) })?;
    Ok(format!("pipe user {sid}"))
}

fn wait_for(service: &Service, want: ServiceState) -> Result<(), String> {
    let deadline = Instant::now() + STOP_WAIT;
    loop {
        let now = service.query_status().map_err(|e| format!("status: {e}"))?.current_state;
        if now == want {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("still {now:?} after {} s", STOP_WAIT.as_secs()));
        }
        std::thread::sleep(POLL);
    }
}

fn start() -> Result<String, String> {
    let service = open(ServiceAccess::QUERY_STATUS | ServiceAccess::START)?.ok_or("not installed")?;
    if service.query_status().map_err(|e| e.to_string())?.current_state == ServiceState::Running {
        return Ok("already running".into());
    }
    service.start::<&str>(&[]).map_err(|e| format!("start: {e}"))?;
    wait_for(&service, ServiceState::Running)?;
    Ok("running".into())
}

fn stop() -> Result<String, String> {
    let Some(service) = open(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)? else {
        return Ok("not installed".into());
    };
    if service.query_status().map_err(|e| e.to_string())?.current_state == ServiceState::Stopped {
        return Ok("already stopped".into());
    }
    service.stop().map_err(|e| format!("stop: {e}"))?;
    wait_for(&service, ServiceState::Stopped)?;
    Ok("stopped".into())
}

/// Deletes the service by name, wherever its image was registered (an older
/// build may sit in another folder); the report names that image so the
/// installer's hook and a person can remove it.
fn delete() -> Result<String, String> {
    let Some(service) = open(ServiceAccess::DELETE | ServiceAccess::QUERY_CONFIG)? else {
        return Ok("not installed".into());
    };
    let image = registered_image(&service)?;
    service.delete().map_err(|e| format!("delete: {e}"))?;
    Ok(format!("deleted (its image was {})", image.display()))
}

/// Keeps `engine\ca.json` while it records anything unremoved, so rerunning
/// uninstall still knows the thumbprints.
fn remove_program_data() -> Result<String, String> {
    let pd = state::program_data()?;
    removal::remove_program_data(&state::sieve_dir(&pd), &state::engine_dir(&pd))
}

/// Every root Sieve recorded and the Firefox policy if Sieve set it. Admin
/// rights reach both, so this runs in the verb, first (plan 2.4).
fn trust() -> Result<String, String> {
    let dir = state::engine_dir(&state::program_data()?);
    removal::remove_trust(&dir, &WindowsRootStore, &RegistryFirefoxPolicy)
}

/// The keys: their DACL is SYSTEM only, so the service deletes them, started
/// once with [`removal::PURGE_ARG`]. It writes the outcome to `ca.json` and a
/// failure's reason to `last-error.txt`.
fn ca_keys() -> Result<String, String> {
    let dir = state::engine_dir(&state::program_data()?);
    removal::purge_through_service(&dir, || {
        let Some(service) = open(ServiceAccess::QUERY_STATUS | ServiceAccess::START)? else {
            return Err("the service is not installed, so the keys cannot be reached: run install, then uninstall".into());
        };
        service.start(&[removal::PURGE_ARG]).map_err(|e| format!("start: {e}"))?;
        wait_for(&service, ServiceState::Stopped)
    })
}

/// A service kept for uninstall's rerun starts on demand only: nothing of Sieve
/// runs at the next boot, and `install` makes it automatic again.
fn hold_for_rerun() -> Result<(), String> {
    let Some(service) = open(ServiceAccess::QUERY_CONFIG | ServiceAccess::CHANGE_CONFIG)? else {
        return Err("the service is not installed: run install, then uninstall".into());
    };
    let held = ServiceInfo { start_type: ServiceStartType::OnDemand, executable_path: registered_image(&service)?, ..info()? };
    service.change_config(&held).map_err(|e| format!("change config: {e}"))
}

fn delete_service() -> Result<String, String> {
    let dir = state::engine_dir(&state::program_data()?);
    removal::delete_service_once_clear(&dir, hold_for_rerun, delete)
}

/// Every route on an interface named "Sieve" and every journalled one (a
/// journal that is not there is fine: nothing was routed).
fn routes() -> Result<String, String> {
    let dir = state::engine_dir(&state::program_data()?);
    let done = clear_stale(&Journal::new(&dir));
    if done.contains("FAILED") { Err(done) } else { Ok(done) }
}

/// The folder check first; when it refuses, nothing else runs: no service is
/// registered for an exe that users can replace.
pub fn install() -> Vec<Step> {
    install_steps(own_folder, || {
        vec![
            Step::run("service", register),
            Step::run("program data", program_data),
            Step::run("owner", record_owner),
            Step::run("start", start),
        ]
    })
}

fn install_steps(folder: impl FnOnce() -> Result<String, String>, rest: impl FnOnce() -> Vec<Step>) -> Vec<Step> {
    let first = Step::run(FOLDER_STEP, folder);
    if first.outcome.is_err() {
        return vec![first];
    }
    let mut steps = vec![first];
    steps.extend(rest());
    steps
}

/// Removal comes first in every off path (plan 2.4); `ca keys` needs the
/// service, so it comes before the deletion, which waits until nothing recorded
/// remains (a rerun needs it too), and `program data` last.
type StepFn = fn() -> Result<String, String>;
const UNINSTALL: [(&str, StepFn); 6] = [
    ("routes", routes),
    ("stop", stop),
    ("trust", trust),
    ("ca keys", ca_keys),
    ("delete service", delete_service),
    ("program data", remove_program_data),
];

pub fn uninstall() -> Vec<Step> {
    UNINSTALL.iter().map(|(name, step)| Step::run(name, *step)).collect()
}

pub fn restore() -> Vec<Step> {
    vec![Step::run("routes", routes), Step::run("stop", stop)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privileges_are_a_double_nul_terminated_list() {
        let w = multi_sz(&["SeA", "SeB"]);
        assert_eq!(String::from_utf16_lossy(&w), "SeA\0SeB\0\0");
        assert_eq!(multi_sz(&[]), [0]);
    }

    #[test]
    fn recovery_restarts_twice_then_does_nothing() {
        let r = recovery();
        let kinds: Vec<_> = r.actions.unwrap().iter().map(|a| (a.action_type, a.delay)).collect();
        assert_eq!(
            kinds,
            [
                (ServiceActionType::Restart, RESTART_DELAY),
                (ServiceActionType::Restart, RESTART_DELAY),
                (ServiceActionType::None, Duration::ZERO)
            ]
        );
        assert!(matches!(r.reset_period, ServiceFailureResetPeriod::After(d) if d == FAILURE_RESET));
    }

    #[test]
    fn trust_steps_come_before_service_deletion() {
        let names: Vec<&str> = UNINSTALL.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, ["routes", "stop", "trust", "ca keys", "delete service", "program data"]);
    }

    #[test]
    fn a_refused_folder_registers_nothing() {
        let mut ran = false;
        let steps = install_steps(|| Err("refused: E:\\Sieve".into()), || {
            ran = true;
            vec![]
        });
        assert!(!ran, "no service step may run after a refusal");
        assert_eq!(steps.len(), 1);
        assert_eq!(super::super::report("install", &steps).1, super::super::EXIT_UNSAFE_FOLDER);
        let steps = install_steps(|| Ok("fine".into()), || vec![Step::run("service", || Ok("created".into()))]);
        assert_eq!(steps.iter().map(|s| s.name).collect::<Vec<_>>(), [FOLDER_STEP, "service"]);
    }

    /// Read only: this test binary sits in the user's own target folder, so
    /// the real check refuses it (and the install verb would register
    /// nothing).
    #[test]
    fn the_test_binary_folder_is_refused() {
        let why = own_folder().unwrap_err();
        assert!(why.starts_with("refused: ") && why.ends_with("Nothing was installed"), "{why}");
    }

    /// Read only: the service manager answers, and the engine's service is
    /// either absent or installed (nothing is changed).
    #[test]
    fn opening_the_service_read_only_works_without_admin() {
        assert!(open(ServiceAccess::QUERY_STATUS).is_ok());
    }
}
