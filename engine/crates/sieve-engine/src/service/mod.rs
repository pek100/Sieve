//! The Windows service and its verbs (plan 1.5, slice 2).
//!
//! `sieve-engine.exe` with no argument is the service itself (started by the
//! SCM). The verbs are run by the NSIS installer, elevated, or by a person at
//! an admin prompt:
//! - `install`: first check that only SYSTEM, Administrators and
//!   TrustedInstaller can change the exe, everything beside it and the
//!   folders above it (`image`; the installer locked the folder and left its
//!   marker). If not, nothing else runs and the exit code is
//!   [`EXIT_UNSAFE_FOLDER`]. Then create or update the service (LocalSystem, automatic start,
//!   restart after 5 s twice then stay stopped, required privileges trimmed),
//!   create `ProgramData\Sieve\engine` with an admin-only DACL, record the
//!   installing user's SID (the pipe's one non-admin user), start it;
//! - `uninstall`: remove Sieve's routes, stop and delete the service (by
//!   name, wherever its registered image is), delete `ProgramData\Sieve`.
//!   Every step runs even when one fails, and rerunning it is safe;
//! - `restore`: the emergency off. Delete every route on an interface named
//!   "Sieve" and stop the service; nothing else;
//! - `update-finish`: the supervisor of a signed update (`update::finish`).
//!
//! The service runs the same `image` check at every start and refuses to run
//! (exit code [`EXIT_UNSAFE_FOLDER`], reason in `last-error.txt`) when it
//! fails, so a later ACL change cannot leave a SYSTEM service that users can
//! replace.
//!
//! The running service routes nothing until the user turns `filtering.engine`
//! on (`SetPolicy`); `runner` has its start-up order (slice 3).

pub mod acl;
pub mod image;
pub mod state;

#[cfg(windows)]
pub mod runner;
#[cfg(windows)]
pub mod scm;

use std::time::Duration;

pub const SERVICE_NAME: &str = "sieve-engine";
pub const DISPLAY_NAME: &str = "Sieve engine";
pub const DESCRIPTION: &str =
    "Sieve's filtering engine. While filtering is off it changes nothing on this computer's network.";

/// Recovery (plan 1.5): restart after this delay, `RESTARTS` times, then stay
/// stopped; the failure count resets after `FAILURE_RESET` without one.
pub const RESTART_DELAY: Duration = Duration::from_secs(5);
pub const RESTARTS: usize = 2;
pub const FAILURE_RESET: Duration = Duration::from_secs(3_600);

/// The privileges the service keeps; Windows strips every other one from its
/// LocalSystem token. Slice 2's pipe and process reads need none beyond
/// traverse checking. Slice 3 creates a Wintun adapter, which installs and
/// loads Wintun's driver on first use (SetupAPI and the driver store: load
/// driver, backup and restore). UNVERIFIED until the live check: an adapter
/// that cannot be created is a Setup blocker (the network stays as it was)
/// and its reason shows in the Engine block.
pub const REQUIRED_PRIVILEGES: &[&str] =
    &["SeChangeNotifyPrivilege", "SeLoadDriverPrivilege", "SeBackupPrivilege", "SeRestorePrivilege"];

/// How long `uninstall` and `restore` wait for the service to stop.
pub const STOP_WAIT: Duration = Duration::from_secs(20);

/// The supervisor of a signed update (`update::finish`), started by the engine
/// from a copy of itself in the staging folder.
pub const FINISH_VERB: &str = "update-finish";

pub const USAGE: &str = "\
usage: sieve-engine.exe [install | uninstall | restore | update-finish]
  (no argument)  run as the Windows service (started by Windows only)
  install        create or update the service and start it (admin)
  uninstall      stop filtering, delete the service and ProgramData\\Sieve (admin)
  restore        delete every route on an interface named \"Sieve\" and stop the service (admin)
  update-finish  finish a signed update in flight, or do nothing (started by the engine only)
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// Run as the service.
    Service,
    Install,
    Uninstall,
    Restore,
    UpdateFinish,
}

/// The verb from the command line (program name already skipped).
pub fn parse_verb<I: IntoIterator<Item = String>>(args: I) -> Result<Verb, String> {
    let args: Vec<String> = args.into_iter().collect();
    match args.as_slice() {
        [] => Ok(Verb::Service),
        [one] => match one.to_ascii_lowercase().as_str() {
            "install" => Ok(Verb::Install),
            "uninstall" => Ok(Verb::Uninstall),
            "restore" => Ok(Verb::Restore),
            FINISH_VERB => Ok(Verb::UpdateFinish),
            other => Err(format!("unknown verb: {other}")),
        },
        _ => Err("one verb at most".into()),
    }
}

/// The exe of a service's registered command line (its ImagePath): the text
/// between the first pair of quotes, or the whole line when it is not
/// quoted (windows-service quotes a path only when it needs it, and Sieve's
/// service has no arguments). The NSIS hooks parse it the same way.
pub fn image_exe(command_line: &str) -> std::path::PathBuf {
    let line = command_line.trim();
    let exe = match line.strip_prefix('"') {
        Some(rest) => rest.split('"').next().unwrap_or(rest),
        None => line,
    };
    std::path::PathBuf::from(exe)
}

/// One step of a verb and what came of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub name: &'static str,
    pub outcome: Result<String, String>,
}

impl Step {
    pub fn run(name: &'static str, f: impl FnOnce() -> Result<String, String>) -> Self {
        Self { name, outcome: f() }
    }
}

/// The step that checks who can change the engine's files (`image`).
pub const FOLDER_STEP: &str = "binary folder";

/// Exit code of a verb whose [`FOLDER_STEP`] refused, and the service's own
/// exit code when it refuses to start for the same reason. The installer's
/// hook names it (law 10).
pub const EXIT_UNSAFE_FOLDER: i32 = 3;

/// Process exit code after the watchdog deleted the routes of a hung engine
/// (plan 1.6.2); the service manager restarts it.
pub const EXIT_WATCHDOG: i32 = 5;

/// The verb's report: one line per step, and the exit code (0 when every
/// step succeeded, [`EXIT_UNSAFE_FOLDER`] when the folder check refused, 1
/// otherwise). A failed step never hides the later ones.
pub fn report(verb: &str, steps: &[Step]) -> (String, i32) {
    let mut text = String::new();
    for s in steps {
        let line = match &s.outcome {
            Ok(done) => format!("{verb}: {}: ok, {done}\n", s.name),
            Err(why) => format!("{verb}: {}: FAILED, {why}\n", s.name),
        };
        text.push_str(&line);
    }
    let failed = steps.iter().filter(|s| s.outcome.is_err()).count();
    text.push_str(&if failed == 0 {
        format!("{verb}: done\n")
    } else {
        format!("{verb}: {failed} of {} steps failed\n", steps.len())
    });
    let unsafe_folder = steps.iter().any(|s| s.name == FOLDER_STEP && s.outcome.is_err());
    let code = if unsafe_folder { EXIT_UNSAFE_FOLDER } else { i32::from(failed > 0) };
    (text, code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn verbs_parse_case_insensitively_and_nothing_else_does() {
        assert_eq!(parse_verb(args(&[])), Ok(Verb::Service));
        assert_eq!(parse_verb(args(&["install"])), Ok(Verb::Install));
        assert_eq!(parse_verb(args(&["UNINSTALL"])), Ok(Verb::Uninstall));
        assert_eq!(parse_verb(args(&["restore"])), Ok(Verb::Restore));
        assert!(parse_verb(args(&["start"])).is_err());
        assert!(parse_verb(args(&["install", "now"])).is_err());
    }

    /// No arguments: every input comes from the pending record (plan 7.5).
    #[test]
    fn update_finish_parses_with_no_arguments_and_usage_names_it() {
        assert_eq!(parse_verb(args(&[FINISH_VERB])), Ok(Verb::UpdateFinish));
        assert!(parse_verb(args(&[FINISH_VERB, r"C:\elsewhere"])).is_err());
        assert!(USAGE.contains(FINISH_VERB));
    }

    #[test]
    fn a_failed_step_is_reported_and_the_rest_still_listed() {
        let steps = [
            Step::run("routes", || Ok("0 removed".into())),
            Step::run("service", || Err("access denied".into())),
            Step::run("program data", || Ok("not there".into())),
        ];
        let (text, code) = report("uninstall", &steps);
        assert_eq!(code, 1);
        assert_eq!(
            text,
            "uninstall: routes: ok, 0 removed\nuninstall: service: FAILED, access denied\n\
             uninstall: program data: ok, not there\nuninstall: 1 of 3 steps failed\n"
        );
        assert_eq!(report("restore", &steps[..1]).1, 0);
    }

    #[test]
    fn the_registered_exe_is_read_quoted_or_not() {
        use std::path::Path;
        assert_eq!(image_exe(r#""C:\Program Files\Sieve\sieve-engine.exe""#), Path::new(r"C:\Program Files\Sieve\sieve-engine.exe"));
        assert_eq!(image_exe(r#""E:\Sieve\sieve-engine.exe" --flag"#), Path::new(r"E:\Sieve\sieve-engine.exe"));
        assert_eq!(image_exe(r"E:\Sieve\sieve-engine.exe"), Path::new(r"E:\Sieve\sieve-engine.exe"));
        assert_eq!(image_exe(" \"E:\\a b\\x.exe"), Path::new(r"E:\a b\x.exe"), "an unclosed quote takes the rest");
    }

    #[test]
    fn a_refused_folder_has_its_own_exit_code() {
        let steps = [Step::run(FOLDER_STEP, || Err("refused: E:\\Sieve: Authenticated Users may change it".into()))];
        let (text, code) = report("install", &steps);
        assert_eq!(code, EXIT_UNSAFE_FOLDER);
        assert_eq!(
            text,
            "install: binary folder: FAILED, refused: E:\\Sieve: Authenticated Users may change it\ninstall: 1 of 1 steps failed\n"
        );
        assert_eq!(report("install", &[Step::run(FOLDER_STEP, || Ok("fine".into()))]).1, 0);
        assert_ne!(EXIT_UNSAFE_FOLDER, 1, "distinct from an ordinary failed step");
    }

    /// The install live check compares `sc qprivs` with this exact list.
    #[test]
    fn the_install_live_check_expects_these_privileges() {
        let script = include_str!("../../../../../scripts/live/engine-install.ps1");
        let line = script.lines().find(|l| l.trim_start().starts_with("$want = @(")).expect("the $want line");
        let mut want: Vec<&str> = line.split('"').skip(1).step_by(2).collect();
        want.sort_unstable();
        let mut ours = REQUIRED_PRIVILEGES.to_vec();
        ours.sort_unstable();
        assert_eq!(want, ours);
    }

    #[test]
    fn recovery_is_two_restarts_then_stopped() {
        assert_eq!((RESTART_DELAY.as_secs(), RESTARTS, FAILURE_RESET.as_secs()), (5, 2, 3_600));
        assert_eq!(REQUIRED_PRIVILEGES[0], "SeChangeNotifyPrivilege");
        for banned in ["SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege"] {
            assert!(!REQUIRED_PRIVILEGES.contains(&banned), "{banned}");
        }
        assert_ne!(EXIT_WATCHDOG, EXIT_UNSAFE_FOLDER);
    }
}
