//! The Windows service and its verbs (plan 1.5, slice 2).
//!
//! `sieve-engine.exe` with no argument is the service itself (started by the
//! SCM). The verbs are run by the NSIS installer, elevated, or by a person at
//! an admin prompt:
//! - `install`: create or update the service (LocalSystem, automatic start,
//!   restart after 5 s twice then stay stopped, required privileges trimmed),
//!   create `ProgramData\Sieve\engine` with an admin-only DACL, record the
//!   installing user's SID (the pipe's one non-admin user), start it;
//! - `uninstall`: remove Sieve's routes, stop and delete the service, delete
//!   `ProgramData\Sieve`. Every step runs even when one fails, and rerunning
//!   it is safe;
//! - `restore`: the emergency off. Delete every route on an interface named
//!   "Sieve" and stop the service; nothing else.
//!
//! In slice 2 the running service changes nothing about traffic: no adapter,
//! no routes. It only answers the pipe.

pub mod acl;
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
/// LocalSystem token. Slice 2 creates a pipe and reads process images and
/// session ids, which need none beyond traverse checking. Slice 3 (the Wintun
/// adapter and routes) must measure and add its own; UNVERIFIED until then.
pub const REQUIRED_PRIVILEGES: &[&str] = &["SeChangeNotifyPrivilege"];

/// How long `uninstall` and `restore` wait for the service to stop.
pub const STOP_WAIT: Duration = Duration::from_secs(20);

pub const USAGE: &str = "\
usage: sieve-engine.exe [install | uninstall | restore]
  (no argument)  run as the Windows service (started by Windows only)
  install        create or update the service and start it (admin)
  uninstall      stop filtering, delete the service and ProgramData\\Sieve (admin)
  restore        delete every route on an interface named \"Sieve\" and stop the service (admin)
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// Run as the service.
    Service,
    Install,
    Uninstall,
    Restore,
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
            other => Err(format!("unknown verb: {other}")),
        },
        _ => Err("one verb at most".into()),
    }
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

/// The verb's report: one line per step, and the exit code (0 when every
/// step succeeded, 1 otherwise). A failed step never hides the later ones.
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
    (text, i32::from(failed > 0))
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
    fn recovery_is_two_restarts_then_stopped() {
        assert_eq!((RESTART_DELAY.as_secs(), RESTARTS, FAILURE_RESET.as_secs()), (5, 2, 3_600));
        assert_eq!(REQUIRED_PRIVILEGES, ["SeChangeNotifyPrivilege"]);
    }
}
