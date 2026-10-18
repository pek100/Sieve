//! sieve-engine.exe: the Windows service (no argument) and its verbs
//! `install`, `uninstall`, `restore` (see `sieve_engine::service`).

#[cfg(not(windows))]
fn main() {
    eprintln!("sieve-engine: Windows only");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    use sieve_engine::service::{USAGE, Verb, parse_verb, report, runner, scm};

    let verb = match parse_verb(std::env::args().skip(1)) {
        Ok(v) => v,
        Err(e) => {
            eprint!("sieve-engine: {e}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let (name, steps) = match verb {
        Verb::Service => {
            if let Err(e) = runner::run() {
                eprint!("sieve-engine: not started by Windows as a service ({e}).\n{USAGE}");
                std::process::exit(2);
            }
            return;
        }
        Verb::Install => ("install", scm::install()),
        Verb::Uninstall => ("uninstall", scm::uninstall()),
        Verb::Restore => ("restore", scm::restore()),
    };
    let (text, code) = report(name, &steps);
    print!("{text}");
    std::process::exit(code);
}
