//! Makes the two artefacts of slice 11 from local files, for the user to sign
//! (`docs/live/updates.md`). No network: both inputs are already on disk.
//!
//! ```text
//! validation_bundle ct-logs <log_list.json> <log_list.sig> <out>
//! validation_bundle crlite <out> <full filter> [<delta> ...]
//! ```
//!
//! Each output goes through the reader the engine uses before it is written, so a
//! file the engine would refuse is never handed over for signing.

use std::path::Path;
use std::process::ExitCode;

use sieve_engine::tls::crlite::{Crlite, encode_bundle};
use sieve_engine::tls::ct::{LOG_LIST_KEY, LogList, encode_envelope};

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(Path::new(path)).map_err(|e| format!("{path}: {e}"))
}

fn ct_logs(json: &str, signature: &str, out: &str) -> Result<String, String> {
    let envelope = encode_envelope(&read(signature)?, &read(json)?)?;
    let list = LogList::from_envelope(&envelope, LOG_LIST_KEY)?;
    std::fs::write(out, envelope).map_err(|e| format!("{out}: {e}"))?;
    Ok(format!("{out}: the log list of {} ms since the epoch, signature good", list.timestamp_ms))
}

fn crlite(out: &str, filters: &[String]) -> Result<String, String> {
    if filters.is_empty() {
        return Err("no filter given".into());
    }
    let filters: Vec<Vec<u8>> = filters.iter().map(|f| read(f)).collect::<Result<_, _>>()?;
    let bundle = encode_bundle(&filters)?;
    let held = Crlite::from_bundle(&bundle)?;
    std::fs::write(out, bundle).map_err(|e| format!("{out}: {e}"))?;
    Ok(format!("{out}: {} filters", held.filters()))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let done = match args.as_slice() {
        ["ct-logs", json, signature, out] => ct_logs(json, signature, out),
        ["crlite", out, filters @ ..] => crlite(out, &filters.iter().map(ToString::to_string).collect::<Vec<_>>()),
        _ => Err("usage: validation_bundle ct-logs <log_list.json> <log_list.sig> <out> | crlite <out> <full filter> [<delta> ...]".into()),
    };
    match done {
        Ok(said) => {
            println!("{said}");
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("{why}");
            ExitCode::FAILURE
        }
    }
}
