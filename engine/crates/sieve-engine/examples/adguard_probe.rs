//! Live proof L1 (docs/live/engine-slice-3.md): what the engine's AdGuard check
//! sees on this computer. With `--send` and AdGuard's service alive it opens one
//! TCP socket to a documentation address, writes nothing, prints one JSON line
//! and exits. It changes nothing, and needs no elevation. Without `--send` it
//! prints this usage and sends nothing.
const USAGE: &str = "usage: adguard_probe --send\n\
Sends one TCP SYN to a documentation address while AdGuard's service is alive, then prints one JSON line.";

#[cfg(windows)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    use sieve_engine::coexist::{self, AdguardService, ProbeObservation, intercepted};
    use sieve_engine::flow::flows::OwnerRow;
    use sieve_engine::route::table::read;

    if std::env::args().nth(1).as_deref() != Some("--send") {
        println!("{USAGE}");
        return Ok(());
    }
    let (state, service) = coexist::adguard_service_state()?;
    let AdguardService::Alive { pid } = service else {
        println!("{}", serde_json::json!({ "service": state, "probed": false, "verdict": false }));
        return Ok(());
    };
    let tables = read::tables()?;
    let Some(obs) = coexist::probe_adguard(&tables).await? else {
        println!("{}", serde_json::json!({ "service": state, "pid": pid, "probed": false, "verdict": false, "no_egress": true }));
        return Ok(());
    };
    let row_text = |r: &OwnerRow| serde_json::json!({ "local": r.local.to_string(), "remote": r.remote.map(|a| a.to_string()), "pid": r.pid });
    let touching: Vec<_> = obs.rows.iter().filter(|r| obs.touches(r)).map(row_text).collect();
    let adguards: Vec<_> = obs.rows.iter().filter(|r| Some(r.pid) == pid).map(row_text).collect();
    let row_witness = intercepted(&ProbeObservation { connected: false, ..obs.clone() }, pid);
    println!(
        "{}",
        serde_json::json!({
            "service": state,
            "pid": pid,
            "probed": true,
            "local": obs.local.to_string(),
            "dest": obs.dest.to_string(),
            "connect_witness": obs.connected,
            "row_witness": row_witness,
            "verdict": intercepted(&obs, pid),
            "rows_touching_the_probe": touching,
            "rows_of_adguards_process": adguards,
        })
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Windows only. {USAGE}");
}
