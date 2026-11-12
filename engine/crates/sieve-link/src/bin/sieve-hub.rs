//! sieve-hub: the machine other devices' traffic exits through.
//!
//!   sieve-hub [--dir D] init [--name NAME]
//!   sieve-hub [--dir D] pair [--addr HOST:PORT] [--ttl SECS] [--label TEXT]
//!   sieve-hub [--dir D] devices
//!   sieve-hub [--dir D] revoke DEVICE
//!   sieve-hub [--dir D] rule DEVICE (allow-suffix|deny-suffix|allow-cidr|deny-cidr) VALUE
//!   sieve-hub [--dir D] limit DEVICE (concurrent|per-minute|bytes-per-sec) N
//!   sieve-hub [--dir D] run [--listen ADDR]... [--dial ADDR]...
//!
//! DEVICE is a fingerprint prefix (8+ hex digits) or the device's name.
//! The directory defaults to ./sieve-hub (or $SIEVE_HUB_DIR).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use sieve_link::hub::{EXIT_NOTICE, revoke_at};
use sieve_link::store::HubStore;
use sieve_link::{Hub, HubConfig};

fn usage() -> ExitCode {
    eprintln!(
        "usage: sieve-hub [--dir D] <init [--name N] | pair [--addr HOST:PORT] [--ttl SECS] [--label T] | devices | revoke DEVICE |\n\
         rule DEVICE allow-suffix|deny-suffix|allow-cidr|deny-cidr VALUE | limit DEVICE concurrent|per-minute|bytes-per-sec N |\n\
         run [--listen ADDR]... [--dial ADDR]...>"
    );
    ExitCode::from(2)
}

fn take_opt(args: &mut Vec<String>, name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    if i + 1 >= args.len() {
        return None;
    }
    let v = args.remove(i + 1);
    args.remove(i);
    Some(v)
}

fn take_all(args: &mut Vec<String>, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(v) = take_opt(args, name) {
        out.push(v);
    }
    out
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let dir = PathBuf::from(
        take_opt(&mut args, "--dir").or_else(|| std::env::var("SIEVE_HUB_DIR").ok()).unwrap_or_else(|| "sieve-hub".into()),
    );
    if args.is_empty() {
        return usage();
    }
    let cmd = args.remove(0);
    let r = match cmd.as_str() {
        "init" => {
            let name = take_opt(&mut args, "--name").unwrap_or_else(|| "hub".into());
            Hub::init(&dir, &name).map(|fp| {
                println!("hub initialized in {}", dir.display());
                println!("hub key fingerprint: {fp}");
            })
        }
        "pair" => {
            let addr = take_opt(&mut args, "--addr");
            let ttl = take_opt(&mut args, "--ttl").and_then(|s| s.parse().ok()).unwrap_or(sieve_link::pairing::DEFAULT_TTL_SECS);
            let label = take_opt(&mut args, "--label").unwrap_or_default();
            Hub::create_pairing_code_at(&dir, ttl, addr.clone(), &label).map(|code| {
                println!("{EXIT_NOTICE}\n");
                println!("One-time pairing code (valid {ttl} s, single use):\n");
                println!("  {}\n", code.encode());
                match addr {
                    Some(a) => println!("On the device:  sieve-link pair <code>   (it will dial {a})"),
                    None => println!("On the device:  sieve-link pair <code> --listen ADDR, then run this hub with --dial to that address"),
                }
                println!("Treat the code like a password until it is used or expires.");
            })
        }
        "devices" => HubStore::new(&dir).load().map(|f| {
            if f.devices.is_empty() {
                println!("no paired devices");
            }
            for d in &f.devices {
                let state = if d.active() { "active" } else { "REVOKED" };
                println!(
                    "{}  {:<20} {state:<8} concurrent={} per-minute={} bytes/s={} allow={:?} deny={:?} allow-cidr={} deny-cidr={}",
                    d.fingerprint.short(),
                    d.name,
                    d.limits.max_concurrent,
                    d.limits.opens_per_minute,
                    d.limits.bytes_per_sec,
                    d.rules.allow_suffixes,
                    d.rules.deny_suffixes,
                    d.rules.allow_cidrs.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(","),
                    d.rules.deny_cidrs.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(","),
                );
            }
            let pending = f.pending.iter().filter(|p| p.expires_at > now()).count();
            if pending > 0 {
                println!("{pending} pairing code(s) outstanding");
            }
        }),
        "revoke" if args.len() == 1 => revoke_at(&HubStore::new(&dir), &args[0]).map(|fp| {
            println!("revoked {} (a running hub cuts its links within a second)", fp.short());
        }),
        "rule" if args.len() == 3 => HubStore::new(&dir).update(|f| {
            let fp = f.find(&args[0])?;
            let d = f.device_mut(&fp).expect("found");
            let v = args[2].clone();
            match args[1].as_str() {
                "allow-suffix" => d.rules.allow_suffixes.push(v),
                "deny-suffix" => d.rules.deny_suffixes.push(v),
                "allow-cidr" => d.rules.allow_cidrs.push(v.parse()?),
                "deny-cidr" => d.rules.deny_cidrs.push(v.parse()?),
                other => return Err(sieve_link::LinkError::Store(format!("unknown rule kind {other}"))),
            }
            println!("updated {}", fp.short());
            Ok(())
        }),
        "limit" if args.len() == 3 => HubStore::new(&dir).update(|f| {
            let fp = f.find(&args[0])?;
            let d = f.device_mut(&fp).expect("found");
            let n: u64 = args[2].parse().map_err(|_| sieve_link::LinkError::Store("N must be a number".into()))?;
            match args[1].as_str() {
                "concurrent" => d.limits.max_concurrent = n as u32,
                "per-minute" => d.limits.opens_per_minute = n as u32,
                "bytes-per-sec" => d.limits.bytes_per_sec = n,
                other => return Err(sieve_link::LinkError::Store(format!("unknown limit {other}"))),
            }
            println!("updated {}", fp.short());
            Ok(())
        }),
        "run" => return run(dir, args).await,
        _ => return usage(),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sieve-hub: {e}");
            ExitCode::FAILURE
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

async fn run(dir: PathBuf, mut args: Vec<String>) -> ExitCode {
    let listens = take_all(&mut args, "--listen");
    let dials = take_all(&mut args, "--dial");
    if !args.is_empty() || (listens.is_empty() && dials.is_empty()) {
        eprintln!("sieve-hub run: give at least one --listen ADDR or --dial ADDR");
        return ExitCode::from(2);
    }
    let hub = match Hub::open(HubConfig::new(&dir)) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("sieve-hub: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("{EXIT_NOTICE}\n");
    println!("hub {:?} key {}", hub.name(), hub.fingerprint());
    for l in listens {
        let addr: SocketAddr = match l.parse() {
            Ok(a) => a,
            Err(_) => {
                eprintln!("sieve-hub: --listen wants IP:PORT, got {l}");
                return ExitCode::from(2);
            }
        };
        match hub.listen(addr).await {
            Ok(a) => println!("listening on {a}"),
            Err(e) => {
                eprintln!("sieve-hub: listen {addr}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    for d in dials {
        println!("dialling out to {d}");
        hub.dial(d);
    }
    println!("audit log: {}", hub.audit_path().display());
    let _ = tokio::signal::ctrl_c().await;
    hub.shutdown();
    println!("stopped");
    ExitCode::SUCCESS
}
