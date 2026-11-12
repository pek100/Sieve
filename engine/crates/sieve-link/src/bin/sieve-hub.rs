//! sieve-hub: the machine other devices' traffic exits through.
//!
//!   sieve-hub [--dir D] init [--name NAME]
//!   sieve-hub [--dir D] secure
//!   sieve-hub [--dir D] pair [--addr HOST:PORT] [--ttl SECS] [--label TEXT]
//!   sieve-hub [--dir D] devices
//!   sieve-hub [--dir D] revoke DEVICE
//!   sieve-hub [--dir D] rule DEVICE (allow-suffix|deny-suffix|allow-cidr|deny-cidr|allow-lan|allow-self|allow-port) VALUE
//!   sieve-hub [--dir D] limit DEVICE (concurrent|per-minute|bytes-per-sec) N
//!   sieve-hub [--dir D] lan [add CIDR | remove CIDR | v6-prefix N]
//!   sieve-hub [--dir D] audit [cap-mib N | min-days N]
//!   sieve-hub [--dir D] status
//!   sieve-hub [--dir D] run [--listen ADDR]... [--dial ADDR]... [--allow-undetected-lan]
//!
//! DEVICE is a fingerprint prefix (8+ hex digits, always tried first) or the
//! device's name. The directory defaults to $SIEVE_HUB_DIR, else
//! %LOCALAPPDATA%\sieve-link\hub (Windows) or ~/.local/state/sieve-link/hub.
//!
//! Rule kinds: `allow-cidr` only lets a device with an allow list name
//! address literals and opens nothing local; `allow-lan` opens part of this
//! machine's network (at most a /16 or /48); `allow-self` opens this machine
//! itself (its own addresses, loopback). Both print a warning.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use sieve_link::audit::{DEFAULT_CAP_MIB, DEFAULT_MIN_DAYS};
use sieve_link::hub::{EXIT_NOTICE, HubStatus, STATUS_STALE_MS, detected_local_net, read_status, revoke_at};
use sieve_link::mux;
use sieve_link::netif::{DEFAULT_V6_SITE_PREFIX, V6_SITE_PREFIX_RANGE};
use sieve_link::pairing::{DEFAULT_TTL_SECS, MAX_TTL_SECS, MIN_TTL_SECS};
use sieve_link::rules::{DEFAULT_DENIED_PORTS, Limits, MAX_BYTES_PER_SEC, MAX_CONCURRENT, MAX_LAN_WIDTH_V4, MAX_LAN_WIDTH_V6, MAX_OPENS_PER_MINUTE, rule_notes};
use sieve_link::store::{self, HubStore};
use sieve_link::{Cidr, Hub, HubConfig, LinkError};

fn usage() -> ExitCode {
    eprintln!(
        "usage: sieve-hub [--dir D] <init [--name N] | secure | pair [--addr HOST:PORT] [--ttl SECS] [--label T] | devices | revoke DEVICE |\n\
         rule DEVICE allow-suffix|deny-suffix|allow-cidr|deny-cidr|allow-lan|allow-self|allow-port VALUE |\n\
         limit DEVICE concurrent|per-minute|bytes-per-sec N | lan [add CIDR | remove CIDR | v6-prefix N] |\n\
         audit [cap-mib N | min-days N] | status | run [--listen ADDR]... [--dial ADDR]... [--allow-undetected-lan]>"
    );
    ExitCode::from(2)
}

/// The running hub's status, if one is running on this directory (a status
/// file older than `STATUS_STALE_MS` is from a hub that stopped).
fn running_status(dir: &std::path::Path) -> Option<HubStatus> {
    read_status(dir).ok().filter(|s| now_ms().saturating_sub(s.updated_ms) < STATUS_STALE_MS)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// An `allow-lan` / `allow-self` block: narrow enough, and never the
/// unspecified address.
fn lan_block(v: &str) -> Result<Cidr, LinkError> {
    let c: Cidr = v.parse()?;
    if !c.narrow_enough_for_lan() {
        return Err(LinkError::Store(format!("{c} is too wide: at most a /{MAX_LAN_WIDTH_V4} (IPv4) or /{MAX_LAN_WIDTH_V6} (IPv6)")));
    }
    if c.addr.is_unspecified() {
        return Err(LinkError::Store("the unspecified address is never allowed".into()));
    }
    Ok(c)
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

fn take_flag(args: &mut Vec<String>, name: &str) -> bool {
    match args.iter().position(|a| a == name) {
        Some(i) => {
            args.remove(i);
            true
        }
        None => false,
    }
}

fn take_all(args: &mut Vec<String>, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(v) = take_opt(args, name) {
        out.push(v);
    }
    out
}

/// Parses a whole number in `min..=max`, refusing anything else (no
/// wrapping, no truncation).
fn number<T: FromStr + PartialOrd + std::fmt::Display + Copy>(s: &str, what: &str, min: T, max: T) -> Result<T, LinkError> {
    let bad = || LinkError::Store(format!("{what} must be a whole number in {min}..={max}"));
    let n: T = s.trim().parse().map_err(|_| bad())?;
    if n < min || n > max {
        return Err(bad());
    }
    Ok(n)
}

/// A device name as printed: control characters shown escaped (names from
/// older stores were not cleaned).
fn shown(name: &str) -> String {
    name.chars().flat_map(|c| if c.is_control() { c.escape_default().collect::<Vec<_>>() } else { vec![c] }).collect()
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let dir = match take_opt(&mut args, "--dir").map(PathBuf::from).or_else(|| std::env::var_os("SIEVE_HUB_DIR").map(PathBuf::from)) {
        Some(d) => d,
        None => match store::default_dir("hub") {
            Ok(d) => d,
            Err(e) => {
                eprintln!("sieve-hub: {e}");
                return ExitCode::from(2);
            }
        },
    };
    if args.is_empty() {
        return usage();
    }
    let cmd = args.remove(0);
    // Every command but these reads a directory that must be owner-only.
    if !matches!(cmd.as_str(), "init" | "secure")
        && let Err(e) = sieve_link::perms::check(&dir)
    {
        eprintln!("sieve-hub: refusing to use {}: {e}", dir.display());
        return ExitCode::FAILURE;
    }
    let r = match cmd.as_str() {
        "init" => {
            let name = take_opt(&mut args, "--name").unwrap_or_else(|| "hub".into());
            Hub::init(&dir, &name).map(|fp| {
                println!("hub initialized in {} (owner-only)", dir.display());
                println!("hub key fingerprint: {fp}");
            })
        }
        "secure" => sieve_link::perms::secure(&dir)
            .map_err(LinkError::from)
            .and_then(|_| sieve_link::perms::check(&dir).map_err(LinkError::Store))
            .map(|_| println!("{} and its files are now readable and writable by this user only", dir.display())),
        "pair" => (|| {
            let addr = take_opt(&mut args, "--addr");
            let ttl = match take_opt(&mut args, "--ttl") {
                Some(s) => number(&s, "--ttl", MIN_TTL_SECS, MAX_TTL_SECS)?,
                None => DEFAULT_TTL_SECS,
            };
            let label = take_opt(&mut args, "--label").unwrap_or_default();
            let code = Hub::create_pairing_code_at(&dir, ttl, addr.clone(), &label)?;
            println!("{EXIT_NOTICE}\n");
            println!("One-time pairing code (valid {ttl} s, single use):\n");
            println!("  {}\n", code.encode());
            match addr {
                Some(a) => println!("On the device:  sieve-link pair   (it asks for the code, then dials {a})"),
                None => println!("On the device:  sieve-link pair --listen ADDR   (it asks for the code), then run this hub with --dial to that address"),
            }
            println!("Treat the code like a password until it is used or expires. Typing it at the prompt keeps it out of the");
            println!("device's process list and shell history; `sieve-link pair CODE` works too but shows it there.");
            Ok(())
        })(),
        "devices" => HubStore::new(&dir).load().map(|f| {
            if f.devices.is_empty() {
                println!("no paired devices");
            }
            for d in &f.devices {
                let state = if d.active() { "active" } else { "REVOKED" };
                let list = |v: &[Cidr]| v.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",");
                println!(
                    "{}  {:<20} {state:<8} concurrent={} per-minute={} bytes/s={} allow={:?} deny={:?} allow-cidr={} deny-cidr={} allow-lan={} allow-self={} allow-port={:?}",
                    d.fingerprint.short(),
                    shown(&d.name),
                    d.limits.max_concurrent,
                    d.limits.opens_per_minute,
                    d.limits.bytes_per_sec,
                    d.rules.allow_suffixes,
                    d.rules.deny_suffixes,
                    list(&d.rules.allow_cidrs),
                    list(&d.rules.deny_cidrs),
                    list(&d.rules.allow_lan),
                    list(&d.rules.allow_self),
                    d.rules.allow_ports,
                );
                if d.active() {
                    for n in rule_notes(&shown(&d.name), &d.rules) {
                        println!("    {n}");
                    }
                }
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
            let who = format!("{} ({})", shown(&d.name), fp.short());
            match args[1].as_str() {
                "allow-suffix" => d.rules.allow_suffixes.push(v),
                "deny-suffix" => d.rules.deny_suffixes.push(v),
                "allow-cidr" => {
                    let c: Cidr = v.parse()?;
                    d.rules.allow_cidrs.push(c);
                    println!("note: allow-cidr {c} lets {who} name addresses in it when it has an allow list; it opens nothing on this");
                    println!("      machine or its network (use allow-lan / allow-self for that)");
                }
                "deny-cidr" => d.rules.deny_cidrs.push(v.parse()?),
                "allow-lan" => {
                    let c = lan_block(&v)?;
                    if !d.rules.allow_lan.contains(&c) {
                        d.rules.allow_lan.push(c);
                    }
                    println!("WARNING: device {who} may now reach {c} on THIS MACHINE'S LOCAL NETWORK.");
                    println!("         This machine itself stays closed to it unless you also give it allow-self.");
                }
                "allow-self" => {
                    let c = lan_block(&v)?;
                    if !d.rules.allow_self.contains(&c) {
                        d.rules.allow_self.push(c);
                    }
                    println!("WARNING: device {who} may now reach THIS MACHINE ITSELF at {c}: every service listening there,");
                    println!("         including ones meant for this machine only (loopback).");
                }
                "allow-port" => {
                    let p: u16 = number(&v, "the port", 1, u16::MAX)?;
                    if !DEFAULT_DENIED_PORTS.contains(&p) {
                        return Err(LinkError::Store(format!("port {p} is not denied by default; only {DEFAULT_DENIED_PORTS:?} need allowing")));
                    }
                    if !d.rules.allow_ports.contains(&p) {
                        d.rules.allow_ports.push(p);
                    }
                }
                other => return Err(LinkError::Store(format!("unknown rule kind {other}"))),
            }
            println!("updated {}", fp.short());
            Ok(())
        }),
        "limit" if args.len() == 3 => HubStore::new(&dir).update(|f| {
            let fp = f.find(&args[0])?;
            let d = f.device_mut(&fp).expect("found");
            let mut l: Limits = d.limits;
            match args[1].as_str() {
                "concurrent" => l.max_concurrent = number(&args[2], "concurrent", 1, MAX_CONCURRENT)?,
                "per-minute" => l.opens_per_minute = number(&args[2], "per-minute", 1, MAX_OPENS_PER_MINUTE)?,
                "bytes-per-sec" => l.bytes_per_sec = number(&args[2], "bytes-per-sec", 0, MAX_BYTES_PER_SEC)?,
                other => return Err(LinkError::Store(format!("unknown limit {other}"))),
            }
            l.validate()?;
            let relink = !mux::link_carries(mux::hub_streams(d.limits.max_concurrent), l.max_concurrent);
            d.limits = l;
            println!("updated {} (a running hub applies it within a second; open streams keep counting)", fp.short());
            if relink {
                println!(
                    "NOTE: concurrent {} is more than the device's current link has room for: a running hub closes that link once,\n\
                     so the device's OPEN CONNECTIONS END; it relinks at once with room for the new limit.",
                    l.max_concurrent
                );
            }
            Ok(())
        }),
        "lan" => lan(&dir, &args),
        "audit" => audit(&dir, &args),
        "status" if args.is_empty() => status(&dir),
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

fn print_blocks(title: &str, v: &[Cidr]) {
    println!("{title}");
    if v.is_empty() {
        println!("  (none)");
    }
    for c in v {
        println!("  {c}");
    }
}

fn lan(dir: &std::path::Path, args: &[String]) -> Result<(), LinkError> {
    let st = HubStore::new(dir);
    match args {
        [] => {
            let f = st.load()?;
            let prefix = f.v6_site_prefix();
            println!("Denied to every device unless its allow-lan (the network) or allow-self (this machine) says otherwise:\n");
            match detected_local_net(prefix) {
                Ok((n, _)) => {
                    print_blocks("this machine itself (its interface addresses):", &n.own);
                    print_blocks(
                        &format!(
                            "\nits network (on-link prefixes, gateways, routed prefixes, and the /{prefix} around each global IPv6 address):"
                        ),
                        &n.lan,
                    );
                    println!("  (read again every few seconds while the hub runs; a block that disappears stays denied for 10 minutes)");
                }
                Err(e) => println!("detected: NONE, the interface list cannot be read ({e}); `run` refuses to start"),
            }
            print_blocks("\nmanual (sieve-hub lan add / remove):", &f.lan_cidrs);
            match running_status(dir) {
                Some(s) => {
                    println!("\nthis machine's public addresses, learned from the links up now (denied to that link as this machine):");
                    if s.learned.is_empty() {
                        println!("  (none yet)");
                    }
                    for l in &s.learned {
                        println!("  {} {:<20} {}", l.device, shown(&l.name), l.addrs.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", "));
                    }
                }
                None => println!("\nlearned public addresses: the hub is not running (they are learned from each link while it runs)"),
            }
            println!(
                "\nThe public address behind a home router is learned from each link without asking any outside service:\n\
                 the device reports the address it reached this machine at. The IPv6 site prefix is /{prefix} (default\n\
                 /{DEFAULT_V6_SITE_PREFIX}: home routers hand out a /56); narrow it with `sieve-hub lan v6-prefix 64` if this\n\
                 network's other /64s are not yours. Private, link-local and loopback addresses are denied in any case."
            );
            Ok(())
        }
        [verb, v] if verb == "v6-prefix" => {
            let n: u8 = number(v, "v6-prefix", *V6_SITE_PREFIX_RANGE.start(), *V6_SITE_PREFIX_RANGE.end())?;
            st.update(|f| {
                f.lan_v6_prefix = (n != DEFAULT_V6_SITE_PREFIX).then_some(n);
                Ok(())
            })?;
            println!("the IPv6 site prefix denied around this machine's global addresses is now /{n} (a running hub applies it within seconds;");
            println!("blocks it no longer covers stay denied for 10 minutes)");
            Ok(())
        }
        [verb, v] if verb == "add" || verb == "remove" => {
            let c: Cidr = v.parse()?;
            st.update(|f| {
                if verb == "add" {
                    if !f.lan_cidrs.contains(&c) {
                        f.lan_cidrs.push(c);
                    }
                } else {
                    let before = f.lan_cidrs.len();
                    f.lan_cidrs.retain(|x| *x != c);
                    if f.lan_cidrs.len() == before {
                        return Err(LinkError::Store(format!("{c} is not a manual block")));
                    }
                }
                Ok(())
            })?;
            println!("{} {c} (a running hub applies it within a second)", if verb == "add" { "added" } else { "removed" });
            Ok(())
        }
        _ => Err(LinkError::Store("lan takes no argument, `add CIDR`, `remove CIDR` or `v6-prefix N`".into())),
    }
}

fn audit(dir: &std::path::Path, args: &[String]) -> Result<(), LinkError> {
    let st = HubStore::new(dir);
    match args {
        [] => {
            let f = st.load()?;
            let c = f.audit_config();
            println!(
                "audit log: size cap {} MiB (all files together), retention floor {} days",
                c.cap_bytes() / (1024 * 1024),
                c.min_retention.as_secs() / 86_400
            );
            println!("Rows younger than the floor are never deleted to make room: when the cap would need that, the hub stops");
            println!("opening new connections and says why (`sieve-hub status`).");
            Ok(())
        }
        [what, v] => {
            st.update(|f| {
                match what.as_str() {
                    "cap-mib" => f.audit_cap_mib = Some(number(v, "cap-mib", 16, 1024 * 1024)?),
                    "min-days" => f.audit_min_days = Some(number(v, "min-days", 0, 3650)?),
                    other => return Err(LinkError::Store(format!("unknown audit setting {other}"))),
                }
                Ok(())
            })?;
            println!("updated; a running hub uses it from its next start (defaults: {DEFAULT_CAP_MIB} MiB, {DEFAULT_MIN_DAYS} days)");
            Ok(())
        }
        _ => Err(LinkError::Store("audit takes no argument, `cap-mib N` or `min-days N`".into())),
    }
}

fn status(dir: &std::path::Path) -> Result<(), LinkError> {
    let Some(s) = running_status(dir) else {
        println!("the hub is not running on {} (no fresh status.json)", dir.display());
        return Ok(());
    };
    println!("hub running (pid {})", s.pid);
    match &s.unavailable {
        None => println!("new connections: allowed"),
        Some(why) => println!("NEW CONNECTIONS REFUSED: {why}"),
    }
    println!("audit log: cap {} MiB, retention floor {} days", s.audit_cap_mib, s.audit_min_days);
    println!("links up: {}", if s.linked.is_empty() { "(none)".to_string() } else { s.linked.iter().map(|l| shown(l)).collect::<Vec<_>>().join("; ") });
    println!("denied: {} block(s) of this machine, {} of its network (IPv6 site prefix /{}; see `sieve-hub lan`)", s.own.len(), s.lan.len(), s.v6_site_prefix);
    for l in &s.learned {
        println!("learned public address(es) via {} {}: {}", l.device, shown(&l.name), l.addrs.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", "));
    }
    Ok(())
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

async fn run(dir: PathBuf, mut args: Vec<String>) -> ExitCode {
    let listens = take_all(&mut args, "--listen");
    let dials = take_all(&mut args, "--dial");
    let allow_undetected = take_flag(&mut args, "--allow-undetected-lan");
    if !args.is_empty() || (listens.is_empty() && dials.is_empty()) {
        eprintln!("sieve-hub run: give at least one --listen ADDR or --dial ADDR");
        return ExitCode::from(2);
    }
    let mut cfg = HubConfig::new(&dir);
    cfg.allow_undetected_lan = allow_undetected;
    let hub = match Hub::open(cfg) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("sieve-hub: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("{EXIT_NOTICE}\n");
    println!("hub {:?} key {}", hub.name(), hub.fingerprint());
    let net = hub.local_net();
    println!("denied as this machine and its network: {} + {} block(s) (see `sieve-hub lan`)", net.own.len(), net.lan.len());
    for d in hub.devices().iter().filter(|d| d.active()) {
        for n in rule_notes(&format!("{} ({})", shown(&d.name), d.fingerprint.short()), &d.rules) {
            println!("{n}");
        }
    }
    let ac = hub.audit_config();
    println!("audit log: cap {} MiB, retention floor {} days", ac.cap_bytes() / (1024 * 1024), ac.min_retention.as_secs() / 86_400);
    if let Some(why) = hub.unavailable() {
        println!("NEW CONNECTIONS REFUSED: {why}");
    }
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
    hub.flush_audit();
    hub.shutdown();
    println!("stopped");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_range_checked_without_wrapping() {
        assert_eq!(number::<u64>("600", "ttl", 30, 86_400).unwrap(), 600);
        assert!(number::<u64>("29", "ttl", 30, 86_400).is_err());
        assert!(number::<u64>("18446744073709551616", "ttl", 30, 86_400).is_err());
        assert!(number::<u64>("-1", "ttl", 30, 86_400).is_err());
        assert!(number::<u32>("4294967296", "concurrent", 1, 256).is_err(), "no truncation to u32");
        assert!(number::<u32>("257", "concurrent", 1, 256).is_err());
        assert!(number::<u16>("65536", "port", 1, u16::MAX).is_err());
        assert!(number::<u16>("0", "port", 1, u16::MAX).is_err());
    }
}
