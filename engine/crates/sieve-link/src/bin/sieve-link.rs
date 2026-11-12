//! sieve-link: the device side.
//!
//!   sieve-link [--dir D] pair [CODE | -] [--name NAME] [--hub HOST:PORT | --listen ADDR]
//!   sieve-link [--dir D] run [--proxy 127.0.0.1:1080] [--hub HOST:PORT | --listen ADDR]
//!                            [--on-hub-down stop|direct]
//!   sieve-link [--dir D] show
//!   sieve-link [--dir D] secure
//!
//! Without CODE, `pair` asks for it at a prompt (not echoed), or reads one
//! line from standard input when that is not a terminal (also with `-`). A
//! CODE given as an argument is visible to other users in the process list
//! and stays in shell history; prefer the prompt.
//!
//! `--listen` waits for the hub to dial in (for a hub behind a home router).
//! The directory defaults to $SIEVE_LINK_DIR, else
//! %LOCALAPPDATA%\sieve-link\device (Windows) or ~/.local/state/sieve-link/device.

use std::io::{BufRead, IsTerminal};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use sieve_link::device::{PairVia, pair};
use sieve_link::store::{self, DeviceFile, read_json, write_json_atomic};
use sieve_link::{HubRoute, Identity, LinkClient, LinkConfig, LinkError, OnHubDown, PairingCode, proxy};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

fn take_opt(args: &mut Vec<String>, name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    if i + 1 >= args.len() {
        return None;
    }
    let v = args.remove(i + 1);
    args.remove(i);
    Some(v)
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: sieve-link [--dir D] <pair [CODE | -] [--name N] [--hub HOST:PORT | --listen ADDR] |\n\
         run [--proxy 127.0.0.1:1080] [--hub HOST:PORT | --listen ADDR] [--on-hub-down stop|direct] | show | secure>\n\
         (pair without CODE asks for it; a CODE argument shows in the process list)"
    );
    ExitCode::from(2)
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let dir = match take_opt(&mut args, "--dir").map(PathBuf::from).or_else(|| std::env::var_os("SIEVE_LINK_DIR").map(PathBuf::from)) {
        Some(d) => d,
        None => match store::default_dir("device") {
            Ok(d) => d,
            Err(e) => {
                eprintln!("sieve-link: {e}");
                return ExitCode::from(2);
            }
        },
    };
    if args.is_empty() {
        return usage();
    }
    let cmd = args.remove(0);
    if matches!(cmd.as_str(), "run" | "show")
        && let Err(e) = sieve_link::perms::check(&dir)
    {
        eprintln!("sieve-link: refusing to use {}: {e}", dir.display());
        return ExitCode::FAILURE;
    }
    let r = match cmd.as_str() {
        "pair" => do_pair(dir, args).await,
        "run" => do_run(dir, args).await,
        "secure" => sieve_link::perms::secure(&dir)
            .map_err(LinkError::from)
            .and_then(|_| sieve_link::perms::check(&dir).map_err(LinkError::Store))
            .map(|_| println!("{} and its files are now readable and writable by this user only", dir.display())),
        "show" => read_json::<DeviceFile>(&dir.join(store::DEVICE_FILE)).map(|f| {
            println!("device {:?}, paired with hub {:?} key {}", f.name, f.hub_name, f.hub);
            println!("hub address: {}", f.hub_addr.as_deref().unwrap_or("(the hub dials this device)"));
            println!("when the hub is down: {:?}", f.on_hub_down);
        }),
        _ => return usage(),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sieve-link: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The pairing code: the argument if given, else a prompt (not echoed) on a
/// terminal, else one line of standard input.
fn read_code(arg: Option<&str>) -> Result<Zeroizing<String>, LinkError> {
    match arg {
        Some(c) if c != "-" => Ok(Zeroizing::new(c.to_string())),
        _ if arg.is_none() && std::io::stdin().is_terminal() => {
            rpassword::prompt_password("Pairing code (not shown as you type or paste): ").map(Zeroizing::new).map_err(LinkError::from)
        }
        _ => {
            let mut line = Zeroizing::new(String::new());
            std::io::stdin().lock().read_line(&mut line)?;
            Ok(line)
        }
    }
}

async fn do_pair(dir: PathBuf, mut args: Vec<String>) -> sieve_link::error::Result<()> {
    let name = store::clean_name(&take_opt(&mut args, "--name").unwrap_or_else(|| "device".into()));
    let hub_override = take_opt(&mut args, "--hub");
    let listen = take_opt(&mut args, "--listen");
    let arg = match args.as_slice() {
        [] => None,
        [one] => Some(one.as_str()),
        _ => return Err(LinkError::Pairing("give at most one pairing code".into())),
    };
    let text = read_code(arg)?;
    let code = PairingCode::decode(&text)?;
    drop(text);
    sieve_link::perms::create_private_dir(&dir)?;
    sieve_link::perms::check(&dir).map_err(LinkError::Store)?;
    let id = Identity::load_or_create(&dir.join(store::IDENTITY_FILE))?;
    println!("NOTICE: once paired, this device's connections through sieve-link exit from the hub's IP address.");
    println!("pairing with hub key {}", code.hub);
    let limit = Duration::from_secs(20);
    let (hub_name, hub_addr) = if let Some(l) = listen {
        let addr: SocketAddr = l.parse().map_err(|_| LinkError::Pairing("--listen wants IP:PORT".into()))?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        println!("waiting on {} for the hub to dial in (until the code expires)", listener.local_addr()?);
        let wait = Duration::from_secs(code.expires_at.saturating_sub(now()).max(1));
        let n = tokio::time::timeout(wait, pair(&id, &code, &name, PairVia::Listener(&listener), limit))
            .await
            .map_err(|_| LinkError::Timeout("the hub did not dial in"))??;
        (n, None)
    } else {
        let addr = hub_override
            .or(code.addr.clone())
            .ok_or_else(|| LinkError::Pairing("the code has no hub address; give --hub or --listen".into()))?;
        (pair(&id, &code, &name, PairVia::Dial(addr.clone()), limit).await?, Some(addr))
    };
    write_json_atomic(
        &dir.join(store::DEVICE_FILE),
        &DeviceFile { version: 1, name: name.clone(), hub: code.hub, hub_name: hub_name.clone(), hub_addr, on_hub_down: OnHubDown::Stop },
    )?;
    println!("paired with hub {hub_name:?}; device key {} (the hub may list it under a suffixed name if {name:?} was taken)", id.fingerprint());
    Ok(())
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

async fn do_run(dir: PathBuf, mut args: Vec<String>) -> sieve_link::error::Result<()> {
    let f: DeviceFile = read_json(&dir.join(store::DEVICE_FILE))?;
    let id = Identity::load(&dir.join(store::IDENTITY_FILE))?;
    let proxy_addr: SocketAddr = take_opt(&mut args, "--proxy")
        .unwrap_or_else(|| "127.0.0.1:1080".into())
        .parse()
        .map_err(|_| LinkError::Store("--proxy wants IP:PORT".into()))?;
    let on_down = match take_opt(&mut args, "--on-hub-down") {
        Some(s) => s.parse()?,
        None => f.on_hub_down,
    };
    let route = if let Some(l) = take_opt(&mut args, "--listen") {
        HubRoute::Listen(l.parse().map_err(|_| LinkError::Store("--listen wants IP:PORT".into()))?)
    } else if let Some(h) = take_opt(&mut args, "--hub").or(f.hub_addr.clone()) {
        HubRoute::Dial(h)
    } else {
        return Err(LinkError::Store("no hub address; give --hub HOST:PORT or --listen ADDR".into()));
    };
    let listener = proxy::bind(proxy_addr).await?;
    let mut cfg = LinkConfig::new(f.hub, route.clone());
    cfg.on_hub_down = on_down;
    let client = LinkClient::start(&id, cfg).await?;
    println!("NOTICE: connections through this proxy exit from hub {:?}'s IP address.", f.hub_name);
    println!("NOTICE: any program on this device can use the proxy port; use socks5h:// (not socks5://) so names resolve at the hub.");
    match &route {
        HubRoute::Dial(a) => println!("linking to hub at {a}"),
        HubRoute::Listen(_) => println!("waiting for the hub to dial in on {}", client.listen_addr().map(|a| a.to_string()).unwrap_or_default()),
    }
    println!("SOCKS5 and HTTP CONNECT proxy on {}", listener.local_addr()?);
    match on_down {
        OnHubDown::Stop => println!("when the hub is down: connections are refused (stop)"),
        OnHubDown::Direct => println!("when the hub is down: connections go DIRECT from this device (and resolve names here)"),
    }
    let stop = CancellationToken::new();
    let serve = tokio::spawn(proxy::serve(listener, client.clone(), stop.clone()));
    let _ = tokio::signal::ctrl_c().await;
    stop.cancel();
    client.shutdown();
    let _ = serve.await;
    Ok(())
}
