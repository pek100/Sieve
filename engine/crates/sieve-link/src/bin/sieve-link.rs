//! sieve-link: the device side.
//!
//!   sieve-link [--dir D] pair CODE [--name NAME] [--hub HOST:PORT | --listen ADDR]
//!   sieve-link [--dir D] run [--proxy 127.0.0.1:1080] [--hub HOST:PORT | --listen ADDR]
//!                            [--on-hub-down stop|direct]
//!   sieve-link [--dir D] show
//!
//! `--listen` waits for the hub to dial in (for a hub behind a home router).
//! The directory defaults to ./sieve-link (or $SIEVE_LINK_DIR).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use sieve_link::device::{PairVia, pair};
use sieve_link::store::{self, DeviceFile, read_json, write_json_atomic};
use sieve_link::{HubRoute, Identity, LinkClient, LinkConfig, OnHubDown, PairingCode, proxy};
use tokio_util::sync::CancellationToken;

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
        "usage: sieve-link [--dir D] <pair CODE [--name N] [--hub HOST:PORT | --listen ADDR] |\n\
         run [--proxy 127.0.0.1:1080] [--hub HOST:PORT | --listen ADDR] [--on-hub-down stop|direct] | show>"
    );
    ExitCode::from(2)
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let dir = PathBuf::from(
        take_opt(&mut args, "--dir").or_else(|| std::env::var("SIEVE_LINK_DIR").ok()).unwrap_or_else(|| "sieve-link".into()),
    );
    if args.is_empty() {
        return usage();
    }
    let cmd = args.remove(0);
    let r = match cmd.as_str() {
        "pair" => do_pair(dir, args).await,
        "run" => do_run(dir, args).await,
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

async fn do_pair(dir: PathBuf, mut args: Vec<String>) -> sieve_link::error::Result<()> {
    let name = take_opt(&mut args, "--name").unwrap_or_else(|| "device".into());
    let hub_override = take_opt(&mut args, "--hub");
    let listen = take_opt(&mut args, "--listen");
    let [code] = args.as_slice() else {
        return Err(sieve_link::LinkError::Pairing("give exactly one pairing code".into()));
    };
    let code = PairingCode::decode(code)?;
    std::fs::create_dir_all(&dir)?;
    let id = Identity::load_or_create(&dir.join(store::IDENTITY_FILE))?;
    println!("NOTICE: once paired, this device's connections through sieve-link exit from the hub's IP address.");
    println!("pairing with hub key {}", code.hub);
    let limit = Duration::from_secs(20);
    let (hub_name, hub_addr) = if let Some(l) = listen {
        let addr: SocketAddr = l.parse().map_err(|_| sieve_link::LinkError::Pairing("--listen wants IP:PORT".into()))?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        println!("waiting on {} for the hub to dial in (until the code expires)", listener.local_addr()?);
        let wait = Duration::from_secs(code.expires_at.saturating_sub(now()).max(1));
        let n = tokio::time::timeout(wait, pair(&id, &code, &name, PairVia::Listener(&listener), limit))
            .await
            .map_err(|_| sieve_link::LinkError::Timeout("the hub did not dial in"))??;
        (n, None)
    } else {
        let addr = hub_override
            .or(code.addr.clone())
            .ok_or_else(|| sieve_link::LinkError::Pairing("the code has no hub address; give --hub or --listen".into()))?;
        (pair(&id, &code, &name, PairVia::Dial(addr.clone()), limit).await?, Some(addr))
    };
    write_json_atomic(
        &dir.join(store::DEVICE_FILE),
        &DeviceFile { version: 1, name, hub: code.hub, hub_name: hub_name.clone(), hub_addr, on_hub_down: OnHubDown::Stop },
    )?;
    println!("paired with hub {hub_name:?}; device key {}", id.fingerprint());
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
        .map_err(|_| sieve_link::LinkError::Store("--proxy wants IP:PORT".into()))?;
    let on_down = match take_opt(&mut args, "--on-hub-down") {
        Some(s) => s.parse()?,
        None => f.on_hub_down,
    };
    let route = if let Some(l) = take_opt(&mut args, "--listen") {
        HubRoute::Listen(l.parse().map_err(|_| sieve_link::LinkError::Store("--listen wants IP:PORT".into()))?)
    } else if let Some(h) = take_opt(&mut args, "--hub").or(f.hub_addr.clone()) {
        HubRoute::Dial(h)
    } else {
        return Err(sieve_link::LinkError::Store("no hub address; give --hub HOST:PORT or --listen ADDR".into()));
    };
    let listener = proxy::bind(proxy_addr).await?;
    let mut cfg = LinkConfig::new(f.hub, route.clone());
    cfg.on_hub_down = on_down;
    let client = LinkClient::start(&id, cfg).await?;
    println!("NOTICE: connections through this proxy exit from hub {:?}'s IP address.", f.hub_name);
    match &route {
        HubRoute::Dial(a) => println!("linking to hub at {a}"),
        HubRoute::Listen(_) => println!("waiting for the hub to dial in on {}", client.listen_addr().map(|a| a.to_string()).unwrap_or_default()),
    }
    println!("SOCKS5 and HTTP CONNECT proxy on {}", listener.local_addr()?);
    match on_down {
        OnHubDown::Stop => println!("when the hub is down: connections are refused (stop)"),
        OnHubDown::Direct => println!("when the hub is down: connections go DIRECT from this device"),
    }
    let stop = CancellationToken::new();
    let serve = tokio::spawn(proxy::serve(listener, client.clone(), stop.clone()));
    let _ = tokio::signal::ctrl_c().await;
    stop.cancel();
    client.shutdown();
    let _ = serve.await;
    Ok(())
}
