//! probe: the live half of the Wintun spike. THE USER RUNS THIS, elevated.
//!
//! What it does, in order:
//! 1. refuses to start unless elevated, printing the exact admin command;
//! 2. resolves the ONE test host (or takes --route-ip) and refuses any
//!    address that is not public unicast; never touches the default route;
//! 3. reads, before any change, which physical interface and source address
//!    reach each test address (forwarder sockets bind to that source and are
//!    pinned with IP_UNICAST_IF); an address with no usable source is skipped;
//! 4. loads wintun.dll (signature checked: signer must be WireGuard LLC),
//!    creates the adapter "Sieve Spike" with a fixed GUID, gives it a host
//!    address in 198.18.0.0/15 (benchmark range) and fd53:6965:7665::1;
//! 5. adds a /32 (/128) route per test address into the adapter;
//! 6. runs ipstack on the adapter for --seconds: every flow is attributed,
//!    classified, logged with its verdict and forwarded (observe), or the
//!    test domain is dropped for the test exe only (--enforce-test);
//! 7. on exit (time up, Ctrl+C, panic) removes its routes and address and
//!    closes the adapter (Wintun removes an adapter when its creator closes
//!    it; a killed process closes it too), then writes the reports.

mod support;
#[cfg(windows)]
mod forward;
#[cfg(windows)]
mod os;
#[cfg(windows)]
mod tun;

#[cfg(not(windows))]
fn main() {
    eprintln!("probe: Windows only");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    std::process::exit(live::run());
}

#[cfg(windows)]
mod live {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use ipstack::{IpStack, IpStackConfig, IpStackStream};
    use sieve_engine::flow::flows::{Attributor, ExeCache, os::IpHelper};
    use crate::support::{self, Args, FlowLog, MAX_ROUTES, Summary, USAGE};
    use sieve_engine::flow::tasks::FlowTasks;

    use crate::forward::{self, Shared};
    use crate::os;
    use crate::tun::{TunCounters, TunDevice};

    /// The adapter's fixed identity, so a leftover is recognisable.
    pub const ADAPTER_NAME: &str = "Sieve Spike";
    pub const TUNNEL_TYPE: &str = "Sieve";
    pub const ADAPTER_GUID: u128 = 0x5e7e_5e7e_51e7_4e00_8a11_5e7e_0000_0001;
    const TUN_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 211, 1);
    const TUN_V6: Ipv6Addr = Ipv6Addr::new(0xfd53, 0x6965, 0x7665, 0, 0, 0, 0, 1);
    const MTU: u16 = 1500;
    const RING: u32 = 0x40_0000; // 4 MiB

    pub fn run() -> i32 {
        let raw: Vec<String> = std::env::args().skip(1).collect();
        let args = match support::parse_args(raw.clone()) {
            Ok(a) => a,
            Err(e) => {
                if !e.is_empty() {
                    eprintln!("error: {e}\n");
                }
                eprint!("{USAGE}");
                return 2;
            }
        };
        if !os::is_elevated() {
            let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "probe.exe".into());
            eprintln!("Not elevated. This probe creates a network adapter and a test route, which needs admin.");
            eprintln!("Nothing was changed. Open Terminal (Admin) and run exactly:\n");
            eprintln!("    {}\n", support::admin_command(&exe, &raw));
            return 3;
        }
        if !args.wintun_dll.is_file() {
            eprintln!("error: wintun.dll not found at {}", args.wintun_dll.display());
            return 2;
        }
        let list_text = match &args.rules_file {
            Some(p) => match std::fs::read_to_string(p) {
                Ok(t) => Some(t),
                Err(e) => {
                    eprintln!("error: cannot read rules {}: {e}", p.display());
                    return 2;
                }
            },
            None => None,
        };
        let candidates = match route_ips(&args) {
            Ok(ips) => ips,
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        };

        // Egress (physical interface and its source address) per test
        // address, read before any change. An address without one is not
        // routed at all (its flows keep going the normal way).
        let mut egress = HashMap::new();
        let mut ips = Vec::new();
        for ip in candidates {
            match (os::best_interface(ip), os::egress_source(ip)) {
                (Ok(if_index), Ok(source)) => {
                    println!("test address {ip}: leaves via interface {if_index} from {source}");
                    egress.insert(ip, forward::Egress { if_index, source });
                    ips.push(ip);
                }
                (Err(e), _) | (_, Err(e)) => println!("skipping {ip}: {e} (not routed; its traffic is untouched)"),
            }
        }
        if ips.is_empty() {
            eprintln!("error: no test address is reachable from a physical interface; nothing was changed");
            return 2;
        }

        // Undo on panic too (the default hook still prints the panic).
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let (ok, failed) = os::cleanup();
            eprintln!("panic: removed {ok} route/address entries ({failed} failed)");
            default_hook(info);
        }));

        let code = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => {
                let code = rt.block_on(session(args, ips, egress, list_text));
                // Never a plain drop: a drop waits without bound for every
                // remaining task and blocking thread.
                rt.shutdown_timeout(RUNTIME_BOUND);
                code
            }
            Err(e) => {
                eprintln!("error: tokio runtime: {e}");
                2
            }
        };
        let (ok, failed) = os::cleanup();
        println!("cleanup: removed {ok} route/address entries ({failed} failed); exiting");
        code
    }

    /// Bound for cancelled flow tasks to finish.
    const TASKS_BOUND: Duration = Duration::from_secs(5);
    /// Bound for the runtime's own shutdown after the session.
    const RUNTIME_BOUND: Duration = Duration::from_secs(3);
    /// Hard limit from "stopping" to process exit, whatever hangs.
    const EXIT_WATCHDOG: Duration = Duration::from_secs(30);

    /// After `after`, removes the routes and address (idempotent) and exits
    /// the process. A normal exit happens long before and ends this thread.
    fn arm_exit_watchdog(after: Duration) {
        std::thread::spawn(move || {
            std::thread::sleep(after);
            let (ok, failed) = os::cleanup();
            eprintln!(
                "watchdog: shutdown took longer than {} s; removed {ok} route/address entries ({failed} failed); exiting",
                after.as_secs()
            );
            std::process::exit(6);
        });
    }

    fn route_ips(args: &Args) -> Result<Vec<IpAddr>, String> {
        let mut ips: Vec<IpAddr> = if !args.route_ips.is_empty() {
            args.route_ips.clone()
        } else {
            (args.route_host.as_str(), 443)
                .to_socket_addrs()
                .map_err(|e| format!("cannot resolve {}: {e}", args.route_host))?
                .map(|s| s.ip())
                .collect()
        };
        ips.sort();
        ips.dedup();
        if ips.is_empty() {
            return Err(format!("{} resolved to no address", args.route_host));
        }
        if ips.len() > MAX_ROUTES {
            return Err(format!("{} addresses; at most {MAX_ROUTES} test routes", ips.len()));
        }
        for ip in &ips {
            support::check_route_target(*ip)?;
        }
        Ok(ips)
    }

    async fn session(
        args: Args,
        ips: Vec<IpAddr>,
        egress: HashMap<IpAddr, forward::Egress>,
        list_text: Option<String>,
    ) -> i32 {
        // SAFETY: loads the DLL the user pointed at; the
        // verify_binary_signature feature checks it is signed by WireGuard LLC
        // before any of its code runs.
        let wintun = match unsafe { wintun_bindings::load_from_path(&args.wintun_dll) } {
            Ok(w) => w,
            Err(e) => {
                eprintln!("error: loading {}: {e}", args.wintun_dll.display());
                return 4;
            }
        };
        if let Ok(old) = wintun_bindings::Adapter::open(&wintun, ADAPTER_NAME) {
            eprintln!("note: an adapter named \"{ADAPTER_NAME}\" already exists (left by a previous run?); not touching it");
            drop(old);
        }
        let adapter = match wintun_bindings::Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, Some(ADAPTER_GUID)) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("error: creating the adapter: {e}");
                return 4;
            }
        };
        // SAFETY: NET_LUID_LH is a union over one u64.
        let luid = unsafe { adapter.get_luid().Value };
        let tun_if_index = adapter.get_adapter_index().unwrap_or(0);
        if let Err(e) = adapter.set_mtu(usize::from(MTU)) {
            eprintln!("warning: set MTU: {e}");
        }
        let has_v6 = ips.iter().any(|i| i.is_ipv6());
        let mut setup = os::add_address(luid, IpAddr::V4(TUN_V4));
        if setup.is_ok() && has_v6 {
            setup = os::add_address(luid, IpAddr::V6(TUN_V6));
        }
        let session = match setup.and_then(|_| adapter.start_session(RING).map_err(|e| e.to_string())) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: adapter setup: {e}");
                return 4;
            }
        };
        for ip in &ips {
            if let Err(e) = os::add_host_route(luid, *ip) {
                eprintln!("error: route {ip}: {e}");
                let _ = session.shutdown();
                return 4;
            }
        }

        let (filter, policy) = support::policy_for(&args, list_text.as_deref());
        let counters = Arc::new(TunCounters::default());
        let shared = Arc::new(Shared {
            start: Instant::now(),
            own_pid: std::process::id(),
            attributor: Mutex::new(Attributor::new(IpHelper, sieve_engine::flow::etw::Unwitnessed)),
            exes: Mutex::new(ExeCache::new(sieve_engine::flow::flows::os::exe_path as fn(u32) -> Option<String>)),
            filter,
            policy,
            enforce: args.enforce.is_some(),
            egress,
            dns_via: args.dns_via,
            log: Mutex::new(FlowLog::default()),
            summary: Mutex::new(Summary::default()),
        });

        banner(&args, &ips, tun_if_index);
        let mut config = IpStackConfig::default();
        if config.mtu(MTU).is_err() {
            return 4;
        }
        config.udp_timeout(Duration::from_secs(30));
        let device = TunDevice::new(session.clone(), ips.clone(), counters.clone());
        let mut stack = IpStack::new(config, device);

        let mut tasks = FlowTasks::new();
        let deadline = tokio::time::sleep(Duration::from_secs(args.seconds));
        tokio::pin!(deadline);
        let reason = loop {
            tokio::select! {
                _ = &mut deadline => break "time up",
                _ = tokio::signal::ctrl_c() => break "Ctrl+C",
                s = stack.accept() => match s {
                    Ok(IpStackStream::Tcp(t)) => tasks.spawn(forward::handle_tcp(shared.clone(), t)),
                    Ok(IpStackStream::Udp(u)) => tasks.spawn(forward::handle_udp(shared.clone(), u)),
                    Ok(_) => {}
                    Err(_) => break "stack stopped",
                },
            }
        };
        println!("\nstopping ({reason})");
        // From here the process is guaranteed to end: if any step below
        // hangs, the watchdog removes the routes and exits.
        arm_exit_watchdog(EXIT_WATCHDOG);
        // 1. Close the Wintun session: the reader thread's blocking read
        //    returns, the device reports EOF, ipstack's packet loop ends.
        let _ = session.shutdown();
        // 2. Cancel every flow task while the runtime still runs, so each
        //    ipstack stream's blocking Drop can complete (run 2's hang).
        let report = tasks.shutdown(TASKS_BOUND).await;
        println!(
            "flow tasks cancelled: {} live at stop, {}",
            report.live,
            if report.drained { "all finished" } else { "some did not finish in time (the watchdog guards the exit)" }
        );
        // 3. Stop the stack, remove routes and address, close the adapter.
        drop(stack);
        let (ok, failed) = os::cleanup();
        println!("routes and address removed: {ok} ({failed} failed)");
        drop(session);
        drop(adapter);
        println!("adapter \"{ADAPTER_NAME}\" closed (Wintun removes it)");

        let mut summary = shared.summary.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        summary.tun_packets_in = load(&counters.packets_in);
        summary.tun_packets_out = load(&counters.packets_out);
        summary.tun_dropped_not_unicast = load(&counters.not_unicast);
        summary.tun_dropped_not_routed = load(&counters.not_routed);
        summary.routed_tcp_syn_v4 = load(&counters.syn_v4);
        summary.routed_tcp_syn_v6 = load(&counters.syn_v6);
        summary.routed_udp_v4 = load(&counters.udp_v4);
        summary.routed_udp_v6 = load(&counters.udp_v6);
        {
            let a = shared.attributor.lock().unwrap_or_else(|p| p.into_inner());
            summary.table_reads = a.stats.table_reads;
            summary.table_read_errors = a.stats.table_read_errors;
        }
        let records = {
            let log = shared.log.lock().unwrap_or_else(|p| p.into_inner());
            summary.flow_records_dropped = log.records_dropped;
            log.records.clone()
        };
        let text = summary.text();
        println!("\n==== summary ====\n{text}");
        write_reports(&args, &ips, &summary, &records, &text);
        0
    }

    fn banner(args: &Args, ips: &[IpAddr], tun_if_index: u32) {
        println!("adapter \"{ADAPTER_NAME}\" up (interface index {tun_if_index}); routed into it:");
        for ip in ips {
            println!("    {ip}");
        }
        match &args.enforce {
            Some(e) => {
                let ip = ips.iter().find(|i| i.is_ipv4()).unwrap_or(&ips[0]);
                let host_ip = if ip.is_ipv6() { format!("[{ip}]") } else { ip.to_string() };
                println!("ENFORCE TEST: dropping {} for {} only. In a second (normal) PowerShell:", e.domain, e.exe);
                println!("    Copy-Item C:\\Windows\\System32\\curl.exe $env:TEMP\\curl-other.exe");
                if e.domain == args.route_host {
                    // The routed host itself: a real name, so the pass case is a clean 200.
                    println!("    curl.exe -s -m 8 -o NUL -w \"%{{http_code}}`n\" https://{d}/", d = e.domain);
                    println!("    & $env:TEMP\\curl-other.exe -s -m 8 -o NUL -w \"%{{http_code}}`n\" https://{d}/", d = e.domain);
                    println!("  expected: curl.exe prints 000 (handshake cut), curl-other.exe prints 200.");
                } else {
                    println!("    curl.exe -vk -m 8 -o NUL --resolve {d}:443:{host_ip} https://{d}/", d = e.domain);
                    println!("    & $env:TEMP\\curl-other.exe -vk -m 8 -o NUL --resolve {d}:443:{host_ip} https://{d}/", d = e.domain);
                    println!("  a real server rejects a made-up name, so both curls may fail; the difference is");
                    println!("  where (no server hello at all when dropped). For a clean 200 pass case, use");
                    println!("  --block-domain {} (the routed host itself).", args.route_host);
                }
                println!("  this window logs verdict=drop for curl.exe and verdict=pass for curl-other.exe.");
            }
            None => {
                println!("OBSERVE: nothing is dropped; verdicts are what Sieve would do.");
                if args.route_ips.is_empty() {
                    let h = &args.route_host;
                    println!("In a second (normal) PowerShell, while this runs:");
                    println!("    curl.exe -s -m 10 -o NUL -w \"%{{http_code}} %{{time_total}}s`n\" https://{h}/");
                    println!("    curl.exe -s -m 10 -o NUL -w \"%{{http_code}} %{{time_total}}s`n\" http://{h}/");
                    if h == support::DEFAULT_ROUTE_HOST {
                        println!("  (quic.nginx.org has no plain HTTP: it reads the request and closes, so curl");
                        println!("   says 'empty reply' (exit 52) with or without the TUN; the log still shows kind=http)");
                    }
                    println!("  and open https://{h}/ in a browser, reload twice (HTTP/3 starts after the first visit).");
                }
            }
        }
        println!("running {} s; Ctrl+C stops early.\n", args.seconds);
    }

    fn write_reports(args: &Args, ips: &[IpAddr], s: &Summary, records: &[crate::support::FlowRecord], text: &str) {
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let base = args.out_dir.join(format!("probe-report-{stamp}"));
        let json = serde_json::json!({
            "mode": if args.enforce.is_some() { "enforce-test" } else { "observe" },
            "enforce": args.enforce.as_ref().map(|e| serde_json::json!({"domain": e.domain, "exe": e.exe})),
            "routed": ips.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
            "seconds": args.seconds,
            "summary": s,
            "flows": records,
        });
        let mut lines: Vec<String> = records.iter().map(|r| r.line()).collect();
        lines.push(String::new());
        lines.push(text.to_string());
        let wrote_json = std::fs::write(base.with_extension("json"), serde_json::to_string_pretty(&json).unwrap_or_default());
        let wrote_text = std::fs::write(base.with_extension("txt"), lines.join("\n"));
        match (wrote_json, wrote_text) {
            (Ok(()), Ok(())) => println!("reports: {0}.json and {0}.txt", base.display()),
            (a, b) => eprintln!("warning: report write failed: {:?} {:?}", a.err(), b.err()),
        }
    }
}
