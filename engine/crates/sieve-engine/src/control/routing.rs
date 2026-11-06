//! Windows: the routing loop. It brings the adapter and its routes up when
//! the user's switch is on and nothing blocks it, and takes them down when
//! the switch goes off, AdGuard intercepts (`coexist`), a full-tunnel VPN
//! comes up or the service stops. It wakes on a policy change, on every route
//! change (`NotifyRouteChange2`) and, while the switch is on, every
//! [`RECHECK_EVERY`] for AdGuard; with the switch off it waits with no timer
//! at all (plan 6: idle CPU 0).
//!
//! Bringing up: load the pinned wintun.dll, create the adapter, give it its
//! addresses, journal and add each planned route, start the stack, arm the
//! watchdog. Any failure takes down what was added and reports a Setup
//! blocker: the network stays as it was. While up, a route change re-reads
//! the tables (pinning follows them) and adds or removes the routes whose
//! plan changed.

use std::sync::Arc;
use std::time::Duration;

use ipstack::{IpStack, IpStackConfig, IpStackStream};
use sieve_ipc::Blocker;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use super::Engine;
use crate::coexist::{self, Coexistence};
use crate::flow::etw::os::{self as etw_os, EtwSession};
use crate::flow::etw::{RingWitness, Sinks, Unwitnessed};
use crate::flow::nat::{NatTable, os as nat_os};
use crate::flow::tasks::FlowTasks;
use crate::lists::https::HttpsFetcher;
use crate::route::apply::{self, SieveLuid};
use crate::route::journal::Journal;
use crate::route::plan::{self, RoutePlan};
use crate::route::prefix::Prefix;
use crate::route::table::{NetTables, read};
use crate::route::watch::{RouteWatch, watch as watch_routes};
use crate::stack::relay::{Relay, UDP_IDLE, Witness, handle_tcp, handle_udp};
use crate::tun::device::{Tun, TunDevice};
#[cfg(not(feature = "relay-experiments"))]
use crate::tun::MTU;
use crate::tun::{TUN_V4, TUN_V6};
use crate::watchdog::monotonic_ms;

/// While the switch is on, AdGuard is checked this often (it has no route
/// change to wake the loop). With its service alive, each check is one probe.
pub const RECHECK_EVERY: Duration = Duration::from_secs(5);
/// Cancelled flow tasks get this long to finish at take-down.
const TASKS_BOUND: Duration = Duration::from_secs(5);

/// What is up while the engine routes.
struct Up {
    tun: Tun,
    luid: SieveLuid,
    routes: Vec<Prefix>,
    relay: Arc<Relay>,
    stop_accept: oneshot::Sender<()>,
    accept: JoinHandle<()>,
    batches: JoinHandle<()>,
    lists: JoinHandle<()>,
    /// Lives exactly as long as the routes; None when it could not start.
    etw: Option<EtwSession>,
}

fn journal(engine: &Engine) -> Option<Journal> {
    engine.dir.as_deref().map(Journal::new)
}

/// The attribution sources of one routing run. Starting them is not a Setup
/// blocker: a failed session, or a consumer that ends later, goes to
/// `last_error` and routing continues with the owner tables alone (fail-open).
fn start_attribution(engine: &Arc<Engine>) -> (Option<EtwSession>, Witness, Arc<NatTable>) {
    let sinks = Sinks::new(std::process::id(), engine.meters.clone());
    let winnat = sinks.winnat.clone();
    let ring = sinks.ring.clone();
    let reporter = engine.clone();
    let report = move |why| reporter.set_facts(|f| f.last_error = Some(why));
    let (session, witness): (Option<EtwSession>, Witness) = match etw_os::start(sinks, report) {
        Ok(session) => {
            if let Some(why) = &session.winnat_error {
                engine.set_facts(|f| f.last_error = Some(why.clone()));
            }
            (Some(session), Box::new(RingWitness { ring, flush: etw_os::flusher(engine.meters.clone()) }))
        }
        Err(why) => {
            engine.set_facts(|f| f.last_error = Some(format!("attribution without ETW: {why}")));
            (None, Box::new(Unwitnessed))
        }
    };
    (session, witness, Arc::new(NatTable::spawn(move || nat_os::reader_sources(winnat))))
}

/// Ends the session without holding the runtime, bounded by [`TASKS_BOUND`].
async fn stop_attribution(engine: &Engine, session: Option<EtwSession>) {
    let Some(session) = session else { return };
    let stopped = tokio::task::spawn_blocking(move || session.stop(TASKS_BOUND)).await;
    if let Ok(Err(why)) = stopped {
        engine.set_facts(|f| f.last_error = Some(why));
    }
}

/// The machine's tables and what may run beside the engine, now. Async because
/// the AdGuard probe waits out its window; a probe that cannot run is an error
/// (a Setup blocker that routes nothing), never a verdict.
async fn evaluate() -> Result<(NetTables, Coexistence), String> {
    let tables = read::tables()?;
    let intercepting = coexist::adguard_intercepts(coexist::adguard_service()?, || coexist::probe_adguard(&tables)).await?;
    let coexistence = coexist::classify(&tables, intercepting);
    Ok((tables, coexistence))
}

/// Runs until `stop` turns true, then takes everything down.
pub async fn run(engine: Arc<Engine>, mut stop: watch::Receiver<bool>) {
    let _watch: Option<RouteWatch> = match watch_routes(engine.wake.clone()) {
        Ok(w) => Some(w),
        Err(e) => {
            engine.set_facts(|f| f.last_error = Some(format!("route changes are not watched: {e}")));
            None
        }
    };
    let mut up: Option<Up> = None;
    loop {
        let on = engine.policy().engine && engine.crash_loop().is_none();
        let mut want: Option<NetTables> = None;
        if on {
            match evaluate().await {
                Ok((tables, c)) => {
                    let blocked = c.blocker.is_some();
                    engine.set_facts(|f| {
                        f.blocker = c.blocker.clone();
                        f.split_tunnels = c.split_tunnels.clone();
                    });
                    if !blocked {
                        want = Some(tables);
                    }
                }
                Err(e) => engine.set_facts(|f| f.blocker = Some(Blocker::Setup { message: e })),
            }
        } else {
            engine.set_facts(|f| {
                f.blocker = None;
                f.split_tunnels.clear();
            });
        }
        up = match (up, want) {
            (Some(u), Some(tables)) => Some(follow(&engine, u, tables)),
            (Some(u), None) => {
                take_down(&engine, u).await;
                None
            }
            (None, Some(tables)) => match bring_up(&engine, &tables).await {
                Ok(u) => Some(u),
                Err(message) => {
                    engine.set_facts(|f| f.blocker = Some(Blocker::Setup { message }));
                    None
                }
            },
            (None, None) => None,
        };
        engine.write_status_file();
        let recheck = async {
            if on { tokio::time::sleep(RECHECK_EVERY).await } else { std::future::pending::<()>().await }
        };
        tokio::select! {
            _ = stop.wait_for(|s| *s) => break,
            _ = engine.wake.notified() => {}
            _ = recheck => {}
        }
    }
    if let Some(u) = up {
        take_down(&engine, u).await;
    }
    engine.write_status_file();
}

/// Removes routes that are no longer planned and adds new ones; the relay
/// pins with the new tables.
fn follow(engine: &Engine, up: Up, tables: NetTables) -> Up {
    let RoutePlan { routes, .. } = plan::plan(&tables);
    *up.relay.tables.write().unwrap_or_else(|p| p.into_inner()) = tables;
    if routes == up.routes {
        return up;
    }
    let mut kept: Vec<Prefix> = Vec::new();
    for p in &up.routes {
        if routes.contains(p) {
            kept.push(*p);
        } else {
            let _ = apply::delete_route(up.luid.value(), *p);
        }
    }
    if let Some(j) = journal(engine) {
        for p in routes.iter().filter(|p| !up.routes.contains(p)) {
            match apply::add_route(&j, up.luid, *p) {
                Ok(()) => kept.push(*p),
                Err(e) => engine.set_facts(|f| f.last_error = Some(e)),
            }
        }
    }
    kept.sort();
    Up { routes: kept, ..up }
}

async fn bring_up(engine: &Arc<Engine>, tables: &NetTables) -> Result<Up, String> {
    let plan = plan::plan(tables);
    if plan.routes.is_empty() {
        return Err("this computer has no default route, so there is nothing to route".into());
    }
    let journal = journal(engine).ok_or("the engine has no state folder for its route journal")?;
    let mut config = IpStackConfig::default();
    #[cfg(feature = "relay-experiments")]
    config.mtu(engine.experiments.settings.tun_mtu).map_err(|e| format!("stack MTU: {e}"))?;
    #[cfg(not(feature = "relay-experiments"))]
    config.mtu(MTU).map_err(|e| format!("stack MTU: {e}"))?;
    config.udp_timeout(UDP_IDLE);
    #[cfg(not(feature = "relay-experiments"))]
    let tun = crate::tun::device::open(&engine.exe)?;
    #[cfg(feature = "relay-experiments")]
    let tun = crate::tun::device::open(&engine.exe, engine.experiments.settings.tun_mtu)?;
    let luid = tun.luid;
    apply::add_address(luid, TUN_V4.into())?;
    if plan.routes.iter().any(|p| !p.is_ipv4()) {
        apply::add_address(luid, TUN_V6.into())?;
    }
    // Before the routes, so a hang starting it cannot hold a route.
    let (etw, witness, nat) = start_attribution(engine);
    let mut added = Vec::new();
    for p in &plan.routes {
        if let Err(e) = apply::add_route(&journal, luid, *p) {
            for a in &added {
                let _ = apply::delete_route(luid.value(), *a);
            }
            let _ = journal.truncate();
            stop_attribution(engine, etw).await;
            return Err(e);
        }
        added.push(*p);
    }

    #[cfg(not(feature = "relay-experiments"))]
    let relay = Arc::new(Relay::new(tun.index, tables.clone(), engine.book.clone(), engine.names.clone(), engine.meters.clone(), engine.filter.clone(), witness, nat));
    #[cfg(feature = "relay-experiments")]
    let relay = {
        let mut relay = Relay::new(tun.index, tables.clone(), engine.book.clone(), engine.names.clone(), engine.meters.clone(), engine.filter.clone(), witness, nat);
        relay.experiments = engine.experiments.settings.clone();
        Arc::new(relay)
    };
    #[cfg(feature = "relay-experiments")]
    let device = TunDevice::experimental(tun.session.clone(), engine.meters.clone(), engine.beats.clone(), &engine.experiments.settings);
    #[cfg(not(feature = "relay-experiments"))]
    let device = TunDevice::new(tun.session.clone(), engine.meters.clone(), engine.beats.clone());
    let stack = IpStack::new(config, device);
    let lists = tokio::spawn(engine.lists.clone().run(HttpsFetcher::new(relay.clone())));
    let (stop_accept, stopped) = oneshot::channel();
    let accept = tokio::spawn(accept(stack, relay.clone(), stopped));
    let batches = {
        let e = engine.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_millis(sieve_ipc::FLOWS_BATCH_MS));
            let per_status = super::STATUS_FILE_EVERY_MS / sieve_ipc::FLOWS_BATCH_MS;
            for tick in 0u64.. {
                every.tick().await;
                e.publish_batch();
                if tick % per_status == 0 {
                    e.write_status_file();
                }
            }
        })
    };
    engine.set_facts(|f| {
        f.routes_up = true;
        f.blocker = None;
        f.up_since = Some(monotonic_ms());
    });
    // A ping left pending by an earlier run must not trip this one.
    engine.beats.relay.end();
    engine.beats.tun.end();
    engine.arm.set(true);
    Ok(Up { tun, luid, routes: added, relay, stop_accept, accept, batches, lists, etw })
}

async fn accept(mut stack: IpStack, relay: Arc<Relay>, mut stop: oneshot::Receiver<()>) {
    let mut tasks = FlowTasks::new();
    loop {
        tokio::select! {
            _ = &mut stop => break,
            s = stack.accept() => match s {
                Ok(IpStackStream::Tcp(t)) => tasks.spawn(handle_tcp(relay.clone(), t)),
                Ok(IpStackStream::Udp(u)) => tasks.spawn(handle_udp(relay.clone(), u)),
                // ICMP and other transports are not relayed (slice 3).
                Ok(_) => {}
                Err(_) => break,
            },
        }
    }
    let _ = tasks.shutdown(TASKS_BOUND).await;
    drop(stack);
}

/// The order that keeps the network: disarm, close the session (the reader
/// returns), cancel the flows while the runtime runs, delete the routes,
/// empty the journal, close the adapter (Wintun removes it). The ETW session
/// stops only after that, so a hang there cannot hold a route.
async fn take_down(engine: &Engine, up: Up) {
    engine.arm.set(false);
    let _ = up.tun.session.shutdown();
    let _ = up.stop_accept.send(());
    let _ = up.accept.await;
    up.batches.abort();
    up.lists.abort();
    for p in &up.routes {
        let _ = apply::delete_route(up.luid.value(), *p);
    }
    if let Some(j) = journal(engine) {
        let _ = j.truncate();
    }
    drop(up.tun);
    // Flows whose tasks were cancelled end here, so no client keeps them open.
    engine.book.lock().unwrap_or_else(|p| p.into_inner()).close_all();
    engine.publish_batch();
    engine.set_facts(|f| {
        f.routes_up = false;
        f.up_since = None;
    });
    stop_attribution(engine, up.etw).await;
}

/// The relay heartbeat's answer to the watchdog's pings, on the runtime.
/// The Stall test build stops answering once the routes have been up for
/// [`STALL_AFTER`], so the live check can watch the watchdog trip.
pub async fn answer_pings(engine: Arc<Engine>, mut pings: mpsc::UnboundedReceiver<()>) {
    while pings.recv().await.is_some() {
        #[cfg(feature = "stall")]
        if engine.facts().up_since.is_some_and(|t| monotonic_ms().saturating_sub(t) >= STALL_AFTER.as_millis() as u64) {
            // Blocks this worker for good: the ping is never answered.
            std::thread::sleep(Duration::from_secs(u64::from(u32::MAX)));
        }
        engine.beats.relay.end();
    }
}

/// The Stall build hangs this long after the routes came up.
#[cfg(feature = "stall")]
pub const STALL_AFTER: Duration = Duration::from_secs(30);

