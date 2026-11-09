//! Windows: the routing loop. It brings the adapter and its routes up when
//! the user's switch is on and nothing blocks it, and takes them down when
//! the switch goes off, AdGuard intercepts (`coexist`), a full-tunnel VPN
//! comes up or the service stops. It wakes on a policy change, on every route
//! change (`NotifyRouteChange2`) and, while the switch is on, every
//! [`RECHECK_EVERY`] for AdGuard; with the switch off it waits with no timer
//! at all (plan 6: idle CPU 0).
//!
//! Bringing up: build the DNS service's TLS, load the pinned wintun.dll, create
//! the adapter and give it its addresses, start the DNS service, wait until
//! the addresses may be a source ([`ADDRESSES_READY_WITHIN`]), journal and add
//! each planned route, start the stack, arm the watchdog. Any failure
//! takes down what was added and
//! reports a Setup blocker: the network stays as it was. While up, a route
//! change re-reads the tables (pinning follows them), drops DNS's sessions when
//! the network outside Sieve changed (they are pinned to the old egress), and
//! adds or removes the routes whose plan changed. Taking down drops the DNS
//! service, so its connections end with the routes.

use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ipstack::{IpStack, IpStackConfig, IpStackStream};
use sieve_ipc::Blocker;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use super::Engine;
use crate::coexist::{self, Coexistence};
use crate::dns::pool::{Context, Tls};
use crate::dns::service::Service;
use crate::dns::upstream;
use crate::exclusions::ExclusionSlot;
use crate::exclusions::browsers::{BrowserSet, WindowsRegistry};
use crate::flow::etw::os::{self as etw_os, EtwSession};
use crate::flow::etw::{RingWitness, Sinks, Unwitnessed};
use crate::flow::nat::{NatTable, os as nat_os};
use crate::flow::tasks::FlowTasks;
use crate::inject::InjectLimits;
use crate::inject::content::ContentHook;
use crate::lists::https::HttpsFetcher;
use crate::policy::wall_ms;
use crate::route::apply::{self, AddressState, SieveLuid};
use crate::route::capture;
use crate::route::wfp;
use crate::route::journal::Journal;
use crate::route::plan::{self, RoutePlan};
use crate::route::prefix::Prefix;
use crate::route::table::{NetTables, read};
use crate::route::watch::{RouteWatch, watch as watch_routes};
use crate::stack::egress::Egress;
use crate::stack::relay::{Relay, RelayParts, UDP_IDLE, Witness, handle_tcp, handle_udp};
use crate::tls::active::Active;
use crate::tls::ech::EchCache;
use crate::tls::intercept::{Interception, wanted};
use crate::tls::upstream::{PlatformTrust, TRUST_TIMEOUT, Verifier};
use crate::tls::validation::ValidationSlot;
use crate::tls::verdict::VerdictCache;
use crate::tun::device::{Tun, TunDevice, TunSink};
#[cfg(not(feature = "relay-experiments"))]
use crate::tun::MTU;
use crate::tun::{TUN_DNS, TUN_V4, TUN_V6};
use crate::watchdog::monotonic_ms;

/// While the switch is on, AdGuard is checked this often (it has no route
/// change to wake the loop). With its service alive, each check is one probe.
pub const RECHECK_EVERY: Duration = Duration::from_secs(5);
/// Cancelled flow tasks get this long to finish at take-down.
const TASKS_BOUND: Duration = Duration::from_secs(5);
const EXCLUSIONS_EVERY: Duration = Duration::from_secs(3_600);

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
    exclusions: JoinHandle<()>,
    /// Lives exactly as long as the routes; None when it could not start.
    etw: Option<EtwSession>,
    /// Empty when it is refused or could not open or be proven; routing goes on
    /// without it.
    capture: CaptureSlot,
}

fn journal(engine: &Engine) -> Option<Journal> {
    engine.dir.as_deref().map(Journal::new)
}

/// The attribution sources of one routing run. Starting them is not a Setup
/// blocker: a failed session, or a consumer that ends later, goes to
/// `last_error` and routing continues with the owner tables alone (fail-open).
fn start_attribution(engine: &Arc<Engine>) -> (Option<EtwSession>, Witness, Arc<NatTable>) {
    engine.attribution_starts();
    let sinks = Sinks::new(std::process::id(), engine.meters.clone());
    let winnat = sinks.winnat.clone();
    let ring = sinks.ring.clone();
    let reporter = engine.clone();
    let report = move |why| reporter.attribution_failed(why);
    let (session, witness): (Option<EtwSession>, Witness) = match etw_os::start(sinks, report) {
        Ok(session) => {
            if let Some(why) = &session.winnat_error {
                engine.attribution_failed(why.clone());
            }
            (Some(session), Box::new(RingWitness { ring, flush: etw_os::flusher(engine.meters.clone()) }))
        }
        Err(why) => {
            engine.attribution_failed(format!("attribution without ETW: {why}"));
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
        engine.attribution_failed(why);
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
            engine.add_error(format!("route changes are not watched: {e}"));
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
            (Some(u), Some(tables)) => Some(follow(&engine, u, tables).await),
            (Some(u), None) => {
                take_down(&engine, u).await;
                None
            }
            (None, Some(tables)) => match bring_up(&engine, &tables, &|| engine.policy().engine && !*stop.borrow()).await {
                Ok(u) => Some(u),
                // Stopped or switched off while it waited: the loop decides again.
                Err(message) if message == NO_LONGER_WANTED => None,
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
async fn follow(engine: &Engine, up: Up, tables: NetTables) -> Up {
    sync_https(engine, &up.relay.egress).await;
    let RoutePlan { routes, .. } = plan::plan(&tables);
    let network_moved = {
        let mut held = up.relay.tables.write().unwrap_or_else(|p| p.into_inner());
        let moved = held.outside_sieve() != tables.outside_sieve();
        *held = tables;
        moved
    };
    if network_moved {
        up.relay.dns.reset();
    }
    let up = if routes == up.routes {
        engine.routes_settled();
        up
    } else {
        let mut kept: Vec<Prefix> = Vec::new();
        for p in &up.routes {
            if routes.contains(p) {
                kept.push(*p);
            } else {
                let _ = apply::delete_route(up.luid.value(), *p);
            }
        }
        if let Some(j) = journal(engine) {
            let missing = routes.iter().copied().filter(|p| !up.routes.contains(p));
            kept.extend(add_missing(engine, missing, |p| apply::add_route(&j, up.luid, p)));
        }
        kept.sort();
        Up { routes: kept, ..up }
    };
    follow_capture(engine, up, network_moved).await
}

/// The DNS Client capture of one routing run (`route::capture`): its filter
/// session, the blocks it holds and when it was last proven.
struct Capture {
    session: wfp::Session,
    blocks: Vec<capture::Block>,
    proven_at: tokio::time::Instant,
}

/// The capture's place in a routing run: held, or empty and when to try again.
#[derive(Default)]
struct CaptureSlot {
    held: Option<Capture>,
    /// An empty slot tries again from then (None: at once).
    retry_at: Option<tokio::time::Instant>,
    /// The last failure reported, so a repeat is not reported again.
    said: Option<String>,
}

impl CaptureSlot {
    /// Reports a failure the first time it is seen, and waits before the next try.
    fn failed(&mut self, engine: &Engine, why: String) {
        if self.said.as_ref() != Some(&why) {
            engine.add_error(format!("the DNS Client's queries are not caught: {why}"));
            self.said = Some(why);
        }
        self.retry_at = Some(tokio::time::Instant::now() + capture::PROBE_EVERY);
    }
}

/// The DNS Client returned this for the probe's NODATA (`DNS_INFO_NO_RECORDS`).
const DNS_INFO_NO_RECORDS: i32 = 9501;

/// Proves the capture: a fresh name asked through the DNS Client must reach the
/// DNS service at [`TUN_DNS`] and its answer come back within [`capture::PROBE_WITHIN`].
async fn prove(dns: &Arc<Service>) -> Result<(), String> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
    let name = capture::probe_name(u64::from_le_bytes(nonce));
    let deadline = tokio::time::Instant::now() + capture::PROBE_WITHIN;
    let asked = {
        let name = name.clone();
        tokio::task::spawn_blocking(move || apply::ask_dns_client(&name))
    };
    let arrived = dns.probe_arrived(&name, capture::PROBE_WITHIN).await;
    let status = tokio::time::timeout_at(deadline, asked).await;
    match (arrived, status) {
        (true, Ok(Ok(0 | DNS_INFO_NO_RECORDS))) => Ok(()),
        (false, _) => Err(format!("a probe through the DNS Client did not reach Sieve's DNS server within {} ms", capture::PROBE_WITHIN.as_millis())),
        (true, Ok(Ok(status))) => Err(format!("the DNS Client answered a probe with error {status}")),
        (true, _) => Err(format!("the DNS Client did not return a probe's answer within {} ms", capture::PROBE_WITHIN.as_millis())),
    }
}

/// Opens the capture: refused when an adapter it would block ties for the DNS
/// Client's first network, else the adapter is put first and names its server,
/// then the block goes on, then the probe proves it. A failure undoes all of it
/// and is the caller's to report; routing goes on.
async fn open_capture(luid: SieveLuid, tables: &NetTables, blocks: Vec<capture::Block>, dns: &Arc<Service>) -> Result<Capture, String> {
    if let Some(why) = capture::refusal(tables, &blocks, read::interface_metric_of) {
        return Err(why);
    }
    let v6 = apply::put_first_for_dns(luid)?;
    if !v6 && blocks.iter().any(|b| !b.v4) {
        return Err("Sieve's adapter has no IPv6 interface to put first for the DNS Client's IPv6 servers".into());
    }
    apply::set_adapter_dns(Some(TUN_DNS))?;
    let opened = tokio::task::spawn_blocking(move || {
        let mut session = wfp::open()?;
        session.set(&blocks)?;
        Ok::<_, String>(Capture { session, blocks, proven_at: tokio::time::Instant::now() })
    })
    .await
    .map_err(|e| format!("the DNS capture's filter task: {e}"))
    .and_then(|r| r);
    let held = match opened {
        Ok(held) => held,
        Err(why) => {
            let _ = apply::set_adapter_dns(None);
            return Err(why);
        }
    };
    match prove(dns).await {
        Ok(()) => Ok(held),
        Err(why) => {
            close_capture(dns, held).await;
            Err(why)
        }
    }
}

/// Ends the rewrite, closes the session (its block goes with it) off the runtime,
/// then the adapter's server. Bounded by [`TASKS_BOUND`]: a filtering engine that
/// does not return holds up no take-down.
async fn close_capture(dns: &Service, capture: Capture) {
    dns.set_every_network_blocked(false);
    let _ = tokio::time::timeout(TASKS_BOUND, tokio::task::spawn_blocking(move || drop(capture))).await;
    let _ = apply::set_adapter_dns(None);
}

/// Keeps the capture on what the fresh tables and routes say: closed when there
/// is nothing to block (the adapter's server goes too) or an adapter now ties for
/// the first network, its block changed and proven again when that changed, proven
/// again every [`capture::PROBE_EVERY`] and after the network moved, opened again
/// when it is empty and its retry is due. A failure closes it and says why: the
/// DNS Client then goes as it would without it. Last, the DNS service hears
/// whether every network is blocked.
async fn follow_capture(engine: &Engine, mut up: Up, network_moved: bool) -> Up {
    let tables = up.relay.tables.read().unwrap_or_else(|p| p.into_inner()).clone();
    let blocks = capture::blocks(&tables, &up.routes);
    let dns = up.relay.dns.clone();
    if network_moved {
        up.capture.retry_at = None;
    }
    let now = tokio::time::Instant::now();
    match up.capture.held.take() {
        Some(held) if blocks.is_empty() => {
            close_capture(&dns, held).await;
            up.capture.said = None;
        }
        Some(held) => {
            let refused = capture::refusal(&tables, &blocks, read::interface_metric_of);
            let changed = blocks != held.blocks;
            let due = network_moved || changed || now.saturating_duration_since(held.proven_at) >= capture::PROBE_EVERY;
            let kept = match refused {
                Some(why) => Err((Some(held), why)),
                None if !due => Ok(held),
                None => match refilter(held, blocks.clone(), changed).await {
                    Ok(mut held) => match prove(&dns).await {
                        Ok(()) => {
                            held.proven_at = tokio::time::Instant::now();
                            Ok(held)
                        }
                        Err(why) => Err((Some(held), why)),
                    },
                    Err(failed) => Err(failed),
                },
            };
            match kept {
                Ok(held) => up.capture.held = Some(held),
                Err((held, why)) => {
                    match held {
                        Some(held) => close_capture(&dns, held).await,
                        None => {
                            dns.set_every_network_blocked(false);
                            let _ = apply::set_adapter_dns(None);
                        }
                    }
                    up.capture.failed(engine, why);
                }
            }
        }
        None if !blocks.is_empty() && up.capture.retry_at.is_none_or(|at| now >= at) => match open_capture(up.luid, &tables, blocks.clone(), &dns).await {
            Ok(held) => {
                up.capture.held = Some(held);
                up.capture.said = None;
            }
            Err(why) => up.capture.failed(engine, why),
        },
        None => {}
    }
    dns.set_every_network_blocked(up.capture.held.is_some() && capture::every_network_blocked(&tables, &blocks));
    apply::drop_system_routes(up.luid);
    up
}

/// The held capture with `blocks` in its session (off the runtime) when they
/// changed; the session is given back with the error, for closing (none when the
/// task panicked with it: its drop closed it).
async fn refilter(mut held: Capture, blocks: Vec<capture::Block>, changed: bool) -> Result<Capture, (Option<Capture>, String)> {
    if !changed {
        return Ok(held);
    }
    let swapped = tokio::task::spawn_blocking(move || {
        let done = held.session.set(&blocks);
        held.blocks = blocks;
        (held, done)
    })
    .await;
    match swapped {
        Ok((held, Ok(()))) => Ok(held),
        Ok((held, Err(why))) => Err((Some(held), why)),
        Err(e) => Err((None, format!("the DNS capture's filter task: {e}"))),
    }
}

/// Adds the routes the plan lacks and returns those that went in. A pass with no
/// failure ends what an earlier one reported; the wake after a failure tries again.
pub(super) fn add_missing(engine: &Engine, missing: impl Iterator<Item = Prefix>, mut add: impl FnMut(Prefix) -> Result<(), String>) -> Vec<Prefix> {
    let mut added = Vec::new();
    let mut settled = true;
    for p in missing {
        match add(p) {
            Ok(()) => added.push(p),
            Err(why) => {
                engine.route_failed(why);
                settled = false;
            }
        }
    }
    if settled {
        engine.routes_settled();
    }
    added
}

/// A new address is tentative while Windows runs duplicate address detection on
/// it (3 probes, about 3 s, for IPv4 on this adapter). Until then a send through
/// the adapter's routes fails with "host unreachable", so a route added earlier
/// takes every lookup and connection into a hole. Bounded: an adapter whose
/// address never settles is a Setup blocker, and the network stays as it was.
pub(super) const ADDRESSES_READY_WITHIN: Duration = Duration::from_secs(10);
const ADDRESS_POLL: Duration = Duration::from_millis(50);

/// What bringing the adapter up does to the system, apart from the order it is
/// done in, which the tests check (`routing_tests`).
pub(super) trait AdapterOps {
    fn add_address(&mut self, ip: IpAddr) -> Result<(), String>;
    fn address_state(&mut self, ip: IpAddr) -> Result<AddressState, String>;
    fn add_route(&mut self, prefix: Prefix) -> Result<(), String>;
    fn delete_route(&mut self, prefix: Prefix);
    fn forget_routes(&mut self);
}

/// The adapter, its journal: the system's side of [`AdapterOps`].
struct Os<'a> {
    journal: &'a Journal,
    luid: SieveLuid,
}

impl AdapterOps for Os<'_> {
    fn add_address(&mut self, ip: IpAddr) -> Result<(), String> {
        apply::add_address(self.luid, ip)
    }

    fn address_state(&mut self, ip: IpAddr) -> Result<AddressState, String> {
        apply::address_state(self.luid, ip)
    }

    fn add_route(&mut self, prefix: Prefix) -> Result<(), String> {
        apply::add_route(self.journal, self.luid, prefix)
    }

    fn delete_route(&mut self, prefix: Prefix) {
        let _ = apply::delete_route(self.luid.value(), prefix);
    }

    fn forget_routes(&mut self) {
        let _ = self.journal.truncate();
    }
}

/// The adapter's own addresses for these routes: IPv6 only when IPv6 is routed.
pub(super) fn adapter_addresses(routes: &[Prefix]) -> Vec<IpAddr> {
    let mut addresses = vec![IpAddr::V4(TUN_V4)];
    if routes.iter().any(|p| !p.is_ipv4()) {
        addresses.push(IpAddr::V6(TUN_V6));
    }
    addresses
}

/// Gives the adapter its addresses. Done first, so their detection runs while
/// the rest of the bring-up does.
pub(super) fn add_addresses(ops: &mut impl AdapterOps, addresses: &[IpAddr]) -> Result<(), String> {
    addresses.iter().try_for_each(|ip| ops.add_address(*ip))
}

/// What a bring-up returns when the stop or the switch going off came while it
/// waited: no blocker, the loop decides again.
pub(super) const NO_LONGER_WANTED: &str = "routing was stopped or switched off while the adapter's address settled";

/// Returns once every address may be a source, or says why it never will. While
/// it waits, `wanted` is asked at every poll: a stop or the switch going off ends
/// the wait at once with [`NO_LONGER_WANTED`].
pub(super) async fn addresses_ready(ops: &mut impl AdapterOps, addresses: &[IpAddr], wanted: &(dyn Fn() -> bool + Sync)) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + ADDRESSES_READY_WITHIN;
    loop {
        let mut tentative = None;
        for ip in addresses {
            match ops.address_state(*ip)? {
                AddressState::Preferred => {}
                AddressState::Tentative | AddressState::NotYet => tentative = Some(*ip),
                AddressState::Duplicate => {
                    return Err(format!(
                        "Sieve's address {ip} is already in use: another VPN or virtual adapter on this computer, or a device on this network, uses Sieve's range 198.18.0.0/15. Turn it off or move it to another range, then turn Sieve on again"
                    ));
                }
                AddressState::Unusable(state) => return Err(format!("Sieve's adapter cannot use its address {ip} (state {state})")),
            }
        }
        let Some(ip) = tentative else { return Ok(()) };
        if !wanted() {
            return Err(NO_LONGER_WANTED.into());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("Sieve's adapter address {ip} was still tentative after {} s", ADDRESSES_READY_WITHIN.as_secs()));
        }
        tokio::time::sleep(ADDRESS_POLL).await;
    }
}

/// Journals and adds each route once the adapter's addresses are usable, so no
/// route points at an adapter that cannot send yet. A failed route removes the
/// ones added before it.
pub(super) async fn route_adapter(ops: &mut impl AdapterOps, addresses: &[IpAddr], routes: &[Prefix], wanted: &(dyn Fn() -> bool + Sync)) -> Result<Vec<Prefix>, String> {
    addresses_ready(ops, addresses, wanted).await?;
    let mut added = Vec::new();
    for p in routes {
        if let Err(e) = ops.add_route(*p) {
            for a in &added {
                ops.delete_route(*a);
            }
            ops.forget_routes();
            return Err(e);
        }
        added.push(*p);
    }
    Ok(added)
}

async fn bring_up(engine: &Arc<Engine>, tables: &NetTables, still_on: &(dyn Fn() -> bool + Sync)) -> Result<Up, String> {
    let plan = plan::plan(tables);
    if plan.routes.is_empty() {
        return Err("this computer has no default route, so there is nothing to route".into());
    }
    let journal = journal(engine).ok_or("the engine has no state folder for its route journal")?;
    // Everything DNS can fail on comes before the first route: a Setup blocker
    // here leaves the network as it was.
    let resolver_tls = Arc::new(Tls::new(crate::tls::public_roots())?);
    let resolvers = upstream::known_resolvers()?;
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
    let mut os = Os { journal: &journal, luid };
    let addresses = adapter_addresses(&plan.routes);
    add_addresses(&mut os, &addresses)?;
    let shared_tables = Arc::new(RwLock::new(tables.clone()));
    let egress = Arc::new(Egress::new(tun.index, shared_tables.clone()));
    let context = Context { connector: egress.clone(), tls: resolver_tls, resolvers };
    #[cfg(not(feature = "relay-experiments"))]
    let mtu = MTU;
    #[cfg(feature = "relay-experiments")]
    let mtu = engine.experiments.settings.tun_mtu;
    // Asked per answer, so `filtering.https` going off keeps every ECH from then on.
    let https = engine.https.clone();
    let may_intercept = Box::new(move |name: &str| https.get().is_some_and(|i| i.may_intercept_name(name)));
    let dns = engine.start_dns_service(|endpoints| Arc::new(Service::new(endpoints, context, shared_tables.clone(), engine.names.clone(), engine.meters.clone(), usize::from(mtu), may_intercept)))?;
    // Before the routes, so reading a large file holds up no flow: `sync_https` below
    // then finds it read.
    if wanted(&engine.policy()) {
        load_validation(engine).await;
    }
    // Before the routes, so a hang starting it cannot hold a route.
    let (etw, witness, nat) = start_attribution(engine);
    let added = match route_adapter(&mut os, &addresses, &plan.routes, still_on).await {
        Ok(added) => added,
        Err(e) => {
            engine.stop_dns_service();
            stop_attribution(engine, etw).await;
            return Err(e);
        }
    };

    sync_https(engine, &egress).await;
    let parts = RelayParts { tables: shared_tables, egress, dns, book: engine.book.clone(), names: engine.names.clone(), meters: engine.meters.clone(), filter: engine.filter.clone(), witness, nat, https: engine.https.clone(), sink: Arc::new(TunSink::new(&tun.session, engine.meters.clone())) };
    #[cfg(not(feature = "relay-experiments"))]
    let relay = Arc::new(Relay::new(parts));
    #[cfg(feature = "relay-experiments")]
    let relay = {
        let mut relay = Relay::new(parts);
        relay.experiments = engine.experiments.settings.clone();
        Arc::new(relay)
    };
    #[cfg(feature = "relay-experiments")]
    let device = TunDevice::experimental(tun.session.clone(), engine.meters.clone(), engine.beats.clone(), &engine.experiments.settings);
    #[cfg(not(feature = "relay-experiments"))]
    let device = TunDevice::new(tun.session.clone(), engine.meters.clone(), engine.beats.clone());
    // This run's own arrivals: a previous run's reader, never joined, may still
    // drain its ring into the process-wide meters.
    let offered = device.offered();
    let stack = IpStack::new(config, device);
    *super::lock(&engine.beats.path) = Some(crate::watchdog::PathWatch::new(offered, stack.progress()));
    let lists = tokio::spawn(engine.lists.clone().run(HttpsFetcher::new(relay.clone())));
    let exclusions = tokio::spawn(refresh_exclusions(engine.exclusions.clone(), HttpsFetcher::new(relay.clone()), engine.validation.clone(), engine.dir.clone()));
    let (stop_accept, stopped) = oneshot::channel();
    let accept = tokio::spawn(accept(stack, relay.clone(), stopped));
    // Last: the DNS Client is sent here only once the stack answers.
    let mut capture = CaptureSlot::default();
    let blocks = capture::blocks(tables, &added);
    if !blocks.is_empty() {
        match open_capture(luid, tables, blocks.clone(), &relay.dns).await {
            Ok(held) => capture.held = Some(held),
            Err(why) => capture.failed(engine, why),
        }
    }
    relay.dns.set_every_network_blocked(capture.held.is_some() && capture::every_network_blocked(tables, &blocks));
    // After the metric changed: no multicast or broadcast send goes into the adapter.
    apply::drop_system_routes(luid);
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
    Ok(Up { tun, luid, routes: added, relay, stop_accept, accept, batches, lists, exclusions, etw, capture })
}

/// Interception as this engine run wires it (task D1, D2). Nothing here runs
/// while the slot is empty, and a failure here means every flow takes the relay.
fn build_interception(engine: &Engine, egress: &Arc<Egress>) -> Result<Interception<Egress>, String> {
    engine.exclusions.set_browsers(BrowserSet::read(&WindowsRegistry), wall_ms());
    let trust = Arc::new(PlatformTrust::new()?);
    let verifier = Arc::new(Verifier::new(crate::tls::public_roots(), trust, TRUST_TIMEOUT, engine.validation.clone())?);
    let lookup = super::lock(&engine.dns_service).clone().ok_or("the DNS service is not running")?;
    let ca = engine.ca();
    Ok(Interception {
        connector: egress.clone(),
        exclusions: engine.exclusions.clone(),
        verifier,
        verdicts: VerdictCache::default(),
        ech: Arc::new(EchCache::new(lookup)),
        active: Active::default(),
        minter: Box::new(move || ca.as_ref().and_then(|c| c.minter())),
        filter: engine.filter.clone(),
        names: engine.names.clone(),
        book: engine.book.clone(),
        meters: engine.meters.clone(),
        watch: engine.heal.clone(),
        hook: Arc::new(ContentHook::new(engine.filter.clone(), engine.meters.clone(), InjectLimits::default())),
        clock: wall_ms,
    })
}

/// What a slot about to fill will judge by. A file unchanged since the last read
/// costs one look at its time.
async fn load_validation(engine: &Engine) {
    if let Some(dir) = &engine.dir {
        engine.validation.reload(dir).await;
    }
}

/// Makes the slot match the policy. Called while routes are up, so a switch
/// turned on reaches new flows at the next wake.
async fn sync_https(engine: &Engine, egress: &Arc<Egress>) {
    sync_https_by(engine, load_validation(engine), || build_interception(engine, egress)).await;
}

/// What the build makes is published only once `load` has finished, or a flow would
/// decrypt what the data on disk forbids, and a flow's verdict lasts as long as it
/// does. The build takes a while, so it is published only if it is still wanted by
/// then ([`Engine::publish_https`]).
pub(super) async fn sync_https_by(engine: &Engine, load: impl Future<Output = ()>, build: impl FnOnce() -> Result<Interception<Egress>, String>) {
    if !wanted(&engine.policy()) {
        engine.https.set(None);
    } else if engine.https.get().is_none() {
        load.await;
        engine.publish_https(build());
    }
}

/// While routes are up: the browsers Windows declares, the fetched exclusion
/// lists when any is enabled, and what the update cycle left for the seeded lists and
/// for validation. One wake an hour, as `Lists::run` (plan 6).
async fn refresh_exclusions(slot: Arc<ExclusionSlot>, fetcher: HttpsFetcher, validation: Arc<ValidationSlot>, dir: Option<PathBuf>) {
    let mut every = tokio::time::interval(EXCLUSIONS_EVERY);
    loop {
        every.tick().await;
        slot.set_browsers(BrowserSet::read(&WindowsRegistry), wall_ms());
        slot.reload_seeds(wall_ms());
        if slot.fetches() {
            slot.refresh(&fetcher, wall_ms()).await;
        }
        if let Some(dir) = &dir {
            validation.reload(dir).await;
        }
    }
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
                Err(_) => {
                    // The worker is gone; the watchdog trips on it. Its error, if any, was recorded first.
                    let reason = stack.progress().exit_reason().unwrap_or_else(|| "no error recorded".into());
                    eprintln!("sieve-engine: the packet worker ended: {reason}");
                    break;
                }
            },
        }
    }
    let _ = tasks.shutdown(TASKS_BOUND).await;
    drop(stack);
}

/// The order that keeps the network: close the DNS capture, disarm, close the session (the reader
/// returns), cancel the flows while the runtime runs, delete the routes,
/// empty the journal, close the adapter (Wintun removes it). The ETW session
/// stops only after that, so a hang there cannot hold a route. The DNS service
/// goes with the last reference to it, the relay's, when this returns.
async fn take_down(engine: &Engine, mut up: Up) {
    // First, so the DNS Client is never sent to a server that is going away.
    if let Some(c) = up.capture.held.take() {
        close_capture(&up.relay.dns, c).await;
    }
    engine.arm.set(false);
    *super::lock(&engine.beats.path) = None;
    let _ = up.tun.session.shutdown();
    engine.https.set(None);
    let _ = up.stop_accept.send(());
    let _ = up.accept.await;
    up.batches.abort();
    up.lists.abort();
    up.exclusions.abort();
    engine.stop_dns_service();
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
    engine.routes_settled();
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
