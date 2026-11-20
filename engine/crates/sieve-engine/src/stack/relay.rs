//! Windows: one task per flow the stack accepts (the spike's forwarder,
//! with its live lessons kept):
//! - only unicast reaches the stack (`tun::admit`);
//! - a flow owned by the engine itself is refused and counted (loop guard),
//!   except its plain HTTP, CryptoAPI's revocation fetches (`guard_tcp`);
//! - every upstream socket comes from [`Egress`], pinned outside Sieve's routes;
//! - a failed connect closes the app side with a FIN at once (live run 1:
//!   a dropped ipstack stream left curl waiting 20 s).
//!
//! TCP with `filtering.https` on goes to `tls::intercept`; off (no slot), it
//! uses the offline-tested `flow::relay::relay_tcp` (server bytes flow at
//! once, client bytes are held until decoded and decided, then relayed or the
//! flow is reset with nothing sent). UDP holds datagrams until decoded and
//! decided; the book entry of a blocked UDP flow, or of one `quic::path` refuses,
//! closes at once and the task stays until idle, so a retransmit costs no new owner
//! lookup, with nothing sent upstream. A blocked flow's client Initials are answered
//! with Version Negotiation (`quic::answer_blocked`) and anything else is swallowed; a
//! refused flow's datagrams with ICMP (`quic::refuse`). A relayed UDP flow is decided
//! again when its way out changes (`relay_udp`), so exiting turning on never leaves
//! an open one going from this computer. Port 53 goes to `stack::dns_flow` instead and is never
//! relayed or blocked. The upstream TCP connect happens before the decision, so
//! server-first bytes may reach an app: a decoded name beats the IP map, so
//! the decision cannot be earlier.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use ipstack::{IpStackTcpStream, IpStackUdpStream};
use sieve_ipc::{FlowAction, FlowEvent, FlowKind, FlowProto, Signal};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use super::attribution::{Attribution, Guard, HeldOwner, decide, guard_tcp, is_own};
use super::book::FlowBook;
use super::dns_flow;
use super::egress::Egress;
use super::path_mtu::{self, TooBig};
use super::progress::{Progress, Watched};
use super::retry;
use super::{DNS_PORT, Meters, close_blocked, kind_of, record_decision};
use crate::dns::NameMap;
use crate::link::exit::{self, Exit, ExitReport, Upstream};
use crate::link::{Change, LinkManager, LinkNet, Plan};
use crate::dns::service::Service;
use crate::domain::{FilterSlot, Flow};
use crate::flow::classify::{Decoded, UdpClassifier};
use crate::flow::etw::PidWitness;
use crate::flow::flows::os::IpHelper;
use crate::flow::flows::{Action, AppKeys, Attributor, ExeCache, FiveTuple, Owner, REFRESH_MIN_MS};
use crate::flow::nat::NatTable;
use crate::flow::packet::Proto;
use crate::flow::relay::relay_tcp_until;
use crate::policy::wall_ms;
use crate::quic::{self, PacketSink, Reply, UdpPath};
use crate::route::table::NetTables;
use crate::tls::intercept::{FlowMeta, HttpsSlot, Who, run as run_intercepted};
use crate::tls::splice::{Abort, Ended, drain_then_abort, splice};
use crate::watchdog::monotonic_ms;

/// A TCP flow that sends nothing this long is decided without a name.
pub const FIRST_BYTES_WAIT: Duration = Duration::from_secs(5);
/// A UDP flow idle this long ends (ipstack's own UDP timeout is the same).
pub const UDP_IDLE: Duration = Duration::from_secs(30);
/// A TCP flow whose app sent no valid segment for this long is reset by the stack:
/// Windows' own keep-alive time, the longest an idle connection goes unprobed, and a
/// keep-alive probe counts as use, so an app that relies on them is never reset. TCP
/// itself has no idle limit; the stack's is only for a connection whose app vanished
/// without a FIN or a RST. ipstack's default of 60 s reset every idle connection a
/// minute in (VM run 7: a WebSocket silent for 2 minutes died at 1.00 with Sieve on,
/// lived with it off), which an idle SSH session, a database pool or a long poll does
/// not survive.
pub const TCP_IDLE: Duration = Duration::from_secs(2 * 60 * 60);

/// The stack's TCP settings: ipstack's, with [`TCP_IDLE`].
pub fn tcp_config() -> ipstack::TcpConfig {
    let mut config = ipstack::TcpConfig::default();
    config.timeout = TCP_IDLE;
    config
}
const DATAGRAM: usize = 65_535;

/// The log's words for UDP while exiting through a hub (`handle_udp`).
const QUIC_ON_LINK: &str = "QUIC is refused while exiting through the other device, so the app uses TCP, which goes through it";
const UDP_ON_LINK: &str = "UDP is not carried through the other device, so it was dropped, as set";
const UDP_DIRECT: &str = "UDP is not carried through the other device; it went directly from this computer, as set";

/// One TCP connect of the relay's (`stack::retry`).
pub type TcpDial = dyn retry::Attempt<Stream = TcpStream> + Send + Sync;

/// One UDP upstream of the relay's, connected to its target.
pub type UdpOpen = dyn Fn(std::net::SocketAddr) -> crate::dns::BoxFuture<'static, Result<UdpSocket, String>> + Send + Sync;

/// The relay's UDP upstreams in production: from `egress`, pinned outside Sieve's
/// routes, with path MTU discovery on (`path_mtu`).
fn egress_udp(egress: Arc<Egress>) -> Arc<UdpOpen> {
    Arc::new(move |remote| {
        let egress = egress.clone();
        Box::pin(async move {
            let socket = egress.socket(remote, true)?;
            path_mtu::discover(&socket, remote.is_ipv4())?;
            let up = UdpSocket::from_std(socket.into()).map_err(|e| e.to_string())?;
            up.connect(remote).await.map_err(|e| e.to_string())?;
            Ok(up)
        })
    })
}

/// A UDP flow's handle in the book: ending it ([`FlowBook::end_where`]) stops its
/// relay, and the flow is decided again, as a new one.
#[derive(Clone, Default)]
struct UdpEnd(Arc<tokio::sync::Notify>);

impl super::book::Idle for UdpEnd {
    /// Never a candidate at the cap: a UDP flow ends itself after [`UDP_IDLE`] of
    /// silence.
    fn idle(&self) -> Duration {
        Duration::ZERO
    }
    fn evict(&self) {
        self.0.notify_one();
    }
}

/// Why a guarded connect was not made.
pub const LEAVES_THROUGH_HUB: &str = "while exiting through the other device, this address is reached only through it";

/// The relay's TCP connects for a flow exiting may concern: a target exiting
/// applies to now ([`LinkManager::may_leave_directly`]) is refused, never
/// dialled from this computer. It covers the first connect and every retry,
/// whatever address the retry came from: the one place a relayed flow's direct
/// connect is decided while exiting is on.
struct Guarded<'a> {
    inner: &'a TcpDial,
    link: &'a LinkManager,
}

impl retry::Attempt for Guarded<'_> {
    type Stream = TcpStream;

    fn attempt(&self, target: std::net::SocketAddr) -> retry::AttemptFuture<'_, TcpStream> {
        if !self.link.may_leave_directly(target.ip()) {
            return Box::pin(async { Err(retry::Failure::Egress(LEAVES_THROUGH_HUB.into())) });
        }
        self.inner.attempt(target)
    }
}

/// A flow's direct connect with its retries, guarded: an alternate address
/// exiting applies to is neither offered nor dialled.
async fn connect_guarded(ctx: &Relay, flow: FiveTuple) -> retry::Connected<TcpStream> {
    let guarded = Guarded { inner: &*ctx.tcp, link: &ctx.link };
    retry::connect(&guarded, flow.remote, || {
        let mut all = alternates(ctx, flow);
        all.retain(|ip| ctx.link.may_leave_directly(*ip));
        all
    })
    .await
}

type ExeLookup = fn(u32) -> Option<String>;
type ProductLookup = fn(&str) -> Option<String>;
type HiddenNameLookup = fn(u32) -> Option<String>;

/// A flow the book took: its id and who it belongs to.
pub(super) struct Admitted {
    pub(super) id: u64,
    owner: HeldOwner,
}

impl Admitted {
    pub(super) fn may_decrypt(&self) -> bool {
        self.owner.as_owner().may_decrypt()
    }
}

/// The ETW ring, or nothing when its session could not start.
pub type Witness = Box<dyn PidWitness + Send>;

/// A flow's origin, and (diagnostic builds) how long finding it took.
pub struct Attributed {
    attribution: Attribution,
    /// A source named the engine itself (`is_own`): the loop guard refuses it.
    own: bool,
    #[cfg(feature = "attribution-diagnostics")]
    elapsed_ms: u64,
}

impl Attributed {
    /// The host process the flow is attributed to, if any.
    pub(super) fn pid(&self) -> Option<u32> {
        self.attribution.event_fields().0
    }
}

/// What every flow task shares.
pub struct Relay {
    #[cfg(feature = "relay-experiments")]
    pub experiments: crate::experiments::Settings,
    pub own_pid: u32,
    pub attributor: Mutex<Attributor<IpHelper, Witness>>,
    /// The NAT state that proves a guest's flow.
    pub nat: Arc<NatTable>,
    pub exes: Mutex<ExeCache<ExeLookup>>,
    pub keys: AppKeys<ProductLookup, HiddenNameLookup>,
    /// The decision snapshot, read once per flow.
    pub filter: Arc<FilterSlot>,
    /// Re-read on every route change (control); pinning and DNS's split rules
    /// read this same table.
    pub tables: Arc<RwLock<NetTables>>,
    pub egress: Arc<Egress>,
    /// The relay's TCP connects: `egress` in production, a scripted one in tests.
    /// Every connect for a flow goes through [`connect_guarded`] unless the flow
    /// is one exiting never concerns (an app that is Off, the switch off).
    pub tcp: Arc<TcpDial>,
    /// The relay's UDP upstreams: `egress` in production, a loopback one in tests.
    pub udp: Arc<UdpOpen>,
    pub dns: Arc<Service>,
    /// The IP-to-names map the decision reads for an unnamed flow.
    pub names: Arc<Mutex<NameMap>>,
    pub book: Arc<Mutex<FlowBook>>,
    pub meters: Arc<Meters>,
    /// `filtering.https`: empty means every flow takes `relay_tcp`.
    pub https: Arc<HttpsSlot<Exit>>,
    /// Where a refused QUIC flow's answers go: the adapter.
    pub sink: Arc<dyn PacketSink>,
    /// Exiting through another device (`crate::link`).
    pub link: Arc<LinkManager>,
}

pub(super) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The Windows session of a process.
pub fn session_of(pid: u32) -> Option<u32> {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    let mut session = 0u32;
    // SAFETY: plain call with an out pointer.
    unsafe { ProcessIdToSessionId(pid, &mut session) }.ok().map(|()| session)
}

/// What a routing run hands its relay.
pub struct RelayParts {
    pub tables: Arc<RwLock<NetTables>>,
    pub egress: Arc<Egress>,
    pub dns: Arc<Service>,
    pub book: Arc<Mutex<FlowBook>>,
    pub names: Arc<Mutex<NameMap>>,
    pub meters: Arc<Meters>,
    pub filter: Arc<FilterSlot>,
    pub witness: Witness,
    pub nat: Arc<NatTable>,
    pub https: Arc<HttpsSlot<Exit>>,
    pub sink: Arc<dyn PacketSink>,
    pub link: Arc<LinkManager>,
}

impl Relay {
    pub fn new(RelayParts { tables, egress, dns, book, names, meters, filter, witness, nat, https, sink, link }: RelayParts) -> Self {
        Self {
            #[cfg(feature = "relay-experiments")]
            experiments: crate::experiments::Settings::default(),
            own_pid: std::process::id(),
            attributor: Mutex::new(Attributor::new(IpHelper, witness)),
            nat,
            exes: Mutex::new(ExeCache::new(crate::flow::flows::os::exe_path as ExeLookup)),
            keys: AppKeys::new(crate::flow::flows::os::product_name as ProductLookup, crate::flow::flows::os::hidden_name as HiddenNameLookup),
            filter,
            tables,
            tcp: egress.clone(),
            udp: egress_udp(egress.clone()),
            egress,
            dns,
            names,
            book,
            meters,
            https,
            sink,
            link,
        }
    }

    /// The owner, retried while the owner table lags (bounded by the
    /// attributor's give-up time).
    async fn owner(&self, flow: FiveTuple) -> Owner {
        loop {
            let answer = lock(&self.attributor).owner(&flow, monotonic_ms());
            if answer != Owner::Pending {
                return answer;
            }
            tokio::time::sleep(Duration::from_millis(REFRESH_MIN_MS)).await;
        }
    }

    /// The flow's origin (`stack::attribution`). NAT is read only on an owner
    /// miss, so a machine with no VMs issues a query only for its rare unknown
    /// flows. An owner answer is checked against the NAT state: a forwarded UDP
    /// flow whose external port equals a host wildcard-bound port would otherwise
    /// match that row and borrow that app's exemption. Only a flow the held state
    /// claims is read for, since that claim may be a guest's ended session.
    ///
    /// TENSION (S24): a NAT session newer than the last read can slip past
    /// that check. A read for every owner answer would add a WMI round trip to
    /// every host DNS lookup, which is not acceptable. On a machine with an active
    /// VM, its own misses keep the index fresh; live proof L3 counts collisions.
    pub(super) async fn attribute(&self, flow: FiveTuple) -> Attributed {
        #[cfg(feature = "attribution-diagnostics")]
        let started = monotonic_ms();
        let owner = self.owner(flow).await;
        let nat = match owner {
            Owner::Disagreed { .. } => None,
            Owner::Unknown => self.nat.fresh_match(&flow, monotonic_ms()).await,
            _ => self.nat.confirmed_match(&flow, monotonic_ms()).await,
        };
        Attributed {
            attribution: decide(owner, nat),
            own: is_own(owner, self.own_pid),
            #[cfg(feature = "attribution-diagnostics")]
            elapsed_ms: monotonic_ms().saturating_sub(started),
        }
    }

    /// The evidence of one admitted flow. An unknown flow's tables are read
    /// again here, for the report only: nothing here reaches a decision.
    #[cfg(feature = "attribution-diagnostics")]
    fn observe(&self, flow: FiveTuple, attributed: &Attributed) {
        use crate::flow::flows::{OwnerSource, Table};
        let (same, other) = if matches!(attributed.attribution, Attribution::Unknown(_)) {
            let same_table = Table::of(&flow);
            let other_table = match same_table {Table::Tcp4 => Table::Tcp6, Table::Tcp6 => Table::Tcp4, Table::Udp4 => Table::Udp6, Table::Udp6 => Table::Udp4};
            (IpHelper.read(same_table), IpHelper.read(other_table))
        } else {
            (None, None)
        };
        let mut report = lock(&self.meters.attribution);
        report.nat = self.nat.stats();
        report.observe(flow, &attributed.attribution, monotonic_ms(), same.as_deref(), other.as_deref(), attributed.elapsed_ms);
    }

    /// Counts the flow and registers it in the book; None when it is the
    /// engine's own (refused) or the book is full.
    pub(super) fn admit(&self, flow: &FiveTuple, attributed: &Attributed, proto: FlowProto, kind: FlowKind) -> Option<Admitted> {
        self.admit_with(flow, attributed, proto, kind, None)
    }

    /// [Self::admit] for a flow the book may end to make room at its cap.
    pub(super) fn admit_with(&self, flow: &FiveTuple, attributed: &Attributed, proto: FlowProto, kind: FlowKind, idle: Option<Box<dyn super::book::Idle>>) -> Option<Admitted> {
        if attributed.own {
            Meters::bump(&self.meters.own_refused);
            return None;
        }
        let attribution = &attributed.attribution;
        attribution.count(&self.meters);
        #[cfg(feature = "attribution-diagnostics")]
        self.observe(*flow, attributed);
        let (pid, forwarded) = attribution.event_fields();
        let exe = pid.and_then(|p| lock(&self.exes).exe(p, monotonic_ms()));
        let app = pid.and_then(|p| self.keys.of_pid(p, exe.as_deref()));
        let event = FlowEvent {
            id: 0,
            pid,
            exe,
            session: pid.and_then(session_of),
            proto,
            local: flow.local.to_string(),
            remote: flow.remote.to_string(),
            kind,
            host: None,
            action: FlowAction::Relayed,
            bytes_up: 0,
            bytes_down: 0,
            open: true,
            reason: None,
            rule: None,
            list: None,
            forwarded,
        };
        let mut book = lock(&self.book);
        let id = book.open_with(event, idle)?;
        let owner = attribution.row_owner(app, &book);
        book.own(id, owner.row_key());
        Some(Admitted { id, owner })
    }

    /// The one decision for a flow whose first bytes were decoded, in the book.
    /// The snapshot is read here, so a flow decided keeps its decision. Port 53
    /// never comes here (`dns_flow`), so `dns` is false.
    fn decide(&self, admitted: &Admitted, d: &Decoded, flow: &FiveTuple) -> Action {
        let decision = self.filter.get().decide(Flow::from_decoded(d, false, flow.remote.ip(), admitted.owner.as_owner()), &self.names, monotonic_ms());
        let mut book = lock(&self.book);
        book.update(admitted.id, |e| record_decision(e, d, false, &decision));
        book.log_decision(admitted.id, &decision, wall_ms());
        decision.action
    }
}

/// Closes the app side promptly (FIN).
pub(super) async fn close_app(app: &mut IpStackTcpStream) {
    let _ = tokio::time::timeout(Duration::from_secs(1), app.shutdown()).await;
}

impl Abort for IpStackTcpStream {
    fn abort(&self) {
        IpStackTcpStream::abort(self);
    }
    fn closed(&self) -> Ended {
        Box::pin(IpStackTcpStream::closed(self))
    }
    fn drained(&self) -> Ended {
        Box::pin(IpStackTcpStream::drained(self))
    }
}

pub async fn handle_tcp(ctx: Arc<Relay>, mut app: IpStackTcpStream) {
    let flow = FiveTuple { proto: Proto::Tcp, local: app.local_addr(), remote: app.peer_addr() };
    if flow.remote.port() == DNS_PORT {
        return dns_flow::tcp(ctx, app, flow).await;
    }
    let accepted_ms = monotonic_ms();
    // Read before the way is chosen, to see a change that comes before the flow is
    // in the book (where a change finds it: `reconnect_the_new_way`).
    let way = ctx.link.way_now();
    // Exiting through a hub: its own path (`handle_exiting`), which keeps this
    // one for the flows that do not exit.
    if let Some(plan) = ctx.link.plan(flow.remote.ip()) {
        return handle_exiting(ctx, app, flow, plan, accepted_ms).await;
    }
    // A destination exiting does not concern, but its retries may be other
    // addresses of the same name: guarded, so none of those leaves directly while
    // exiting applies to it (whose flow it is is not known yet, so an app that is
    // Off loses those alternates too while exiting is on).
    let (attributed, connected) = tokio::join!(ctx.attribute(flow), connect_guarded(&ctx, flow));
    if guard_tcp(attributed.own, flow.remote.port()) == Guard::RelayOwn {
        return relay_own(app, connected.result).await;
    }
    let Some(admitted) = ctx.admit_with(&flow, &attributed, FlowProto::Tcp, FlowKind::Other, Some(Box::new(app.handle()))) else { return close_app(&mut app).await };
    // The way out changed while this flow connected directly, too late for the
    // change to find it in the book: if exiting now applies to it, it ends here as
    // the change ends every other (a reset; the app reconnects the new way).
    if ctx.link.way_now() != way && exiting_applies(&ctx, admitted.owner.as_owner(), &flow).is_some() {
        drop(connected);
        app.abort();
        let mut book = lock(&ctx.book);
        book.close(admitted.id, FlowAction::Relayed, 0, 0);
        note_ended(&mut book, 1, Change::Way(sieve_ipc::ExitVia::Hub));
        return;
    }
    serve_connected(ctx, app, flow, admitted, connected, accepted_ms).await;
}

/// The way out changed ([`crate::link::ExitChanged`]). [`Change::Way`]: every open
/// flow of a sieved app (not Off) to a destination exiting `concerns` is ended, so
/// it reconnects the new way (through the hub, or from this computer): TCP with a
/// reset, UDP by deciding it again. [`Change::WentDirect`]: only the TCP flows of
/// those that went directly while the hub could not be reached (UDP sent directly
/// is the UDP choice's, which the hub's return does not change). One row says how
/// many. A connection never changes its way in the middle: ending it is the only
/// way the "every connection" the app promises holds.
pub fn reconnect_the_new_way(book: &Mutex<FlowBook>, filter: &FilterSlot, concerns: &dyn Fn(std::net::IpAddr) -> bool, change: Change) -> usize {
    let filter = filter.get();
    let mut book = lock(book);
    let sieved_to = |e: &sieve_ipc::FlowEvent, key: Option<&str>| !key.is_some_and(|k| filter.is_off_key(k)) && e.remote.parse::<std::net::SocketAddr>().is_ok_and(|a| concerns(a.ip()));
    let ended = match change {
        Change::Way(_) => book.end_where(|e, key, _| sieved_to(e, key)),
        Change::WentDirect { .. } => book.end_where(|e, key, went_direct| went_direct && e.proto == FlowProto::Tcp && sieved_to(e, key)),
    };
    note_ended(&mut book, ended, change);
    ended
}

/// The one row that says how many open flows a change of the way out ended.
fn note_ended(book: &mut FlowBook, ended: usize, change: Change) {
    if ended == 0 {
        return;
    }
    let (s, they) = if ended == 1 { ("", "it reconnects") } else { ("s", "they reconnect") };
    let (via, reason) = match change {
        Change::Way(via) => {
            let how = if via == sieve_ipc::ExitVia::Hub { "through the other device" } else { "directly from this computer" };
            (via, format!("The way out changed: {ended} open connection{s} ended so {they} {how}"))
        }
        Change::WentDirect { hub_back: true } => {
            (sieve_ipc::ExitVia::Hub, format!("The other device can be reached again: {ended} connection{s} that went directly from this computer ended so {they} through it"))
        }
        Change::WentDirect { hub_back: false } => (
            sieve_ipc::ExitVia::Hub,
            format!("Connections are now stopped while the other device cannot be reached: {ended} connection{s} that went directly from this computer ended"),
        ),
    };
    book.note(sieve_ipc::LogOutcome::Exit { via, target: None, reason: Some(reason) });
}

/// Exiting through a hub applies to this flow now: its plan, or None (the switch
/// off, the app Off, or exiting does not concern the destination now).
fn exiting_applies(ctx: &Relay, owner: crate::domain::Owner<'_>, flow: &FiveTuple) -> Option<Plan> {
    let filter = ctx.filter.get();
    if !filter.enabled || filter.is_off(owner) {
        return None;
    }
    ctx.link.plan(flow.remote.ip())
}

/// The other addresses a failed connect may try; the name map is read only once
/// the connect failed or its race is due (`retry`).
fn alternates(ctx: &Relay, flow: FiveTuple) -> Vec<std::net::IpAddr> {
    let filter = ctx.filter.get();
    retry::alternates(&lock(&ctx.names), flow.remote.ip(), monotonic_ms(), |name| filter.blocks_name(name))
}

/// An admitted flow whose SYN-time connect has its result: served, or closed
/// with its problem.
async fn serve_connected(ctx: Arc<Relay>, mut app: IpStackTcpStream, flow: FiveTuple, admitted: Admitted, connected: retry::Connected<TcpStream>, accepted_ms: u64) {
    if let Some(how) = connected.retry() {
        lock(&ctx.book).retried(admitted.id, how, connected.result.is_ok());
    }
    let upstream = match connected.result {
        Ok(u) => u,
        Err(failure) => {
            {
                let mut book = lock(&ctx.book);
                book.problem(admitted.id, failure.signal());
                book.close(admitted.id, FlowAction::Failed, 0, 0);
            }
            return close_app(&mut app).await;
        }
    };
    serve_admitted(ctx, app, flow, admitted, Upstream::Tcp(upstream), accepted_ms, None).await;
}

/// A TCP flow while exiting through a hub. Its origin is found first, as the
/// path depends on it: an app that is Off and every flow while the global switch
/// is off connect at once from this computer, as without the hub. Any other flow
/// gets an upstream that opens through the hub only once decided (`link::exit`):
/// nothing reaches the hub for a blocked flow, no retry to another address (the
/// hub resolves names and tries its own), and the hub is asked for the name the
/// flow carries. The engine's own plain HTTP (certificate status and issuer
/// fetches) goes through the hub too, by its Host: from this computer it would
/// say which site is being visited.
async fn handle_exiting(ctx: Arc<Relay>, mut app: IpStackTcpStream, flow: FiveTuple, plan: Plan, accepted_ms: u64) {
    let attributed = ctx.attribute(flow).await;
    if guard_tcp(attributed.own, flow.remote.port()) == Guard::RelayOwn {
        return relay_own_through(ctx, app, flow, plan).await;
    }
    let Some(admitted) = ctx.admit_with(&flow, &attributed, FlowProto::Tcp, FlowKind::Other, Some(Box::new(app.handle()))) else { return close_app(&mut app).await };
    let exits = {
        let filter = ctx.filter.get();
        filter.enabled && !filter.is_off(admitted.owner.as_owner())
    };
    if !exits {
        // Exiting never concerns this flow: as without the hub, unguarded.
        let connected = retry::connect(&*ctx.tcp, flow.remote, || alternates(&ctx, flow)).await;
        return serve_connected(ctx, app, flow, admitted, connected, accepted_ms).await;
    }
    let (upstream, starter) = exit::lazy();
    let starter = FlowExit { starter, plan, net: ctx.egress.clone(), book: ctx.book.clone(), id: Some(admitted.id), remote: flow.remote };
    serve_admitted(ctx, app, flow, admitted, Upstream::Lazy(upstream), accepted_ms, Some(starter)).await;
}

/// Opens an exiting flow's upstream once it is decided, and logs how it went
/// (on the flow's row; the engine's own flow has none).
pub(super) struct FlowExit {
    starter: exit::Starter,
    plan: Plan,
    net: Arc<dyn LinkNet>,
    book: Arc<Mutex<FlowBook>>,
    id: Option<u64>,
    remote: std::net::SocketAddr,
}

impl FlowExit {
    #[cfg(test)]
    pub(super) fn for_test(ctx: &Relay, starter: exit::Starter, plan: Plan, id: u64, remote: std::net::SocketAddr) -> Self {
        Self { starter, plan, net: ctx.egress.clone(), book: ctx.book.clone(), id: Some(id), remote }
    }

    /// The flow passed with what its first bytes said: the hub is asked for the
    /// name they carry, else for the address (never a name only Sieve's DNS
    /// recorded for it: `link::exit`).
    fn start(&self, decoded: &Decoded) {
        let host = exit::choose_host(decoded.domain.as_deref(), self.remote.ip());
        let (plan, net, book, id, remote) = (self.plan.clone(), self.net.clone(), self.book.clone(), self.id, self.remote);
        self.starter.start(async move {
            let (opened, report) = exit::open(&plan, &*net, &host, remote.port(), remote).await;
            if let Some(id) = id {
                lock(&book).exit(id, report);
            }
            opened
        });
    }
}

/// The engine's own plain HTTP ([`guard_tcp`]): not the user's flow, so no book
/// entry and no decision, only the copy.
async fn relay_own(mut app: IpStackTcpStream, upstream: Result<TcpStream, retry::Failure>) {
    if let Ok(upstream) = upstream {
        let closed = app.closed();
        splice(&mut app, upstream, &[], closed).await;
    }
    close_app(&mut app).await;
}

/// The engine's own plain HTTP while exiting applies to its destination: its
/// first bytes are read for the Host, then it opens through the hub as any flow
/// does (stopped with the hub down when so set). No book entry, no decision.
pub(super) async fn relay_own_through(ctx: Arc<Relay>, mut app: IpStackTcpStream, flow: FiveTuple, plan: Plan) {
    let (upstream, starter) = exit::lazy();
    let exit = FlowExit { starter, plan, net: ctx.egress.clone(), book: ctx.book.clone(), id: None, remote: flow.remote };
    let closed = app.closed();
    let decide = |d: &Decoded| {
        exit.start(d);
        Action::Pass
    };
    let out = relay_tcp_until(&mut app, Upstream::Lazy(upstream), FIRST_BYTES_WAIT, decide, closed).await;
    if out.reset_app {
        drain_then_abort(&app).await;
    }
    close_app(&mut app).await;
}

/// An admitted flow with its SYN-time socket, or with an upstream that `exit`
/// opens through the hub once the flow passed, to its end.
pub(super) async fn serve_admitted(ctx: Arc<Relay>, mut app: IpStackTcpStream, flow: FiveTuple, admitted: Admitted, upstream: Upstream, accepted_ms: u64, exit: Option<FlowExit>) {
    let decide = |d: &Decoded| {
        let action = ctx.decide(&admitted, d, &flow);
        if action != Action::Drop
            && let Some(exit) = &exit
        {
            exit.start(d);
        }
        action
    };
    // One path per flow, chosen once (task D1): no slot is today's relay.
    if let Some(https) = ctx.https.get() {
        let event = lock(&ctx.book).snapshot_of(admitted.id);
        let pid = event.as_ref().and_then(|e| e.pid);
        let decide = |d: &Decoded| {
            if let (Some(pid), Some(host)) = (pid, d.domain.as_deref()) {
                ctx.meters.quic.tcp_seen(pid, host, accepted_ms);
            }
            decide(d)
        };
        let meta = FlowMeta {
            id: admitted.id,
            remote: flow.remote,
            exe: event.as_ref().and_then(|e| e.exe.as_deref()),
            session: event.as_ref().and_then(|e| e.session),
            owner: admitted.owner.as_owner(),
            names_now_ms: monotonic_ms(),
            decide: &decide,
        };
        let out = run_intercepted(&https, app, upstream, meta).await;
        if out.action == FlowAction::Blocked {
            close_blocked(&ctx.book, &ctx.meters, admitted.id);
        } else {
            lock(&ctx.book).close(admitted.id, out.action, out.bytes_up, out.bytes_down);
        }
        return;
    }
    let progress = Progress::new(monotonic_ms);
    let upstream = Watched::new(upstream, progress.clone());
    // The app's connection's end ends the relay even while only the server is read.
    let closed = app.closed();
    #[cfg(feature = "relay-experiments")]
    let out = if let Some(capacity) = ctx.experiments.copy_buffer_bytes {
        crate::flow::relay::relay_tcp_buffered(&mut app, upstream, FIRST_BYTES_WAIT, decide, capacity, closed).await
    } else {
        relay_tcp_until(&mut app, upstream, FIRST_BYTES_WAIT, decide, closed).await
    };
    #[cfg(not(feature = "relay-experiments"))]
    let out = relay_tcp_until(&mut app, upstream, FIRST_BYTES_WAIT, decide, closed).await;
    // The server's side broke: the app hears a reset, not the FIN of a complete
    // answer, once what reached it is acknowledged.
    if out.reset_app {
        drain_then_abort(&app).await;
    }
    if out.dropped {
        close_blocked(&ctx.book, &ctx.meters, admitted.id);
        app.abort();
    } else {
        let action = if out.upstream_write_failed { FlowAction::Failed } else { FlowAction::Relayed };
        let mut book = lock(&ctx.book);
        if progress.stalled() {
            book.problem(admitted.id, Signal::Stall);
        }
        book.close(admitted.id, action, out.bytes_up, out.bytes_down);
    }
    if out.stop {
        close_app(&mut app).await;
    }
}

pub async fn handle_udp(ctx: Arc<Relay>, mut app: IpStackUdpStream) {
    let flow = FiveTuple { proto: Proto::Udp, local: app.local_addr(), remote: app.peer_addr() };
    if flow.remote.port() == DNS_PORT {
        return dns_flow::udp(ctx, app, flow).await;
    }
    let attribution = {
        let c = ctx.clone();
        tokio::spawn(async move { c.attribute(flow).await })
    };
    // Datagrams are held until the flow is decoded (a QUIC ClientHello can
    // span two Initials).
    let mut classifier = UdpClassifier::new();
    let mut held: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![0u8; DATAGRAM];
    let mut first_datagram_ms = None;
    let decided = loop {
        match tokio::time::timeout(UDP_IDLE, app.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                first_datagram_ms.get_or_insert_with(monotonic_ms);
                held.push(buf[..n].to_vec());
                if let Some(d) = classifier.push(&buf[..n]) {
                    break d;
                }
            }
            _ => return,
        }
    };
    let Ok(attributed) = attribution.await else { return };
    let is_quic = decided.kind == Some(crate::flow::classify::Kind::Quic);
    // Once more when a refusal ends on a datagram (that datagram is a new flow), and
    // when a relayed flow's way out changed (decided again, as a new flow).
    loop {
        let end = UdpEnd::default();
        let Some(admitted) = ctx.admit_with(&flow, &attributed, FlowProto::Udp, kind_of(&decided), Some(Box::new(end.clone()))) else { return };
        let id = admitted.id;
        let action = ctx.decide(&admitted, &decided, &flow);
        // Read only with the slot there, so off asks nothing new. A slot that comes up
        // in between reads as an unknown app: relayed, which is the fail-open way.
        let event = ctx.https.get().and_then(|_| lock(&ctx.book).snapshot_of(id));
        let owner = admitted.owner.as_owner();
        // Exiting through a hub, which carries TCP only: QUIC is refused so the app
        // falls back to TCP (through the hub); other UDP to a public address is
        // dropped or sent directly, as the owner set. An app that is Off and
        // everything while the global switch is off are left as they are.
        let exiting = || exiting_applies(&ctx, owner, &flow).is_some();
        let on_link = || (action != Action::Drop).then(|| exiting_applies(&ctx, owner, &flow)).flatten().map(|plan| exit::udp_on_link(is_quic, plan.udp));
        let mut direct_as_set = false;
        if let Some(on_link) = on_link() {
            match on_link {
                exit::UdpOnLink::RefuseQuic => {
                    lock(&ctx.book).exit(id, ExitReport { via: sieve_ipc::ExitVia::Dropped, target: None, reason: Some(QUIC_ON_LINK.into()), signal: None });
                    quic::close_refused(&ctx.book, id);
                    let reply = Reply { ends: (flow.local, flow.remote), refusal: quic::REFUSAL, sink: &*ctx.sink, meters: &ctx.meters.quic };
                    held = quic::refuse(&mut app, &reply, held, &mut buf, UDP_IDLE, exiting).await;
                    if held.is_empty() {
                        return;
                    }
                    continue;
                }
                exit::UdpOnLink::Drop => {
                    {
                        let mut book = lock(&ctx.book);
                        book.exit(id, ExitReport { via: sieve_ipc::ExitVia::Dropped, target: None, reason: Some(UDP_ON_LINK.into()), signal: Some(sieve_ipc::Signal::UdpDropped) });
                        book.close(id, FlowAction::Relayed, 0, 0);
                    }
                    // Swallowed until idle, so a retransmit is no new flow.
                    while let Ok(Ok(n)) = tokio::time::timeout(UDP_IDLE, app.read(&mut buf)).await {
                        if n == 0 {
                            break;
                        }
                    }
                    return;
                }
                exit::UdpOnLink::Direct => {
                    lock(&ctx.book).exit(id, ExitReport { via: sieve_ipc::ExitVia::Direct, target: None, reason: Some(UDP_DIRECT.into()), signal: None });
                    direct_as_set = true;
                }
            }
        }
        let who = Who {
            remote: flow.remote,
            exe: event.as_ref().and_then(|e| e.exe.as_deref()),
            session: event.as_ref().and_then(|e| e.session),
            may_decrypt: owner.may_decrypt(),
            app_off: event.is_some() && ctx.filter.get().is_off(owner),
            names_now_ms: monotonic_ms(),
        };
        match quic::path(action, &ctx.https, &decided, &who, id) {
            UdpPath::Drop => {
                close_blocked(&ctx.book, &ctx.meters, id);
                return quic::answer_blocked(&mut app, &held, &mut buf, UDP_IDLE, &ctx.meters.quic.blocked_replies).await;
            }
            UdpPath::Refuse(refusal) => {
                quic::close_refused(&ctx.book, id);
                if let (Some(pid), Some(host), Some(first)) = (event.as_ref().and_then(|e| e.pid), decided.domain.as_deref(), first_datagram_ms.take()) {
                    ctx.meters.quic.refused(pid, host, first);
                }
                let reply = Reply { ends: (flow.local, flow.remote), refusal, sink: &*ctx.sink, meters: &ctx.meters.quic };
                held = quic::refuse(&mut app, &reply, held, &mut buf, UDP_IDLE, || ctx.https.refuses(owner)).await;
                if held.is_empty() {
                    return;
                }
                continue;
            }
            UdpPath::Relay => {}
        }
        let held = std::mem::take(&mut held);
        if relay_udp(&ctx, &mut app, flow, id, &end, held, &mut buf, on_link, direct_as_set).await == Relayed::Ended {
            return;
        }
    }
}

/// How a relayed UDP flow's relay ended.
#[derive(Debug, PartialEq, Eq)]
enum Relayed {
    /// The flow is over (idle, or a side closed or failed).
    Ended,
    /// Its way out changed: the flow is decided again, as a new one.
    Again,
}

/// A decided UDP flow relayed from this computer until it ends, or until its way
/// out changes ([`Relayed::Again`]): the book ended it (a change of the way out,
/// `reconnect_the_new_way`), or the way out moved ([`LinkManager::way_out`]) and
/// `on_link` now says drop or refuse (exiting turned on, sieving resumed, UDP set
/// to drop). Its decision is taken once, at its start: without this an open flow
/// would keep leaving from this computer's address after exiting turned on.
#[allow(clippy::too_many_arguments)]
async fn relay_udp(ctx: &Relay, app: &mut IpStackUdpStream, flow: FiveTuple, id: u64, end: &UdpEnd, held: Vec<Vec<u8>>, buf: &mut [u8], on_link: impl Fn() -> Option<exit::UdpOnLink>, mut direct_as_set: bool) -> Relayed {
    // Watched from before the socket opens: a change meanwhile is seen at once.
    let mut way = ctx.link.way_out();
    way.borrow_and_update();
    let up = match (ctx.udp)(flow.remote).await {
        Ok(u) => u,
        Err(_) => {
            lock(&ctx.book).close(id, FlowAction::Failed, 0, 0);
            return Relayed::Ended;
        }
    };
    let ipv4 = flow.remote.is_ipv4();
    // The adapter's MTU is larger than the real path: see `path_mtu`.
    let too_big = TooBig { ends: (flow.local, flow.remote), sink: &*ctx.sink, meters: &ctx.meters };
    let send_up = async |d: &[u8]| too_big.after_send(up.send(d).await, d, || path_mtu::of(&up, ipv4));
    let (mut bytes_up, mut bytes_down) = (0u64, 0u64);
    for d in &held {
        match send_up(d).await {
            Ok(sent) => bytes_up += sent as u64,
            Err(_) => {
                lock(&ctx.book).close(id, FlowAction::Failed, 0, 0);
                return Relayed::Ended;
            }
        }
    }
    let mut down = vec![0u8; DATAGRAM];
    let mut way_gone = false;
    let ended = loop {
        tokio::select! {
            r = tokio::time::timeout(UDP_IDLE, app.read(buf)) => match r {
                Ok(Ok(n)) if n > 0 => match send_up(&buf[..n]).await {
                    Ok(sent) => bytes_up += sent as u64,
                    Err(_) => break Relayed::Ended,
                },
                _ => break Relayed::Ended,
            },
            r = tokio::time::timeout(UDP_IDLE, up.recv(&mut down)) => match r {
                Ok(Ok(n)) => {
                    if app.write_all(&down[..n]).await.is_err() { break Relayed::Ended; }
                    bytes_down += n as u64;
                }
                _ => break Relayed::Ended,
            },
            () = end.0.notified() => break Relayed::Again,
            changed = way.changed(), if !way_gone => {
                if changed.is_err() {
                    // The manager is gone, so nothing exits any more: as it is.
                    way_gone = true;
                    continue;
                }
                match on_link() {
                    // Exiting does not concern it (now): from this computer is right.
                    None => {}
                    Some(exit::UdpOnLink::Direct) => {
                        if !direct_as_set {
                            lock(&ctx.book).exit(id, ExitReport { via: sieve_ipc::ExitVia::Direct, target: None, reason: Some(UDP_DIRECT.into()), signal: None });
                            direct_as_set = true;
                        }
                    }
                    Some(exit::UdpOnLink::Drop | exit::UdpOnLink::RefuseQuic) => break Relayed::Again,
                }
            }
        }
    };
    lock(&ctx.book).close(id, FlowAction::Relayed, bytes_up, bytes_down);
    ended
}
