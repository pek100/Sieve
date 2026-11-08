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
//! refused flow's datagrams with ICMP (`quic::refuse`). Port 53 goes to `stack::dns_flow` instead and is never
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
use crate::dns::service::Service;
use crate::domain::{FilterSlot, Flow};
use crate::flow::classify::{Decoded, UdpClassifier};
use crate::flow::etw::PidWitness;
use crate::flow::flows::os::IpHelper;
use crate::flow::flows::{Action, AppKeys, Attributor, ExeCache, FiveTuple, Owner, REFRESH_MIN_MS};
use crate::flow::nat::NatTable;
use crate::flow::packet::Proto;
use crate::flow::relay::relay_tcp;
use crate::policy::wall_ms;
use crate::quic::{self, PacketSink, Reply, UdpPath};
use crate::route::table::NetTables;
use crate::tls::intercept::{FlowMeta, HttpsSlot, Who, run as run_intercepted};
use crate::tls::splice::{Abort, splice};
use crate::watchdog::monotonic_ms;

/// A TCP flow that sends nothing this long is decided without a name.
pub const FIRST_BYTES_WAIT: Duration = Duration::from_secs(5);
/// A UDP flow idle this long ends (ipstack's own UDP timeout is the same).
pub const UDP_IDLE: Duration = Duration::from_secs(30);
const DATAGRAM: usize = 65_535;

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
    pub dns: Arc<Service>,
    /// The IP-to-names map the decision reads for an unnamed flow.
    pub names: Arc<Mutex<NameMap>>,
    pub book: Arc<Mutex<FlowBook>>,
    pub meters: Arc<Meters>,
    /// `filtering.https`: empty means every flow takes `relay_tcp`.
    pub https: Arc<HttpsSlot<Egress>>,
    /// Where a refused QUIC flow's answers go: the adapter.
    pub sink: Arc<dyn PacketSink>,
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
    pub https: Arc<HttpsSlot<Egress>>,
    pub sink: Arc<dyn PacketSink>,
}

impl Relay {
    pub fn new(RelayParts { tables, egress, dns, book, names, meters, filter, witness, nat, https, sink }: RelayParts) -> Self {
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
            egress,
            dns,
            names,
            book,
            meters,
            https,
            sink,
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
        let id = book.open(event)?;
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
}

pub async fn handle_tcp(ctx: Arc<Relay>, mut app: IpStackTcpStream) {
    let flow = FiveTuple { proto: Proto::Tcp, local: app.local_addr(), remote: app.peer_addr() };
    if flow.remote.port() == DNS_PORT {
        return dns_flow::tcp(ctx, app, flow).await;
    }
    let accepted_ms = monotonic_ms();
    // The name map is read only once the connect failed or its race is due (`retry`).
    let alternates = || {
        let filter = ctx.filter.get();
        retry::alternates(&lock(&ctx.names), flow.remote.ip(), monotonic_ms(), |name| filter.blocks_name(name))
    };
    let (attributed, connected) = tokio::join!(ctx.attribute(flow), retry::connect(&*ctx.egress, flow.remote, alternates));
    if guard_tcp(attributed.own, flow.remote.port()) == Guard::RelayOwn {
        return relay_own(app, connected.result).await;
    }
    let Some(admitted) = ctx.admit(&flow, &attributed, FlowProto::Tcp, FlowKind::Other) else { return close_app(&mut app).await };
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
    serve_admitted(ctx, app, flow, admitted, upstream, accepted_ms).await;
}

/// The engine's own plain HTTP ([`guard_tcp`]): not the user's flow, so no book
/// entry and no decision, only the copy.
async fn relay_own(mut app: IpStackTcpStream, upstream: Result<TcpStream, retry::Failure>) {
    if let Ok(upstream) = upstream {
        splice(&mut app, upstream, &[]).await;
    }
    close_app(&mut app).await;
}

/// An admitted flow with its SYN-time socket, to its end.
pub(super) async fn serve_admitted(ctx: Arc<Relay>, mut app: IpStackTcpStream, flow: FiveTuple, admitted: Admitted, upstream: TcpStream, accepted_ms: u64) {
    let decide = |d: &Decoded| ctx.decide(&admitted, d, &flow);
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
    #[cfg(feature = "relay-experiments")]
    let out = if let Some(capacity) = ctx.experiments.copy_buffer_bytes {
        crate::flow::relay::relay_tcp_buffered(&mut app, upstream, FIRST_BYTES_WAIT, decide, capacity).await
    } else {
        relay_tcp(&mut app, upstream, FIRST_BYTES_WAIT, decide).await
    };
    #[cfg(not(feature = "relay-experiments"))]
    let out = relay_tcp(&mut app, upstream, FIRST_BYTES_WAIT, decide).await;
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
    // Once more when a refusal ends on a datagram: that datagram is a new flow.
    let id = loop {
        let Some(admitted) = ctx.admit(&flow, &attributed, FlowProto::Udp, kind_of(&decided)) else { return };
        let id = admitted.id;
        let action = ctx.decide(&admitted, &decided, &flow);
        // Read only with the slot there, so off asks nothing new. A slot that comes up
        // in between reads as an unknown app: relayed, which is the fail-open way.
        let event = ctx.https.get().and_then(|_| lock(&ctx.book).snapshot_of(id));
        let owner = admitted.owner.as_owner();
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
            }
            UdpPath::Relay => break id,
        }
    };
    let ipv4 = flow.remote.is_ipv4();
    let socket = ctx.egress.socket(flow.remote, true).and_then(|s| path_mtu::discover(&s, ipv4).map(|()| s));
    let up = match socket.and_then(|s| UdpSocket::from_std(s.into()).map_err(|e| e.to_string())) {
        Ok(u) => u,
        Err(_) => return lock(&ctx.book).close(id, FlowAction::Failed, 0, 0),
    };
    if up.connect(flow.remote).await.is_err() {
        return lock(&ctx.book).close(id, FlowAction::Failed, 0, 0);
    }
    // The adapter's MTU is larger than the real path: see `path_mtu`.
    let too_big = TooBig { ends: (flow.local, flow.remote), sink: &*ctx.sink, meters: &ctx.meters };
    let send_up = async |d: &[u8]| too_big.after_send(up.send(d).await, d, || path_mtu::of(&up, ipv4));
    let (mut bytes_up, mut bytes_down) = (0u64, 0u64);
    for d in &held {
        match send_up(d).await {
            Ok(sent) => bytes_up += sent as u64,
            Err(_) => return lock(&ctx.book).close(id, FlowAction::Failed, 0, 0),
        }
    }
    let mut down = vec![0u8; DATAGRAM];
    loop {
        tokio::select! {
            r = tokio::time::timeout(UDP_IDLE, app.read(&mut buf)) => match r {
                Ok(Ok(n)) if n > 0 => match send_up(&buf[..n]).await {
                    Ok(sent) => bytes_up += sent as u64,
                    Err(_) => break,
                },
                _ => break,
            },
            r = tokio::time::timeout(UDP_IDLE, up.recv(&mut down)) => match r {
                Ok(Ok(n)) => {
                    if app.write_all(&down[..n]).await.is_err() { break; }
                    bytes_down += n as u64;
                }
                _ => break,
            },
        }
    }
    lock(&ctx.book).close(id, FlowAction::Relayed, bytes_up, bytes_down);
}
