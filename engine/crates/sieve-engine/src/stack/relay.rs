//! Windows: one task per flow the stack accepts (the spike's forwarder,
//! with its live lessons kept):
//! - only unicast reaches the stack (`tun::admit`);
//! - a flow owned by the engine itself is refused and counted (loop guard);
//! - every upstream socket is bound to the egress interface's own source
//!   address and pinned with IP_UNICAST_IF / IPV6_UNICAST_IF, both computed
//!   with Sieve's routes ignored (`route::pin`); "would loop" is refused;
//! - a failed connect closes the app side with a FIN at once (live run 1:
//!   a dropped ipstack stream left curl waiting 20 s).
//!
//! TCP uses the offline-tested `flow::relay::relay_tcp` (server bytes flow at
//! once, client bytes are held until decoded and decided, then relayed or the
//! flow is closed with nothing sent). UDP holds datagrams until decoded and
//! decided; a blocked UDP flow's book entry closes and its datagrams are
//! swallowed until idle. Port 53 is DNS: the query goes to the server it was
//! sent to, every answer is recorded in the IP-to-names map, and a lookup is
//! never blocked. The upstream TCP connect happens before the decision, so
//! server-first bytes may reach an app: a decoded name beats the IP map, so
//! the decision cannot be earlier.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use ipstack::{IpStackTcpStream, IpStackUdpStream};
use sieve_ipc::{FlowAction, FlowEvent, FlowKind, FlowProto};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use super::book::FlowBook;
use super::{DNS_PORT, Meters, close_blocked, drain_udp, kind_of, record_decision};
use crate::dns::{self, NameMap};
use crate::domain::{FilterSlot, Flow, Owner as FlowOwner};
use crate::flow::classify::{Decoded, UdpClassifier};
use crate::flow::flows::os::IpHelper;
use crate::flow::flows::{Action, AppKeys, Attributor, ExeCache, FiveTuple, Owner, REFRESH_MIN_MS};
use crate::flow::packet::Proto;
use crate::flow::relay::relay_tcp;
use crate::route::pin::{self, unicast_if_value};
use crate::route::table::NetTables;
use crate::watchdog::monotonic_ms;

/// A TCP flow that sends nothing this long is decided without a name.
pub const FIRST_BYTES_WAIT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A UDP flow idle this long ends (ipstack's own UDP timeout is the same).
pub const UDP_IDLE: Duration = Duration::from_secs(30);
/// A DNS flow is one query and its answer: it ends this long after the last
/// datagram, so the DNS Client's one-port-per-query traffic holds no socket
/// for half a minute.
pub const DNS_IDLE: Duration = Duration::from_secs(5);
const DATAGRAM: usize = 65_535;

type ExeLookup = fn(u32) -> Option<String>;
type ProductLookup = fn(&str) -> Option<String>;

/// A flow the book took: its id and its app's key, when it has one.
struct Admitted {
    id: u64,
    app: Option<String>,
}

/// What every flow task shares.
pub struct Relay {
    #[cfg(feature = "relay-experiments")]
    pub experiments: crate::experiments::Settings,
    pub own_pid: u32,
    pub tun_index: u32,
    pub attributor: Mutex<Attributor<IpHelper>>,
    pub exes: Mutex<ExeCache<ExeLookup>>,
    pub keys: AppKeys<ProductLookup>,
    /// The decision snapshot, read once per flow.
    pub filter: Arc<FilterSlot>,
    /// Re-read on every route change (control); pinning asks it.
    pub tables: RwLock<NetTables>,
    pub book: Arc<Mutex<FlowBook>>,
    pub names: Arc<Mutex<NameMap>>,
    pub meters: Arc<Meters>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The Windows session of a process.
pub fn session_of(pid: u32) -> Option<u32> {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    let mut session = 0u32;
    // SAFETY: plain call with an out pointer.
    unsafe { ProcessIdToSessionId(pid, &mut session) }.ok().map(|()| session)
}

impl Relay {
    pub fn new(tun_index: u32, tables: NetTables, book: Arc<Mutex<FlowBook>>, names: Arc<Mutex<NameMap>>, meters: Arc<Meters>, filter: Arc<FilterSlot>) -> Self {
        Self {
            #[cfg(feature = "relay-experiments")]
            experiments: crate::experiments::Settings::default(),
            own_pid: std::process::id(),
            tun_index,
            attributor: Mutex::new(Attributor::new(IpHelper)),
            exes: Mutex::new(ExeCache::new(crate::flow::flows::os::exe_path as ExeLookup)),
            keys: AppKeys::new(crate::flow::flows::os::product_name as ProductLookup),
            filter,
            tables: RwLock::new(tables),
            book,
            names,
            meters,
        }
    }

    /// The owner pid, retried while the owner table lags (bounded by the
    /// attributor's give-up time).
    async fn owner(&self, flow: FiveTuple) -> Option<u32> {
        #[cfg(feature = "attribution-diagnostics")]
        let started = monotonic_ms();
        loop {
            let answer = lock(&self.attributor).owner(&flow, monotonic_ms());
            match answer {
                Owner::Pid(pid) => {
                    #[cfg(feature = "attribution-diagnostics")]
                    lock(&self.meters.attribution).observe(flow, true, monotonic_ms(), None, None, monotonic_ms().saturating_sub(started));
                    return Some(pid);
                }
                Owner::Unknown => {
                    #[cfg(feature = "attribution-diagnostics")]
                    self.unknown_diagnostics(flow, monotonic_ms().saturating_sub(started));
                    return None;
                }
                Owner::Pending => tokio::time::sleep(Duration::from_millis(REFRESH_MIN_MS)).await,
            }
        }
    }

    #[cfg(feature = "attribution-diagnostics")]
    fn unknown_diagnostics(&self, flow: FiveTuple, lookup_elapsed_ms: u64) {
        use crate::flow::flows::{OwnerSource, Table};
        let same_table = Table::of(&flow);
        let other_table = match same_table {Table::Tcp4 => Table::Tcp6, Table::Tcp6 => Table::Tcp4, Table::Udp4 => Table::Udp6, Table::Udp6 => Table::Udp4};
        let same = IpHelper.read(same_table);
        let other = IpHelper.read(other_table);
        lock(&self.meters.attribution).observe(flow, false, monotonic_ms(), same.as_deref(), other.as_deref(), lookup_elapsed_ms);
    }

    /// Counts the flow and registers it in the book; None when it is the
    /// engine's own (refused) or the book is full.
    fn admit(&self, flow: &FiveTuple, pid: Option<u32>, proto: FlowProto, kind: FlowKind) -> Option<Admitted> {
        if pid == Some(self.own_pid) {
            Meters::bump(&self.meters.own_refused);
            return None;
        }
        Meters::bump(&self.meters.flows);
        if pid.is_some() {
            Meters::bump(&self.meters.attributed);
        }
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
        };
        lock(&self.book).open(event).map(|id| Admitted { id, app })
    }

    /// The one decision for a flow whose first bytes were decoded, in the book.
    /// The snapshot is read here, so a flow decided keeps its decision.
    fn decide(&self, admitted: &Admitted, d: &Decoded, dns: bool, flow: &FiveTuple) -> Action {
        let owner = admitted.app.as_deref().map_or(FlowOwner::Unknown, |key| FlowOwner::App { key });
        let decision = self.filter.get().decide(Flow::from_decoded(d, dns, flow.remote.ip(), owner), &self.names, monotonic_ms());
        lock(&self.book).update(admitted.id, |e| record_decision(e, d, dns, &decision));
        decision.action
    }

    /// A socket for `target`, bound to the egress source and pinned to the
    /// egress interface (never the engine's adapter).
    fn egress_socket(&self, target: SocketAddr, udp: bool) -> Result<socket2::Socket, String> {
        use socket2::{Domain, Protocol, Socket, Type};
        let e = {
            let tables = self.tables.read().unwrap_or_else(|p| p.into_inner());
            pin::egress(&tables, Some(self.tun_index), target.ip()).map_err(|e| e.to_string())?
        };
        let domain = if target.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let (ty, proto) = if udp { (Type::DGRAM, Protocol::UDP) } else { (Type::STREAM, Protocol::TCP) };
        let sock = Socket::new(domain, ty, Some(proto)).map_err(|e| format!("socket: {e}"))?;
        sock.set_nonblocking(true).map_err(|e| format!("nonblocking: {e}"))?;
        sock.bind(&SocketAddr::new(e.source, 0).into()).map_err(|err| format!("bind {}: {err}", e.source))?;
        pin_to_interface(&sock, target, e.if_index)?;
        Ok(sock)
    }

    /// A connected TCP stream on the egress interface (flows and the engine's
    /// own downloads alike).
    pub async fn connect(&self, target: SocketAddr) -> Result<TcpStream, String> {
        let sock = self.egress_socket(target, false)?;
        let socket = TcpSocket::from_std_stream(sock.into());
        match tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(target)).await {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(format!("connect {target}: {e}")),
            Err(_) => Err(format!("connect {target}: timeout")),
        }
    }
}

fn pin_to_interface(sock: &socket2::Socket, target: SocketAddr, index: u32) -> Result<(), String> {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, setsockopt};
    let s = SOCKET(sock.as_raw_socket() as usize);
    let (level, name) = if target.is_ipv4() { (IPPROTO_IP.0, IP_UNICAST_IF) } else { (IPPROTO_IPV6.0, IPV6_UNICAST_IF) };
    let value = unicast_if_value(index, target.is_ipv4());
    // SAFETY: `s` is a live socket; the option value is a 4-byte DWORD.
    let r = unsafe { setsockopt(s, level, name, Some(&value)) };
    if r == 0 { Ok(()) } else { Err(format!("setsockopt UNICAST_IF: {}", std::io::Error::last_os_error())) }
}

/// Closes the app side promptly (FIN).
async fn close_app(app: &mut IpStackTcpStream) {
    let _ = tokio::time::timeout(Duration::from_secs(1), app.shutdown()).await;
}

pub async fn handle_tcp(ctx: Arc<Relay>, mut app: IpStackTcpStream) {
    let flow = FiveTuple { proto: Proto::Tcp, local: app.local_addr(), remote: app.peer_addr() };
    let dns = flow.remote.port() == DNS_PORT;
    let (pid, upstream) = tokio::join!(ctx.owner(flow), ctx.connect(flow.remote));
    let kind = if dns { FlowKind::Dns } else { FlowKind::Other };
    let Some(admitted) = ctx.admit(&flow, pid, FlowProto::Tcp, kind) else { return close_app(&mut app).await };
    let upstream = match upstream {
        Ok(u) => u,
        Err(_) => {
            lock(&ctx.book).close(admitted.id, FlowAction::Failed, 0, 0);
            return close_app(&mut app).await;
        }
    };
    let decide = |d: &Decoded| ctx.decide(&admitted, d, dns, &flow);
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
    } else {
        let action = if out.upstream_write_failed { FlowAction::Failed } else { FlowAction::Relayed };
        lock(&ctx.book).close(admitted.id, action, out.bytes_up, out.bytes_down);
    }
    if out.stop {
        close_app(&mut app).await;
    }
}

pub async fn handle_udp(ctx: Arc<Relay>, mut app: IpStackUdpStream) {
    let flow = FiveTuple { proto: Proto::Udp, local: app.local_addr(), remote: app.peer_addr() };
    let dns = flow.remote.port() == DNS_PORT;
    let owner = {
        let c = ctx.clone();
        tokio::spawn(async move { c.owner(flow).await })
    };
    // Datagrams are held until the flow is decoded (a QUIC ClientHello can
    // span two Initials); a DNS query is decoded by its question.
    let mut classifier = UdpClassifier::new();
    let mut held: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![0u8; DATAGRAM];
    let decided = loop {
        match tokio::time::timeout(UDP_IDLE, app.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                held.push(buf[..n].to_vec());
                if dns {
                    break Decoded { domain: dns::parse(&buf[..n]).and_then(|m| m.question), ..Decoded::default() };
                }
                if let Some(d) = classifier.push(&buf[..n]) {
                    break d;
                }
            }
            _ => return,
        }
    };
    let pid = owner.await.unwrap_or(None);
    let Some(admitted) = ctx.admit(&flow, pid, FlowProto::Udp, if dns { FlowKind::Dns } else { kind_of(&decided) }) else { return };
    let id = admitted.id;
    if ctx.decide(&admitted, &decided, dns, &flow) == Action::Drop {
        close_blocked(&ctx.book, &ctx.meters, id);
        return drain_udp(&mut app, UDP_IDLE).await;
    }
    let up = match ctx.egress_socket(flow.remote, true).and_then(|s| UdpSocket::from_std(s.into()).map_err(|e| e.to_string())) {
        Ok(u) => u,
        Err(_) => return lock(&ctx.book).close(id, FlowAction::Failed, 0, 0),
    };
    if up.connect(flow.remote).await.is_err() {
        return lock(&ctx.book).close(id, FlowAction::Failed, 0, 0);
    }
    let (mut bytes_up, mut bytes_down) = (0u64, 0u64);
    let mut transactions = dns::Transactions::default();
    for d in &held {
        if up.send(d).await.is_err() {
            return lock(&ctx.book).close(id, FlowAction::Failed, 0, 0);
        }
        bytes_up += d.len() as u64;
        if dns { transactions.remember(d, monotonic_ms()); }
    }
    let mut down = vec![0u8; DATAGRAM];
    let idle = if dns { DNS_IDLE } else { UDP_IDLE };
    loop {
        tokio::select! {
            r = tokio::time::timeout(idle, app.read(&mut buf)) => match r {
                Ok(Ok(n)) if n > 0 => {
                    if up.send(&buf[..n]).await.is_err() { break; }
                    bytes_up += n as u64;
                    if dns { transactions.remember(&buf[..n], monotonic_ms()); }
                }
                _ => break,
            },
            r = tokio::time::timeout(idle, up.recv(&mut down)) => match r {
                Ok(Ok(n)) => {
                    if dns && let Some(m) = transactions.answer(&down[..n], monotonic_ms()) {
                        lock(&ctx.names).record_message(&m, monotonic_ms());
                        Meters::bump(&ctx.meters.dns_answers);
                    }
                    if app.write_all(&down[..n]).await.is_err() { break; }
                    bytes_down += n as u64;
                }
                _ => break,
            },
        }
    }
    lock(&ctx.book).close(id, FlowAction::Relayed, bytes_up, bytes_down);
}
