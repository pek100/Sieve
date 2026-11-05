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
//! once, client bytes are held until decoded, then relayed). UDP holds
//! datagrams until decoded, then relays both ways. Port 53 is DNS: the query
//! goes to the server it was sent to, and every answer is recorded in the
//! IP-to-names map. Nothing is dropped for its content in slice 3.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use ipstack::{IpStackTcpStream, IpStackUdpStream};
use sieve_ipc::{FlowAction, FlowEvent, FlowKind, FlowProto};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use super::attribution::{Attribution, decide};
use super::book::FlowBook;
use super::{DNS_PORT, Meters, kind_of};
use crate::dns::{self, NameMap};
use crate::flow::classify::{Decoded, UdpClassifier};
use crate::flow::etw::PidWitness;
use crate::flow::flows::os::IpHelper;
use crate::flow::flows::{Action, Attributor, ExeCache, FiveTuple, Owner, REFRESH_MIN_MS};
use crate::flow::nat::NatTable;
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
/// The ETW ring, or nothing when its session could not start.
pub type Witness = Box<dyn PidWitness + Send>;

/// A flow's origin, and (diagnostic builds) how long finding it took.
pub struct Attributed {
    attribution: Attribution,
    #[cfg(feature = "attribution-diagnostics")]
    elapsed_ms: u64,
}

/// What every flow task shares.
pub struct Relay {
    #[cfg(feature = "relay-experiments")]
    pub experiments: crate::experiments::Settings,
    pub own_pid: u32,
    pub tun_index: u32,
    pub attributor: Mutex<Attributor<IpHelper, Witness>>,
    /// The NAT state that proves a guest's flow.
    pub nat: Arc<NatTable>,
    pub exes: Mutex<ExeCache<ExeLookup>>,
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
    pub fn new(
        tun_index: u32,
        tables: NetTables,
        book: Arc<Mutex<FlowBook>>,
        names: Arc<Mutex<NameMap>>,
        meters: Arc<Meters>,
        witness: Witness,
        nat: Arc<NatTable>,
    ) -> Self {
        Self {
            #[cfg(feature = "relay-experiments")]
            experiments: crate::experiments::Settings::default(),
            own_pid: std::process::id(),
            tun_index,
            attributor: Mutex::new(Attributor::new(IpHelper, witness)),
            nat,
            exes: Mutex::new(ExeCache::new(crate::flow::flows::os::exe_path as ExeLookup)),
            tables: RwLock::new(tables),
            book,
            names,
            meters,
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
    /// flows. An owner answer is checked against the NAT state already held: a
    /// forwarded UDP flow whose external port equals a host wildcard-bound
    /// port would otherwise match that row and borrow that app's exemption.
    ///
    /// TENSION (S24): a NAT session newer than the last read can slip past
    /// that check. A fresh read here would add a WMI round trip to every host
    /// DNS lookup, which is not acceptable. On a machine with an active VM,
    /// its own misses keep the index fresh; live proof L3 counts collisions.
    async fn attribute(&self, flow: FiveTuple) -> Attributed {
        #[cfg(feature = "attribution-diagnostics")]
        let started = monotonic_ms();
        let owner = self.owner(flow).await;
        let nat = match owner {
            Owner::Disagreed => None,
            Owner::Unknown => self.nat.fresh_match(&flow, monotonic_ms()).await,
            _ => self.nat.held_match(&flow),
        };
        Attributed {
            attribution: decide(owner, nat),
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
    fn admit(&self, flow: &FiveTuple, attributed: &Attributed, proto: FlowProto, kind: FlowKind) -> Option<u64> {
        let attribution = &attributed.attribution;
        if attribution.pid() == Some(self.own_pid) {
            Meters::bump(&self.meters.own_refused);
            return None;
        }
        attribution.count(&self.meters);
        #[cfg(feature = "attribution-diagnostics")]
        self.observe(*flow, attributed);
        let (pid, forwarded) = attribution.event_fields();
        let exe = pid.and_then(|p| lock(&self.exes).exe(p, monotonic_ms()));
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
            forwarded,
        };
        lock(&self.book).open(event)
    }

    fn decided(&self, id: u64, d: &Decoded, dns: bool) {
        lock(&self.book).update(id, |e| {
            e.kind = if dns { FlowKind::Dns } else { kind_of(d) };
            e.host.clone_from(&d.domain);
        });
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

    async fn connect(&self, target: SocketAddr) -> Result<TcpStream, String> {
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
    let (attributed, upstream) = tokio::join!(ctx.attribute(flow), ctx.connect(flow.remote));
    let kind = if dns { FlowKind::Dns } else { FlowKind::Other };
    let Some(id) = ctx.admit(&flow, &attributed, FlowProto::Tcp, kind) else { return close_app(&mut app).await };
    let upstream = match upstream {
        Ok(u) => u,
        Err(_) => {
            lock(&ctx.book).close(id, FlowAction::Failed, 0, 0);
            return close_app(&mut app).await;
        }
    };
    #[cfg(feature = "relay-experiments")]
    let out = if let Some(capacity) = ctx.experiments.copy_buffer_bytes {
        crate::flow::relay::relay_tcp_buffered(&mut app, upstream, FIRST_BYTES_WAIT, |d| {
            ctx.decided(id, d, dns);
            Action::Pass
        }, capacity).await
    } else {
        relay_tcp(&mut app, upstream, FIRST_BYTES_WAIT, |d| {
            ctx.decided(id, d, dns);
            Action::Pass
        }).await
    };
    #[cfg(not(feature = "relay-experiments"))]
    let out = relay_tcp(&mut app, upstream, FIRST_BYTES_WAIT, |d| {
        ctx.decided(id, d, dns);
        Action::Pass
    })
    .await;
    let action = if out.upstream_write_failed { FlowAction::Failed } else { FlowAction::Relayed };
    lock(&ctx.book).close(id, action, out.bytes_up, out.bytes_down);
    if out.stop {
        close_app(&mut app).await;
    }
}

pub async fn handle_udp(ctx: Arc<Relay>, mut app: IpStackUdpStream) {
    let flow = FiveTuple { proto: Proto::Udp, local: app.local_addr(), remote: app.peer_addr() };
    let dns = flow.remote.port() == DNS_PORT;
    let attribution = {
        let c = ctx.clone();
        tokio::spawn(async move { c.attribute(flow).await })
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
    let Ok(attributed) = attribution.await else { return };
    let Some(id) = ctx.admit(&flow, &attributed, FlowProto::Udp, if dns { FlowKind::Dns } else { kind_of(&decided) }) else { return };
    ctx.decided(id, &decided, dns);
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
