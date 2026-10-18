//! The DNS proxy: a UDP and a TCP server on one address. A query for a
//! blocked name is answered here; everything else is forwarded unchanged to
//! the upstreams.
//!
//! Block answer: A -> 0.0.0.0, AAAA -> ::, every other type (HTTPS, SVCB,
//! TXT, ...) -> NOERROR with no records, all with a `BLOCK_TTL_SECS` TTL.
//! Not NXDOMAIN, because the Windows DNS client treats NXDOMAIN as "try the
//! next suffix in the search list" and re-asks for `ads.example.com.corp`
//! and friends (more queries, and the blocked name leaks to the network's
//! resolver). A null address answers the question, connections to it fail
//! at once, and it is what AdGuard answers by default. The short TTL keeps
//! a name unblocked by the user from staying dead in caches for long.
//!
//! Forwarding: upstreams in order, first success wins. Each is asked over
//! UDP (resent every `RETRANSMIT_MS` within the timeout); a truncated answer (TC bit) is asked again over TCP. A UDP client
//! gets the full TCP answer when it fits its advertised size, otherwise the
//! truncated one (it then retries over TCP itself). Sequential, not raced:
//! a race would send every query to every upstream.
//!
//! Pass-through: while set (the global Sieving switch is off) every query
//! is forwarded, blocked names too, and nothing is counted as blocked. The
//! proxy keeps answering, so anything that sends its lookups here keeps working.
//!
//! The self check's canary (`rules::CANARY_NAME`, `.invalid`) always gets
//! the block answer, pass-through or not, and is never counted: not in
//! `queries`, `blocked` or the top blocked names.
//!
//! Lifecycle: `Proxy::start` binds a UDP and a TCP socket on every listen
//! address (a requested port 0 gets the same free port for UDP and TCP of
//! that address), `stop` ends every server and every in-flight task, which
//! frees the ports. Dropping a `Proxy` also stops its servers (the shutdown
//! channel closes), without waiting. It listens on both 127.0.0.1 and ::1,
//! so a client of either address family can ask it.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use super::DnsError;
use super::rules::{RuleSet, Verdict, normalize_query};

/// Where the proxy listens by default: the IPv4 and IPv6 loopback, port 53.
/// Sieve never points Windows at them; `crate::windns` only reads whether
/// something else did.
pub const DEFAULT_BINDS: [&str; 2] = ["127.0.0.1:53", "[::1]:53"];
pub const DEFAULT_UPSTREAMS: [&str; 2] = ["1.1.1.1:53", "9.9.9.9:53"];
/// TTL of a block answer, seconds (AdGuard's default too).
pub const BLOCK_TTL_SECS: u32 = 10;
/// Per-upstream, per-transport timeout.
pub const UPSTREAM_TIMEOUT_MS: u64 = 2_000;
/// A UDP query with no answer after this long is sent again (the Windows
/// DNS client's first retry interval).
pub const RETRANSMIT_MS: u64 = 1_000;
/// A TCP client connection idle this long is closed.
pub const TCP_IDLE_TIMEOUT_MS: u64 = 10_000;
/// How many top blocked domains the stats report.
pub const TOP_BLOCKED_N: usize = 20;
/// Distinct blocked names counted one by one; later names are counted in
/// `untracked` only, so a flood of random names cannot grow memory.
pub const MAX_TRACKED_DOMAINS: usize = 4_096;

/// Largest DNS message (the TCP length prefix is a u16).
const MAX_MESSAGE: usize = 65_535;
/// With port 0, how many random ports to try for a UDP and TCP pair.
const BIND_ATTEMPTS: usize = 64;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Listen addresses, at least one; each gets a UDP and a TCP server.
    pub binds: Vec<SocketAddr>,
    pub upstreams: Vec<SocketAddr>,
    pub upstream_timeout: Duration,
}

/// The live rule set; swapped whole when a list refresh lands.
pub type SharedRules = Arc<RwLock<Arc<RuleSet>>>;

/// Counters at one moment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub queries: u64,
    pub blocked: u64,
    pub forwarded: u64,
    pub failed: u64,
    /// Blocked queries whose name was not tracked (see MAX_TRACKED_DOMAINS).
    pub untracked: u64,
    pub last_error: Option<String>,
    /// Most blocked names, count descending then name ascending.
    pub top_blocked: Vec<(String, u64)>,
}

#[derive(Default)]
struct Stats {
    queries: AtomicU64,
    blocked: AtomicU64,
    forwarded: AtomicU64,
    failed: AtomicU64,
    untracked: AtomicU64,
    last_error: Mutex<Option<String>>,
    per_domain: Mutex<HashMap<String, u64>>,
}

/// A poisoned lock only means another task panicked mid-update of a
/// counter map; the data is still usable.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Stats {
    fn note_error(&self, e: String) {
        *lock(&self.last_error) = Some(e);
    }

    fn note_blocked(&self, name: &str) {
        self.blocked.fetch_add(1, Ordering::Relaxed);
        let mut map = lock(&self.per_domain);
        if let Some(n) = map.get_mut(name) {
            *n += 1;
        } else if map.len() < MAX_TRACKED_DOMAINS {
            map.insert(name.to_owned(), 1);
        } else {
            self.untracked.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> StatsSnapshot {
        let mut top: Vec<(String, u64)> =
            lock(&self.per_domain).iter().map(|(k, v)| (k.clone(), *v)).collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top.truncate(TOP_BLOCKED_N);
        StatsSnapshot {
            queries: self.queries.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            untracked: self.untracked.load(Ordering::Relaxed),
            last_error: lock(&self.last_error).clone(),
            top_blocked: top,
        }
    }
}

struct Shared {
    rules: SharedRules,
    /// Forward everything, block nothing (see the module doc).
    pass_through: AtomicBool,
    upstreams: Vec<SocketAddr>,
    timeout: Duration,
    stats: Stats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

/// A running proxy. See the module doc for the lifecycle.
pub struct Proxy {
    /// One per listen address, in the configured order; never empty.
    local_addrs: Vec<SocketAddr>,
    shared: Arc<Shared>,
    shutdown: watch::Sender<bool>,
    servers: Vec<JoinHandle<()>>,
}

impl Proxy {
    pub async fn start(config: ProxyConfig, rules: RuleSet) -> Result<Proxy, DnsError> {
        if config.upstreams.is_empty() {
            return Err(DnsError::Config("at least one upstream is needed".to_owned()));
        }
        if config.binds.is_empty() {
            return Err(DnsError::Config("at least one listen address is needed".to_owned()));
        }
        // Bind everything before serving anything: a taken second address
        // fails the start as a whole (the bound sockets drop here).
        let mut pairs = Vec::with_capacity(config.binds.len());
        let mut local_addrs = Vec::with_capacity(config.binds.len());
        for &bind in &config.binds {
            let (udp, tcp) = bind_pair(bind).await?;
            local_addrs.push(udp.local_addr().map_err(|source| DnsError::Bind { addr: bind, source })?);
            pairs.push((udp, tcp));
        }
        let shared = Arc::new(Shared {
            rules: Arc::new(RwLock::new(Arc::new(rules))),
            pass_through: AtomicBool::new(false),
            upstreams: config.upstreams,
            timeout: config.upstream_timeout,
            stats: Stats::default(),
        });
        let (shutdown, rx) = watch::channel(false);
        let servers = pairs
            .into_iter()
            .flat_map(|(udp, tcp)| {
                [
                    tokio::spawn(serve_udp(udp, shared.clone(), rx.clone())),
                    tokio::spawn(serve_tcp(tcp, shared.clone(), rx.clone())),
                ]
            })
            .collect();
        Ok(Proxy { local_addrs, shared, shutdown, servers })
    }

    /// The first bound address (the real port when 0 was asked for).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addrs[0]
    }

    /// Every bound address, in the configured order.
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.local_addrs
    }

    /// The live rules, for a refresher to swap.
    pub fn rules(&self) -> SharedRules {
        self.shared.rules.clone()
    }

    pub fn stats(&self) -> StatsSnapshot {
        self.shared.stats.snapshot()
    }

    /// Forward every query, blocked names too (true), or filter again (false).
    /// Takes effect on the next query.
    pub fn set_pass_through(&self, on: bool) {
        self.shared.pass_through.store(on, Ordering::SeqCst);
    }

    pub fn pass_through(&self) -> bool {
        self.shared.pass_through.load(Ordering::SeqCst)
    }

    /// Stops both servers and every in-flight query; the port is free when
    /// this returns.
    pub async fn stop(mut self) {
        // A send error means every receiver is gone: the servers already ended.
        let _ = self.shutdown.send(true);
        for server in self.servers.drain(..) {
            // A server that panicked has ended too; nothing left to stop.
            let _ = server.await;
        }
    }
}

/// UDP and TCP on the same address. A fixed port is bound once. For port 0
/// (tests) a random port of the dynamic range is tried for both, again on
/// any failure.
///
/// Why not let the OS pick for one protocol and reuse it for the other:
/// Windows reserves TCP and UDP port ranges separately and they move
/// (Hyper-V, WinNAT: `netsh int ipv4 show excludedportrange protocol=udp`,
/// about 1500 ports in 100-port blocks on the dev machine, 2026-10-17), and
/// the OS hands out ephemeral ports nearly in sequence. A port picked by one
/// protocol sat inside the other's exclusion for every retry: 4 of 54 DNS
/// tests failed with WSAEACCES (10013) with UDP picking, 20 of 118 with TCP
/// picking, on different runs. Random ports spread over the range escape a
/// block within a few tries.
async fn bind_pair(addr: SocketAddr) -> Result<(UdpSocket, TcpListener), DnsError> {
    if addr.port() != 0 {
        let tcp = TcpListener::bind(addr).await.map_err(|source| DnsError::Bind { addr, source })?;
        let udp = UdpSocket::bind(addr).await.map_err(|source| DnsError::Bind { addr, source })?;
        return Ok((udp, tcp));
    }
    let mut last = None;
    for _ in 0..BIND_ATTEMPTS {
        let candidate = SocketAddr::new(addr.ip(), random_dynamic_port());
        match TcpListener::bind(candidate).await {
            Ok(tcp) => match UdpSocket::bind(candidate).await {
                Ok(udp) => return Ok((udp, tcp)),
                Err(e) => last = Some(e),
            },
            Err(e) => last = Some(e),
        }
    }
    let source = last.unwrap_or_else(|| std::io::Error::other("no bind attempt made"));
    Err(DnsError::Bind { addr, source })
}

/// First port of the IANA dynamic range (also Windows' default for both protocols).
const DYNAMIC_PORTS_START: u16 = 49_152;

/// A random port in 49152..=65535. RandomState is seeded per instance by the
/// standard library, so no random-number crate is needed for this.
fn random_dynamic_port() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let r = std::collections::hash_map::RandomState::new().build_hasher().finish();
    let span = u64::from(u16::MAX - DYNAMIC_PORTS_START) + 1;
    DYNAMIC_PORTS_START + u16::try_from(r % span).unwrap_or(0)
}

async fn serve_udp(socket: UdpSocket, shared: Arc<Shared>, mut shutdown: watch::Receiver<bool>) {
    let socket = Arc::new(socket);
    let mut tasks = JoinSet::new();
    let mut buf = vec![0u8; MAX_MESSAGE];
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            received = socket.recv_from(&mut buf) => match received {
                Ok((n, peer)) => {
                    let query = buf[..n].to_vec();
                    let (shared, socket) = (shared.clone(), socket.clone());
                    tasks.spawn(async move {
                        if let Some(reply) = shared.answer(&query, Transport::Udp).await
                            && let Err(e) = socket.send_to(&reply, peer).await
                        {
                            shared.stats.note_error(format!("udp reply to {peer}: {e}"));
                        }
                    });
                }
                // Windows reports an ICMP port-unreachable for an earlier
                // reply as ConnectionReset on the next receive. The socket
                // is fine; the client simply left.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                Err(e) => shared.stats.note_error(format!("udp receive: {e}")),
            }
        }
        while tasks.try_join_next().is_some() {}
    }
    tasks.shutdown().await;
}

async fn serve_tcp(listener: TcpListener, shared: Arc<Shared>, mut shutdown: watch::Receiver<bool>) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    tasks.spawn(serve_tcp_conn(stream, shared.clone()));
                }
                Err(e) => shared.stats.note_error(format!("tcp accept: {e}")),
            }
        }
        while tasks.try_join_next().is_some() {}
    }
    tasks.shutdown().await;
}

async fn serve_tcp_conn(mut stream: TcpStream, shared: Arc<Shared>) {
    let idle = Duration::from_millis(TCP_IDLE_TIMEOUT_MS);
    loop {
        let len = match tokio::time::timeout(idle, stream.read_u16()).await {
            Ok(Ok(len)) => usize::from(len),
            _ => return,
        };
        let mut query = vec![0u8; len];
        if !matches!(tokio::time::timeout(idle, stream.read_exact(&mut query)).await, Ok(Ok(_))) {
            return;
        }
        let Some(reply) = shared.answer(&query, Transport::Tcp).await else {
            return;
        };
        let Ok(reply_len) = u16::try_from(reply.len()) else {
            return;
        };
        let mut framed = Vec::with_capacity(reply.len() + 2);
        framed.extend_from_slice(&reply_len.to_be_bytes());
        framed.extend_from_slice(&reply);
        if stream.write_all(&framed).await.is_err() {
            return;
        }
    }
}

impl Shared {
    /// The reply bytes for one query, or None when there is nothing to say.
    async fn answer(&self, query: &[u8], transport: Transport) -> Option<Vec<u8>> {
        let msg = match Message::from_vec(query) {
            Ok(m) => m,
            Err(e) => {
                self.stats.queries.fetch_add(1, Ordering::Relaxed);
                self.stats.note_error(format!("malformed query: {e}"));
                return formerr(query);
            }
        };
        let (name, verdict) = match filterable_name(&msg) {
            Some(name) => {
                let rules = self.rules.read().unwrap_or_else(PoisonError::into_inner).clone();
                let verdict = rules.verdict(&name);
                (name, verdict)
            }
            None => (String::new(), Verdict::None),
        };
        // The self check's canary: answered here in every mode (it proves
        // this listener answers) and kept out of every counter and the top
        // blocked list, which count the user's own lookups only.
        if verdict == Verdict::Canary {
            return encode(&block_response(&msg), &self.stats);
        }
        self.stats.queries.fetch_add(1, Ordering::Relaxed);
        if verdict == Verdict::Block && !self.pass_through.load(Ordering::SeqCst) {
            self.stats.note_blocked(&name);
            return encode(&block_response(&msg), &self.stats);
        }
        let client_max = match transport {
            Transport::Udp => usize::from(msg.max_payload()),
            Transport::Tcp => MAX_MESSAGE,
        };
        match forward(query, msg.metadata.id, &self.upstreams, self.timeout, client_max).await {
            Ok(reply) => {
                self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
                Some(reply)
            }
            Err(e) => {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
                self.stats.note_error(e);
                encode(&reply_to(&msg, ResponseCode::ServFail), &self.stats)
            }
        }
    }
}

fn encode(msg: &Message, stats: &Stats) -> Option<Vec<u8>> {
    match msg.to_vec() {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            stats.note_error(format!("encode reply: {e}"));
            None
        }
    }
}

/// The name to filter: only a standard query with exactly one question.
fn filterable_name(msg: &Message) -> Option<String> {
    let standard = msg.metadata.message_type == MessageType::Query
        && msg.metadata.op_code == OpCode::Query
        && msg.queries.len() == 1;
    standard.then(|| normalize_query(&msg.queries[0].name().to_ascii()))
}

/// An empty reply to `query` with `code`, echoing id, question, RD and EDNS.
fn reply_to(query: &Message, code: ResponseCode) -> Message {
    let mut r = Message::response(query.metadata.id, query.metadata.op_code);
    r.metadata.recursion_desired = query.metadata.recursion_desired;
    r.metadata.recursion_available = true;
    r.metadata.response_code = code;
    r.add_queries(query.queries.iter().cloned());
    if query.edns.is_some() {
        r.edns = Some(Edns::new());
    }
    r
}

/// The block answer (see the module doc for why null addresses).
pub fn block_response(query: &Message) -> Message {
    let mut r = reply_to(query, ResponseCode::NoError);
    if let Some(q) = query.queries.first() {
        let rdata = match q.query_type() {
            RecordType::A => Some(RData::A(A(Ipv4Addr::UNSPECIFIED))),
            RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))),
            _ => None,
        };
        if let Some(rdata) = rdata {
            r.add_answer(Record::from_rdata(q.name().clone(), BLOCK_TTL_SECS, rdata));
        }
    }
    r
}

/// FORMERR for a query we could not parse, when it at least has an id.
fn formerr(query: &[u8]) -> Option<Vec<u8>> {
    let id = u16::from_be_bytes([*query.first()?, *query.get(1)?]);
    Message::error_msg(id, OpCode::Query, ResponseCode::FormErr).to_vec().ok()
}

fn is_truncated(reply: &[u8]) -> bool {
    reply.get(2).is_some_and(|flags| flags & 0x02 != 0)
}

async fn forward(
    query: &[u8],
    id: u16,
    upstreams: &[SocketAddr],
    timeout: Duration,
    client_max: usize,
) -> Result<Vec<u8>, String> {
    let mut errors = Vec::new();
    let mut truncated_fallback = None;
    for &upstream in upstreams {
        match udp_exchange(upstream, query, id, timeout).await {
            Ok(reply) if is_truncated(&reply) => match tcp_exchange(upstream, query, id, timeout).await {
                Ok(full) if full.len() <= client_max => return Ok(full),
                Ok(_) => return Ok(reply),
                Err(e) => {
                    errors.push(format!("{upstream} tcp: {e}"));
                    truncated_fallback.get_or_insert(reply);
                }
            },
            Ok(reply) => return Ok(reply),
            Err(e) => errors.push(format!("{upstream} udp: {e}")),
        }
    }
    truncated_fallback.ok_or_else(|| format!("all upstreams failed: {}", errors.join("; ")))
}

/// True when `reply` is a response carrying `id`.
fn answers(reply: &[u8], id: u16) -> bool {
    reply.len() >= 12 && reply[..2] == id.to_be_bytes() && reply[2] & 0x80 != 0
}

/// One UDP question and answer with `server`, resending the same query
/// every `RETRANSMIT_MS` until `timeout`, as DNS clients do (UDP may drop
/// a datagram). Also the probe's transport.
///
/// Measured on the dev machine (AdGuard for Windows running, 2026-10-17):
/// the first datagram that reaches a newly bound socket which has not sent
/// anything yet is dropped, plain `std::net` sockets included; a socket
/// that sent first receives its replies. So a freshly started proxy loses
/// the first query sent to it, and only a resend gets an answer.
pub(crate) async fn udp_exchange(
    server: SocketAddr,
    query: &[u8],
    id: u16,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let local: SocketAddr = match server.ip() {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let retransmit = Duration::from_millis(RETRANSMIT_MS);
    let exchange = async {
        let socket = UdpSocket::bind(local).await.map_err(|e| e.to_string())?;
        socket.connect(server).await.map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; MAX_MESSAGE];
        loop {
            socket.send(query).await.map_err(|e| e.to_string())?;
            // Elapsed: nothing yet, so send again (a late reply to the
            // earlier send still matches the id and is taken).
            if let Ok(reply) = tokio::time::timeout(retransmit, recv_answer(&socket, &mut buf, id)).await {
                return reply;
            }
        }
    };
    tokio::time::timeout(timeout, exchange).await.map_err(|_| "timed out".to_owned())?
}

async fn recv_answer(socket: &UdpSocket, buf: &mut [u8], id: u16) -> Result<Vec<u8>, String> {
    loop {
        let n = socket.recv(buf).await.map_err(|e| e.to_string())?;
        if answers(&buf[..n], id) {
            return Ok(buf[..n].to_vec());
        }
    }
}

async fn tcp_exchange(
    server: SocketAddr,
    query: &[u8],
    id: u16,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let len = u16::try_from(query.len()).map_err(|_| "query too large".to_owned())?;
    let exchange = async {
        let mut stream = TcpStream::connect(server).await.map_err(|e| e.to_string())?;
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(query);
        stream.write_all(&framed).await.map_err(|e| e.to_string())?;
        let n = usize::from(stream.read_u16().await.map_err(|e| e.to_string())?);
        let mut reply = vec![0u8; n];
        stream.read_exact(&mut reply).await.map_err(|e| e.to_string())?;
        if answers(&reply, id) { Ok(reply) } else { Err("reply id mismatch".to_owned()) }
    };
    tokio::time::timeout(timeout, exchange).await.map_err(|_| "timed out".to_owned())?
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::rules::CANARY_NAME;
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;

    /// A fake upstream on 127.0.0.1:0 (UDP and TCP on one port) that answers
    /// every A query with 192.0.2.1 and counts what it sees. With
    /// `truncate_udp`, UDP replies carry only the TC bit and the full answer
    /// is given over TCP.
    pub(crate) struct FakeUpstream {
        pub addr: SocketAddr,
        pub udp_queries: Arc<AtomicU64>,
        pub tcp_queries: Arc<AtomicU64>,
        tasks: Vec<JoinHandle<()>>,
    }

    impl Drop for FakeUpstream {
        fn drop(&mut self) {
            for t in &self.tasks {
                t.abort();
            }
        }
    }

    pub(crate) const FAKE_ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    fn fake_reply(query: &[u8], truncate: bool) -> Vec<u8> {
        let q = Message::from_vec(query).expect("fake upstream got a valid query");
        let mut r = reply_to(&q, ResponseCode::NoError);
        if truncate {
            r.metadata.truncation = true;
        } else if let Some(first) = q.queries.first() {
            r.add_answer(Record::from_rdata(first.name().clone(), 300, RData::A(A(FAKE_ANSWER))));
        }
        r.to_vec().expect("encode")
    }

    /// A real upstream has received datagrams for years; a fresh test socket
    /// has not, and on a machine that drops a new socket's first inbound
    /// datagram (see `udp_exchange`) it would lose the first forwarded
    /// query. One throwaway datagram, received or dropped, puts the fake in
    /// the real upstream's state, so the counts below stay exact.
    async fn warm(socket: &UdpSocket) {
        let primer = UdpSocket::bind("127.0.0.1:0").await.expect("bind primer");
        primer.send_to(&[0], socket.local_addr().expect("addr")).await.expect("send primer");
        let mut buf = [0u8; 8];
        let _ = tokio::time::timeout(Duration::from_millis(300), socket.recv_from(&mut buf)).await;
    }

    /// The same for a fresh TCP listener: one connection, accepted and closed.
    async fn warm_tcp(listener: &TcpListener) {
        let addr = listener.local_addr().expect("addr");
        let connect = tokio::spawn(TcpStream::connect(addr));
        let _ = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;
        let _ = connect.await;
    }

    impl FakeUpstream {
        pub(crate) async fn start(truncate_udp: bool) -> FakeUpstream {
            let (udp, tcp) = bind_pair("127.0.0.1:0".parse().expect("addr")).await.expect("bind");
            let addr = udp.local_addr().expect("addr");
            warm(&udp).await;
            warm_tcp(&tcp).await;
            let (udp_queries, tcp_queries) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
            let uq = udp_queries.clone();
            let udp_task = tokio::spawn(async move {
                let mut buf = vec![0u8; MAX_MESSAGE];
                while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
                    uq.fetch_add(1, Ordering::SeqCst);
                    let _ = udp.send_to(&fake_reply(&buf[..n], truncate_udp), peer).await;
                }
            });
            let tq = tcp_queries.clone();
            let tcp_task = tokio::spawn(async move {
                while let Ok((mut s, _)) = tcp.accept().await {
                    tq.fetch_add(1, Ordering::SeqCst);
                    let Ok(len) = s.read_u16().await else { continue };
                    let mut q = vec![0u8; usize::from(len)];
                    if s.read_exact(&mut q).await.is_err() {
                        continue;
                    }
                    let reply = fake_reply(&q, false);
                    let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
                    framed.extend_from_slice(&reply);
                    let _ = s.write_all(&framed).await;
                }
            });
            FakeUpstream { addr, udp_queries, tcp_queries, tasks: vec![udp_task, tcp_task] }
        }
    }

    fn query_bytes(name: &str, qtype: RecordType, id: u16) -> Vec<u8> {
        let mut m = Message::query();
        m.metadata.id = id;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name).expect("name"), qtype));
        m.to_vec().expect("encode")
    }

    async fn ask_udp(server: SocketAddr, name: &str, qtype: RecordType) -> Message {
        let id = 0x5157;
        let reply = udp_exchange(server, &query_bytes(name, qtype, id), id, Duration::from_secs(5))
            .await
            .expect("proxy answered");
        Message::from_vec(&reply).expect("valid reply")
    }

    async fn ask_tcp(server: SocketAddr, name: &str, qtype: RecordType) -> Message {
        let id = 0x7c9a;
        let reply = tcp_exchange(server, &query_bytes(name, qtype, id), id, Duration::from_secs(5))
            .await
            .expect("proxy answered");
        Message::from_vec(&reply).expect("valid reply")
    }

    fn fixture_rules() -> RuleSet {
        let mut r = RuleSet::new();
        r.add_text("||ads.sieve-test.invalid^\n||doubleclick.net^\n@@||ok.doubleclick.net^");
        r
    }

    async fn start_with(upstreams: Vec<SocketAddr>) -> Proxy {
        let config = ProxyConfig {
            binds: vec!["127.0.0.1:0".parse().expect("addr")],
            upstreams,
            upstream_timeout: Duration::from_millis(UPSTREAM_TIMEOUT_MS),
        };
        Proxy::start(config, fixture_rules()).await.expect("proxy starts")
    }

    /// Spends a fresh proxy's first datagram (dropped on some machines, see
    /// `udp_exchange`) on a blocked name of its own, then waits out any
    /// resend, so counts taken after this are exact. The warm name is
    /// blocked, so upstream counts are untouched.
    const WARM_NAME: &str = "warm.ads.sieve-test.invalid.";
    async fn warm_proxy(addr: SocketAddr) {
        ask_udp(addr, WARM_NAME, RecordType::A).await;
        tokio::time::sleep(Duration::from_millis(RETRANSMIT_MS * 3 / 2)).await;
    }

    fn ips(m: &Message) -> Vec<IpAddr> {
        m.answers.iter().filter_map(|r| r.data.ip_addr()).collect()
    }

    #[tokio::test]
    async fn a_lost_udp_datagram_is_recovered_by_the_resend() {
        // A server that ignores the first query it receives, like a network
        // that dropped it, and answers every later one.
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        warm(&server).await;
        let addr = server.local_addr().expect("addr");
        let seen = Arc::new(AtomicU64::new(0));
        let s = seen.clone();
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_MESSAGE];
            while let Ok((n, peer)) = server.recv_from(&mut buf).await {
                if s.fetch_add(1, Ordering::SeqCst) > 0 {
                    let _ = server.send_to(&fake_reply(&buf[..n], false), peer).await;
                }
            }
        });
        let id = 0x0101;
        let q = query_bytes("example.com.", RecordType::A, id);
        let reply = udp_exchange(addr, &q, id, Duration::from_millis(RETRANSMIT_MS * 3)).await;
        task.abort();
        assert!(reply.is_ok(), "{reply:?}");
        assert_eq!(seen.load(Ordering::SeqCst), 2, "one lost send, one resend");
    }

    #[tokio::test]
    async fn blocked_a_and_aaaa_get_null_addresses_with_short_ttl() {
        let up = FakeUpstream::start(false).await;
        let proxy = start_with(vec![up.addr]).await;
        let a = ask_udp(proxy.local_addr(), "x.ads.sieve-test.invalid.", RecordType::A).await;
        assert_eq!(a.metadata.response_code, ResponseCode::NoError);
        assert_eq!(ips(&a), vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]);
        assert_eq!(a.answers[0].ttl, BLOCK_TTL_SECS);
        let aaaa = ask_udp(proxy.local_addr(), "doubleclick.net.", RecordType::AAAA).await;
        assert_eq!(ips(&aaaa), vec![IpAddr::V6(Ipv6Addr::UNSPECIFIED)]);
        assert_eq!(up.udp_queries.load(Ordering::SeqCst), 0, "blocked names never reach upstream");
        proxy.stop().await;
    }

    #[tokio::test]
    async fn blocked_other_types_get_nodata() {
        let up = FakeUpstream::start(false).await;
        let proxy = start_with(vec![up.addr]).await;
        let https = ask_udp(proxy.local_addr(), "doubleclick.net.", RecordType::HTTPS).await;
        assert_eq!(https.metadata.response_code, ResponseCode::NoError);
        assert!(https.answers.is_empty());
        assert_eq!(up.udp_queries.load(Ordering::SeqCst), 0);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn allowed_and_unlisted_names_are_forwarded() {
        let up = FakeUpstream::start(false).await;
        let proxy = start_with(vec![up.addr]).await;
        warm_proxy(proxy.local_addr()).await;
        for name in ["example.com.", "ok.doubleclick.net."] {
            let r = ask_udp(proxy.local_addr(), name, RecordType::A).await;
            assert_eq!(ips(&r), vec![IpAddr::V4(FAKE_ANSWER)], "{name}");
        }
        assert_eq!(up.udp_queries.load(Ordering::SeqCst), 2);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn tcp_clients_are_served_and_filtered() {
        let up = FakeUpstream::start(false).await;
        let proxy = start_with(vec![up.addr]).await;
        let blocked = ask_tcp(proxy.local_addr(), "ads.sieve-test.invalid.", RecordType::A).await;
        assert_eq!(ips(&blocked), vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]);
        let fwd = ask_tcp(proxy.local_addr(), "example.com.", RecordType::A).await;
        assert_eq!(ips(&fwd), vec![IpAddr::V4(FAKE_ANSWER)]);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn truncated_upstream_answer_is_retried_over_tcp() {
        let up = FakeUpstream::start(true).await;
        let proxy = start_with(vec![up.addr]).await;
        warm_proxy(proxy.local_addr()).await;
        let r = ask_udp(proxy.local_addr(), "big.example.com.", RecordType::A).await;
        assert!(!r.metadata.truncation);
        assert_eq!(ips(&r), vec![IpAddr::V4(FAKE_ANSWER)]);
        assert_eq!(up.udp_queries.load(Ordering::SeqCst), 1);
        assert_eq!(up.tcp_queries.load(Ordering::SeqCst), 1);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn dead_first_upstream_falls_through_to_the_next() {
        // A bound socket that never answers: the first upstream times out.
        let silent = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let up = FakeUpstream::start(false).await;
        let proxy = start_with(vec![silent.local_addr().expect("addr"), up.addr]).await;
        let r = ask_udp(proxy.local_addr(), "example.com.", RecordType::A).await;
        assert_eq!(ips(&r), vec![IpAddr::V4(FAKE_ANSWER)]);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn all_upstreams_failing_gives_servfail_and_records_the_error() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        // Upstream timeout under RETRANSMIT_MS, so SERVFAIL lands before the
        // client would resend and exactly one query is counted.
        let config = ProxyConfig {
            binds: vec!["127.0.0.1:0".parse().expect("addr")],
            upstreams: vec![silent.local_addr().expect("addr")],
            upstream_timeout: Duration::from_millis(RETRANSMIT_MS / 2),
        };
        let proxy = Proxy::start(config, fixture_rules()).await.expect("start");
        warm_proxy(proxy.local_addr()).await;
        let before = proxy.stats();
        let r = ask_udp(proxy.local_addr(), "example.com.", RecordType::A).await;
        assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
        let s = proxy.stats();
        assert_eq!((s.queries - before.queries, s.failed, s.forwarded), (1, 1, 0));
        assert!(s.last_error.is_some_and(|e| e.contains("all upstreams failed")));
        proxy.stop().await;
    }

    #[tokio::test]
    async fn counters_and_top_blocked_are_kept() {
        let up = FakeUpstream::start(false).await;
        let proxy = start_with(vec![up.addr]).await;
        let addr = proxy.local_addr();
        warm_proxy(addr).await;
        let before = proxy.stats();
        for _ in 0..3 {
            ask_udp(addr, "doubleclick.net.", RecordType::A).await;
        }
        ask_udp(addr, "ADS.sieve-test.invalid.", RecordType::A).await;
        ask_udp(addr, "example.com.", RecordType::A).await;
        let s = proxy.stats();
        assert_eq!(
            (s.queries - before.queries, s.blocked - before.blocked, s.forwarded, s.failed),
            (5, 4, 1, 0)
        );
        let warm = before.blocked;
        let mut expected = vec![
            ("doubleclick.net".to_owned(), 3),
            ("ads.sieve-test.invalid".to_owned(), 1),
            (WARM_NAME.trim_end_matches('.').to_owned(), warm),
        ];
        expected.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        assert_eq!(s.top_blocked, expected);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn the_canary_is_answered_here_and_never_counted_or_shown() {
        let up = FakeUpstream::start(false).await;
        let config = ProxyConfig {
            binds: vec!["127.0.0.1:0".parse().expect("addr")],
            upstreams: vec![up.addr],
            upstream_timeout: Duration::from_millis(UPSTREAM_TIMEOUT_MS),
        };
        // No list at all: the canary is a built-in rule.
        let proxy = Proxy::start(config, RuleSet::new()).await.expect("start");
        let addr = proxy.local_addr();
        let canary = format!("{CANARY_NAME}.");
        let first = ask_udp(addr, &canary, RecordType::A).await;
        assert_eq!(ips(&first), vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]);
        tokio::time::sleep(Duration::from_millis(RETRANSMIT_MS * 3 / 2)).await;
        let aaaa = ask_udp(addr, &canary, RecordType::AAAA).await;
        assert_eq!(ips(&aaaa), vec![IpAddr::V6(Ipv6Addr::UNSPECIFIED)]);
        let tcp = ask_tcp(addr, &canary, RecordType::A).await;
        assert_eq!(ips(&tcp), vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]);
        proxy.set_pass_through(true);
        let paused = ask_udp(addr, &canary, RecordType::A).await;
        assert_eq!(ips(&paused), vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)], "answered while passing through too");
        assert_eq!(up.udp_queries.load(Ordering::SeqCst) + up.tcp_queries.load(Ordering::SeqCst), 0, "never forwarded");
        assert_eq!(proxy.stats(), StatsSnapshot::default(), "no counter, no top blocked entry");
        // A real lookup after it is counted as usual (the law can fail).
        proxy.set_pass_through(false);
        ask_udp(addr, "example.com.", RecordType::A).await;
        assert_eq!(proxy.stats().queries, 1);
        proxy.stop().await;
    }

    #[test]
    fn per_domain_tracking_is_bounded() {
        let stats = Stats::default();
        for i in 0..MAX_TRACKED_DOMAINS + 10 {
            stats.note_blocked(&format!("n{i}.example"));
        }
        stats.note_blocked("n0.example");
        let s = stats.snapshot();
        assert_eq!(s.blocked, (MAX_TRACKED_DOMAINS + 11) as u64);
        assert_eq!(s.untracked, 10);
        assert_eq!(s.top_blocked.len(), TOP_BLOCKED_N);
        assert_eq!(s.top_blocked[0], ("n0.example".to_owned(), 2));
        assert_eq!(lock(&stats.per_domain).len(), MAX_TRACKED_DOMAINS);
    }

    #[tokio::test]
    async fn pass_through_forwards_a_blocked_name_and_counts_no_block() {
        let up = FakeUpstream::start(false).await;
        let proxy = start_with(vec![up.addr]).await;
        let addr = proxy.local_addr();
        warm_proxy(addr).await;
        let before = proxy.stats();
        let sent_before = up.udp_queries.load(Ordering::SeqCst);

        proxy.set_pass_through(true);
        assert!(proxy.pass_through());
        let m = ask_udp(addr, "ads.sieve-test.invalid.", RecordType::A).await;
        assert_eq!(ips(&m), vec![IpAddr::V4(FAKE_ANSWER)], "the upstream's answer, not the block answer");
        assert_eq!(up.udp_queries.load(Ordering::SeqCst), sent_before + 1, "the blocked name reached the upstream");
        let s = proxy.stats();
        assert_eq!((s.blocked - before.blocked, s.forwarded - before.forwarded), (0, 1));

        // Off again: the same name is blocked here, not forwarded.
        proxy.set_pass_through(false);
        let m = ask_udp(addr, "ads.sieve-test.invalid.", RecordType::A).await;
        assert_eq!(ips(&m), vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]);
        assert_eq!(up.udp_queries.load(Ordering::SeqCst), sent_before + 1);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn malformed_query_gets_formerr() {
        let up = FakeUpstream::start(false).await;
        let proxy = start_with(vec![up.addr]).await;
        let junk = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
        let reply = udp_exchange(proxy.local_addr(), &junk, 0x1234, Duration::from_secs(5))
            .await
            .expect("answered");
        let m = Message::from_vec(&reply).expect("valid");
        assert_eq!(m.metadata.response_code, ResponseCode::FormErr);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn rules_swap_takes_effect_on_the_next_query() {
        let up = FakeUpstream::start(false).await;
        let proxy = start_with(vec![up.addr]).await;
        let mut next = RuleSet::new();
        next.add_text("||example.com^");
        *proxy.rules().write().expect("lock") = Arc::new(next);
        let r = ask_udp(proxy.local_addr(), "example.com.", RecordType::A).await;
        assert_eq!(ips(&r), vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]);
        let r = ask_udp(proxy.local_addr(), "doubleclick.net.", RecordType::A).await;
        assert_eq!(ips(&r), vec![IpAddr::V4(FAKE_ANSWER)]);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn stop_frees_the_port_for_udp_and_tcp() {
        let up = FakeUpstream::start(false).await;
        let proxy = start_with(vec![up.addr]).await;
        let addr = proxy.local_addr();
        // An in-flight TCP client must not keep the port alive.
        let _client = TcpStream::connect(addr).await.expect("connect");
        proxy.stop().await;
        let udp = UdpSocket::bind(addr).await.expect("udp port is free after stop");
        let tcp = TcpListener::bind(addr).await.expect("tcp port is free after stop");
        drop((udp, tcp));
    }

    #[tokio::test]
    async fn no_upstream_is_a_config_error() {
        let config = ProxyConfig {
            binds: vec!["127.0.0.1:0".parse().expect("addr")],
            upstreams: vec![],
            upstream_timeout: Duration::from_millis(100),
        };
        assert!(matches!(Proxy::start(config, RuleSet::new()).await, Err(DnsError::Config(_))));
    }

    #[test]
    fn random_ports_stay_in_the_dynamic_range_and_vary() {
        let ports: std::collections::HashSet<u16> = (0..200).map(|_| random_dynamic_port()).collect();
        assert!(ports.iter().all(|&p| p >= DYNAMIC_PORTS_START));
        assert!(ports.len() > 150, "spread over the range, got {} distinct", ports.len());
    }

    #[tokio::test]
    async fn no_listen_address_is_a_config_error() {
        let config = ProxyConfig {
            binds: vec![],
            upstreams: vec!["127.0.0.1:9".parse().expect("addr")],
            upstream_timeout: Duration::from_millis(100),
        };
        assert!(matches!(Proxy::start(config, RuleSet::new()).await, Err(DnsError::Config(_))));
    }

    /// A client may ask ::1 instead of 127.0.0.1, so the proxy must answer there
    /// too, over UDP and TCP, with the same rules and counters.
    #[tokio::test]
    async fn listens_on_ipv4_and_ipv6_loopback_at_once() {
        let up = FakeUpstream::start(false).await;
        let config = ProxyConfig {
            binds: vec!["127.0.0.1:0".parse().expect("addr"), "[::1]:0".parse().expect("addr")],
            upstreams: vec![up.addr],
            upstream_timeout: Duration::from_millis(UPSTREAM_TIMEOUT_MS),
        };
        let proxy = Proxy::start(config, fixture_rules()).await.expect("proxy starts on both");
        let addrs = proxy.local_addrs().to_vec();
        assert_eq!(addrs.len(), 2);
        assert!(addrs[0].is_ipv4() && addrs[0].ip().is_loopback());
        assert!(addrs[1].is_ipv6() && addrs[1].ip().is_loopback());
        for addr in &addrs {
            let a = ask_udp(*addr, "ads.sieve-test.invalid.", RecordType::A).await;
            assert_eq!(ips(&a), vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)], "udp {addr}");
            let t = ask_tcp(*addr, "doubleclick.net.", RecordType::AAAA).await;
            assert_eq!(ips(&t), vec![IpAddr::V6(Ipv6Addr::UNSPECIFIED)], "tcp {addr}");
        }
        assert_eq!(proxy.stats().top_blocked.iter().map(|(_, n)| n).sum::<u64>(), proxy.stats().blocked);
        proxy.stop().await;
        for addr in addrs {
            UdpSocket::bind(addr).await.expect("udp port is free after stop");
            TcpListener::bind(addr).await.expect("tcp port is free after stop");
        }
    }

    #[tokio::test]
    async fn a_taken_second_address_fails_the_whole_start_and_frees_the_first() {
        let taken = UdpSocket::bind("[::1]:0").await.expect("bind");
        // A port free for both protocols, found the way the proxy finds one, then released.
        let (udp, tcp) = bind_pair("127.0.0.1:0".parse().expect("addr")).await.expect("bind");
        let first = udp.local_addr().expect("addr");
        drop((udp, tcp));
        let config = ProxyConfig {
            binds: vec![first, taken.local_addr().expect("addr")],
            upstreams: vec!["127.0.0.1:9".parse().expect("addr")],
            upstream_timeout: Duration::from_millis(100),
        };
        assert!(matches!(Proxy::start(config, RuleSet::new()).await, Err(DnsError::Bind { .. })));
        UdpSocket::bind(first).await.expect("the first address was released");
    }

    #[tokio::test]
    async fn a_taken_port_is_a_bind_error() {
        let taken = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let config = ProxyConfig {
            binds: vec![taken.local_addr().expect("addr")],
            upstreams: vec!["127.0.0.1:9".parse().expect("addr")],
            upstream_timeout: Duration::from_millis(100),
        };
        assert!(matches!(Proxy::start(config, RuleSet::new()).await, Err(DnsError::Bind { .. })));
    }
}
