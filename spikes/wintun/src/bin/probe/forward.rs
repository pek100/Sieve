//! Per-flow handling: attribute, classify, decide once, then relay or drop.
//!
//! TCP: the upstream connection is opened at once (bound to the physical
//! interface) and server bytes flow to the app immediately, so
//! server-speaks-first protocols are never stalled. Client bytes are held
//! by the classifier until it decides (or [`FIRST_BYTES_WAIT`] passes with
//! nothing to decide on); then the verdict: pass forwards the held bytes and
//! relays the rest, drop closes both sides (the app sees its connection
//! closed during the handshake).
//!
//! UDP: datagrams are held until the classifier decides (a QUIC ClientHello
//! may span two Initials), then pass sends them and relays both ways, drop
//! discards them and the flow (QUIC retransmits are dropped the same way, as
//! each new ipstack UDP stream is classified again).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipstack::{IpStackTcpStream, IpStackUdpStream};
use spike::classify::{Decoded, TcpClassifier, UdpClassifier};
use spike::flows::{Action, AppPolicy, Attributor, ExeCache, FiveTuple, Owner, os::IpHelper, verdict};
use spike::packet::Proto;
use spike::probe_support::{FlowRecord, Summary, record};
use spike::rules::RuleSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// How long a TCP flow may stay silent before it is decided without a
/// domain (server-first protocols, idle keep-alive opens).
pub const FIRST_BYTES_WAIT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_IDLE: Duration = Duration::from_secs(30);

type ExeLookup = fn(u32) -> Option<String>;

pub struct Shared {
    pub start: Instant,
    pub attributor: Mutex<Attributor<IpHelper>>,
    pub exes: Mutex<ExeCache<ExeLookup>>,
    pub rules: RuleSet,
    pub policy: AppPolicy,
    pub enforce: bool,
    /// The TUN's interface index: a forwarder socket must never use it.
    pub tun_if_index: u32,
    /// Physical interface per routed IP, read before the routes existed.
    pub physical: std::collections::HashMap<std::net::IpAddr, u32>,
    pub dns_via: Option<SocketAddr>,
    pub records: Mutex<Vec<FlowRecord>>,
    pub summary: Mutex<Summary>,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn error(&self, what: &str) {
        self.summary.lock().unwrap_or_else(|p| p.into_inner()).forwarder_error(what);
    }

    /// Owner pid with retries while the table lags (bounded by GIVE_UP_MS).
    async fn owner(&self, flow: FiveTuple) -> (Option<u32>, bool) {
        let mut retried = false;
        loop {
            let now = self.now_ms();
            let answer = self.attributor.lock().unwrap_or_else(|p| p.into_inner()).owner(&flow, now);
            match answer {
                Owner::Pid(pid) => return (Some(pid), retried),
                Owner::Unknown => return (None, retried),
                Owner::Pending => {
                    retried = true;
                    tokio::time::sleep(Duration::from_millis(spike::flows::REFRESH_MIN_MS)).await;
                }
            }
        }
    }

    fn exe(&self, pid: Option<u32>) -> Option<String> {
        let pid = pid?;
        let now = self.now_ms();
        self.exes.lock().unwrap_or_else(|p| p.into_inner()).exe(pid, now)
    }

    /// Decide, log and count one flow. Returns the action to apply.
    fn decide(&self, proto: &'static str, flow: &FiveTuple, pid: Option<u32>, retried: bool, d: &Decoded) -> Action {
        let exe = self.exe(pid);
        let decision = verdict(d.domain.as_deref(), exe.as_deref(), &self.rules, &self.policy);
        let rec = record(self.now_ms(), proto, flow.local, flow.remote, pid, exe, d, decision, self.enforce);
        println!("{}", rec.line());
        {
            let mut s = self.summary.lock().unwrap_or_else(|p| p.into_inner());
            s.add(&rec);
            if retried && pid.is_some() {
                s.attributed_after_retry += 1;
            }
        }
        self.records.lock().unwrap_or_else(|p| p.into_inner()).push(rec);
        if self.enforce { decision.action } else { Action::Pass }
    }

    /// The physical interface for `ip`; never the TUN.
    fn physical_for(&self, ip: std::net::IpAddr) -> Result<u32, String> {
        let index = match self.physical.get(&ip) {
            Some(i) => *i,
            None => crate::os::best_interface(ip)?,
        };
        if index == self.tun_if_index {
            return Err(format!("{ip} resolves to the TUN itself (would loop)"));
        }
        Ok(index)
    }
}

fn socket_for(target: SocketAddr, udp: bool) -> std::io::Result<socket2::Socket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if target.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let (ty, proto) = if udp { (Type::DGRAM, Protocol::UDP) } else { (Type::STREAM, Protocol::TCP) };
    let s = Socket::new(domain, ty, Some(proto))?;
    s.set_nonblocking(true)?;
    Ok(s)
}

async fn connect_upstream(shared: &Shared, target: SocketAddr) -> Result<TcpStream, String> {
    let sock = socket_for(target, false).map_err(|e| format!("socket: {e}"))?;
    if !target.ip().is_loopback() {
        let index = shared.physical_for(target.ip())?;
        crate::os::bind_to_interface(&sock, target, index)?;
    }
    let std_stream: std::net::TcpStream = sock.into();
    let socket = TcpSocket::from_std_stream(std_stream);
    match tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(target)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(format!("connect {target}: {e}")),
        Err(_) => Err(format!("connect {target}: timeout")),
    }
}

pub async fn handle_tcp(shared: Arc<Shared>, mut app: IpStackTcpStream) {
    let flow = FiveTuple { proto: Proto::Tcp, local: app.local_addr(), remote: app.peer_addr() };
    let owner = {
        let s = shared.clone();
        tokio::spawn(async move { s.owner(flow).await })
    };
    let upstream = match connect_upstream(&shared, flow.remote).await {
        Ok(u) => u,
        Err(e) => {
            shared.error("tcp connect");
            eprintln!("tcp {} -> {}: {e}", flow.local, flow.remote);
            return;
        }
    };
    let (mut up_read, mut up_write) = upstream.into_split();
    let (mut app_read, mut app_write) = tokio::io::split(&mut app);

    // Server -> app at once; client -> server waits for the verdict.
    let server_to_app = async {
        let _ = tokio::io::copy(&mut up_read, &mut app_write).await;
        let _ = app_write.shutdown().await;
    };
    // Returns true when the flow must end now (dropped, or broken before a
    // decision); false after a normal client EOF.
    let client_to_server = async {
        let mut classifier = TcpClassifier::new();
        let mut buf = vec![0u8; 16 * 1024];
        let decided = loop {
            match tokio::time::timeout(FIRST_BYTES_WAIT, app_read.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(n)) => {
                    if let Some(d) = classifier.push(&buf[..n]) {
                        break d;
                    }
                }
                Err(_) => break Decoded { failure: Some("no client bytes in time"), ..Decoded::default() },
            }
        };
        let (pid, retried) = owner.await.unwrap_or((None, false));
        if shared.decide("tcp", &flow, pid, retried, &decided) == Action::Drop {
            return true; // dropping both halves closes the app's connection
        }
        if up_write.write_all(&classifier.take_held()).await.is_err() {
            shared.error("tcp write upstream");
            return true;
        }
        let _ = tokio::io::copy(&mut app_read, &mut up_write).await;
        let _ = up_write.shutdown().await;
        false
    };
    tokio::pin!(server_to_app, client_to_server);
    tokio::select! {
        stop = &mut client_to_server => if !stop { server_to_app.await },
        _ = &mut server_to_app => { client_to_server.await; }
    }
}

pub async fn handle_udp(shared: Arc<Shared>, mut app: IpStackUdpStream) {
    let flow = FiveTuple { proto: Proto::Udp, local: app.local_addr(), remote: app.peer_addr() };
    let is_dns = flow.remote.port() == 53;
    let target = match (is_dns, shared.dns_via) {
        (true, Some(via)) => via,
        _ => flow.remote,
    };
    if is_dns {
        shared.summary.lock().unwrap_or_else(|p| p.into_inner()).dns_flows += 1;
    }
    let owner = {
        let s = shared.clone();
        tokio::spawn(async move { s.owner(flow).await })
    };

    // Hold datagrams until decided.
    let mut classifier = UdpClassifier::new();
    let mut held: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![0u8; 65_535];
    let decided = loop {
        match tokio::time::timeout(UDP_IDLE, app.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
            Ok(Ok(n)) => {
                held.push(buf[..n].to_vec());
                if is_dns {
                    break Decoded { failure: Some("dns"), ..Decoded::default() };
                }
                if let Some(d) = classifier.push(&buf[..n]) {
                    break d;
                }
            }
        }
    };
    let (pid, retried) = owner.await.unwrap_or((None, false));
    if shared.decide(if is_dns { "dns" } else { "udp" }, &flow, pid, retried, &decided) == Action::Drop {
        return;
    }

    let sock = match socket_for(target, true) {
        Ok(s) => s,
        Err(_) => return shared.error("udp socket"),
    };
    if !target.ip().is_loopback() {
        match shared.physical_for(target.ip()) {
            Ok(index) => {
                if crate::os::bind_to_interface(&sock, target, index).is_err() {
                    return shared.error("udp bind interface");
                }
            }
            Err(_) => return shared.error("udp no physical interface"),
        }
    }
    let any: SocketAddr = if target.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    if sock.bind(&any.into()).is_err() {
        return shared.error("udp bind");
    }
    let Ok(up) = UdpSocket::from_std(sock.into()) else { return shared.error("udp tokio socket") };
    if up.connect(target).await.is_err() {
        return shared.error("udp connect");
    }
    for d in held {
        if up.send(&d).await.is_err() {
            return shared.error("udp send");
        }
    }
    let mut down = vec![0u8; 65_535];
    loop {
        tokio::select! {
            r = tokio::time::timeout(UDP_IDLE, app.read(&mut buf)) => match r {
                Ok(Ok(n)) if n > 0 => { if up.send(&buf[..n]).await.is_err() { shared.error("udp send"); break; } }
                _ => break,
            },
            r = tokio::time::timeout(UDP_IDLE, up.recv(&mut down)) => match r {
                Ok(Ok(n)) => { if app.write_all(&down[..n]).await.is_err() { break; } }
                _ => break,
            },
        }
    }
}
