//! Per-flow handling: admit, attribute, classify, decide once, then relay
//! or drop.
//!
//! Admission (live run 1 lessons): only flows to a routed test address get
//! here (the TUN reader discards the rest), and a flow owned by this probe
//! is refused (loop guard). Upstream sockets are bound to the physical
//! interface's own source address for that destination AND pinned with
//! IP_UNICAST_IF / IPV6_UNICAST_IF, both read before the routes existed.
//!
//! TCP: the upstream connection is opened at once and server bytes flow to
//! the app immediately, so server-speaks-first protocols are never stalled.
//! Client bytes are held by the classifier until it decides (or
//! [`FIRST_BYTES_WAIT`] passes). Pass forwards the held bytes and relays the
//! rest; drop, or any failure, closes the app side with a FIN at once (an
//! ipstack stream that is only dropped leaves the app waiting for its own
//! timeout: the 20 s curl hang of live run 1).
//!
//! UDP: datagrams are held until the classifier decides (a QUIC ClientHello
//! may span two Initials), then pass sends them and relays both ways, drop
//! discards them and the flow.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipstack::{IpStackTcpStream, IpStackUdpStream};
use spike::classify::{Decoded, TcpClassifier, UdpClassifier};
use spike::flows::{Action, AppPolicy, Attributor, ExeCache, FiveTuple, Owner, os::IpHelper, verdict};
use spike::packet::Proto;
use spike::probe_support::{FlowLog, Summary, admit_owner, record};
use spike::rules::RuleSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// How long a TCP flow may stay silent before it is decided without a
/// domain (server-first protocols, idle keep-alive opens).
pub const FIRST_BYTES_WAIT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_IDLE: Duration = Duration::from_secs(30);

type ExeLookup = fn(u32) -> Option<String>;

/// How to reach one routed address without the TUN, read before routing.
#[derive(Debug, Clone, Copy)]
pub struct Egress {
    pub if_index: u32,
    pub source: IpAddr,
}

pub struct Shared {
    pub start: Instant,
    pub own_pid: u32,
    pub attributor: Mutex<Attributor<IpHelper>>,
    pub exes: Mutex<ExeCache<ExeLookup>>,
    pub rules: RuleSet,
    pub policy: AppPolicy,
    pub enforce: bool,
    /// Egress per routed address. Only these destinations are forwarded.
    pub egress: HashMap<IpAddr, Egress>,
    pub dns_via: Option<SocketAddr>,
    pub log: Mutex<FlowLog>,
    pub summary: Mutex<Summary>,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn summary(&self) -> std::sync::MutexGuard<'_, Summary> {
        self.summary.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn error(&self, what: &str) {
        self.summary().forwarder_error(what);
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

    /// The loop guard: true (and counted, logged once) for our own flows.
    fn is_own(&self, pid: Option<u32>, flow: &FiveTuple) -> bool {
        if admit_owner(pid, self.own_pid).is_ok() {
            return false;
        }
        let mut s = self.summary();
        if s.own_process_dropped == 0 {
            println!("LOOP GUARD: flow {} -> {} belongs to this probe; refused (further ones only counted)", flow.local, flow.remote);
        }
        s.own_process_dropped += 1;
        true
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
        {
            let mut s = self.summary();
            s.add(&rec);
            if retried && pid.is_some() {
                s.attributed_after_retry += 1;
            }
        }
        if let Some(line) = self.log.lock().unwrap_or_else(|p| p.into_inner()).push(rec) {
            println!("{line}");
        }
        if self.enforce { decision.action } else { Action::Pass }
    }

    fn egress_for(&self, ip: IpAddr) -> Result<Egress, String> {
        self.egress.get(&ip).copied().ok_or_else(|| format!("{ip} is not a routed address"))
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

/// A socket bound to the physical source address and pinned to the
/// physical interface (or unbound for a loopback target such as
/// `--dns-via 127.0.0.1:53`).
fn egress_socket(shared: &Shared, target: SocketAddr, udp: bool) -> Result<socket2::Socket, String> {
    let sock = socket_for(target, udp).map_err(|e| format!("socket: {e}"))?;
    if target.ip().is_loopback() {
        if udp {
            let any: SocketAddr = if target.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
            sock.bind(&any.into()).map_err(|e| format!("bind: {e}"))?;
        }
        return Ok(sock);
    }
    let e = shared.egress_for(target.ip())?;
    sock.bind(&SocketAddr::new(e.source, 0).into()).map_err(|err| format!("bind {}: {err}", e.source))?;
    crate::os::bind_to_interface(&sock, target, e.if_index)?;
    Ok(sock)
}

async fn connect_upstream(shared: &Shared, target: SocketAddr) -> Result<TcpStream, String> {
    let sock = egress_socket(shared, target, false)?;
    let std_stream: std::net::TcpStream = sock.into();
    let socket = TcpSocket::from_std_stream(std_stream);
    match tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(target)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(format!("connect {target}: {e}")),
        Err(_) => Err(format!("connect {target}: timeout")),
    }
}

/// Closes the app side promptly (FIN), so a dropped or failed flow ends at
/// once instead of at the app's own timeout.
async fn close_app(app: &mut IpStackTcpStream) {
    let _ = tokio::time::timeout(Duration::from_secs(1), app.shutdown()).await;
}

pub async fn handle_tcp(shared: Arc<Shared>, mut app: IpStackTcpStream) {
    let flow = FiveTuple { proto: Proto::Tcp, local: app.local_addr(), remote: app.peer_addr() };
    let (owner, upstream) = tokio::join!(shared.owner(flow), connect_upstream(&shared, flow.remote));
    let (pid, retried) = owner;
    if shared.is_own(pid, &flow) {
        return close_app(&mut app).await;
    }
    let upstream = match upstream {
        Ok(u) => u,
        Err(e) => {
            shared.error("tcp connect");
            let d = Decoded { failure: Some("upstream connect failed"), ..Decoded::default() };
            shared.decide("tcp", &flow, pid, retried, &d);
            eprintln!("tcp {} -> {}: {e}", flow.local, flow.remote);
            return close_app(&mut app).await;
        }
    };
    let stop = {
        let (mut up_read, mut up_write) = upstream.into_split();
        let (mut app_read, mut app_write) = tokio::io::split(&mut app);
        // Server -> app at once; client -> server waits for the verdict.
        let server_to_app = async {
            let _ = tokio::io::copy(&mut up_read, &mut app_write).await;
            let _ = app_write.shutdown().await;
        };
        // true: end the flow now (dropped or broken before a decision).
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
            if shared.decide("tcp", &flow, pid, retried, &decided) == Action::Drop {
                return true;
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
            stop = &mut client_to_server => { if !stop { server_to_app.await; } stop }
            _ = &mut server_to_app => client_to_server.await,
        }
    };
    if stop {
        close_app(&mut app).await;
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
        shared.summary().dns_flows += 1;
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
    if shared.is_own(pid, &flow) {
        return;
    }
    if shared.decide(if is_dns { "dns" } else { "udp" }, &flow, pid, retried, &decided) == Action::Drop {
        return;
    }
    let sock = match egress_socket(&shared, target, true) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("udp {} -> {target}: {e}", flow.local);
            return shared.error("udp egress socket");
        }
    };
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
