//! How one flow goes out while exiting through a hub.
//!
//! The relay connects upstream at SYN time; a flow that exits through the hub
//! does not. Its upstream is a [`Lazy`] stream that opens only once the flow
//! is decided (`stack::relay` starts it from the decision): a blocked flow never
//! reaches the hub, and the hub is asked for the name the flow actually
//! carries ([`choose_host`]). Until it opens, reads and writes wait.
//!
//! Name or address. The hub resolves names itself, so its rules and its
//! geography apply. The engine sends:
//! 1. the flow's own name (TLS SNI, HTTP Host) when it has one: the name the
//!    app asked the server for, already judged by Sieve's filter, and what the
//!    server's certificate must match anyway;
//! 2. else the address the app connected to.
//!
//! Never a name Sieve's DNS recorded for the address: any page can make the
//! resolver record `x.attacker.example` for a victim's address, and a nameless
//! protocol to that address (SSH or Redis by IP, say) would then be sent by the
//! hub to wherever the attacker's DNS points.
//!
//! Trade-offs: an app that chose one of a name's addresses on purpose (a pinned
//! edge, a game server picked by address) reaches whichever address the hub
//! resolves for the name instead; a nameless protocol reaches exactly the
//! address the app chose, as the hub sees it (an address this computer's DNS
//! gave that the hub's network would answer differently is not re-resolved); a
//! name the local DNS answered differently (split horizon) resolves the hub's
//! way, which is the point, and a local-only name is refused by the hub; a name
//! Sieve's DNS blocked never gets here, because the flow carrying it is
//! blocked by the same decision first.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use sieve_ipc::{ExitVia, LinkHubDown, Signal};
use sieve_link::{LinkClient, LinkError, LinkStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::{LinkManager, LinkNet, Plan};
use crate::dns::{BoxFuture, Connector, ResolverStream};
use crate::flow::relay::Reset;
use crate::tls::intercept::{Dial, DialFuture};

/// An upstream once connected: a socket of this computer's, or a stream
/// through the hub.
pub enum Opened {
    Tcp(TcpStream),
    Hub(LinkStream),
}

/// A flow's upstream: connected at SYN time, or opened once decided.
pub enum Upstream {
    Tcp(TcpStream),
    Opened(Opened),
    Lazy(Lazy),
}

impl From<Opened> for Upstream {
    fn from(o: Opened) -> Self {
        Upstream::Opened(o)
    }
}

/// How a flow went out, for its log row and its app's problems.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitReport {
    pub via: ExitVia,
    /// What the hub was asked for, `host:port` (`[v6]:port`).
    pub target: Option<String>,
    pub reason: Option<String>,
    pub signal: Option<Signal>,
}

/// `host:port` as a reader writes it.
pub fn shown(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

/// A row's reason: one plain line, capped (the hub's refusal is the hub's text).
fn reason(text: impl AsRef<str>) -> Option<String> {
    Some(super::said(text))
}

/// A host name the hub can be asked for: letters, digits, `-`, `_` and dots,
/// at least one dot, not an address.
fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.contains('.')
        && !s.starts_with('.')
        && !s.ends_with('.')
        && s.parse::<IpAddr>().is_err()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// What the hub is asked to connect to (the module's rules 1 and 2): the name
/// the flow's own bytes carry, else its address.
pub fn choose_host(carried: Option<&str>, ip: IpAddr) -> String {
    match carried.map(|n| n.trim_end_matches('.')).filter(|n| is_name(n)) {
        Some(name) => name.to_ascii_lowercase(),
        None => ip.to_string(),
    }
}

/// What becomes of a sieved app's UDP flow to a public address while exiting
/// through a hub, which carries TCP only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpOnLink {
    /// QUIC, whatever the UDP setting: refused (the existing per-flow refusal),
    /// so the browser falls back to TCP, which goes through the hub. Leaving it
    /// direct would show this computer's address to the very sites the owner
    /// wants to see the hub's.
    RefuseQuic,
    /// Other UDP, setting Drop: dropped, with a row.
    Drop,
    /// Other UDP, setting Direct: relayed from this computer, with a row.
    Direct,
}

pub fn udp_on_link(quic: bool, setting: sieve_ipc::LinkUdp) -> UdpOnLink {
    match (quic, setting) {
        (true, _) => UdpOnLink::RefuseQuic,
        (false, sieve_ipc::LinkUdp::Drop) => UdpOnLink::Drop,
        (false, sieve_ipc::LinkUdp::Direct) => UdpOnLink::Direct,
    }
}

/// How an open through the link failed, for what follows it.
#[derive(Debug, PartialEq, Eq)]
pub enum Failed {
    /// The hub answered no, or is linked and did not answer usably: never direct.
    Refused(String),
    /// The link is not there: the hub-down setting decides.
    Down(String),
}

/// Sorts a failed open: only a link that is not there (none, down, or its own
/// socket broken) is `Down`. `linked`: the link is up now.
pub fn failed(e: LinkError, linked: bool) -> Failed {
    match e {
        LinkError::Refused { status, message } => Failed::Refused(format!("{}: {message}", format!("{status:?}").to_lowercase())),
        LinkError::HubDown => Failed::Down("the other device cannot be reached".into()),
        LinkError::Io(e) => Failed::Down(format!("the other device cannot be reached: {e}")),
        // Linked, but no answer in time (a busy hub, a slow target), or an answer
        // that made no sense: as a refusal, so a slow hub never sends a flow out
        // from this computer.
        LinkError::Timeout(_) if linked => Failed::Refused("the other device did not answer in time".into()),
        e if linked => Failed::Refused(format!("the other device's answer could not be used: {e}")),
        e => Failed::Down(format!("the other device cannot be reached: {e}")),
    }
}

/// Opens one connection for `remote` through the hub as `host:port`, or, when
/// the link is not up, as the plan's hub-down setting says: stop (an error) or
/// directly from this computer to `remote`. A hub that answered and refused, or
/// that is linked but did not answer in time (busy, slow, a target that takes
/// long), is never a reason to go direct: only a link that is not there is.
/// The running link is read now, not when the flow began.
pub async fn open(plan: &Plan, net: &dyn LinkNet, host: &str, port: u16, remote: SocketAddr) -> (io::Result<Opened>, ExitReport) {
    let target = Some(shown(host, port));
    let down = |why: String| -> (io::Result<Opened>, ExitReport) {
        (Err(io::Error::new(io::ErrorKind::ConnectionRefused, why.clone())), ExitReport { via: ExitVia::Stopped, target: target.clone(), reason: reason(&why), signal: Some(Signal::HubDown) })
    };
    let refused = |why: String| -> (io::Result<Opened>, ExitReport) {
        (Err(io::Error::new(io::ErrorKind::ConnectionRefused, why.clone())), ExitReport { via: ExitVia::Refused, target: target.clone(), reason: reason(&why), signal: Some(Signal::HubRefused) })
    };
    let client = plan.client();
    let outcome = match &client {
        Some(client) => client.open(host, port).await,
        None => Err(LinkError::HubDown),
    };
    let why_down = match outcome {
        Ok(stream) => return (Ok(Opened::Hub(stream)), ExitReport { via: ExitVia::Hub, target, reason: None, signal: None }),
        Err(e) => match failed(e, client.as_ref().is_some_and(LinkClient::is_up)) {
            Failed::Refused(why) => return refused(why),
            Failed::Down(why) => why,
        },
    };
    match plan.on_hub_down {
        LinkHubDown::Stop => down(format!("{why_down}; stopped, as set")),
        LinkHubDown::Direct => match net.connect(remote).await {
            Ok(tcp) => (Ok(Opened::Tcp(tcp)), ExitReport { via: ExitVia::Direct, target, reason: reason(format!("{why_down}; went directly from this computer, as set")), signal: None }),
            Err(e) => (
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, e.clone())),
                ExitReport { via: ExitVia::Direct, target, reason: reason(format!("{why_down}; the direct connect failed too: {e}")), signal: Some(Signal::ConnectFailed) },
            ),
        },
    }
}

#[derive(Default)]
struct Slot {
    started: bool,
    result: Option<io::Result<Opened>>,
    read: Option<Waker>,
    write: Option<Waker>,
}

impl Slot {
    fn wake(&mut self) {
        for w in [self.read.take(), self.write.take()].into_iter().flatten() {
            w.wake();
        }
    }
}

/// An upstream that opens once its [`Starter`] is given what to open. Both
/// halves of a split relay wait on it and both are woken.
pub struct Lazy {
    slot: Arc<Mutex<Slot>>,
    opened: Option<Opened>,
    failed: Option<(io::ErrorKind, String)>,
}

/// Starts a [`Lazy`]; only the first start counts.
#[derive(Clone)]
pub struct Starter {
    slot: Arc<Mutex<Slot>>,
}

pub fn lazy() -> (Lazy, Starter) {
    let slot = Arc::new(Mutex::new(Slot::default()));
    (Lazy { slot: slot.clone(), opened: None, failed: None }, Starter { slot })
}

fn lock(slot: &Mutex<Slot>) -> std::sync::MutexGuard<'_, Slot> {
    slot.lock().unwrap_or_else(|p| p.into_inner())
}

impl Starter {
    /// Opens with `open` in a task of its own; the result wakes the stream.
    pub fn start(&self, open: impl std::future::Future<Output = io::Result<Opened>> + Send + 'static) {
        {
            let mut slot = lock(&self.slot);
            if slot.started {
                return;
            }
            slot.started = true;
        }
        let slot = self.slot.clone();
        tokio::spawn(async move {
            let result = open.await;
            let mut s = lock(&slot);
            s.result = Some(result);
            s.wake();
        });
    }
}

impl Lazy {
    /// The opened stream, waiting for it (`write` says which half asks).
    fn poll_open(&mut self, cx: &mut Context<'_>, write: bool) -> Poll<io::Result<&mut Opened>> {
        if self.opened.is_none() {
            if let Some((kind, why)) = &self.failed {
                return Poll::Ready(Err(io::Error::new(*kind, why.clone())));
            }
            let mut slot = lock(&self.slot);
            match slot.result.take() {
                Some(Ok(o)) => self.opened = Some(o),
                Some(Err(e)) => {
                    self.failed = Some((e.kind(), e.to_string()));
                    return Poll::Ready(Err(e));
                }
                None => {
                    let waker = Some(cx.waker().clone());
                    if write { slot.write = waker } else { slot.read = waker }
                    return Poll::Pending;
                }
            }
        }
        Poll::Ready(Ok(self.opened.as_mut().expect("just set")))
    }

    fn started(&self) -> bool {
        self.opened.is_some() || self.failed.is_some() || lock(&self.slot).started
    }

    /// Waits until it is open; the error of an open that failed.
    pub async fn ready(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| self.poll_open(cx, false).map_ok(|_| ())).await
    }
}

macro_rules! each {
    ($s:expr, $x:ident => $body:expr) => {
        match $s {
            Opened::Tcp($x) => $body,
            Opened::Hub($x) => $body,
        }
    };
}

impl AsyncRead for Opened {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        each!(self.get_mut(), s => Pin::new(s).poll_read(cx, buf))
    }
}

impl AsyncWrite for Opened {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        each!(self.get_mut(), s => Pin::new(s).poll_write(cx, buf))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        each!(self.get_mut(), s => Pin::new(s).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        each!(self.get_mut(), s => Pin::new(s).poll_shutdown(cx))
    }
}

impl AsyncRead for Upstream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Upstream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Upstream::Opened(s) => Pin::new(s).poll_read(cx, buf),
            Upstream::Lazy(l) => match l.poll_open(cx, false) {
                Poll::Ready(Ok(s)) => Pin::new(s).poll_read(cx, buf),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl AsyncWrite for Upstream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Upstream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Upstream::Opened(s) => Pin::new(s).poll_write(cx, buf),
            Upstream::Lazy(l) => match l.poll_open(cx, true) {
                Poll::Ready(Ok(s)) => Pin::new(s).poll_write(cx, buf),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            },
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Upstream::Tcp(s) => Pin::new(s).poll_flush(cx),
            Upstream::Opened(s) => Pin::new(s).poll_flush(cx),
            // Nothing was written to a stream never started.
            Upstream::Lazy(l) if !l.started() => Poll::Ready(Ok(())),
            Upstream::Lazy(l) => match l.poll_open(cx, true) {
                Poll::Ready(Ok(s)) => Pin::new(s).poll_flush(cx),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            },
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Upstream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Upstream::Opened(s) => Pin::new(s).poll_shutdown(cx),
            Upstream::Lazy(l) if !l.started() => Poll::Ready(Ok(())),
            Upstream::Lazy(l) => match l.poll_open(cx, true) {
                Poll::Ready(Ok(s)) => Pin::new(s).poll_shutdown(cx),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

/// A socket of this computer's ends with a reset; a stream through the hub has
/// none (the hub closes its own side), so it ends as a close.
impl Reset for Opened {
    fn reset(&self) {
        if let Opened::Tcp(s) = self {
            s.reset();
        }
    }
}

impl Reset for Upstream {
    fn reset(&self) {
        match self {
            Upstream::Tcp(s) => s.reset(),
            Upstream::Opened(o) => o.reset(),
            Upstream::Lazy(l) => {
                if let Some(o) = &l.opened {
                    o.reset();
                }
            }
        }
    }
}

/// Interception's connector (`tls::intercept::Dial`) while routes are up: a
/// fresh connection exits through the hub when the plan says so (by the flow's
/// name when known, else by address), and every other one leaves through `net`
/// as before. No dial of it leaves directly for a destination exiting concerns.
pub struct Exit {
    pub net: Arc<dyn LinkNet>,
    pub link: Arc<LinkManager>,
    /// Where a fresh dial's way out is written, on its flow's row.
    pub book: Arc<Mutex<crate::stack::book::FlowBook>>,
}

impl Exit {
    async fn fresh(&self, target: SocketAddr, host: Option<&str>, flow: Option<u64>) -> Result<Upstream, String> {
        let Some(plan) = self.link.plan(target.ip()) else { return self.net.connect(target).await.map(Upstream::Tcp) };
        let (opened, report) = open(&plan, &*self.net, &choose_host(host, target.ip()), target.port(), target).await;
        // A stop or a refusal is the hub's problem on the flow's row, so the
        // flow's failure that follows is not counted as the app's breakage.
        if let Some(id) = flow {
            self.book.lock().unwrap_or_else(|p| p.into_inner()).exit(id, report);
        }
        opened.map(Upstream::from).map_err(|e| e.to_string())
    }
}

impl Dial for Exit {
    type Stream = Upstream;

    /// By address: through the hub when the plan says so, as every dial here.
    fn dial(&self, target: SocketAddr) -> DialFuture<'_, Upstream> {
        Box::pin(self.fresh(target, None, None))
    }

    fn dial_named<'a>(&'a self, target: SocketAddr, host: &'a str, flow: u64) -> DialFuture<'a, Upstream> {
        Box::pin(self.fresh(target, Some(host), Some(flow)))
    }

    fn ready<'a>(&'a self, stream: &'a mut Upstream) -> DialFuture<'a, ()> {
        Box::pin(async move {
            match stream {
                Upstream::Lazy(l) => l.ready().await.map_err(|e| e.to_string()),
                _ => Ok(()),
            }
        })
    }
}

/// The DNS service's connector while routes are up: an encrypted resolver's
/// session (DNS over HTTPS or TLS) goes through the hub, by the resolver's name,
/// when the plan says so; plain and LAN lookups and DNS over QUIC stay on
/// `inner` (the link carries TCP only, and a LAN server is never asked through
/// it). A hub that cannot be reached follows the hub-down setting, as a flow does.
pub struct DnsExit {
    pub inner: Arc<dyn Connector>,
    pub net: Arc<dyn LinkNet>,
    pub link: Arc<LinkManager>,
}

impl Connector for DnsExit {
    fn tcp(&self, target: SocketAddr) -> BoxFuture<'_, Result<TcpStream, String>> {
        self.inner.tcp(target)
    }

    fn udp(&self, target: SocketAddr) -> Result<socket2::Socket, String> {
        self.inner.udp(target)
    }

    fn address(&self, target: SocketAddr) -> SocketAddr {
        self.inner.address(target)
    }

    fn resolver_stream<'a>(&'a self, target: SocketAddr, host: &'a str) -> BoxFuture<'a, Result<ResolverStream, String>> {
        Box::pin(async move {
            let Some(plan) = self.link.plan(target.ip()) else { return self.inner.resolver_stream(target, host).await };
            match open(&plan, &*self.net, host, target.port(), target).await.0 {
                Ok(Opened::Tcp(tcp)) => {
                    let _ = tcp.set_nodelay(true);
                    Ok(Box::new(tcp) as ResolverStream)
                }
                Ok(hub) => Ok(Box::new(hub) as ResolverStream),
                Err(e) => Err(format!("{host} through the other device: {e}")),
            }
        })
    }
}
