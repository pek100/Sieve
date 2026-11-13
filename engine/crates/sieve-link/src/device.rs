//! The device side: pairs with a hub, holds the link (dialling the hub, or
//! waiting for the hub to dial in), reconnects with back-off, and opens
//! streams through it. `LinkClient::open` is the seed of the SDK.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, watch};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;

use crate::error::{LinkError, Result};
use crate::gate::{Gate, GateConfig};
use crate::identity::{Fingerprint, Identity};
use crate::mux::{self, LinkIo, Mode, MuxHandle};
use crate::pairing::{self, PairingCode};
use crate::tls::{self, Established, PeerPolicy, Pinned};
use crate::wire::{Message, Status, WireError, read_msg, write_msg};

/// What `open` does while the hub is unreachable. A per-device setting.
///
/// The owner has not chosen the default yet; until then it is `Stop`: a
/// linked device never silently sends traffic from its own address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnHubDown {
    /// Refuse the connection (`LinkError::HubDown`).
    #[default]
    Stop,
    /// Connect directly from this device, and say so on stderr.
    Direct,
}

impl std::str::FromStr for OnHubDown {
    type Err = LinkError;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "stop" => Ok(OnHubDown::Stop),
            "direct" => Ok(OnHubDown::Direct),
            _ => Err(LinkError::Store("on-hub-down is stop or direct".into())),
        }
    }
}

/// How the link is made.
#[derive(Clone, Debug)]
pub enum HubRoute {
    /// The device dials the hub at this address.
    Dial(String),
    /// The device listens here and the hub dials in (hub behind NAT).
    Listen(SocketAddr),
}

#[derive(Clone, Debug)]
pub struct LinkConfig {
    pub hub: Fingerprint,
    pub route: HubRoute,
    pub on_hub_down: OnHubDown,
    /// How long `open` waits for a link that is (re)connecting.
    pub hub_wait: Duration,
    pub keepalive: Duration,
    pub dead_after: Duration,
    /// Dialling the hub: TCP connect plus TLS handshake.
    pub handshake_timeout: Duration,
    /// `Listen`: an accepted connection must finish its handshake within
    /// this (a silent socket frees its slot fast).
    pub accept_timeout: Duration,
    /// `Listen`: admission before authentication.
    pub gate: GateConfig,
    pub request_timeout: Duration,
    /// How long `open` waits for one of the hub's stream slots (the limit the
    /// hub announced) before answering `Busy` itself.
    pub busy_wait: Duration,
    /// Test hook: the hub address reported on the control stream instead of
    /// the link's real TCP peer (loopback tests stand in for public ones).
    #[doc(hidden)]
    pub report_hub_addr: Option<IpAddr>,
}

impl LinkConfig {
    pub fn new(hub: Fingerprint, route: HubRoute) -> Self {
        LinkConfig {
            hub,
            route,
            on_hub_down: OnHubDown::Stop,
            hub_wait: Duration::from_secs(3),
            keepalive: Duration::from_secs(15),
            dead_after: Duration::from_secs(45),
            handshake_timeout: Duration::from_secs(10),
            accept_timeout: Duration::from_secs(3),
            gate: GateConfig::device(),
            request_timeout: Duration::from_secs(15),
            busy_wait: Duration::from_secs(2),
            report_hub_addr: None,
        }
    }
}

/// How long a device waiting for its hub gives one accepted connection to
/// finish the handshake while pairing.
const PAIR_ACCEPT_LIMIT: Duration = Duration::from_secs(3);

/// How long an open whose stream ended before the hub answered waits to see
/// whether the whole link is going (then it retries on the new link).
const LINK_GONE_GRACE: Duration = Duration::from_secs(1);

/// Streams one link may have open on this side, the control stream aside:
/// the device's own yamux session holds `mux::MAX_STREAMS`.
const DEVICE_STREAM_CAP: u32 = mux::MAX_STREAMS as u32 - 1;

/// The streams this device may have open on one link: the hub's announced
/// limit, counted here so an open over it is answered `Busy` on the device
/// instead of reaching the hub's yamux ceiling (which would end the link).
#[derive(Debug)]
struct Slots {
    state: std::sync::Mutex<(u32, u32)>,
    freed: Notify,
}

impl Slots {
    fn new(limit: u32) -> Arc<Self> {
        Arc::new(Slots { state: std::sync::Mutex::new((0, limit.clamp(1, DEVICE_STREAM_CAP))), freed: Notify::new() })
    }

    fn set_limit(&self, limit: u32) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).1 = limit.clamp(1, DEVICE_STREAM_CAP);
        self.freed.notify_waiters();
    }

    fn limit(&self) -> u32 {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).1
    }

    fn try_take(self: &Arc<Self>) -> Option<Slot> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.0 >= st.1 {
            return None;
        }
        st.0 += 1;
        Some(Slot(self.clone()))
    }

    /// Takes a slot, waiting up to `wait` for one to free.
    async fn take(self: &Arc<Self>, wait: Duration) -> Option<Slot> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let freed = self.freed.notified();
            if let Some(s) = self.try_take() {
                return Some(s);
            }
            if tokio::time::timeout_at(deadline, freed).await.is_err() {
                return self.try_take();
            }
        }
    }
}

/// One of the hub's stream slots, held by an open stream; freed on drop.
#[derive(Debug)]
struct Slot(Arc<Slots>);

impl Drop for Slot {
    fn drop(&mut self) {
        let mut st = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        st.0 = st.0.saturating_sub(1);
        drop(st);
        self.0.freed.notify_waiters();
    }
}

/// The link in use: its session and its stream slots.
#[derive(Clone, Debug)]
struct Current {
    handle: MuxHandle,
    slots: Arc<Slots>,
}

struct ClientInner {
    cfg: LinkConfig,
    link: watch::Sender<Option<Current>>,
    shutdown: CancellationToken,
    listen_addr: Option<SocketAddr>,
}

/// A device's link to its hub. Cheap to clone.
#[derive(Clone)]
pub struct LinkClient {
    inner: Arc<ClientInner>,
}

impl LinkClient {
    /// Starts holding the link in the background.
    pub async fn start(identity: &Identity, cfg: LinkConfig) -> Result<Self> {
        match cfg.route.clone() {
            HubRoute::Dial(addr) => {
                let tls_cfg = tls::client_config(identity, Arc::new(Pinned(cfg.hub)))?;
                let me = Self::new(cfg, None);
                tokio::spawn(dial_loop(me.inner.clone(), addr, tls_cfg));
                Ok(me)
            }
            HubRoute::Listen(addr) => {
                let listener = TcpListener::bind(addr).await?;
                Self::start_with_listener(identity, cfg, listener)
            }
        }
    }

    /// Like `start` with `HubRoute::Listen`, on a listener the caller bound.
    pub fn start_with_listener(identity: &Identity, cfg: LinkConfig, listener: TcpListener) -> Result<Self> {
        let tls_cfg = tls::server_config(identity, Arc::new(Pinned(cfg.hub)))?;
        let me = Self::new(cfg, Some(listener.local_addr()?));
        tokio::spawn(listen_loop(me.inner.clone(), listener, tls_cfg));
        Ok(me)
    }

    fn new(cfg: LinkConfig, listen_addr: Option<SocketAddr>) -> Self {
        let (link, _) = watch::channel(None);
        LinkClient { inner: Arc::new(ClientInner { cfg, link, shutdown: CancellationToken::new(), listen_addr }) }
    }

    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.inner.listen_addr
    }

    pub fn is_up(&self) -> bool {
        self.inner.link.borrow().as_ref().is_some_and(|c| !c.handle.is_closed())
    }

    /// Waits up to `limit` for the link to be up.
    pub async fn wait_up(&self, limit: Duration) -> bool {
        self.current(limit, None).await.is_some()
    }

    /// The streams the hub currently lets this device have open (once the
    /// link is up).
    pub fn stream_limit(&self) -> Option<u32> {
        self.inner.link.borrow().as_ref().map(|c| c.slots.limit())
    }

    /// The link in use and its stream slots (for a test that timed out).
    #[doc(hidden)]
    pub fn debug_state(&self) -> String {
        match self.inner.link.borrow().as_ref() {
            Some(c) => {
                let (used, limit) = *c.slots.state.lock().unwrap_or_else(|e| e.into_inner());
                format!("device: link {} closed={} slots {used}/{limit} shutdown={}", c.handle.id(), c.handle.is_closed(), self.inner.shutdown.is_cancelled())
            }
            None => format!("device: no link, shutdown={}", self.inner.shutdown.is_cancelled()),
        }
    }

    /// The link in use, waiting up to `limit` for one; `not` skips a link
    /// that just failed (so a relink race waits for the NEW link).
    async fn current(&self, limit: Duration, not: Option<u64>) -> Option<Current> {
        let mut rx = self.inner.link.subscribe();
        let ok = |c: &Option<Current>| c.as_ref().is_some_and(|c| !c.handle.is_closed() && Some(c.handle.id()) != not);
        let r = tokio::time::timeout(limit, rx.wait_for(ok)).await;
        match r {
            Ok(Ok(c)) => c.clone(),
            _ => None,
        }
    }

    /// Opens a TCP connection to `host:port` that exits through the hub. The
    /// hub resolves `host`. At most the hub's announced limit of streams are
    /// open at once: an open over it waits up to `busy_wait` for one to close
    /// and is then refused `Busy` here, without reaching the hub. If the link
    /// drops during the open, the open waits up to `hub_wait` for the new
    /// link and tries once more. While the hub is unreachable the device's
    /// `on_hub_down` setting decides: refuse (`Stop`) or go direct.
    pub async fn open(&self, host: &str, port: u16) -> Result<LinkStream> {
        let cfg = &self.inner.cfg;
        let mut failed = None;
        for _ in 0..2 {
            let Some(cur) = self.current(cfg.hub_wait, failed).await else {
                return self.hub_down(host, port).await;
            };
            let Some(slot) = cur.slots.take(cfg.busy_wait).await else {
                let n = cur.slots.limit();
                return Err(LinkError::Refused { status: Status::Busy, message: format!("{n} connections already open (this device's limit at the hub)") });
            };
            match open_on(&cur.handle, host, port, cfg.request_timeout).await {
                Err(LinkError::HubDown) => failed = Some(cur.handle.id()),
                other => return other.map(|io| LinkStream::Link(HubStream { io, _slot: slot })),
            }
        }
        self.hub_down(host, port).await
    }

    async fn hub_down(&self, host: &str, port: u16) -> Result<LinkStream> {
        match self.inner.cfg.on_hub_down {
            OnHubDown::Stop => Err(LinkError::HubDown),
            OnHubDown::Direct => {
                eprintln!("sieve-link: the hub is down; connecting to {host}:{port} DIRECTLY from this device (on-hub-down = direct)");
                let s = tokio::time::timeout(self.inner.cfg.request_timeout, TcpStream::connect((host, port)))
                    .await
                    .map_err(|_| LinkError::Timeout("direct connect"))??;
                Ok(LinkStream::Direct(s))
            }
        }
    }

    pub fn shutdown(&self) {
        self.inner.shutdown.cancel();
    }
}

async fn open_on(h: &MuxHandle, host: &str, port: u16, limit: Duration) -> Result<LinkIo> {
    let mut s = h.open().await?;
    let fut = async {
        write_msg(&mut s, &Message::Connect { host: host.to_string(), port }).await?;
        read_msg(&mut s).await
    };
    let resp = match tokio::time::timeout(limit, fut).await {
        Err(_) => return Err(LinkError::Timeout("hub answer")),
        Ok(Err(e)) => {
            // A stream that ends before the hub's answer: the hub only does
            // that when the link itself is going (cut, replaced, relinked),
            // which this side may learn a moment later.
            let gone = h.cancel_token();
            if tokio::time::timeout(LINK_GONE_GRACE, gone.cancelled()).await.is_ok() {
                return Err(LinkError::HubDown);
            }
            return Err(e.into());
        }
        Ok(Ok(r)) => r,
    };
    match resp {
        Message::Response { status: Status::Ok, .. } => Ok(s),
        Message::Response { status, message } => Err(LinkError::Refused { status, message }),
        _ => Err(LinkError::Protocol("unexpected answer".into())),
    }
}

fn jittered(d: Duration) -> Duration {
    let mut b = [0u8; 1];
    let _ = aws_lc_rs::rand::fill(&mut b);
    d.mul_f64(0.75 + (b[0] as f64 / 255.0) * 0.5)
}

async fn dial_loop(inner: Arc<ClientInner>, addr: String, tls_cfg: Arc<rustls::ClientConfig>) {
    let mut backoff = Duration::from_millis(250);
    loop {
        let r = tokio::select! {
            _ = inner.shutdown.cancelled() => return,
            r = tls::dial(&addr, tls_cfg.clone(), inner.cfg.handshake_timeout) => r,
        };
        match r {
            Ok(est) => {
                backoff = Duration::from_millis(250);
                run_link(inner.clone(), est).await;
            }
            Err(e) => {
                if backoff >= Duration::from_secs(8) {
                    eprintln!("sieve-link: dial {addr}: {e}");
                }
            }
        }
        tokio::select! {
            _ = inner.shutdown.cancelled() => return,
            _ = tokio::time::sleep(jittered(backoff)) => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn listen_loop(inner: Arc<ClientInner>, listener: TcpListener, tls_cfg: Arc<rustls::ServerConfig>) {
    let gate = Gate::new(inner.cfg.gate);
    loop {
        let r = tokio::select! {
            _ = inner.shutdown.cancelled() => return,
            r = listener.accept() => r,
        };
        let Ok((tcp, peer)) = r else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Some(ticket) = gate.admit(peer.ip()) else { continue };
        let inner = inner.clone();
        let tls_cfg = tls_cfg.clone();
        tokio::spawn(async move {
            let Some(pass) = ticket.enter().await else { return };
            let est = tls::accept(tcp, tls_cfg, inner.cfg.accept_timeout).await;
            drop(pass);
            if let Ok(est) = est {
                run_link(inner, est).await;
            }
        });
    }
}

/// Runs one established link until it ends. The newest link replaces any older one.
async fn run_link(inner: Arc<ClientInner>, est: Established) {
    let cancel = inner.shutdown.child_token();
    // The hub never opens streams toward a device: drop any it tries.
    let (handle, task) = mux::spawn(est.io.compat(), Mode::Client, |_s| {}, cancel.clone());
    // The address this device reached the hub at, for the hub to deny to
    // devices as its own (its public address, behind a router).
    let seen = inner.cfg.report_hub_addr.unwrap_or(est.remote.ip());
    // In TLS 1.3 the client finishes its handshake before the server has
    // checked the client's key, so a finished handshake does not mean the
    // hub accepted us. The link counts as up only after the hub answers a
    // first ping on the control stream.
    match tokio::time::timeout(inner.cfg.handshake_timeout, control_open(&handle, seen)).await {
        Ok(Ok((io, limit))) => {
            let slots = Slots::new(limit);
            let old = inner.link.send_replace(Some(Current { handle: handle.clone(), slots: slots.clone() }));
            if let Some(old) = old {
                old.handle.close();
            }
            tokio::spawn(keepalive(handle.clone(), slots, io, inner.cfg.keepalive, inner.cfg.dead_after));
        }
        _ => handle.close(),
    }
    let _ = task.await;
    inner.link.send_if_modified(|cur| {
        if cur.as_ref().is_some_and(|c| c.handle.id() == handle.id()) {
            *cur = None;
            true
        } else {
            false
        }
    });
}

/// Opens the control stream, reports the hub's address as seen from here,
/// and completes a first ping. Returns the stream and the hub's limit (sent
/// before the first pong; a hub that sends none gets this side's own cap).
async fn control_open(h: &MuxHandle, seen: IpAddr) -> Result<(LinkIo, u32)> {
    let mut io = h.open().await?;
    write_msg(&mut io, &Message::Control).await?;
    write_msg(&mut io, &Message::Observed(seen)).await?;
    write_msg(&mut io, &Message::Ping(0)).await?;
    let mut limit = DEVICE_STREAM_CAP;
    loop {
        match read_msg(&mut io).await {
            Ok(Message::Limit(n)) => limit = n,
            Ok(Message::Pong(0)) => return Ok((io, limit)),
            // A notice from a newer hub.
            Err(WireError::UnknownTag(_)) => {}
            Ok(_) => return Err(LinkError::Protocol("the hub did not answer the first ping".into())),
            Err(e) => return Err(e.into()),
        }
    }
}

/// Pings every `every`; reads pongs and limit changes as they come. Nothing
/// read for `dead_after` (pings go out more often than that) ends the link.
async fn keepalive(h: MuxHandle, slots: Arc<Slots>, io: LinkIo, every: Duration, dead_after: Duration) {
    let stop = h.cancel_token();
    let (mut r, mut w) = tokio::io::split(io);
    let pinger = async {
        let mut n: u64 = 0;
        loop {
            tokio::time::sleep(every).await;
            n += 1;
            if write_msg(&mut w, &Message::Ping(n)).await.is_err() {
                return;
            }
        }
    };
    let reader = async {
        loop {
            match tokio::time::timeout(dead_after, read_msg(&mut r)).await {
                Ok(Ok(Message::Pong(_))) => {}
                Ok(Ok(Message::Limit(n))) => slots.set_limit(n),
                // A notice from a newer hub.
                Ok(Err(WireError::UnknownTag(_))) => {}
                _ => return,
            }
        }
    };
    tokio::select! {
        _ = stop.cancelled() => return,
        _ = pinger => {}
        _ = reader => {}
    }
    h.close();
}

/// Where the device meets the hub to pair.
pub enum PairVia<'a> {
    /// Dial the hub (the code's address, or another).
    Dial(String),
    /// A TCP connection to the hub the caller made (e.g. from a chosen
    /// local address, or through a proxy).
    Connected(TcpStream),
    /// Wait on this listener for the hub to dial in (as long as the caller
    /// lets this future run).
    Listener(&'a TcpListener),
}

/// Waits on `l` for the pinned hub: handshakes run side by side behind a
/// gate, so strangers' silent connections cannot hold the hub out.
async fn accept_hub(l: &TcpListener, cfg: Arc<rustls::ServerConfig>) -> Result<Established> {
    let gate = Gate::new(GateConfig::device());
    let mut set = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            r = l.accept() => {
                let Ok((tcp, peer)) = r else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let Some(ticket) = gate.admit(peer.ip()) else { continue };
                let cfg = cfg.clone();
                set.spawn(async move {
                    let _pass = ticket.enter().await?;
                    tls::accept(tcp, cfg, PAIR_ACCEPT_LIMIT).await.ok()
                });
            }
            Some(done) = set.join_next(), if !set.is_empty() => {
                // Anyone may connect; only the pinned hub completes the handshake.
                if let Ok(Some(est)) = done {
                    return Ok(est);
                }
            }
        }
    }
}

/// Redeems a pairing code: connects to the hub the code names (pinning its
/// key), proves knowledge of the code's secret bound to this session, and
/// returns the hub's name. The caller stores the hub's fingerprint.
///
/// `limit` bounds dialling and, once connected, the exchange; waiting on a
/// listener for the hub to dial in is bounded by the caller.
pub async fn pair(identity: &Identity, code: &PairingCode, name: &str, via: PairVia<'_>, limit: Duration) -> Result<String> {
    if code.is_expired(crate::now_secs()) {
        return Err(LinkError::Pairing("the code has expired; ask the hub's owner for a new one".into()));
    }
    let policy: Arc<dyn PeerPolicy> = Arc::new(Pinned(code.hub));
    let est = match via {
        PairVia::Dial(addr) => tls::dial(&addr, tls::client_config(identity, policy)?, limit).await?,
        PairVia::Connected(tcp) => tls::connect(tcp, tls::client_config(identity, policy)?, limit).await?,
        PairVia::Listener(l) => accept_hub(l, tls::server_config(identity, policy)?).await?,
    };
    let me = identity.fingerprint();
    let fut = async {
        let proof = pairing::proof(&code.secret, &est.exporter, &me, &code.hub);
        let cancel = CancellationToken::new();
        let (h, task) = mux::spawn(est.io.compat(), Mode::Client, |_s| {}, cancel.clone());
        let r = async {
            let mut s = h.open().await.map_err(|_| LinkError::Pairing("the hub closed the link".into()))?;
            write_msg(&mut s, &Message::Pair { proof, name: name.to_string() }).await?;
            read_msg(&mut s).await.map_err(|e| match e {
                WireError::UnknownStatus(n) => LinkError::Pairing(format!(
                    "this hub speaks a newer version of sieve-link (it answered with status {n}, which this device does not know); \
                     update sieve-link on this device and pair again"
                )),
                other => LinkError::from(other),
            })
        }
        .await;
        cancel.cancel();
        let _ = task.await;
        // TLS 1.3: a hub that refuses our key does so after our side of the
        // handshake has finished, so the refusal shows up here as a closed link.
        let r = r.map_err(|e| match e {
            LinkError::Io(_) | LinkError::Protocol(_) => {
                LinkError::Pairing("the hub closed the connection: the code is used, expired, or from another hub".into())
            }
            other => other,
        });
        match r? {
            Message::Response { status: Status::Ok, message } => Ok(message),
            Message::Response { status: Status::Busy, .. } => Err(LinkError::Pairing(
                "the hub was busy (other pairing attempts were in progress); the code is still valid, try again in a few seconds".into(),
            )),
            Message::Response { message, .. } => Err(LinkError::Pairing(format!("the hub refused: {message}"))),
            _ => Err(LinkError::Pairing("unexpected answer".into())),
        }
    };
    tokio::time::timeout(limit, fut).await.map_err(|_| LinkError::Timeout("pairing"))?
}

/// A stream through the hub; holds one of the hub's stream slots until
/// dropped.
pub struct HubStream {
    io: LinkIo,
    _slot: Slot,
}

impl HubStream {
    pub fn get_mut(&mut self) -> &mut LinkIo {
        &mut self.io
    }
}

/// A connection opened by `LinkClient::open`.
pub enum LinkStream {
    /// Through the hub.
    Link(HubStream),
    /// Direct from this device (only with `OnHubDown::Direct`).
    Direct(TcpStream),
}

impl LinkStream {
    pub fn is_direct(&self) -> bool {
        matches!(self, LinkStream::Direct(_))
    }
}

impl AsyncRead for LinkStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            LinkStream::Link(s) => Pin::new(&mut s.io).poll_read(cx, buf),
            LinkStream::Direct(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LinkStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            LinkStream::Link(s) => Pin::new(&mut s.io).poll_write(cx, buf),
            LinkStream::Direct(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            LinkStream::Link(s) => Pin::new(&mut s.io).poll_flush(cx),
            LinkStream::Direct(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            LinkStream::Link(s) => Pin::new(&mut s.io).poll_shutdown(cx),
            LinkStream::Direct(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
