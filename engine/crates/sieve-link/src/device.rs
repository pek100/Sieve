//! The device side: pairs with a hub, holds the link (dialling the hub, or
//! waiting for the hub to dial in), reconnects with back-off, and opens
//! streams through it. `LinkClient::open` is the seed of the SDK.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;

use crate::error::{LinkError, Result};
use crate::gate::{Gate, GateConfig};
use crate::identity::{Fingerprint, Identity};
use crate::mux::{self, LinkIo, Mode, MuxHandle};
use crate::pairing::{self, PairingCode};
use crate::tls::{self, Established, PeerPolicy, Pinned};
use crate::wire::{Message, Status, read_msg, write_msg};

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
        }
    }
}

/// How long a device waiting for its hub gives one accepted connection to
/// finish the handshake while pairing.
const PAIR_ACCEPT_LIMIT: Duration = Duration::from_secs(3);

struct ClientInner {
    cfg: LinkConfig,
    link: watch::Sender<Option<MuxHandle>>,
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
        self.inner.link.borrow().as_ref().is_some_and(|h| !h.is_closed())
    }

    /// Waits up to `limit` for the link to be up.
    pub async fn wait_up(&self, limit: Duration) -> bool {
        self.current(limit).await.is_some()
    }

    async fn current(&self, limit: Duration) -> Option<MuxHandle> {
        let mut rx = self.inner.link.subscribe();
        let r = tokio::time::timeout(limit, rx.wait_for(|h| h.as_ref().is_some_and(|h| !h.is_closed()))).await;
        match r {
            Ok(Ok(h)) => h.clone(),
            _ => None,
        }
    }

    /// Opens a TCP connection to `host:port` that exits through the hub. The
    /// hub resolves `host`. While the hub is unreachable the device's
    /// `on_hub_down` setting decides: refuse (`Stop`) or go direct.
    pub async fn open(&self, host: &str, port: u16) -> Result<LinkStream> {
        let cfg = &self.inner.cfg;
        let Some(h) = self.current(cfg.hub_wait).await else {
            return self.hub_down(host, port).await;
        };
        match open_on(&h, host, port, cfg.request_timeout).await {
            Err(LinkError::HubDown) => self.hub_down(host, port).await,
            other => other.map(LinkStream::Link),
        }
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
        Ok(Err(e)) if h.is_closed() => {
            let _ = e;
            return Err(LinkError::HubDown);
        }
        Ok(r) => r?,
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
    // In TLS 1.3 the client finishes its handshake before the server has
    // checked the client's key, so a finished handshake does not mean the
    // hub accepted us. The link counts as up only after the hub answers a
    // first ping on the control stream.
    match tokio::time::timeout(inner.cfg.handshake_timeout, control_open(&handle)).await {
        Ok(Ok(io)) => {
            let old = inner.link.send_replace(Some(handle.clone()));
            if let Some(old) = old {
                old.close();
            }
            tokio::spawn(keepalive(handle.clone(), io, inner.cfg.keepalive, inner.cfg.dead_after));
        }
        _ => handle.close(),
    }
    let _ = task.await;
    inner.link.send_if_modified(|cur| {
        if cur.as_ref().is_some_and(|h| h.id() == handle.id()) {
            *cur = None;
            true
        } else {
            false
        }
    });
}

/// Opens the control stream and completes a first ping.
async fn control_open(h: &MuxHandle) -> Result<LinkIo> {
    let mut io = h.open().await?;
    write_msg(&mut io, &Message::Control).await?;
    write_msg(&mut io, &Message::Ping(0)).await?;
    match read_msg(&mut io).await? {
        Message::Pong(0) => Ok(io),
        _ => Err(LinkError::Protocol("the hub did not answer the first ping".into())),
    }
}

async fn keepalive(h: MuxHandle, mut io: LinkIo, every: Duration, dead_after: Duration) {
    let stop = h.cancel_token();
    let mut n: u64 = 0;
    loop {
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = tokio::time::sleep(every) => {}
        }
        n += 1;
        if write_msg(&mut io, &Message::Ping(n)).await.is_err() {
            h.close();
            return;
        }
        match tokio::time::timeout(dead_after, read_msg(&mut io)).await {
            Ok(Ok(Message::Pong(m))) if m == n => {}
            _ => {
                h.close();
                return;
            }
        }
    }
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
            read_msg(&mut s).await.map_err(LinkError::from)
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

/// A connection opened by `LinkClient::open`.
pub enum LinkStream {
    /// Through the hub.
    Link(LinkIo),
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
            LinkStream::Link(s) => Pin::new(s).poll_read(cx, buf),
            LinkStream::Direct(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LinkStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            LinkStream::Link(s) => Pin::new(s).poll_write(cx, buf),
            LinkStream::Direct(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            LinkStream::Link(s) => Pin::new(s).poll_flush(cx),
            LinkStream::Direct(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            LinkStream::Link(s) => Pin::new(s).poll_shutdown(cx),
            LinkStream::Direct(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
