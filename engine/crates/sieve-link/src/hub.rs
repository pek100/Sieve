//! The hub: accepts (or dials) links from paired devices, opens their
//! `connect host:port` streams under each device's rules and limits, relays
//! bytes it never decrypts, and audits every stream.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;

use crate::audit::{Audit, AuditRow};
use crate::error::Result;
use crate::identity::{Fingerprint, Identity};
use crate::mux::{self, LinkIo, Mode};
use crate::pairing::{self, PairingCode};
use crate::resolve::{self, Resolver, SystemResolver};
use crate::rules::{self, Bucket, Limits, Rules};
use crate::store::{self, DeviceRecord, HubFile, HubStore, PendingCode};
use crate::tls::{self, Established, PeerPolicy};
use crate::wire::{Message, Status, WireError, read_msg, write_msg};
use crate::{now_ms, now_secs};

/// Shown when the hub starts and whenever a pairing code is made.
pub const EXIT_NOTICE: &str = "\
NOTICE: devices paired with this hub send their internet traffic out through
THIS machine's connection. Sites they reach see this machine's public IP
address, and anything they do is traced back to it. Pair only your own
devices and people you trust. Each device can be revoked at once with
`sieve-hub revoke <device>`; every connection is recorded in audit.log.";

pub struct HubConfig {
    pub dir: PathBuf,
    pub handshake_timeout: Duration,
    /// How long a new stream may take to send its request.
    pub request_timeout: Duration,
    /// How long the hub waits for a target to accept.
    pub connect_timeout: Duration,
    /// A link with no keep-alive ping for this long is dropped.
    pub dead_after: Duration,
    /// How often the store file is checked for changes made by the CLI.
    pub reload_every: Duration,
    pub resolver: Arc<dyn Resolver>,
}

impl HubConfig {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        HubConfig {
            dir: dir.into(),
            handshake_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            dead_after: Duration::from_secs(45),
            reload_every: Duration::from_secs(1),
            resolver: Arc::new(SystemResolver),
        }
    }
}

/// Live state of one device: one cancel token for all its links (revoking
/// fires it) and its limiters, shared by all its links.
struct Live {
    cancel: CancellationToken,
    state: Mutex<LiveState>,
}

struct LiveState {
    limits: Limits,
    concurrent: Arc<Semaphore>,
    opens: Bucket,
    bytes: Option<Arc<Mutex<Bucket>>>,
}

impl LiveState {
    fn new(l: Limits) -> Self {
        let opm = l.opens_per_minute as f64;
        LiveState {
            limits: l,
            concurrent: Arc::new(Semaphore::new(l.max_concurrent as usize)),
            opens: Bucket::new(opm, opm / 60.0),
            bytes: (l.bytes_per_sec > 0).then(|| {
                let b = l.bytes_per_sec as f64;
                Arc::new(Mutex::new(Bucket::new(b, b)))
            }),
        }
    }
}

#[derive(Debug)]
struct HubPolicy {
    snap: Arc<RwLock<HubFile>>,
}

impl PeerPolicy for HubPolicy {
    fn accepts(&self, peer: &Fingerprint) -> bool {
        let s = self.snap.read().unwrap_or_else(|e| e.into_inner());
        // A paired, unrevoked device; or, while a pairing code is
        // outstanding, an unknown key that may be about to redeem it.
        match s.device(peer) {
            Some(d) => d.active(),
            None => s.has_pending(now_secs()),
        }
    }
}

struct Inner {
    cfg: HubConfig,
    store: HubStore,
    fp: Fingerprint,
    snap: Arc<RwLock<HubFile>>,
    snap_mtime: Mutex<Option<SystemTime>>,
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
    live: Mutex<HashMap<Fingerprint, Arc<Live>>>,
    audit: Audit,
    shutdown: CancellationToken,
    /// Handshakes in progress (unauthenticated work is bounded).
    handshakes: Arc<Semaphore>,
    /// Pairing sessions in progress.
    pairings: Arc<Semaphore>,
}

#[derive(Clone)]
pub struct Hub {
    inner: Arc<Inner>,
}

impl Hub {
    /// Creates a hub directory: a new key and an empty `hub.json`.
    pub fn init(dir: impl Into<PathBuf>, name: &str) -> Result<Fingerprint> {
        let dir = dir.into();
        let st = HubStore::new(&dir);
        st.create(name)?;
        let id = Identity::load_or_create(&dir.join(store::IDENTITY_FILE))?;
        Ok(id.fingerprint())
    }

    /// The hub key's fingerprint, without starting a hub.
    pub fn fingerprint_at(dir: impl Into<PathBuf>) -> Result<Fingerprint> {
        Ok(Identity::load(&dir.into().join(store::IDENTITY_FILE))?.fingerprint())
    }

    /// Adds a one-time pairing code to the store (works whether or not the
    /// hub is running; a running hub picks it up within `reload_every`).
    pub fn create_pairing_code_at(dir: impl Into<PathBuf>, ttl_secs: u64, addr: Option<String>, label: &str) -> Result<PairingCode> {
        let dir = dir.into();
        let fp = Self::fingerprint_at(&dir)?;
        let code = PairingCode::new(fp, ttl_secs, addr)?;
        let secret: String = code.secret.iter().map(|b| format!("{b:02x}")).collect();
        HubStore::new(&dir).update(|f| {
            f.purge_expired(now_secs());
            f.pending.push(PendingCode { secret, expires_at: code.expires_at, label: label.to_string() });
            Ok(())
        })?;
        Ok(code)
    }

    /// Opens an initialized hub directory. Nothing listens or dials yet.
    pub fn open(cfg: HubConfig) -> Result<Hub> {
        let store = HubStore::new(&cfg.dir);
        let identity = Identity::load(&cfg.dir.join(store::IDENTITY_FILE))?;
        let file = store.load()?;
        let snap = Arc::new(RwLock::new(file));
        let policy: Arc<dyn PeerPolicy> = Arc::new(HubPolicy { snap: snap.clone() });
        let server_cfg = tls::server_config(&identity, policy.clone())?;
        let client_cfg = tls::client_config(&identity, policy)?;
        let audit = Audit::open(&cfg.dir.join(store::AUDIT_FILE))?;
        let mtime = std::fs::metadata(store.file_path()).and_then(|m| m.modified()).ok();
        let inner = Arc::new(Inner {
            fp: identity.fingerprint(),
            store,
            snap,
            snap_mtime: Mutex::new(mtime),
            server_cfg,
            client_cfg,
            live: Mutex::new(HashMap::new()),
            audit,
            shutdown: CancellationToken::new(),
            handshakes: Arc::new(Semaphore::new(64)),
            pairings: Arc::new(Semaphore::new(4)),
            cfg,
        });
        let hub = Hub { inner };
        hub.spawn_reloader();
        Ok(hub)
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.inner.fp
    }

    pub fn name(&self) -> String {
        self.inner.read().name.clone()
    }

    pub fn devices(&self) -> Vec<DeviceRecord> {
        self.inner.read().devices.clone()
    }

    pub fn create_pairing_code(&self, ttl_secs: u64, addr: Option<String>, label: &str) -> Result<PairingCode> {
        let c = Self::create_pairing_code_at(&self.inner.cfg.dir, ttl_secs, addr, label)?;
        self.reload()?;
        Ok(c)
    }

    /// Revokes a device (fingerprint prefix or name) and cuts its links and
    /// streams at once.
    pub fn revoke(&self, key: &str) -> Result<Fingerprint> {
        let fp = revoke_at(&self.inner.store, key)?;
        self.reload()?;
        Ok(fp)
    }

    pub fn set_rules(&self, key: &str, rules: Rules) -> Result<()> {
        self.inner.store.update(|f| {
            let fp = f.find(key)?;
            f.device_mut(&fp).expect("found").rules = rules;
            Ok(())
        })?;
        self.reload()
    }

    pub fn set_limits(&self, key: &str, limits: Limits) -> Result<()> {
        self.inner.store.update(|f| {
            let fp = f.find(key)?;
            f.device_mut(&fp).expect("found").limits = limits;
            Ok(())
        })?;
        self.reload()
    }

    /// Re-reads the store; cuts revoked or removed devices; applies new limits.
    pub fn reload(&self) -> Result<()> {
        self.inner.reload()
    }

    /// Listens for devices on `addr` (TCP). Returns the bound address.
    pub async fn listen(&self, addr: SocketAddr) -> Result<SocketAddr> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        tokio::spawn(accept_loop(self.inner.clone(), listener));
        Ok(local)
    }

    /// Keeps a link dialled OUT to `addr` (a device, or a rendezvous point,
    /// that is publicly reachable). The hub is still the hub on it.
    pub fn dial(&self, addr: String) {
        tokio::spawn(dial_loop(self.inner.clone(), addr));
    }

    pub fn shutdown(&self) {
        self.inner.shutdown.cancel();
    }

    pub fn audit_path(&self) -> PathBuf {
        self.inner.cfg.dir.join(store::AUDIT_FILE)
    }

    fn spawn_reloader(&self) {
        let inner = Arc::downgrade(&self.inner);
        let every = self.inner.cfg.reload_every;
        let stop = self.inner.shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop.cancelled() => return,
                    _ = tokio::time::sleep(every) => {}
                }
                let Some(inner) = inner.upgrade() else { return };
                let m = std::fs::metadata(inner.store.file_path()).and_then(|m| m.modified()).ok();
                let changed = *inner.snap_mtime.lock().unwrap() != m;
                if changed && let Err(e) = inner.reload() {
                    eprintln!("sieve-hub: reload failed: {e}");
                }
            }
        });
    }
}

/// Marks a device revoked in the store (CLI path; a running hub cuts it off
/// on its next reload).
pub fn revoke_at(store: &HubStore, key: &str) -> Result<Fingerprint> {
    store.update(|f| {
        let fp = f.find(key)?;
        let d = f.device_mut(&fp).expect("found");
        if d.revoked_at.is_none() {
            d.revoked_at = Some(now_secs());
        }
        Ok(fp)
    })
}

impl Inner {
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HubFile> {
        self.snap.read().unwrap_or_else(|e| e.into_inner())
    }

    fn reload(&self) -> Result<()> {
        let mtime = std::fs::metadata(self.store.file_path()).and_then(|m| m.modified()).ok();
        let file = self.store.load()?;
        *self.snap.write().unwrap_or_else(|e| e.into_inner()) = file.clone();
        *self.snap_mtime.lock().unwrap() = mtime;
        let mut cut = Vec::new();
        {
            let mut live = self.live.lock().unwrap();
            live.retain(|fp, l| match file.device(fp) {
                Some(d) if d.active() => {
                    let mut st = l.state.lock().unwrap();
                    if st.limits != d.limits {
                        *st = LiveState::new(d.limits);
                    }
                    true
                }
                other => {
                    l.cancel.cancel();
                    cut.push((*fp, other.map(|d| d.name.clone())));
                    false
                }
            });
        }
        for (fp, name) in cut {
            self.audit.record(AuditRow { event: "revoked", device: Some(fp.short()), name, outcome: "links cut".into(), ..Default::default() });
        }
        Ok(())
    }

    fn live_for(&self, rec: &DeviceRecord) -> Arc<Live> {
        let mut m = self.live.lock().unwrap();
        m.entry(rec.fingerprint)
            .or_insert_with(|| Arc::new(Live { cancel: self.shutdown.child_token(), state: Mutex::new(LiveState::new(rec.limits)) }))
            .clone()
    }
}

fn jittered(d: Duration) -> Duration {
    let mut b = [0u8; 1];
    let _ = aws_lc_rs::rand::fill(&mut b);
    d.mul_f64(0.75 + (b[0] as f64 / 255.0) * 0.5)
}

async fn accept_loop(inner: Arc<Inner>, listener: TcpListener) {
    loop {
        let accepted = tokio::select! {
            _ = inner.shutdown.cancelled() => return,
            r = listener.accept() => r,
        };
        let Ok((tcp, peer)) = accepted else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(permit) = inner.handshakes.clone().try_acquire_owned() else {
            drop(tcp);
            continue;
        };
        let inner = inner.clone();
        tokio::spawn(async move {
            let est = tls::accept(tcp, inner.server_cfg.clone(), inner.cfg.handshake_timeout).await;
            drop(permit);
            match est {
                Ok(est) => serve_conn(inner, est).await,
                Err(e) => inner.audit.record(AuditRow {
                    event: "handshake_refused",
                    peer: Some(peer.to_string()),
                    outcome: e.to_string(),
                    ..Default::default()
                }),
            }
        });
    }
}

async fn dial_loop(inner: Arc<Inner>, addr: String) {
    let mut backoff = Duration::from_millis(250);
    loop {
        if inner.shutdown.is_cancelled() {
            return;
        }
        let r = tokio::select! {
            _ = inner.shutdown.cancelled() => return,
            r = tls::dial(&addr, inner.client_cfg.clone(), inner.cfg.handshake_timeout) => r,
        };
        match r {
            Ok(est) => {
                backoff = Duration::from_millis(250);
                serve_conn(inner.clone(), est).await;
            }
            Err(e) => {
                if backoff >= Duration::from_secs(8) {
                    eprintln!("sieve-hub: dial {addr}: {e}");
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

/// Serves one authenticated connection, whoever dialled it.
async fn serve_conn(inner: Arc<Inner>, est: Established) {
    let rec = inner.read().device(&est.peer).cloned();
    match rec {
        Some(r) if r.active() => serve_device(inner, est, r).await,
        Some(r) => inner.audit.record(AuditRow {
            event: "refused",
            device: Some(r.fingerprint.short()),
            name: Some(r.name),
            peer: Some(est.remote.to_string()),
            outcome: "revoked device".into(),
            ..Default::default()
        }),
        None => serve_pairing(inner, est).await,
    }
}

async fn serve_device(inner: Arc<Inner>, est: Established, rec: DeviceRecord) {
    let live = inner.live_for(&rec);
    // Re-check after registering, so a revoke racing this link still cuts it.
    if !inner.read().device(&rec.fingerprint).is_some_and(|d| d.active()) || live.cancel.is_cancelled() {
        return;
    }
    let conn_cancel = live.cancel.child_token();
    let last_ping = Arc::new(AtomicU64::new(now_ms()));
    let peer = est.remote;
    inner.audit.record(AuditRow {
        event: "link_up",
        device: Some(rec.fingerprint.short()),
        name: Some(rec.name.clone()),
        peer: Some(peer.to_string()),
        outcome: est.kx_group.map(|g| format!("{g:?}")).unwrap_or_default(),
        ..Default::default()
    });
    let dev = Arc::new(DeviceCtx { fp: rec.fingerprint, name: rec.name.clone(), peer });
    let handler = {
        let inner = inner.clone();
        let live = live.clone();
        let cancel = conn_cancel.clone();
        let last_ping = last_ping.clone();
        let dev = dev.clone();
        move |s: yamux::Stream| {
            tokio::spawn(handle_stream(inner.clone(), live.clone(), dev.clone(), s.compat(), cancel.clone(), last_ping.clone()));
        }
    };
    let (_handle, task) = mux::spawn(est.io.compat(), Mode::Server, handler, conn_cancel.clone());
    // Watchdog: no ping for dead_after drops the link.
    let dead_after = inner.cfg.dead_after;
    let wd_cancel = conn_cancel.clone();
    let wd_ping = last_ping.clone();
    tokio::spawn(async move {
        let tick = (dead_after / 4).max(Duration::from_millis(50));
        loop {
            tokio::select! {
                _ = wd_cancel.cancelled() => return,
                _ = tokio::time::sleep(tick) => {}
            }
            if now_ms().saturating_sub(wd_ping.load(Ordering::Relaxed)) > dead_after.as_millis() as u64 {
                wd_cancel.cancel();
                return;
            }
        }
    });
    let _ = task.await;
    conn_cancel.cancel();
    inner.audit.record(AuditRow {
        event: "link_down",
        device: Some(dev.fp.short()),
        name: Some(dev.name.clone()),
        peer: Some(peer.to_string()),
        outcome: if live.cancel.is_cancelled() { "cut off".into() } else { "closed".into() },
        ..Default::default()
    });
}

struct DeviceCtx {
    fp: Fingerprint,
    name: String,
    peer: SocketAddr,
}

async fn respond(io: &mut LinkIo, status: Status, message: &str) {
    let _ = write_msg(io, &Message::Response { status, message: message.to_string() }).await;
}

async fn handle_stream(inner: Arc<Inner>, live: Arc<Live>, dev: Arc<DeviceCtx>, mut io: LinkIo, cancel: CancellationToken, last_ping: Arc<AtomicU64>) {
    let first = tokio::select! {
        _ = cancel.cancelled() => return,
        r = tokio::time::timeout(inner.cfg.request_timeout, read_msg(&mut io)) => r,
    };
    let msg = match first {
        Ok(Ok(m)) => m,
        Ok(Err(WireError::Io(_))) | Err(_) => return,
        Ok(Err(e)) => {
            respond(&mut io, Status::BadRequest, &e.to_string()).await;
            inner.audit.record(AuditRow {
                event: "bad_request",
                device: Some(dev.fp.short()),
                name: Some(dev.name.clone()),
                outcome: e.to_string(),
                ..Default::default()
            });
            return;
        }
    };
    match msg {
        Message::Control => control_loop(&inner, io, cancel, last_ping).await,
        Message::Connect { host, port } => connect(&inner, &live, &dev, io, host, port, cancel).await,
        _ => respond(&mut io, Status::BadRequest, "expected connect or control").await,
    }
}

async fn control_loop(inner: &Inner, mut io: LinkIo, cancel: CancellationToken, last_ping: Arc<AtomicU64>) {
    loop {
        let r = tokio::select! {
            _ = cancel.cancelled() => return,
            r = tokio::time::timeout(inner.cfg.dead_after, read_msg(&mut io)) => r,
        };
        match r {
            Ok(Ok(Message::Ping(n))) => {
                last_ping.store(now_ms(), Ordering::Relaxed);
                if write_msg(&mut io, &Message::Pong(n)).await.is_err() {
                    return;
                }
            }
            _ => return,
        }
    }
}

async fn connect(inner: &Inner, live: &Live, dev: &DeviceCtx, mut io: LinkIo, host: String, port: u16, cancel: CancellationToken) {
    let started = Instant::now();
    let target = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let row = |event: &'static str, outcome: String| AuditRow {
        event,
        device: Some(dev.fp.short()),
        name: Some(dev.name.clone()),
        peer: Some(dev.peer.to_string()),
        target: Some(target.clone()),
        outcome,
        ..Default::default()
    };

    // Limits first: they cost nothing and protect what follows.
    let admitted = {
        let mut st = live.state.lock().unwrap();
        if !st.opens.take(1.0, Instant::now()) {
            Err((Status::RateLimited, "too many new connections per minute".to_string()))
        } else {
            match st.concurrent.clone().try_acquire_owned() {
                Ok(p) => Ok((p, st.bytes.clone())),
                Err(_) => Err((Status::Busy, format!("{} connections already open", st.limits.max_concurrent))),
            }
        }
    };
    let (_permit, bytes_bucket) = match admitted {
        Ok(v) => v,
        Err((status, why)) => {
            respond(&mut io, status, &why).await;
            inner.audit.record(row("denied", why));
            return;
        }
    };

    let current = {
        let s = inner.read();
        s.device(&dev.fp).filter(|d| d.active()).map(|d| (d.rules.clone(), s.lan_cidrs.clone()))
    };
    let Some((rules, lan)) = current else {
        respond(&mut io, Status::Denied, "revoked").await;
        inner.audit.record(row("denied", "revoked".into()));
        return;
    };
    if let Err(why) = rules::check_host(&rules, &host) {
        respond(&mut io, Status::Denied, &why).await;
        inner.audit.record(row("denied", why));
        return;
    }
    let addrs = match tokio::time::timeout(inner.cfg.connect_timeout, resolve::resolve(inner.cfg.resolver.as_ref(), &host, port)).await {
        Ok(Ok(a)) if !a.is_empty() => a,
        _ => {
            respond(&mut io, Status::Unreachable, "cannot resolve the name at the hub").await;
            inner.audit.record(row("unreachable", "resolve failed".into()));
            return;
        }
    };
    let mut first_denial = None;
    let allowed: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|a| match rules::check_addr(&rules, &lan, a.ip()) {
            Ok(()) => true,
            Err(why) => {
                first_denial.get_or_insert(why);
                false
            }
        })
        .collect();
    if allowed.is_empty() {
        let why = first_denial.unwrap_or_else(|| "no address".into());
        respond(&mut io, Status::Denied, &why).await;
        inner.audit.record(row("denied", why));
        return;
    }
    let mut upstream = None;
    for a in &allowed {
        let attempt = tokio::select! {
            _ = cancel.cancelled() => return,
            r = tokio::time::timeout(inner.cfg.connect_timeout, TcpStream::connect(a)) => r,
        };
        if let Ok(Ok(s)) = attempt {
            upstream = Some((s, *a));
            break;
        }
    }
    let Some((tcp, addr)) = upstream else {
        respond(&mut io, Status::Unreachable, "the target did not accept").await;
        inner.audit.record(row("unreachable", "connect failed".into()));
        return;
    };
    let _ = tcp.set_nodelay(true);
    if write_msg(&mut io, &Message::Response { status: Status::Ok, message: String::new() }).await.is_err() {
        return;
    }
    let (up, down, how) = relay(io, tcp, &cancel, bytes_bucket).await;
    let mut r = row("stream", how.to_string());
    r.addr = Some(addr.to_string());
    r.up = Some(up);
    r.down = Some(down);
    r.ms = Some(started.elapsed().as_millis() as u64);
    inner.audit.record(r);
}

/// Copies both ways until both sides finish or `cancel` fires. Fixed 16 KiB
/// buffers; an optional byte bucket shared by all the device's streams.
pub(crate) async fn relay<A, B>(a: A, b: B, cancel: &CancellationToken, bucket: Option<Arc<Mutex<Bucket>>>) -> (u64, u64, &'static str)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let up = AtomicU64::new(0);
    let down = AtomicU64::new(0);
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let both = async {
        tokio::join!(pump(&mut ar, &mut bw, &up, bucket.clone()), pump(&mut br, &mut aw, &down, bucket.clone()));
    };
    let how = tokio::select! {
        _ = both => "closed",
        _ = cancel.cancelled() => "cut off",
    };
    (up.load(Ordering::Relaxed), down.load(Ordering::Relaxed), how)
}

async fn pump<R, W>(r: &mut R, w: &mut W, count: &AtomicU64, bucket: Option<Arc<Mutex<Bucket>>>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if let Some(b) = &bucket {
            let wait = b.lock().unwrap().debit(n as f64, Instant::now());
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
        }
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        count.fetch_add(n as u64, Ordering::Relaxed);
    }
    let _ = w.shutdown().await;
}

fn clean_name(name: &str) -> String {
    let n: String = name.chars().filter(|c| !c.is_control()).take(64).collect();
    let n = n.trim().to_string();
    if n.is_empty() { "device".into() } else { n }
}

async fn serve_pairing(inner: Arc<Inner>, est: Established) {
    let peer = est.peer;
    let remote = est.remote;
    let refuse = |why: &str| {
        inner.audit.record(AuditRow {
            event: "pair_refused",
            device: Some(peer.short()),
            peer: Some(remote.to_string()),
            outcome: why.to_string(),
            ..Default::default()
        })
    };
    let Ok(_permit) = inner.pairings.clone().try_acquire_owned() else {
        refuse("too many pairings at once");
        return;
    };
    if !inner.read().has_pending(now_secs()) {
        refuse("no pairing code outstanding");
        return;
    }
    let exporter = est.exporter;
    let cancel = inner.shutdown.child_token();
    let (tx, rx) = oneshot::channel();
    let mut tx = Some(tx);
    let (_handle, task) = mux::spawn(est.io.compat(), Mode::Server, move |s| {
        if let Some(t) = tx.take() {
            let _ = t.send(s);
        }
    }, cancel.clone());

    let outcome: std::result::Result<String, String> = async {
        let s = tokio::time::timeout(Duration::from_secs(30), rx).await.map_err(|_| "no request".to_string())?.map_err(|_| "closed".to_string())?;
        let mut io = s.compat();
        let msg = tokio::time::timeout(Duration::from_secs(10), read_msg(&mut io)).await.map_err(|_| "timeout".to_string())?.map_err(|e| e.to_string())?;
        let Message::Pair { proof, name } = msg else {
            respond(&mut io, Status::BadRequest, "not paired; expected a pairing request").await;
            return Err("unpaired key sent something other than a pairing request".into());
        };
        let name = clean_name(&name);
        let hub = inner.fp;
        let matched = inner.store.update(|f| {
            f.purge_expired(now_secs());
            if f.device(&peer).is_some() {
                return Ok(false);
            }
            let idx = f.pending.iter().position(|p| p.secret_bytes().is_some_and(|s| pairing::verify_proof(&s, &exporter, &peer, &hub, &proof)));
            let Some(i) = idx else { return Ok(false) };
            f.pending.remove(i);
            let d = f.defaults.clone();
            f.devices.push(DeviceRecord { fingerprint: peer, name: name.clone(), paired_at: now_secs(), revoked_at: None, rules: d.rules, limits: d.limits });
            Ok(true)
        });
        match matched {
            Ok(true) => {
                let _ = inner.reload();
                let hub_name = inner.read().name.clone();
                respond(&mut io, Status::Ok, &hub_name).await;
                let _ = io.shutdown().await;
                // Let the device read the answer and close.
                let _ = tokio::time::timeout(Duration::from_secs(5), async {
                    let mut b = [0u8; 1];
                    let _ = io.read(&mut b).await;
                })
                .await;
                Ok(name)
            }
            Ok(false) => {
                respond(&mut io, Status::PairingRefused, "the code is wrong, used or expired").await;
                Err("proof matched no outstanding code".into())
            }
            Err(e) => {
                respond(&mut io, Status::PairingRefused, "the hub could not store the pairing").await;
                Err(format!("store: {e}"))
            }
        }
    }
    .await;
    cancel.cancel();
    let _ = task.await;
    match outcome {
        Ok(name) => inner.audit.record(AuditRow {
            event: "paired",
            device: Some(peer.short()),
            name: Some(name),
            peer: Some(remote.to_string()),
            outcome: "ok".into(),
            ..Default::default()
        }),
        Err(why) => refuse(&why),
    }
}
