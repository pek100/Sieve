//! The hub: accepts (or dials) links from paired devices, opens their
//! `connect host:port` streams under each device's rules and limits, relays
//! bytes it never decrypts, and audits every stream.
//!
//! It fails closed. It opens no new stream while it cannot read its store
//! (a revocation might be in it), cannot write its audit log, or cannot read
//! its own network addresses (its LAN would not be denied); and it refuses to
//! start at all without its network addresses unless the owner says so.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;

use crate::audit::{Audit, AuditConfig, AuditRow};
use crate::error::{LinkError, Result};
use crate::gate::{Gate, GateConfig, Pass};
use crate::identity::{Fingerprint, Identity};
use crate::mux::{self, LinkIo, Mode};
use crate::netif::{self, InterfaceSource, SystemInterfaces};
use crate::pairing::{self, PairingCode};
use crate::resolve::{self, Resolver, SystemResolver};
use crate::rules::{self, Bucket, Cidr, Limits, Rules};
use crate::store::{self, DeviceRecord, FileStamp, HubFile, HubStore, PendingCode};
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
    /// Dialling out: TCP connect plus TLS handshake.
    pub handshake_timeout: Duration,
    /// An accepted connection must finish its TLS handshake within this, so
    /// a silent socket frees its slot in seconds.
    pub accept_timeout: Duration,
    /// Admission of accepted connections before they authenticate.
    pub gate: GateConfig,
    /// An unknown key (while a code is outstanding) must open its stream and
    /// send its pairing request within this.
    pub pair_timeout: Duration,
    /// Pairing sessions at once (each source at most one).
    pub pair_slots: usize,
    /// How long a new stream of a paired device may take to send its request.
    pub request_timeout: Duration,
    /// How long the hub waits for a target to accept.
    pub connect_timeout: Duration,
    /// A relay with no byte either way for this long is closed (and its
    /// concurrency slot freed).
    pub idle_timeout: Duration,
    /// A link with no keep-alive ping for this long is dropped.
    pub dead_after: Duration,
    /// How often the store file is checked for changes made by the CLI.
    pub reload_every: Duration,
    /// The store is re-read at least this often, changed or not.
    pub reload_force_every: Duration,
    pub resolver: Arc<dyn Resolver>,
    /// Where the hub reads its own interface addresses (the OS by default).
    pub interfaces: Arc<dyn InterfaceSource>,
    /// How often the interface list is read again.
    pub lan_refresh_every: Duration,
    /// Run even when the interface list cannot be read. The hub's LAN is
    /// then denied only by the default address classes and the owner's
    /// manual blocks. Off by default: the hub refuses to start.
    pub allow_undetected_lan: bool,
    pub audit: AuditConfig,
    /// How often coalesced audit counts are written out.
    pub audit_flush_every: Duration,
}

impl HubConfig {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        HubConfig {
            dir: dir.into(),
            handshake_timeout: Duration::from_secs(10),
            accept_timeout: Duration::from_secs(3),
            gate: GateConfig::hub(),
            pair_timeout: Duration::from_secs(3),
            pair_slots: 4,
            request_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            dead_after: Duration::from_secs(45),
            reload_every: Duration::from_secs(1),
            reload_force_every: Duration::from_secs(30),
            resolver: Arc::new(SystemResolver),
            interfaces: Arc::new(SystemInterfaces),
            lan_refresh_every: Duration::from_secs(10),
            allow_undetected_lan: false,
            audit: AuditConfig::default(),
            audit_flush_every: Duration::from_secs(60),
        }
    }
}

/// The clock the limiters run on (tokio's, so tests can pause it).
fn tnow() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

/// Live state of one device: one cancel token for all its links (revoking
/// fires it), its links (at most `MAX_LINKS_PER_DEVICE`), and its limiters,
/// shared by all its links.
struct Live {
    cancel: CancellationToken,
    state: Mutex<LiveState>,
    links: Mutex<VecDeque<LinkEntry>>,
}

struct LinkEntry {
    id: u64,
    cancel: CancellationToken,
    /// Why the hub closed this link itself, if it did (`ENDED_*`).
    ended: Arc<AtomicU8>,
}

const ENDED_REPLACED: u8 = 1;
const ENDED_RESIZED: u8 = 2;

struct LiveState {
    limits: Limits,
    /// Streams holding a concurrency slot (taken when the stream arrives,
    /// before its request is read).
    open: u32,
    opens: Bucket,
    /// Shared by all the device's relays; a rate of 0 is unlimited.
    bytes: Arc<Mutex<Bucket>>,
}

fn byte_rate(l: &Limits) -> (f64, f64) {
    let b = l.bytes_per_sec as f64;
    (b, b)
}

impl LiveState {
    fn new(l: Limits) -> Self {
        let now = tnow();
        let opm = l.opens_per_minute as f64;
        let (cap, rate) = byte_rate(&l);
        LiveState { limits: l, open: 0, opens: Bucket::new_at(opm, opm / 60.0, now), bytes: Arc::new(Mutex::new(Bucket::new_at(cap, rate, now))) }
    }
}

/// One concurrency slot of a device; freed when dropped.
struct StreamPermit {
    live: Arc<Live>,
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        let mut st = self.live.state.lock().unwrap_or_else(|e| e.into_inner());
        st.open = st.open.saturating_sub(1);
    }
}

impl Live {
    /// Takes a concurrency slot and a new-stream token, or says why not.
    fn admit(self: &Arc<Self>) -> std::result::Result<StreamPermit, (Status, String)> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.open >= st.limits.max_concurrent {
            return Err((Status::Busy, format!("{} connections already open", st.limits.max_concurrent)));
        }
        if !st.opens.take(1.0, tnow()) {
            return Err((Status::RateLimited, "too many new connections per minute".to_string()));
        }
        st.open += 1;
        Ok(StreamPermit { live: self.clone() })
    }

    /// A stream that turned out to be the link's control stream does not
    /// count as a new connection.
    fn refund_open(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).opens.refund(1.0);
    }

    /// New limits apply at once without resetting anything: streams already
    /// open keep counting against the new concurrency limit, and the buckets
    /// keep their level (cut to the new capacity).
    ///
    /// A link's stream count and windows are fixed when it comes up (they
    /// bound the hub's memory by the limit, see `mux`). A LOWER limit leaves
    /// the links alone (the old, larger bound holds until the next link); a
    /// HIGHER one closes them so the device comes straight back on links
    /// sized for it (its open streams end; the device reconnects at once).
    fn set_limits(&self, l: Limits) {
        let grown = {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if st.limits == l {
                return;
            }
            let now = tnow();
            let opm = l.opens_per_minute as f64;
            st.opens.set_rate(opm, opm / 60.0, now);
            let (cap, rate) = byte_rate(&l);
            st.bytes.lock().unwrap_or_else(|e| e.into_inner()).set_rate(cap, rate, now);
            let grown = mux::hub_streams(l.max_concurrent) > mux::hub_streams(st.limits.max_concurrent);
            st.limits = l;
            grown
        };
        if grown {
            for link in self.links.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
                link.ended.store(ENDED_RESIZED, Ordering::SeqCst);
                link.cancel.cancel();
            }
        }
    }

    fn limits(&self) -> Limits {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).limits
    }

    fn bytes(&self) -> Arc<Mutex<Bucket>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).bytes.clone()
    }

    /// Registers a link; the oldest beyond the cap is closed (newest wins).
    fn add_link(&self, id: u64, cancel: CancellationToken) -> Arc<AtomicU8> {
        let ended = Arc::new(AtomicU8::new(0));
        let mut links = self.links.lock().unwrap_or_else(|e| e.into_inner());
        links.push_back(LinkEntry { id, cancel, ended: ended.clone() });
        while links.len() > mux::MAX_LINKS_PER_DEVICE {
            let old = links.pop_front().expect("non-empty");
            old.ended.store(ENDED_REPLACED, Ordering::SeqCst);
            old.cancel.cancel();
        }
        ended
    }

    fn remove_link(&self, id: u64) {
        self.links.lock().unwrap_or_else(|e| e.into_inner()).retain(|l| l.id != id);
    }
}

#[derive(Debug)]
struct HubPolicy {
    snap: Arc<RwLock<HubFile>>,
    store_ok: Arc<AtomicBool>,
}

impl PeerPolicy for HubPolicy {
    fn accepts(&self, peer: &Fingerprint) -> bool {
        // An unreadable store might hold a revocation: accept nobody.
        if !self.store_ok.load(Ordering::SeqCst) {
            return false;
        }
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
    stamp: Mutex<Option<FileStamp>>,
    store_ok: Arc<AtomicBool>,
    /// Blocks detected from the hub's interfaces.
    lan: RwLock<Vec<Cidr>>,
    lan_ok: AtomicBool,
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
    live: Mutex<HashMap<Fingerprint, Arc<Live>>>,
    audit: Audit,
    shutdown: CancellationToken,
    /// Admission before authentication.
    gate: Arc<Gate>,
    /// Pairing sessions: `pair_slots` at once, one per source.
    pair_gate: Arc<Gate>,
    run_id: String,
    seq: AtomicU64,
}

#[derive(Clone)]
pub struct Hub {
    inner: Arc<Inner>,
}

/// Reads this machine's network blocks (what `sieve-hub lan` shows).
pub fn detected_lan_blocks() -> std::io::Result<Vec<Cidr>> {
    Ok(netif::blocks(&netif::detect(&SystemInterfaces)?))
}

impl Hub {
    /// Creates a hub directory (owner-only): a new key and an empty `hub.json`.
    pub fn init(dir: impl Into<PathBuf>, name: &str) -> Result<Fingerprint> {
        let dir = dir.into();
        crate::perms::create_private_dir(&dir)?;
        crate::perms::secure(&dir)?;
        let st = HubStore::new(&dir);
        st.create(name)?;
        let id = Identity::load_or_create(&dir.join(store::IDENTITY_FILE))?;
        crate::perms::check(&dir).map_err(LinkError::Store)?;
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
        let label = store::clean_name(label);
        HubStore::new(&dir).update(|f| {
            f.purge_expired(now_secs());
            f.pending.push(PendingCode { secret, expires_at: code.expires_at, label });
            Ok(())
        })?;
        Ok(code)
    }

    /// Opens an initialized hub directory. Nothing listens or dials yet.
    /// Refuses a directory others can read or write, and (unless
    /// `allow_undetected_lan`) a machine whose interfaces cannot be read.
    pub fn open(cfg: HubConfig) -> Result<Hub> {
        crate::perms::check(&cfg.dir).map_err(LinkError::Store)?;
        let lan = match netif::detect(cfg.interfaces.as_ref()) {
            Ok(net) => netif::blocks(&net),
            Err(e) if cfg.allow_undetected_lan => {
                eprintln!("sieve-hub: WARNING: cannot read this machine's network addresses ({e}); running anyway as asked. Only the default private classes and `sieve-hub lan add` blocks protect the local network.");
                Vec::new()
            }
            Err(e) => {
                return Err(LinkError::Store(format!(
                    "cannot read this machine's network addresses ({e}), so its local network cannot be denied to devices; \
                     the hub will not run without them (the owner can override with --allow-undetected-lan)"
                )));
            }
        };
        let store = HubStore::new(&cfg.dir);
        let identity = Identity::load(&cfg.dir.join(store::IDENTITY_FILE))?;
        let stamp = store::stamp(&store.file_path()).ok();
        let file = store.load()?;
        let snap = Arc::new(RwLock::new(file));
        let store_ok = Arc::new(AtomicBool::new(true));
        let policy: Arc<dyn PeerPolicy> = Arc::new(HubPolicy { snap: snap.clone(), store_ok: store_ok.clone() });
        let server_cfg = tls::server_config(&identity, policy.clone())?;
        let client_cfg = tls::client_config(&identity, policy)?;
        let audit = Audit::open_with(&cfg.dir.join(store::AUDIT_FILE), cfg.audit)?;
        let mut rid = [0u8; 4];
        let _ = aws_lc_rs::rand::fill(&mut rid);
        let pair_slots = cfg.pair_slots.max(1);
        let inner = Arc::new(Inner {
            fp: identity.fingerprint(),
            store,
            snap,
            stamp: Mutex::new(stamp),
            store_ok,
            lan: RwLock::new(lan),
            lan_ok: AtomicBool::new(true),
            server_cfg,
            client_cfg,
            live: Mutex::new(HashMap::new()),
            audit,
            shutdown: CancellationToken::new(),
            gate: Gate::new(cfg.gate),
            pair_gate: Gate::new(GateConfig { slots: pair_slots, per_source: 1, queue: pair_slots * 4, wait: Duration::ZERO }),
            run_id: rid.iter().map(|b| format!("{b:02x}")).collect(),
            seq: AtomicU64::new(0),
            cfg,
        });
        let hub = Hub { inner };
        hub.spawn_housekeeping();
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

    /// Every block denied as the hub's LAN: detected and manual.
    pub fn lan_blocks(&self) -> Vec<Cidr> {
        self.inner.lan_blocks()
    }

    pub fn create_pairing_code(&self, ttl_secs: u64, addr: Option<String>, label: &str) -> Result<PairingCode> {
        let c = Self::create_pairing_code_at(&self.inner.cfg.dir, ttl_secs, addr, label)?;
        self.reload()?;
        Ok(c)
    }

    /// Revokes a device (fingerprint prefix or name) and cuts its links and
    /// streams at once. Blocks briefly on the store lock.
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
        limits.validate()?;
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

    /// Writes pending coalesced audit counts now.
    pub fn flush_audit(&self) {
        self.inner.audit.flush();
    }

    /// Test hook: makes every audit write fail (or work again).
    #[doc(hidden)]
    pub fn fail_audit_writes(&self, on: bool) {
        self.inner.audit.set_fault(on);
    }

    fn spawn_housekeeping(&self) {
        let stop = self.inner.shutdown.clone();
        let cfg = &self.inner.cfg;
        every(Arc::downgrade(&self.inner), stop.clone(), cfg.reload_every, {
            let mut last_forced = tokio::time::Instant::now();
            move |inner: Arc<Inner>| {
                let st = store::stamp(&inner.store.file_path()).ok();
                let force = last_forced.elapsed() >= inner.cfg.reload_force_every;
                let changed = st != *inner.stamp.lock().unwrap_or_else(|e| e.into_inner()) || !inner.store_ok.load(Ordering::SeqCst);
                if force {
                    last_forced = tokio::time::Instant::now();
                }
                if (changed || force)
                    && let Err(e) = inner.reload()
                {
                    eprintln!("sieve-hub: reload failed: {e}");
                }
            }
        });
        every(Arc::downgrade(&self.inner), stop.clone(), cfg.audit_flush_every, |inner: Arc<Inner>| inner.audit.flush());
        let weak = Arc::downgrade(&self.inner);
        let period = cfg.lan_refresh_every;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop.cancelled() => return,
                    _ = tokio::time::sleep(period) => {}
                }
                let Some(inner) = weak.upgrade() else { return };
                let src = inner.cfg.interfaces.clone();
                let r = tokio::task::spawn_blocking(move || netif::detect(src.as_ref())).await;
                inner.apply_lan(r.map_err(std::io::Error::other).and_then(|r| r));
            }
        });
    }
}

/// Runs `f` every `period` until `stop` fires or the hub is gone.
fn every<F>(weak: Weak<Inner>, stop: CancellationToken, period: Duration, mut f: F)
where
    F: FnMut(Arc<Inner>) + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop.cancelled() => return,
                _ = tokio::time::sleep(period) => {}
            }
            let Some(inner) = weak.upgrade() else { return };
            f(inner);
        }
    });
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

    fn lan_blocks(&self) -> Vec<Cidr> {
        let mut v = self.lan.read().unwrap_or_else(|e| e.into_inner()).clone();
        v.extend(self.read().lan_cidrs.iter().copied());
        v
    }

    fn apply_lan(&self, r: std::io::Result<netif::HostNet>) {
        match r {
            Ok(net) => {
                *self.lan.write().unwrap_or_else(|e| e.into_inner()) = netif::blocks(&net);
                if !self.lan_ok.swap(true, Ordering::SeqCst) {
                    eprintln!("sieve-hub: this machine's network addresses can be read again; new streams are allowed");
                    self.audit.record(AuditRow { event: "lan_resumed", outcome: "network addresses read again".into(), ..Default::default() });
                }
            }
            // The last blocks stay in force either way.
            Err(_) if self.cfg.allow_undetected_lan => {}
            Err(e) => {
                if self.lan_ok.swap(false, Ordering::SeqCst) {
                    eprintln!("sieve-hub: cannot read this machine's network addresses ({e}); no new streams until it can");
                    self.audit.record(AuditRow { event: "lan_unreadable", outcome: e.to_string(), ..Default::default() });
                }
            }
        }
    }

    /// Why the hub opens no new stream right now, if it does not.
    fn unavailable(&self) -> Option<&'static str> {
        if !self.store_ok.load(Ordering::SeqCst) {
            return Some("the hub cannot read its store; it opens no new connections until it can");
        }
        if !self.lan_ok.load(Ordering::SeqCst) {
            return Some("the hub cannot read its own network addresses; it opens no new connections until it can");
        }
        if !self.audit.check() {
            return Some("the hub cannot write its audit log; nothing is relayed without a record");
        }
        None
    }

    fn reload(&self) -> Result<()> {
        let stamp = store::stamp(&self.store.file_path()).ok();
        let file = match self.store.load() {
            Ok(f) => f,
            Err(e) => {
                *self.stamp.lock().unwrap_or_else(|p| p.into_inner()) = stamp;
                if self.store_ok.swap(false, Ordering::SeqCst) {
                    eprintln!("sieve-hub: cannot read the store ({e}); no new links or streams until it can be read");
                    self.audit.record(AuditRow { event: "store_unreadable", outcome: e.to_string(), ..Default::default() });
                }
                return Err(e);
            }
        };
        *self.snap.write().unwrap_or_else(|e| e.into_inner()) = file.clone();
        *self.stamp.lock().unwrap_or_else(|e| e.into_inner()) = stamp;
        if !self.store_ok.swap(true, Ordering::SeqCst) {
            eprintln!("sieve-hub: the store can be read again");
            self.audit.record(AuditRow { event: "store_resumed", outcome: "the store can be read again".into(), ..Default::default() });
        }
        let mut cut = Vec::new();
        {
            let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            live.retain(|fp, l| match file.device(fp) {
                Some(d) if d.active() => {
                    l.set_limits(d.limits.clamped());
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
        let mut m = self.live.lock().unwrap_or_else(|e| e.into_inner());
        m.entry(rec.fingerprint)
            .or_insert_with(|| {
                Arc::new(Live {
                    cancel: self.shutdown.child_token(),
                    state: Mutex::new(LiveState::new(rec.limits.clamped())),
                    links: Mutex::new(VecDeque::new()),
                })
            })
            .clone()
    }

    fn next_id(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed) + 1
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
        // Too many from this source, or too many waiting: closed at once.
        let Some(ticket) = inner.gate.admit(peer.ip()) else {
            drop(tcp);
            inner.audit.refusal("handshake_refused", peer.ip(), "too many connections from this source, or too many waiting".into());
            continue;
        };
        let inner = inner.clone();
        tokio::spawn(async move {
            let Some(pass) = ticket.enter().await else {
                inner.audit.refusal("handshake_refused", peer.ip(), "no handshake slot came free in time".into());
                return;
            };
            match tls::accept(tcp, inner.server_cfg.clone(), inner.cfg.accept_timeout).await {
                Ok(est) => serve_conn(inner, est, Some(pass)).await,
                Err(e) => inner.audit.refusal("handshake_refused", peer.ip(), e.to_string()),
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
                serve_conn(inner.clone(), est, None).await;
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

/// Serves one authenticated connection, whoever dialled it. A paired device
/// gives its handshake slot back at once; an unknown key keeps it for its
/// whole (short) pairing session, so unauthenticated work stays bounded.
async fn serve_conn(inner: Arc<Inner>, est: Established, pass: Option<Pass>) {
    let rec = inner.read().device(&est.peer).cloned();
    match rec {
        Some(r) if r.active() => {
            drop(pass);
            serve_device(inner, est, r).await
        }
        Some(r) => inner.audit.refusal("refused", est.remote.ip(), format!("revoked device {}", r.fingerprint.short())),
        None => serve_pairing(inner, est, pass).await,
    }
}

async fn serve_device(inner: Arc<Inner>, est: Established, rec: DeviceRecord) {
    let live = inner.live_for(&rec);
    // Re-check after registering, so a revoke racing this link still cuts it.
    if !inner.read().device(&rec.fingerprint).is_some_and(|d| d.active()) || live.cancel.is_cancelled() {
        return;
    }
    let conn_cancel = live.cancel.child_token();
    let link_id = inner.next_id();
    let ended = live.add_link(link_id, conn_cancel.clone());
    let last_ping = Arc::new(AtomicU64::new(now_ms()));
    let control_taken = Arc::new(AtomicBool::new(false));
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
        let control_taken = control_taken.clone();
        move |s: yamux::Stream| {
            // The slot is taken as the stream arrives, before anything is
            // read from it, so streams that never send a request count too.
            let admitted = live.admit();
            let link = LinkCtx { cancel: cancel.clone(), last_ping: last_ping.clone(), control_taken: control_taken.clone() };
            tokio::spawn(handle_stream(inner.clone(), live.clone(), dev.clone(), s.compat(), link, admitted));
        }
    };
    let cfg = mux::hub_config(live.limits().max_concurrent);
    let (_handle, task) = mux::spawn_with(est.io.compat(), Mode::Server, cfg, handler, conn_cancel.clone());
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
    live.remove_link(link_id);
    let outcome = if live.cancel.is_cancelled() {
        "cut off"
    } else {
        match ended.load(Ordering::SeqCst) {
            ENDED_REPLACED => "replaced by a newer link of the same device",
            ENDED_RESIZED => "closed so the device relinks with room for its raised limit",
            _ => "closed",
        }
    };
    inner.audit.record(AuditRow {
        event: "link_down",
        device: Some(dev.fp.short()),
        name: Some(dev.name.clone()),
        peer: Some(peer.to_string()),
        outcome: outcome.into(),
        ..Default::default()
    });
}

struct DeviceCtx {
    fp: Fingerprint,
    name: String,
    peer: SocketAddr,
}

struct LinkCtx {
    cancel: CancellationToken,
    last_ping: Arc<AtomicU64>,
    control_taken: Arc<AtomicBool>,
}

async fn respond(io: &mut LinkIo, status: Status, message: &str) {
    let msg = Message::Response { status, message: message.to_string() };
    let _ = tokio::time::timeout(Duration::from_secs(2), write_msg(io, &msg)).await;
}

fn dev_row(dev: &DeviceCtx, event: &'static str, outcome: String) -> AuditRow {
    AuditRow { event, device: Some(dev.fp.short()), name: Some(dev.name.clone()), peer: Some(dev.peer.to_string()), outcome, ..Default::default() }
}

async fn handle_stream(
    inner: Arc<Inner>,
    live: Arc<Live>,
    dev: Arc<DeviceCtx>,
    mut io: LinkIo,
    link: LinkCtx,
    admitted: std::result::Result<StreamPermit, (Status, String)>,
) {
    let permit = match admitted {
        Ok(p) => p,
        Err((status, why)) => {
            respond(&mut io, status, &why).await;
            inner.audit.denial(dev_row(&dev, "denied", why));
            return;
        }
    };
    let first = tokio::select! {
        _ = link.cancel.cancelled() => return,
        r = tokio::time::timeout(inner.cfg.request_timeout, read_msg(&mut io)) => r,
    };
    let msg = match first {
        Ok(Ok(m)) => m,
        Ok(Err(WireError::Io(_))) | Err(_) => return,
        Ok(Err(e)) => {
            respond(&mut io, Status::BadRequest, &e.to_string()).await;
            inner.audit.denial(dev_row(&dev, "bad_request", e.to_string()));
            return;
        }
    };
    match msg {
        Message::Control => {
            if link.control_taken.swap(true, Ordering::SeqCst) {
                respond(&mut io, Status::BadRequest, "one control stream per link").await;
                inner.audit.denial(dev_row(&dev, "bad_request", "a second control stream".into()));
                return;
            }
            // The control stream is not a connection: it frees its slot and
            // its new-stream token.
            live.refund_open();
            drop(permit);
            control_loop(&inner, io, link.cancel, link.last_ping).await
        }
        Message::Connect { host, port } => connect(&inner, &live, &dev, io, host, port, link.cancel, permit).await,
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

#[allow(clippy::too_many_arguments)]
async fn connect(inner: &Inner, live: &Live, dev: &DeviceCtx, mut io: LinkIo, host: String, port: u16, cancel: CancellationToken, _permit: StreamPermit) {
    let started = tokio::time::Instant::now();
    let sid = format!("{}-{}", inner.run_id, inner.next_id());
    let target = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let row = |event: &'static str, outcome: String, addr: Option<SocketAddr>| AuditRow {
        sid: Some(sid.clone()),
        target: Some(target.clone()),
        addr: addr.map(|a| a.to_string()),
        ..dev_row(dev, event, outcome)
    };

    if let Some(why) = inner.unavailable() {
        respond(&mut io, Status::Unavailable, why).await;
        inner.audit.denial(row("refused", why.into(), None));
        return;
    }
    let current = {
        let s = inner.read();
        s.device(&dev.fp).filter(|d| d.active()).map(|d| d.rules.clone())
    };
    let Some(rules) = current else {
        respond(&mut io, Status::Denied, "revoked").await;
        inner.audit.denial(row("denied", "revoked".into(), None));
        return;
    };
    if let Err(why) = rules::check_port(&rules, port).and_then(|_| rules::check_host(&rules, &host)) {
        respond(&mut io, Status::Denied, &why).await;
        inner.audit.denial(row("denied", why, None));
        return;
    }
    let addrs = match tokio::time::timeout(inner.cfg.connect_timeout, resolve::resolve(inner.cfg.resolver.as_ref(), &host, port)).await {
        Ok(Ok(a)) if !a.is_empty() => a,
        _ => {
            respond(&mut io, Status::Unreachable, "cannot resolve the name at the hub").await;
            inner.audit.denial(row("unreachable", "resolve failed".into(), None));
            return;
        }
    };
    let lan = inner.lan_blocks();
    let mut first_denial: Option<(String, SocketAddr)> = None;
    let allowed: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|a| match rules::check_addr(&rules, &lan, a.ip()) {
            Ok(()) => true,
            Err(why) => {
                first_denial.get_or_insert((why, *a));
                false
            }
        })
        .collect();
    if allowed.is_empty() {
        // The device learns the class; the address goes to the audit log.
        let (why, addr) = first_denial.map(|(w, a)| (w, Some(a))).unwrap_or_else(|| ("no address".into(), None));
        respond(&mut io, Status::Denied, &why).await;
        inner.audit.denial(row("denied", why, addr));
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
        inner.audit.denial(row("unreachable", "connect failed".into(), None));
        return;
    };
    // Keep-alive finds a target that vanished without closing.
    tls::tune(&tcp);
    // On record before a byte is relayed; the closing row repeats the sid.
    if !inner.audit.record(row("stream_open", "connected".into(), Some(addr))) {
        drop(tcp);
        respond(&mut io, Status::Unavailable, "the hub cannot write its audit log; nothing is relayed without a record").await;
        return;
    }
    if write_msg(&mut io, &Message::Response { status: Status::Ok, message: String::new() }).await.is_err() {
        inner.audit.record(AuditRow { up: Some(0), down: Some(0), ..row("stream", "the device left before the answer".into(), Some(addr)) });
        return;
    }
    let (up, down, how) = relay(io, tcp, &cancel, Some(live.bytes()), inner.cfg.idle_timeout).await;
    let mut r = row("stream", how.to_string(), Some(addr));
    r.up = Some(up);
    r.down = Some(down);
    r.ms = Some(started.elapsed().as_millis() as u64);
    inner.audit.record(r);
}

/// Copies both ways until both sides finish, `cancel` fires, or nothing
/// moves either way for `idle`. Fixed 16 KiB buffers; an optional byte
/// bucket shared by all the device's streams.
pub(crate) async fn relay<A, B>(a: A, b: B, cancel: &CancellationToken, bucket: Option<Arc<Mutex<Bucket>>>, idle: Duration) -> (u64, u64, &'static str)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let start = tokio::time::Instant::now();
    let last = AtomicU64::new(0);
    let up = AtomicU64::new(0);
    let down = AtomicU64::new(0);
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let both = async {
        tokio::join!(pump(&mut ar, &mut bw, &up, bucket.clone(), start, &last), pump(&mut br, &mut aw, &down, bucket.clone(), start, &last));
    };
    let idle_watch = async {
        loop {
            let deadline = start + Duration::from_millis(last.load(Ordering::Relaxed)) + idle;
            if tokio::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    };
    let how = tokio::select! {
        _ = both => "closed",
        _ = cancel.cancelled() => "cut off",
        _ = idle_watch => "idle",
    };
    (up.load(Ordering::Relaxed), down.load(Ordering::Relaxed), how)
}

async fn pump<R, W>(r: &mut R, w: &mut W, count: &AtomicU64, bucket: Option<Arc<Mutex<Bucket>>>, start: tokio::time::Instant, last: &AtomicU64)
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
        last.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
        if let Some(b) = &bucket {
            let wait = b.lock().unwrap_or_else(|e| e.into_inner()).debit(n as f64, tnow());
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
        }
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        count.fetch_add(n as u64, Ordering::Relaxed);
        last.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    let _ = w.shutdown().await;
}

async fn serve_pairing(inner: Arc<Inner>, est: Established, _pass: Option<Pass>) {
    let peer = est.peer;
    let remote = est.remote;
    let refuse = |why: &str| inner.audit.refusal("pair_refused", remote.ip(), format!("key {}: {why}", peer.short()));
    if !inner.read().has_pending(now_secs()) {
        refuse("no pairing code outstanding");
        return;
    }
    // One pairing per source and `pair_slots` in all; the rest are told the
    // hub is busy (after the same short wait for their request).
    let slot = match inner.pair_gate.admit(remote.ip()) {
        Some(t) => t.enter().await,
        None => None,
    };
    let exporter = est.exporter;
    let cancel = inner.shutdown.child_token();
    let (tx, rx) = oneshot::channel();
    let mut tx = Some(tx);
    // An unknown key gets the smallest session: a few streams, small windows.
    let (_handle, task) = mux::spawn_with(
        est.io.compat(),
        Mode::Server,
        mux::hub_config(1),
        move |s| {
            if let Some(t) = tx.take() {
                let _ = t.send(s);
            }
        },
        cancel.clone(),
    );

    let outcome: std::result::Result<String, String> = async {
        let deadline = tokio::time::Instant::now() + inner.cfg.pair_timeout;
        let s = tokio::time::timeout_at(deadline, rx).await.map_err(|_| "no request in time".to_string())?.map_err(|_| "closed".to_string())?;
        let mut io = s.compat();
        let msg = tokio::time::timeout_at(deadline, read_msg(&mut io)).await.map_err(|_| "no request in time".to_string())?.map_err(|e| e.to_string())?;
        let Message::Pair { proof, name } = msg else {
            respond(&mut io, Status::BadRequest, "not paired; expected a pairing request").await;
            return Err("unpaired key sent something other than a pairing request".into());
        };
        if slot.is_none() {
            respond(&mut io, Status::Busy, "the hub is busy with other pairings; try again in a few seconds").await;
            return Err("busy: too many pairings at once, or one already from this source".into());
        }
        let hub = inner.fp;
        let store = inner.store.clone();
        let wanted = store::clean_name(&name);
        // The store lock blocks: off the runtime threads.
        let matched = tokio::task::spawn_blocking(move || {
            store.update(|f| {
                f.purge_expired(now_secs());
                if f.device(&peer).is_some() {
                    return Ok(None);
                }
                let idx = f.pending.iter().position(|p| p.secret_bytes().is_some_and(|s| pairing::verify_proof(&s, &exporter, &peer, &hub, &proof)));
                let Some(i) = idx else { return Ok(None) };
                f.pending.remove(i);
                let name = f.unique_name(&wanted);
                let d = f.defaults.clone();
                f.devices.push(DeviceRecord { fingerprint: peer, name: name.clone(), paired_at: now_secs(), revoked_at: None, rules: d.rules, limits: d.limits });
                Ok(Some(name))
            })
        })
        .await
        .unwrap_or_else(|e| Err(LinkError::Store(e.to_string())));
        match matched {
            Ok(Some(name)) => {
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
            Ok(None) => {
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
        Ok(name) => {
            inner.audit.record(AuditRow {
                event: "paired",
                device: Some(peer.short()),
                name: Some(name),
                peer: Some(remote.to_string()),
                outcome: "ok".into(),
                ..Default::default()
            });
        }
        Err(why) => refuse(&why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The byte limit on paused time: exact, not wall-clock luck.
    #[tokio::test(start_paused = true)]
    async fn byte_rate_limit_paces_the_relay_exactly() {
        let (dev_side, mut dev) = tokio::io::duplex(64 * 1024);
        let (tgt_side, mut tgt) = tokio::io::duplex(64 * 1024);
        // 100 KB/s, burst 100 KB.
        let bucket = Arc::new(Mutex::new(Bucket::new_at(100_000.0, 100_000.0, tnow())));
        let cancel = CancellationToken::new();
        let relay_task = tokio::spawn(async move { relay(dev_side, tgt_side, &cancel, Some(bucket), Duration::from_secs(3600)).await });
        let echo = tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = tgt.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                tgt.write_all(&buf[..n]).await.unwrap();
            }
            let _ = tgt.shutdown().await;
        });
        let start = tokio::time::Instant::now();
        let payload = vec![1u8; 300_000];
        let (mut dr, mut dw) = tokio::io::split(&mut dev);
        let writer = async {
            dw.write_all(&payload).await.unwrap();
            dw.shutdown().await.unwrap();
        };
        let reader = async {
            let mut got = Vec::new();
            dr.read_to_end(&mut got).await.unwrap();
            got.len()
        };
        let (_, n) = tokio::join!(writer, reader);
        let took = start.elapsed();
        assert_eq!(n, 300_000);
        // 600 KB both ways at 100 KB/s with a 100 KB burst: 5 s, give or
        // take one 16 KiB chunk.
        assert!(took >= Duration::from_millis(4800) && took <= Duration::from_millis(5300), "{took:?}");
        let (up, down, how) = relay_task.await.unwrap();
        assert_eq!((up, down, how), (300_000, 300_000, "closed"));
        echo.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_relay_is_closed() {
        let (dev_side, _dev) = tokio::io::duplex(1024);
        let (tgt_side, _tgt) = tokio::io::duplex(1024);
        let cancel = CancellationToken::new();
        let start = tokio::time::Instant::now();
        let (_, _, how) = relay(dev_side, tgt_side, &cancel, None, Duration::from_secs(300)).await;
        assert_eq!(how, "idle");
        let took = start.elapsed();
        assert!(took >= Duration::from_secs(300) && took < Duration::from_secs(301), "{took:?}");
    }

    #[test]
    fn a_limit_change_keeps_open_streams_counted() {
        let live = Arc::new(Live {
            cancel: CancellationToken::new(),
            state: Mutex::new(LiveState::new(Limits { max_concurrent: 4, opens_per_minute: 100, bytes_per_sec: 0 })),
            links: Mutex::new(VecDeque::new()),
        });
        let a = live.admit().unwrap();
        let b = live.admit().unwrap();
        let c = live.admit().unwrap();
        live.set_limits(Limits { max_concurrent: 2, opens_per_minute: 100, bytes_per_sec: 0 });
        assert_eq!(live.admit().err().unwrap().0, Status::Busy, "three open, limit two");
        drop(a);
        assert_eq!(live.admit().err().unwrap().0, Status::Busy, "two open, limit two");
        drop(b);
        let d = live.admit().expect("one open, limit two");
        drop((c, d));
        // The opens bucket is not refilled by a change: 4 taken of 100, a
        // new capacity of 3 leaves 3, not a fresh 100.
        live.set_limits(Limits { max_concurrent: 50, opens_per_minute: 3, bytes_per_sec: 0 });
        let held: Vec<_> = (0..3).map(|_| live.admit().unwrap()).collect();
        assert_eq!(live.admit().err().unwrap().0, Status::RateLimited);
        drop(held);
    }

    #[test]
    fn the_newest_link_wins() {
        let live = Live { cancel: CancellationToken::new(), state: Mutex::new(LiveState::new(Limits::default())), links: Mutex::new(VecDeque::new()) };
        let toks: Vec<CancellationToken> = (0..3).map(|_| CancellationToken::new()).collect();
        let flags: Vec<_> = toks.iter().enumerate().map(|(i, t)| live.add_link(i as u64, t.clone())).collect();
        assert!(toks[0].is_cancelled());
        assert_eq!(flags[0].load(Ordering::SeqCst), ENDED_REPLACED);
        assert!(!toks[1].is_cancelled() && !toks[2].is_cancelled());
        assert_eq!(live.links.lock().unwrap().len(), mux::MAX_LINKS_PER_DEVICE);
        live.remove_link(1);
        assert_eq!(live.links.lock().unwrap().len(), 1);
        // A lower limit leaves the link; a higher one relinks it.
        live.set_limits(Limits { max_concurrent: 8, ..Limits::default() });
        assert!(!toks[2].is_cancelled());
        live.set_limits(Limits { max_concurrent: 9, ..Limits::default() });
        assert!(toks[2].is_cancelled());
        assert_eq!(flags[2].load(Ordering::SeqCst), ENDED_RESIZED);
    }
}
