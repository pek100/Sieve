//! Exiting through another device (a Sieve link hub): the engine is a
//! `sieve_link` device. The owner pairs it with a hub from the app, then turns
//! "exit through the hub" on; from then on, while Sieve routes, every TCP
//! connection of a sieved app to a public address is opened through the hub
//! (`exit`), after Sieve has done everything it does locally first.
//!
//! - [`LinkManager`]: the pairing, the stored hub and key, the owner's choices,
//!   the running `LinkClient` (only while exiting is on and routes are up), and
//!   the status line;
//! - [`exit`]: how one flow or one resolver session goes out, and what the log
//!   says of it.
//!
//! What never goes through the link: the link's own socket (opened through
//! [`LinkNet`], which is `stack::egress` in production, pinned outside Sieve's
//! adapter), destinations that are not public or are on this computer's own
//! networks ([`LinkManager::plan`]), the engine's own connections (lists,
//! updates, the sign-in check: they use the egress directly), apps that are Off
//! and everything while the global switch is off (the relay checks those).
//!
//! Files, in `ProgramData\Sieve\engine\link` (SYSTEM and Administrators only,
//! as the whole engine folder; uninstall deletes it): `identity.key` (this
//! engine's key, PKCS#8) and `link.json` (the hub's fingerprint and name, the
//! choices). A pairing code is never written, logged or kept after use.

pub mod exit;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sieve_ipc::{LINK_ADDRESS_MAX, LINK_CODE_MAX, LINK_TEXT_MAX, LinkHubDown, LinkRoute, LinkSettings, LinkState, LinkStatus, LinkUdp, cap_text};
use sieve_link::device::{PairVia, pair};
use sieve_link::{Dialer, Fingerprint, HubRoute, Identity, LinkClient, LinkConfig, OnHubDown, PairingCode};
use tokio::net::TcpStream;

use crate::dns::BoxFuture;

pub const LINK_DIR: &str = "link";
pub const LINK_FILE: &str = "link.json";
pub const KEY_FILE: &str = "identity.key";
/// Dialling the hub to pair: the TCP connect, the handshake and the answer.
const PAIR_DIAL_LIMIT: Duration = Duration::from_secs(30);
/// Waiting for a hub that dials in to pair: until the code expires, at most this.
const PAIR_LISTEN_MAX: Duration = Duration::from_secs(15 * 60);

pub const NOT_A_CODE: &str = "That is not a pairing code. Copy the whole code the other device printed, from SL1- to its end.";
pub const CODE_EXPIRED: &str = "That pairing code has expired. Make a new one on the other device.";
pub const NO_ADDRESS: &str = "This code names no address to dial: give the other device's address, or let it dial this computer.";
pub const NOT_PAIRED: &str = "Sieve is not paired with another device.";
pub const PAIRING_RUNS: &str = "A pairing is already under way.";
pub const NO_FOLDER: &str = "The engine has no folder to keep the pairing in.";

/// The network as the link sees it. Production is `stack::egress::Egress`:
/// sockets pinned to the interface Windows would use without Sieve, so the
/// link's own connection never enters Sieve's adapter; tests use loopback.
pub trait LinkNet: Send + Sync + 'static {
    /// A TCP connection to `target` that leaves outside Sieve's adapter.
    fn connect(&self, target: SocketAddr) -> BoxFuture<'_, Result<TcpStream, String>>;
    /// The address a hub may dial in to: the adapter Windows uses for the
    /// internet. None when there is none.
    fn listen_ip(&self) -> Option<IpAddr>;
    /// `ip` is on one of this computer's own networks (an on-link prefix of an
    /// adapter other than Sieve's): it never goes through a hub.
    fn is_local(&self, ip: IpAddr) -> bool;
}

/// Where a network comes from while Sieve does not route (to pair).
pub type NetSource = Box<dyn Fn() -> Result<Arc<dyn LinkNet>, String> + Send + Sync>;

/// `link.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stored {
    version: u32,
    hub: Fingerprint,
    hub_name: String,
    settings: LinkSettings,
}

/// What exiting through the hub means for one destination, while it applies.
#[derive(Clone)]
pub struct Plan {
    /// The running link; None while it is being (re)started.
    pub client: Option<LinkClient>,
    pub on_hub_down: LinkHubDown,
    pub udp: LinkUdp,
}

struct Running {
    client: LinkClient,
    route: LinkRoute,
    /// The address actually listened on (listen mode).
    listening: Option<SocketAddr>,
    generation: u64,
    ever_up: bool,
    up: bool,
    watcher: tokio::task::AbortHandle,
}

#[derive(Default)]
struct State {
    stored: Option<Stored>,
    identity: Option<Arc<Identity>>,
    pairing: Option<tokio::task::AbortHandle>,
    /// While a pairing waits for the hub to dial in: where.
    pairing_listen: Option<SocketAddr>,
    /// While Sieve routes.
    net: Option<Arc<dyn LinkNet>>,
    dns_reset: Option<Arc<dyn Fn() + Send + Sync>>,
    running: Option<Running>,
    since_ms: u64,
    last_error: Option<String>,
}

pub struct LinkManager {
    dir: Option<PathBuf>,
    fallback_net: NetSource,
    /// The name this engine gives itself at pairing.
    name: String,
    state: Mutex<State>,
    generation: AtomicU64,
    clock: fn() -> u64,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// An error as the status shows it: one line, capped.
fn said(text: impl AsRef<str>) -> String {
    let one_line: String = text.as_ref().chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    cap_text(&one_line, LINK_TEXT_MAX).to_string()
}

/// A route the engine can use: a dial address is an IP address with a port (a
/// name would need DNS, which itself may go through the link), a listen port
/// is not 0.
pub fn check_route(route: &LinkRoute) -> Result<SocketAddr, String> {
    match route {
        LinkRoute::Dial { address } => {
            if address.len() > LINK_ADDRESS_MAX {
                return Err("That address is too long.".into());
            }
            address.trim().parse::<SocketAddr>().map_err(|_| {
                "Give the other device's address as an IP address with a port, like 203.0.113.20:7443 or [2001:db8::1]:7443 (names are not accepted yet).".to_string()
            })
        }
        LinkRoute::Listen { port } if *port == 0 => Err("Choose a port from 1 to 65535.".into()),
        LinkRoute::Listen { port } => Ok(SocketAddr::new(IpAddr::from([0, 0, 0, 0]), *port)),
    }
}

/// The name this computer gives itself at pairing (the hub lists it so).
fn computer_name() -> String {
    std::env::var("COMPUTERNAME").ok().map(|n| sieve_link::store::clean_name(&format!("sieve-{}", n.to_lowercase()))).unwrap_or_else(|| "sieve".into())
}

/// Polls a future once: Some when it finished without waiting. For
/// `LinkClient::start` with a dial route, which only spawns its task.
fn ready_now<F: std::future::Future>(f: F) -> Option<F::Output> {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match f.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => Some(v),
        std::task::Poll::Pending => None,
    }
}

impl LinkManager {
    /// Reads what `dir` holds (`dir` is the engine folder; the link's files are
    /// in its `link` folder). Nothing runs until routes come up.
    pub fn new(engine_dir: Option<&Path>, fallback_net: NetSource, clock: fn() -> u64) -> Self {
        let dir = engine_dir.map(|d| d.join(LINK_DIR));
        let mut state = State { since_ms: clock(), ..State::default() };
        if let Some(dir) = &dir {
            match load(dir) {
                Ok(Some((stored, identity))) => {
                    state.stored = Some(stored);
                    state.identity = Some(Arc::new(identity));
                }
                Ok(None) => {}
                Err(why) => state.last_error = Some(said(format!("the stored pairing could not be read, so Sieve is not paired: {why}"))),
            }
        }
        Self { dir, fallback_net, name: computer_name(), state: Mutex::new(state), generation: AtomicU64::new(0), clock }
    }

    /// The status line.
    pub fn status(&self) -> LinkStatus {
        let st = lock(&self.state);
        let state = match (&st.stored, &st.running) {
            (None, _) if st.pairing.is_some() => LinkState::Pairing,
            (None, _) => LinkState::Unpaired,
            (Some(s), _) if !s.settings.exit => LinkState::Off,
            (Some(_), Some(r)) if r.up => LinkState::Up,
            (Some(_), Some(r)) if r.ever_up => LinkState::Down,
            (Some(_), _) => LinkState::Connecting,
        };
        let client_error = st.running.as_ref().filter(|r| !r.up).and_then(|r| r.client.last_error());
        let listening = st.running.as_ref().and_then(|r| r.listening).or(st.pairing_listen).map(|a| a.to_string());
        LinkStatus {
            state,
            hub_name: st.stored.as_ref().map(|s| s.hub_name.clone()),
            hub_fingerprint: st.stored.as_ref().map(|s| s.hub.to_string()),
            device_fingerprint: st.identity.as_ref().map(|i| i.fingerprint().to_string()),
            settings: st.stored.as_ref().map(|s| s.settings.clone()),
            since_ms: Some(st.since_ms),
            last_error: client_error.map(said).or_else(|| st.last_error.clone()),
            listening,
        }
    }

    /// What exiting means for a connection to `dest` right now; None when it
    /// does not exit through the hub: exiting is off, Sieve does not route, or
    /// `dest` is not public (loopback, private, link-local, shared, unique-local,
    /// multicast, reserved, and their mapped forms: `sieve_link`'s own classes),
    /// on this computer's own networks, or the hub's own dial address.
    pub fn plan(&self, dest: IpAddr) -> Option<Plan> {
        let st = lock(&self.state);
        let stored = st.stored.as_ref().filter(|s| s.settings.exit)?;
        let net = st.net.as_ref()?;
        if sieve_link::rules::denied_class(dest).is_some() || net.is_local(dest) {
            return None;
        }
        if let LinkRoute::Dial { address } = &stored.settings.route
            && address.parse::<SocketAddr>().is_ok_and(|a| a.ip() == dest)
        {
            return None;
        }
        Some(Plan { client: st.running.as_ref().map(|r| r.client.clone()), on_hub_down: stored.settings.on_hub_down, udp: stored.settings.udp })
    }

    /// Sieve routes now: the link runs if exiting is on. `dns_reset` drops the
    /// resolver sessions, so they reopen by the path in force.
    pub fn routes_up(self: &Arc<Self>, net: Arc<dyn LinkNet>, dns_reset: Arc<dyn Fn() + Send + Sync>) {
        {
            let mut st = lock(&self.state);
            st.net = Some(net);
            st.dns_reset = Some(dns_reset);
        }
        self.sync();
    }

    /// Sieve stops routing: the link and its listening port close.
    pub fn routes_down(&self) {
        let mut st = lock(&self.state);
        st.net = None;
        st.dns_reset = None;
        if let Some(r) = st.running.take() {
            stop(r);
        }
    }

    /// The network changed: a listening link moves to the new address.
    pub fn network_changed(self: &Arc<Self>) {
        self.sync();
    }

    /// Redeems `code` (see `ClientMessage::LinkPair`). Returns at once; the
    /// pairing runs on. The code moves into that task and is wiped with it.
    pub fn pair(self: &Arc<Self>, code: &str, route: Option<LinkRoute>) -> Result<(), String> {
        if code.len() > LINK_CODE_MAX {
            return Err(NOT_A_CODE.into());
        }
        let code = PairingCode::decode(code.trim()).map_err(|_| NOT_A_CODE.to_string())?;
        if code.is_expired(wall_secs()) {
            return Err(CODE_EXPIRED.into());
        }
        let route = match route {
            Some(r) => r,
            None => LinkRoute::Dial { address: code.addr.clone().ok_or(NO_ADDRESS)? },
        };
        let target = check_route(&route)?;
        let dir = self.dir.clone().ok_or(NO_FOLDER)?;
        let net = {
            let st = lock(&self.state);
            if let Some(s) = &st.stored {
                return Err(format!("Sieve is already paired with {}. Unpair first.", s.hub_name));
            }
            if st.pairing.is_some() {
                return Err(PAIRING_RUNS.into());
            }
            st.net.clone()
        };
        let net = match net {
            Some(n) => n,
            None => (self.fallback_net)()?,
        };
        let listener = match &route {
            LinkRoute::Listen { port } => {
                let ip = net.listen_ip().ok_or("This computer has no network address the other device could dial.")?;
                Some(bind(SocketAddr::new(ip, *port)).map_err(|e| format!("Port {port} could not be opened: {e}"))?)
            }
            LinkRoute::Dial { .. } => None,
        };
        let weak = Arc::downgrade(self);
        let name = self.name.clone();
        let mut st = lock(&self.state);
        st.pairing_listen = listener.as_ref().and_then(|l| l.local_addr().ok());
        let task = tokio::spawn(async move {
            let outcome = redeem(&code, &name, &*net, target, listener).await;
            drop(code);
            if let Some(me) = weak.upgrade() {
                me.paired(&dir, route, outcome);
            }
        });
        st.pairing = Some(task.abort_handle());
        st.since_ms = (self.clock)();
        st.last_error = None;
        Ok(())
    }

    /// A pairing ended: kept on success, said on failure.
    fn paired(self: &Arc<Self>, dir: &Path, route: LinkRoute, outcome: Result<(Identity, Fingerprint, String), String>) {
        {
            let mut st = lock(&self.state);
            st.pairing = None;
            st.pairing_listen = None;
            st.since_ms = (self.clock)();
            match outcome.and_then(|(identity, hub, hub_name)| {
                let stored = Stored { version: 1, hub, hub_name, settings: LinkSettings { exit: false, on_hub_down: LinkHubDown::Stop, udp: LinkUdp::Drop, route } };
                save_new(dir, &stored, &identity)?;
                Ok((stored, identity))
            }) {
                Ok((stored, identity)) => {
                    st.stored = Some(stored);
                    st.identity = Some(Arc::new(identity));
                    st.last_error = None;
                }
                Err(why) => st.last_error = Some(said(format!("Pairing failed: {why}"))),
            }
        }
        self.sync();
    }

    /// Forgets the hub and this engine's key for it; any pairing stops.
    pub fn unpair(&self) -> Result<(), String> {
        let reset = {
            let mut st = lock(&self.state);
            if let Some(p) = st.pairing.take() {
                p.abort();
            }
            st.pairing_listen = None;
            if let Some(r) = st.running.take() {
                stop(r);
            }
            st.stored = None;
            st.identity = None;
            st.since_ms = (self.clock)();
            st.last_error = None;
            st.dns_reset.clone()
        };
        if let Some(reset) = reset {
            reset();
        }
        match &self.dir {
            Some(dir) => remove_files(dir),
            None => Ok(()),
        }
    }

    /// The owner's choices: kept, and in force at once.
    pub fn set(self: &Arc<Self>, settings: LinkSettings) -> Result<(), String> {
        check_route(&settings.route)?;
        {
            let mut st = lock(&self.state);
            let Some(stored) = st.stored.as_mut() else { return Err(NOT_PAIRED.into()) };
            let next = Stored { settings, ..stored.clone() };
            if let Some(dir) = &self.dir {
                write_stored(dir, &next)?;
            }
            if stored.settings.exit != next.settings.exit {
                st.since_ms = (self.clock)();
            }
            *st.stored.as_mut().expect("checked") = next;
            st.last_error = None;
        }
        self.sync();
        Ok(())
    }

    /// Starts, stops or restarts the link to match what is wanted.
    fn sync(self: &Arc<Self>) {
        let reset = {
            let mut st = lock(&self.state);
            let wanted = match (&st.stored, &st.identity, &st.net) {
                (Some(s), Some(id), Some(net)) if s.settings.exit => Some((s.clone(), id.clone(), net.clone())),
                _ => None,
            };
            let keep = match (&wanted, &st.running) {
                (Some((s, _, net)), Some(r)) => r.route == s.settings.route && listen_still_right(r, &**net),
                _ => false,
            };
            if keep {
                return;
            }
            let had = st.running.take();
            let changed = had.is_some() || wanted.is_some();
            if let Some(r) = had {
                stop(r);
            }
            if let Some((stored, identity, net)) = wanted {
                match self.start(&stored, &identity, net) {
                    Ok(r) => {
                        st.running = Some(r);
                        st.last_error = None;
                    }
                    Err(why) => st.last_error = Some(said(why)),
                }
                st.since_ms = (self.clock)();
            }
            changed.then(|| st.dns_reset.clone()).flatten()
        };
        if let Some(reset) = reset {
            reset();
        }
    }

    fn start(self: &Arc<Self>, stored: &Stored, identity: &Identity, net: Arc<dyn LinkNet>) -> Result<Running, String> {
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let (client, listening) = match &stored.settings.route {
            LinkRoute::Dial { address } => {
                let mut cfg = LinkConfig::new(stored.hub, HubRoute::Dial(address.clone()));
                cfg.on_hub_down = OnHubDown::Stop;
                cfg.dialer = Some(dialer(net));
                let client = ready_now(LinkClient::start(identity, cfg)).ok_or("the link did not start")?.map_err(|e| e.to_string())?;
                (client, None)
            }
            LinkRoute::Listen { port } => {
                let ip = net.listen_ip().ok_or("this computer has no network address the other device could dial")?;
                let listener = bind(SocketAddr::new(ip, *port)).map_err(|e| format!("port {port} on {ip} could not be opened: {e}"))?;
                let at = listener.local_addr().ok();
                let mut cfg = LinkConfig::new(stored.hub, HubRoute::Listen(SocketAddr::new(ip, *port)));
                cfg.on_hub_down = OnHubDown::Stop;
                (LinkClient::start_with_listener(identity, cfg, listener).map_err(|e| e.to_string())?, at)
            }
        };
        let weak = Arc::downgrade(self);
        let watched = client.clone();
        let watcher = tokio::spawn(watch(weak, watched, generation)).abort_handle();
        Ok(Running { client, route: stored.settings.route.clone(), listening, generation, ever_up: false, up: false, watcher })
    }

    /// The running link of `generation` went up or down.
    fn turned(&self, generation: u64, up: bool) {
        let reset = {
            let mut st = lock(&self.state);
            let Some(r) = st.running.as_mut().filter(|r| r.generation == generation) else { return };
            r.up = up;
            r.ever_up |= up;
            st.since_ms = (self.clock)();
            st.dns_reset.clone()
        };
        if let Some(reset) = reset {
            reset();
        }
    }
}

/// Follows one running link's ups and downs until it is stopped.
async fn watch(manager: Weak<LinkManager>, client: LinkClient, generation: u64) {
    let mut up = false;
    loop {
        if !client.wait_until(!up).await {
            return;
        }
        up = !up;
        match manager.upgrade() {
            Some(m) => m.turned(generation, up),
            None => return,
        }
    }
}

fn stop(r: Running) {
    r.watcher.abort();
    r.client.shutdown();
}

/// A listening link whose address is no longer the one to listen on restarts.
fn listen_still_right(r: &Running, net: &dyn LinkNet) -> bool {
    match (&r.route, r.listening) {
        (LinkRoute::Listen { .. }, Some(at)) => net.listen_ip() == Some(at.ip()),
        (LinkRoute::Listen { .. }, None) => false,
        _ => true,
    }
}

/// The link's own TCP connect: through `net`, never Sieve's adapter.
fn dialer(net: Arc<dyn LinkNet>) -> Dialer {
    Dialer(Arc::new(move |addr: String| {
        let net = net.clone();
        Box::pin(async move {
            let target: SocketAddr = addr.parse().map_err(|_| std::io::Error::other("the hub's address is not an IP address with a port"))?;
            net.connect(target).await.map_err(std::io::Error::other)
        })
    }))
}

/// A listener on exactly `at`, for the hub to dial in. Its address is that of
/// the adapter Windows uses for the internet, so an inbound connection and its
/// answers stay on that adapter (Windows' strong host model): never Sieve's.
fn bind(at: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let l = std::net::TcpListener::bind(at)?;
    l.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(l)
}

fn wall_secs() -> u64 {
    crate::policy::wall_ms() / 1000
}

/// Pairs a new key with the hub `code` names: its identity, the hub's
/// fingerprint and name.
async fn redeem(code: &PairingCode, name: &str, net: &dyn LinkNet, target: SocketAddr, listener: Option<tokio::net::TcpListener>) -> Result<(Identity, Fingerprint, String), String> {
    let identity = Identity::generate().map_err(|e| e.to_string())?;
    let hub_name = match listener {
        None => {
            let tcp = tokio::time::timeout(PAIR_DIAL_LIMIT, net.connect(target)).await.map_err(|_| format!("{target} did not answer in time"))??;
            pair(&identity, code, name, PairVia::Connected(tcp), PAIR_DIAL_LIMIT).await.map_err(|e| e.to_string())?
        }
        Some(l) => {
            let left = code.expires_at.saturating_sub(wall_secs());
            let wait = Duration::from_secs(left).min(PAIR_LISTEN_MAX) + PAIR_DIAL_LIMIT;
            tokio::time::timeout(wait, pair(&identity, code, name, PairVia::Listener(&l), PAIR_DIAL_LIMIT))
                .await
                .map_err(|_| "the other device did not dial in before the code expired".to_string())?
                .map_err(|e| e.to_string())?
        }
    };
    Ok((identity, code.hub, sieve_link::store::clean_name(&hub_name)))
}

fn load(dir: &Path) -> Result<Option<(Stored, Identity)>, String> {
    let file = dir.join(LINK_FILE);
    if !file.exists() {
        return Ok(None);
    }
    let stored: Stored = sieve_link::store::read_json(&file).map_err(|e| e.to_string())?;
    check_route(&stored.settings.route)?;
    let identity = Identity::load(&dir.join(KEY_FILE)).map_err(|e| e.to_string())?;
    Ok(Some((stored, identity)))
}

fn write_stored(dir: &Path, stored: &Stored) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    sieve_link::store::write_json_atomic(&dir.join(LINK_FILE), stored).map_err(|e| e.to_string())
}

/// The key first, then the record that names its hub: a record never points
/// at a key that is not there.
fn save_new(dir: &Path, stored: &Stored, identity: &Identity) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let key = dir.join(KEY_FILE);
    let _ = std::fs::remove_file(&key);
    identity.save_new(&key).map_err(|e| e.to_string())?;
    write_stored(dir, stored)
}

/// Unpairing: the record first (a key alone pairs with nothing), then the key.
fn remove_files(dir: &Path) -> Result<(), String> {
    for name in [LINK_FILE, KEY_FILE] {
        match std::fs::remove_file(dir.join(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{name} could not be deleted: {e}")),
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
