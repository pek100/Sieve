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
//! updates, the sign-in check: they use the egress directly) and apps that are
//! Off (the relay checks those). While the global switch is off there is no exit
//! at all: the link is stopped, its port closed, and DNS goes as without it.
//!
//! While exiting is on, a public destination is reached only through the link:
//! every direct connect the relay makes for a flow passes
//! [`LinkManager::may_leave_directly`] (`stack::relay`'s guarded connect), so an
//! address the app did not choose (a retry's alternate) cannot leave from this
//! computer's own address.
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
use sieve_ipc::{ExitVia, LINK_ADDRESS_MAX, LINK_CODE_MAX, LINK_TEXT_MAX, LinkHubDown, LinkRoute, LinkSettings, LinkState, LinkStatus, LinkUdp, cap_text};
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

/// The running link, shared with every [`Plan`]: a flow decided after a restart
/// opens on the new link, never on the one its SYN saw.
type ClientSlot = Arc<Mutex<Option<LinkClient>>>;

/// What exiting through the hub means for one destination, while it applies.
/// The hub-down choice is not in it: an open reads it when it needs it
/// ([`LinkManager::on_hub_down`]), as the owner may change it in between.
#[derive(Clone)]
pub struct Plan {
    current: ClientSlot,
    pub udp: LinkUdp,
}

impl Plan {
    /// The link running now; None while it is being (re)started or stopped.
    pub fn client(&self) -> Option<LinkClient> {
        lock(&self.current).clone()
    }
}

/// What changed about the way out, for [`ExitChanged`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// The way out itself changed (exiting turned on or off, the link restarted
    /// on another route or network, sieving turned on or off): every open
    /// connection of a sieved app it concerns ends, so it reconnects this way.
    Way(ExitVia),
    /// Only the connections that went directly from this computer while the hub
    /// could not be reached (hub-down set to Direct) end, so they reconnect
    /// through it: the hub is back (`hub_back`), or the owner chose Stop.
    WentDirect { hub_back: bool },
}

/// Told when the way out changed: open connections of sieved apps to public
/// destinations are ended, so they reconnect the new way. The first argument
/// says which destinations exiting concerns.
pub type ExitChanged = Arc<dyn Fn(&dyn Fn(IpAddr) -> bool, Change) + Send + Sync>;

/// A link that has not reached its hub for this long since it started is said
/// to be down, as one that was up and went: the owner is then offered the way
/// out of a stop (the app's "Turn off exiting"), whether or not this network
/// ever reached the hub. 20 s is a few of the link's own dial attempts.
pub const CONNECTING_LIMIT_MS: u64 = 20_000;

struct Running {
    client: LinkClient,
    route: LinkRoute,
    /// The address actually listened on (listen mode).
    listening: Option<SocketAddr>,
    generation: u64,
    /// When this link started (`LinkManager::clock`).
    started_ms: u64,
    ever_up: bool,
    up: bool,
    watcher: tokio::task::AbortHandle,
}

struct State {
    stored: Option<Stored>,
    identity: Option<Arc<Identity>>,
    pairing: Option<tokio::task::AbortHandle>,
    /// Counts pairings started and unpairs: a pairing that finishes applies only
    /// while no unpair (or newer pairing) came after it started.
    pair_generation: u64,
    /// While a pairing waits for the hub to dial in: where.
    pairing_listen: Option<SocketAddr>,
    /// The global switch (`policy.sieving`): off, nothing exits and the link stops.
    sieving: bool,
    /// While Sieve routes.
    net: Option<Arc<dyn LinkNet>>,
    dns_reset: Option<Arc<dyn Fn() + Send + Sync>>,
    exit_changed: Option<ExitChanged>,
    running: Option<Running>,
    since_ms: u64,
    last_error: Option<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            stored: None,
            identity: None,
            pairing: None,
            pair_generation: 0,
            pairing_listen: None,
            sieving: true,
            net: None,
            dns_reset: None,
            exit_changed: None,
            running: None,
            since_ms: 0,
            last_error: None,
        }
    }
}

pub struct LinkManager {
    dir: Option<PathBuf>,
    fallback_net: NetSource,
    /// The name this engine gives itself at pairing.
    name: String,
    state: Mutex<State>,
    /// The running link's client, read by every plan when its open starts.
    current: ClientSlot,
    generation: AtomicU64,
    /// Moves on every change of what exiting means for a flow ([`Self::way_out`]).
    way: tokio::sync::watch::Sender<u64>,
    clock: fn() -> u64,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Characters that reorder or hide text around them (bidirectional controls).
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Text from outside (an error, the hub's refusal) as one plain line, capped:
/// control and bidirectional characters become spaces, so it cannot break a log
/// row or disguise itself in the app.
pub fn said(text: impl AsRef<str>) -> String {
    let one_line: String = text.as_ref().chars().map(|c| if c.is_control() || is_bidi_control(c) { ' ' } else { c }).collect();
    cap_text(&one_line, LINK_TEXT_MAX).to_string()
}

/// The route as it is kept and used, and its address: a dial address in its one
/// written form (no spaces around it), so every reader of the kept route
/// (`concerns`, the dialer) parses exactly what was checked.
pub fn canonical_route(route: LinkRoute) -> Result<(LinkRoute, SocketAddr), String> {
    let at = check_route(&route)?;
    let route = match route {
        LinkRoute::Dial { .. } => LinkRoute::Dial { address: at.to_string() },
        listen @ LinkRoute::Listen { .. } => listen,
    };
    Ok((route, at))
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
        Self { dir, fallback_net, name: computer_name(), state: Mutex::new(state), current: ClientSlot::default(), generation: AtomicU64::new(0), way: tokio::sync::watch::Sender::new(0), clock }
    }

    /// Follows the way out: its value moves whenever what exiting means for a
    /// flow may have changed (exiting on or off, sieving on or off, a pairing or
    /// an unpair, routes up or down, the link restarted, up or down, any choice
    /// changed). An open flow decided once watches it and decides again.
    pub fn way_out(&self) -> tokio::sync::watch::Receiver<u64> {
        self.way.subscribe()
    }

    /// The way out's value now ([`Self::way_out`]): a flow that read it before its
    /// direct connect and reads another after it may have raced a change.
    pub fn way_now(&self) -> u64 {
        *self.way.borrow()
    }

    /// The way out moved. Called with the state's lock held, after the change, so
    /// whoever sees the new value sees the new state too.
    fn moved(&self) {
        self.way.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// The status line.
    pub fn status(&self) -> LinkStatus {
        let st = lock(&self.state);
        let now = (self.clock)();
        let state = match (&st.stored, &st.running) {
            (None, _) if st.pairing.is_some() => LinkState::Pairing,
            (None, _) => LinkState::Unpaired,
            // Paused (the global switch off): nothing runs, as when exiting is off.
            (Some(s), _) if !s.settings.exit || !st.sieving => LinkState::Off,
            (Some(_), Some(r)) if r.up => LinkState::Up,
            // Down once it was up, or once it has tried for long enough: a network
            // that never reaches the hub is no less down than one that lost it.
            (Some(_), Some(r)) if r.ever_up || now.saturating_sub(r.started_ms) > CONNECTING_LIMIT_MS => LinkState::Down,
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
        let stored = st.stored.as_ref().filter(|s| s.settings.exit && st.sieving)?;
        let net = st.net.as_ref()?;
        if !concerns(&stored.settings.route, &**net, dest) {
            return None;
        }
        Some(Plan { current: self.current.clone(), udp: stored.settings.udp })
    }

    /// The hub-down choice in force now; Stop once nothing is paired any more.
    pub fn on_hub_down(&self) -> LinkHubDown {
        lock(&self.state).stored.as_ref().map_or(LinkHubDown::Stop, |s| s.settings.on_hub_down)
    }

    /// Apps were switched from Off back to sieved: while exiting applies, the way
    /// out moved for their flows. Moves [`Self::way_out`] (a flow of theirs
    /// deciding or connecting meanwhile looks again) and returns which
    /// destinations exiting concerns, so their open connections can be ended
    /// ([`ExitChanged`]'s first argument); None while exiting is not in force.
    /// Called after the filter took the new Off set.
    pub fn sieved_again(&self) -> Option<Box<dyn Fn(IpAddr) -> bool + Send>> {
        let st = lock(&self.state);
        let stored = st.stored.as_ref().filter(|s| s.settings.exit && st.sieving)?;
        let net = st.net.clone()?;
        let route = stored.settings.route.clone();
        self.moved();
        Some(Box::new(move |ip| concerns(&route, &*net, ip)))
    }

    /// Whether a connection to `dest` may leave directly from this computer for
    /// a sieved app's flow: always, unless exiting applies to `dest` now (then
    /// only the link may carry it). The relay's every direct connect asks this.
    pub fn may_leave_directly(&self, dest: IpAddr) -> bool {
        self.plan(dest).is_none()
    }

    /// The global switch (`policy.sieving`): off stops the link and closes its
    /// port, and nothing exits (DNS included) until it is on again.
    pub fn set_sieving(self: &Arc<Self>, on: bool) {
        {
            let mut st = lock(&self.state);
            if st.sieving == on {
                return;
            }
            st.sieving = on;
            st.since_ms = (self.clock)();
        }
        self.sync();
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

    /// Who hears of a change of the way out while routes are up ([`ExitChanged`]).
    pub fn on_exit_change(&self, changed: ExitChanged) {
        lock(&self.state).exit_changed = Some(changed);
    }

    /// Sieve stops routing: the link and its listening port close.
    pub fn routes_down(&self) {
        let mut st = lock(&self.state);
        st.net = None;
        st.dns_reset = None;
        st.exit_changed = None;
        if let Some(r) = st.running.take() {
            stop(r);
        }
        *lock(&self.current) = None;
        self.moved();
    }

    /// The network moved: the link restarts on it, a dialling link as well as a
    /// listening one (a socket pinned to the old adapter would only linger until
    /// it is found dead, and every flow meanwhile would wait on it).
    pub fn network_changed(self: &Arc<Self>) {
        self.sync_with(true);
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
        let (route, target) = canonical_route(route)?;
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
        st.pair_generation += 1;
        let generation = st.pair_generation;
        st.pairing_listen = listener.as_ref().and_then(|l| l.local_addr().ok());
        let task = tokio::spawn(async move {
            let outcome = redeem(&code, &name, &*net, target, listener).await;
            // `PairingCode` wipes its secret when dropped.
            drop(code);
            if let Some(me) = weak.upgrade() {
                me.paired(generation, &dir, route, outcome);
            }
        });
        st.pairing = Some(task.abort_handle());
        st.since_ms = (self.clock)();
        st.last_error = None;
        Ok(())
    }

    /// A pairing ended: kept on success, said on failure. A pairing an unpair (or
    /// a newer pairing) came after is dropped whole: nothing is written, and an
    /// unpair is never undone by a pairing that was already finishing.
    fn paired(self: &Arc<Self>, generation: u64, dir: &Path, route: LinkRoute, outcome: Result<(Identity, Fingerprint, String), String>) {
        {
            let mut st = lock(&self.state);
            if st.pair_generation != generation {
                return;
            }
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
        let (reset, changed) = {
            let mut st = lock(&self.state);
            st.pair_generation += 1;
            if let Some(p) = st.pairing.take() {
                p.abort();
            }
            st.pairing_listen = None;
            let was_running = st.running.take().map(stop).is_some();
            *lock(&self.current) = None;
            let route = st.stored.take().map(|s| s.settings.route);
            let changed = route.filter(|_| was_running).and_then(|r| change_of_way(&st, &r, Change::Way(ExitVia::Direct)));
            st.identity = None;
            st.since_ms = (self.clock)();
            st.last_error = None;
            self.moved();
            (st.dns_reset.clone(), changed)
        };
        if let Some(reset) = reset {
            reset();
        }
        if let Some(tell) = changed {
            tell();
        }
        match &self.dir {
            Some(dir) => remove_files(dir),
            None => Ok(()),
        }
    }

    /// The owner's choices: kept, and in force at once.
    pub fn set(self: &Arc<Self>, mut settings: LinkSettings) -> Result<(), String> {
        settings.route = canonical_route(settings.route)?.0;
        let stop_set = {
            let mut st = lock(&self.state);
            let Some(stored) = st.stored.as_mut() else { return Err(NOT_PAIRED.into()) };
            let next = Stored { settings, ..stored.clone() };
            if let Some(dir) = &self.dir {
                write_stored(dir, &next)?;
            }
            let toggled = stored.settings.exit != next.settings.exit;
            // Direct to Stop: what went directly while the hub was down ends.
            let to_stop = stored.settings.on_hub_down == LinkHubDown::Direct && next.settings.on_hub_down == LinkHubDown::Stop;
            if toggled {
                st.since_ms = (self.clock)();
            }
            let stop_set = to_stop && next.settings.exit && st.sieving;
            let route = next.settings.route.clone();
            *st.stored.as_mut().expect("checked") = next;
            st.last_error = None;
            // Any choice may change a flow's way (the UDP choice, the hub-down one).
            self.moved();
            stop_set.then(|| change_of_way(&st, &route, Change::WentDirect { hub_back: false })).flatten()
        };
        self.sync();
        if let Some(tell) = stop_set {
            tell();
        }
        Ok(())
    }

    /// Starts, stops or restarts the link to match what is wanted.
    fn sync(self: &Arc<Self>) {
        self.sync_with(false);
    }

    /// [`Self::sync`]; `restart` restarts a running link even when nothing about
    /// it changed (the network moved under it).
    fn sync_with(self: &Arc<Self>, restart: bool) {
        let (reset, changed) = {
            let mut st = lock(&self.state);
            let wanted = match (&st.stored, &st.identity, &st.net) {
                (Some(s), Some(id), Some(net)) if s.settings.exit && st.sieving => Some((s.clone(), id.clone(), net.clone())),
                _ => None,
            };
            let keep = match (&wanted, &st.running) {
                (Some((s, _, net)), Some(r)) => !restart && r.route == s.settings.route && listen_still_right(r, &**net),
                _ => false,
            };
            if keep {
                return;
            }
            let had = st.running.take();
            let route_before = had.as_ref().map(|r| r.route.clone());
            let changed = had.is_some() || wanted.is_some();
            if let Some(r) = had {
                stop(r);
            }
            *lock(&self.current) = None;
            if let Some((stored, identity, net)) = &wanted {
                match self.start(stored, identity, net.clone()) {
                    Ok(r) => {
                        *lock(&self.current) = Some(r.client.clone());
                        st.running = Some(r);
                        st.last_error = None;
                    }
                    Err(why) => st.last_error = Some(said(why)),
                }
                st.since_ms = (self.clock)();
            }
            if changed {
                self.moved();
            }
            // The destinations exiting concerns, by the route in force now (or,
            // turned off, by the one that was).
            let tell = match (&wanted, route_before) {
                (Some((s, _, _)), _) => change_of_way(&st, &s.settings.route, Change::Way(ExitVia::Hub)),
                (None, Some(before)) => change_of_way(&st, &before, Change::Way(ExitVia::Direct)),
                (None, None) => None,
            };
            (changed.then(|| st.dns_reset.clone()).flatten(), tell)
        };
        if let Some(reset) = reset {
            reset();
        }
        if let Some(tell) = changed {
            tell();
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
        Ok(Running { client, route: stored.settings.route.clone(), listening, generation, started_ms: (self.clock)(), ever_up: false, up: false, watcher })
    }

    /// The running link of `generation` went up or down. Up, the connections that
    /// went directly while it could not be reached (hub-down Direct) end, so they
    /// reconnect through it: none stays on this computer's address once the hub
    /// is back.
    fn turned(&self, generation: u64, up: bool) {
        let (reset, tell) = {
            let mut st = lock(&self.state);
            let Some(r) = st.running.as_mut().filter(|r| r.generation == generation) else { return };
            r.up = up;
            r.ever_up |= up;
            let route = r.route.clone();
            st.since_ms = (self.clock)();
            self.moved();
            let tell = up.then(|| change_of_way(&st, &route, Change::WentDirect { hub_back: true })).flatten();
            (st.dns_reset.clone(), tell)
        };
        if let Some(reset) = reset {
            reset();
        }
        if let Some(tell) = tell {
            tell();
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

/// Whether exiting concerns `dest` on `route`: a public address (not loopback,
/// private, link-local, shared, unique-local, multicast, reserved, nor their
/// mapped forms: `sieve_link`'s own classes), not on this computer's own
/// networks, and not the hub's own dial address.
fn concerns(route: &LinkRoute, net: &dyn LinkNet, dest: IpAddr) -> bool {
    if sieve_link::rules::denied_class(dest).is_some() || net.is_local(dest) {
        return false;
    }
    !matches!(route, LinkRoute::Dial { address } if address.parse::<SocketAddr>().is_ok_and(|a| a.ip() == dest))
}

/// What to tell [`ExitChanged`] of a change of the way out, to be called once the
/// state's lock is let go: None while routes are down or nobody listens.
fn change_of_way(st: &State, route: &LinkRoute, change: Change) -> Option<Box<dyn FnOnce() + Send>> {
    let tell = st.exit_changed.clone()?;
    let net = st.net.clone()?;
    let route = route.clone();
    Some(Box::new(move || tell(&|ip| concerns(&route, &*net, ip), change)))
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
    let mut stored: Stored = sieve_link::store::read_json(&file).map_err(|e| e.to_string())?;
    // A record from before routes were kept in their one form reads as if it were.
    stored.settings.route = canonical_route(stored.settings.route)?.0;
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
