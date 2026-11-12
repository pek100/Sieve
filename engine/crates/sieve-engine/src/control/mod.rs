//! The running engine's state and the one place its facts come from
//! (plan 1.6): the policy it holds, why it does not route, the routes, the
//! flow book and the counters. The pipe reads it ([`crate::ipc::Backend`]);
//! the routing loop (`routing`, Windows) writes it.
//!
//! Turning the engine on through `SetPolicy` after a crash loop forgives
//! the earlier failures (the user's explicit act, plan 1.6.4).

pub mod certs;
#[cfg(windows)]
pub mod routing;
#[cfg(all(test, windows))]
mod routing_tests;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use sieve_filter::rules::RuleSet;
use sieve_ipc::{Blocker, CertStatus, DnsUpstreams, EngineStatus, ExclusionsView, FlowEvent, ListStatus, LogRow, Policy};
use tokio::sync::{Notify, broadcast, watch};

use crate::ca::Ca;
use crate::dns::service::{Mode, Service};
use crate::dns::upstream::Upstream;
use crate::dns::{NameMap, config};
use crate::domain::{DomainFilter, FilterSlot, UserRules};
use crate::exclusions::ExclusionSlot;
use crate::heal::{Heal, Retry};
use crate::ipc::{Backend, HealAnswer, IssuesAnswer, Subscription};
use crate::lists::Lists;
use crate::policy::{self, Runs};
use crate::route::sign_in::SignIn;
use crate::stack::Meters;
use crate::stack::book::FlowBook;
use crate::update::cycle::UpdateControl;
use crate::watchdog::{Arm, Beats};

/// Batches a slow client may fall behind by before it is disconnected (it
/// then reconnects and gets the open flows again).
pub const FLOWS_BACKLOG: usize = 64;

/// The engine's Status for an admin prompt (`scripts/live/engine-route.ps1`).
pub const STATUS_FILE: &str = "status.json";
/// The encrypted DNS sessions' facts for an admin prompt, at the same cadence
/// (docs/live/encrypted-dns.md). Never a queried name; not on the pipe.
pub const DNS_STATUS_FILE: &str = "dns-status.json";
/// While routes are up, `status.json` is rewritten this often.
pub const STATUS_FILE_EVERY_MS: u64 = 30_000;

/// What the routing loop reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    pub routes_up: bool,
    pub blocker: Option<Blocker>,
    pub split_tunnels: Vec<String>,
    /// Reasons reported once each, kept for the whole run ([`Engine::add_error`]).
    pub last_error: Option<String>,
    /// Why `dns.json` was not used at start-up, until a list set on the pipe
    /// replaces the file. Status reports it after `last_error`.
    pub dns_file_error: Option<String>,
    /// The newest route failure ([`Engine::route_failed`]). Status reports it
    /// last.
    pub route_error: Option<String>,
    /// Why interception could not be built, while that is still so
    /// ([`Engine::publish_https`]). Status reports it after `route_error`.
    pub https_error: Option<String>,
    /// What went wrong with attribution's sources in the latest routing run
    /// ([`Engine::attribution_failed`]). Status reports it after `route_error`.
    pub attribution_error: Option<String>,
    /// Why the policy in force is not on disk, until a later save works. Its
    /// own field, as a full disk fails on every SetPolicy and `add_error` would
    /// grow the Status with each one. Status reports it after `attribution_error`.
    pub policy_save_error: Option<String>,
    /// When the routes came up (monotonic ms), for the Stall test build.
    pub up_since: Option<u64>,
    /// The DNS Client capture's state while routes are up (`routing`); None otherwise.
    pub dns_capture: Option<sieve_ipc::DnsCapture>,
}

pub struct Engine {
    #[cfg(feature = "relay-experiments")]
    pub experiments: crate::experiments::Loaded,
    #[cfg(feature = "relay-experiments")]
    pub runtime_workers: std::sync::atomic::AtomicUsize,
    /// `ProgramData\Sieve\engine` (policy, runs, journal); None in tests.
    pub dir: Option<PathBuf>,
    /// This exe (wintun.dll sits beside it).
    pub exe: PathBuf,
    policy: Mutex<Policy>,
    runs: Mutex<Runs>,
    crash_loop: Mutex<Option<u32>>,
    facts: Mutex<Facts>,
    dns_upstreams: Mutex<DnsUpstreams>,
    /// Up from just before the routes are added until they are taken down.
    dns_service: Mutex<Option<Arc<Service>>>,
    pub book: Arc<Mutex<FlowBook>>,
    pub names: Arc<Mutex<NameMap>>,
    pub meters: Arc<Meters>,
    /// The decision snapshot the relay reads; rebuilt off the hot path.
    pub filter: Arc<FilterSlot>,
    /// The default lists: download state, cache and compile.
    pub lists: Arc<Lists>,
    /// What is never decrypted (plan 4.1).
    pub exclusions: Arc<ExclusionSlot>,
    /// Self-healing: outlives each `Interception`, so a switch off and on forgets
    /// nothing. Hears flows only through one.
    pub heal: Arc<Heal>,
    /// The log list and CRLite data, outliving the switch (slice 11).
    pub validation: Arc<crate::tls::validation::ValidationSlot>,
    /// `filtering.https`: built by the routing loop while it is wanted and
    /// routes are up, empty otherwise.
    #[cfg(windows)]
    pub https: Arc<crate::tls::intercept::HttpsSlot<crate::stack::egress::Egress>>,
    pub flows: broadcast::Sender<Arc<Vec<FlowEvent>>>,
    /// What the filter did, on the same cadence (plan 8.3).
    pub log: broadcast::Sender<Arc<Vec<LogRow>>>,
    /// Whether routes are up, for subscriptions (they end when it turns false).
    routes_up: watch::Sender<bool>,
    /// Wakes the routing loop: a policy change or a route change.
    pub wake: Arc<Notify>,
    pub beats: Arc<Beats>,
    pub arm: Arc<Arm>,
    /// The root CA, set by the runner (unset when it could not be made, and
    /// in tests that have no use for one).
    ca: OnceLock<Arc<Ca>>,
    /// Wakes the certificate loop. Its own: `wake` is the routing loop's and
    /// a single permit would be stolen.
    pub ca_wake: Notify,
    /// The user asked for a new root; the certificate loop takes it.
    reinstall: AtomicBool,
    /// Signed updates: `not_configured` until the service attaches its worker.
    pub updates: Arc<UpdateControl>,
    /// A Wi-Fi that wants a sign-in and the user's pause of the DNS Client
    /// capture for it (`route::sign_in`). Memory only: a restart starts empty.
    sign_in: Mutex<SignIn>,
}

/// `install_root`'s refusal while the switch is off (plan 7.3: no root
/// without the user's act, and the act here is the switch).
pub const HTTPS_OFF: &str = "HTTPS filtering is off, so there is no certificate to reinstall";
pub const NO_CA: &str = "the certificate service did not start";

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Whether a built interception has a use: its switch is on and routes can carry it.
#[cfg(windows)]
fn https_can_run(policy: &Policy) -> bool {
    crate::tls::intercept::wanted(policy) && policy.engine
}

/// One error text from whichever of the two reasons exist.
fn beside(held: Option<String>, reason: Option<String>) -> Option<String> {
    match (held, reason) {
        (Some(held), Some(reason)) => Some(format!("{held}; {reason}")),
        (held, reason) => held.or(reason),
    }
}

impl Engine {
    pub fn new(dir: Option<PathBuf>, exe: PathBuf, policy: Policy, runs: Runs, crash_loop: Option<u32>) -> Self {
        // Flows pass until the lists' first snapshot lands (D13); the user's
        // own rules are small and hold from the start.
        let filter = Arc::new(FilterSlot::new(DomainFilter::new(&policy, RuleSet::empty())));
        let lists = Arc::new(Lists::new(dir.as_deref(), filter.clone(), policy.lists.clone()));
        let user = Arc::new(lists.user_engine_for(UserRules::of(&policy)));
        filter.update(|f| DomainFilter::new(&policy, RuleSet { user, lists: f.rules.lists.clone() }));
        lists.set_custom(policy.custom_lists.clone(), policy::wall_ms());
        let (dns_upstreams, unused_dns_file) = dir.as_deref().map(config::load).unwrap_or_else(|| (config::defaults(), None));
        let exclusions = Arc::new(ExclusionSlot::new(dir.as_deref(), &policy.exclusions, policy::wall_ms()));
        let meters: Arc<Meters> = Arc::default();
        let heal = Arc::new(Heal::new(exclusions.clone(), meters.clone()));
        let validation = Arc::new(crate::tls::validation::ValidationSlot::new(meters.clone()));
        Self {
            #[cfg(feature = "relay-experiments")]
            experiments: dir.as_deref().map(crate::experiments::Loaded::load).unwrap_or_else(crate::experiments::Loaded::absent),
            #[cfg(feature = "relay-experiments")]
            runtime_workers: std::sync::atomic::AtomicUsize::new(0),
            dir,
            exe,
            policy: Mutex::new(policy),
            runs: Mutex::new(runs),
            crash_loop: Mutex::new(crash_loop),
            facts: Mutex::new(Facts { dns_file_error: unused_dns_file, ..Facts::default() }),
            dns_upstreams: Mutex::new(dns_upstreams),
            dns_service: Mutex::new(None),
            book: Arc::default(),
            names: Arc::default(),
            meters,
            filter,
            lists,
            exclusions,
            heal,
            validation,
            #[cfg(windows)]
            https: Arc::default(),
            flows: broadcast::channel(FLOWS_BACKLOG).0,
            log: broadcast::channel(FLOWS_BACKLOG).0,
            routes_up: watch::channel(false).0,
            wake: Arc::default(),
            beats: Arc::default(),
            arm: Arc::default(),
            ca: OnceLock::new(),
            ca_wake: Notify::new(),
            reinstall: AtomicBool::new(false),
            updates: Arc::default(),
            sign_in: Mutex::default(),
        }
    }

    /// The sign-in state, for the routing loop and the pipe.
    pub fn sign_in(&self) -> std::sync::MutexGuard<'_, SignIn> {
        lock(&self.sign_in)
    }

    /// Gives the running engine its CA (once, from the runner).
    pub fn attach_ca(&self, ca: Arc<Ca>) {
        let _ = self.ca.set(ca);
    }

    /// Whether the user asked for a new root since the last call.
    pub fn take_reinstall(&self) -> bool {
        self.reinstall.swap(false, Ordering::SeqCst)
    }

    pub fn policy(&self) -> Policy {
        lock(&self.policy).clone()
    }

    /// A changed policy reaches the decision: an Off-app or switch change
    /// recompiles nothing, the user's rules recompile their small engine, and
    /// a new list selection wakes the refresh task.
    fn apply_to_filter(&self, before: &Policy, now: &Policy) {
        let user_rules = UserRules::of(now);
        let user = (UserRules::of(before) != user_rules).then(|| Arc::new(self.lists.user_engine_for(user_rules)));
        self.filter.update(|f| {
            let rules = RuleSet { user: user.unwrap_or_else(|| f.rules.user.clone()), lists: f.rules.lists.clone() };
            DomainFilter::new(now, rules)
        });
        self.lists.set_selection(now.lists.clone());
        self.lists.set_custom(now.custom_lists.clone(), policy::wall_ms());
        self.exclusions.set_user(&now.exclusions, policy::wall_ms());
        // Off closes every decrypted flow now; on waits for the routing loop,
        // which holds the pinned sockets.
        #[cfg(windows)]
        {
            if !crate::tls::intercept::wanted(now) {
                self.https.set(None);
            }
            if !https_can_run(now) {
                self.set_facts(|f| f.https_error = None);
            }
        }
    }

    /// What building interception came to. Under the policy's lock, as `set_policy`
    /// empties the slot under it: a switch that went off during the build is seen
    /// here, or finds this published and empties it, so no flow decrypts after off.
    /// Each outcome replaces the last, and one that no longer matters says nothing.
    #[cfg(windows)]
    pub fn publish_https(&self, built: Result<crate::tls::intercept::Interception<crate::stack::egress::Egress>, String>) {
        let policy = lock(&self.policy);
        if !https_can_run(&policy) {
            return;
        }
        match built {
            Ok(interception) => {
                self.https.set(Some(Arc::new(interception)));
                self.set_facts(|f| f.https_error = None);
            }
            Err(why) => self.set_facts(|f| f.https_error = Some(format!("HTTPS filtering is not running: {why}"))),
        }
    }

    /// The root CA, once the runner attached it.
    pub fn ca(&self) -> Option<Arc<Ca>> {
        self.ca.get().cloned()
    }

    /// Restarts that stopped routing, when this run is a crash loop.
    pub fn crash_loop(&self) -> Option<u32> {
        *lock(&self.crash_loop)
    }

    pub fn facts(&self) -> Facts {
        lock(&self.facts).clone()
    }

    pub fn set_facts(&self, f: impl FnOnce(&mut Facts)) {
        let up = {
            let mut facts = lock(&self.facts);
            f(&mut facts);
            facts.routes_up
        };
        self.routes_up.send_if_modified(|was| std::mem::replace(was, up) != up);
    }

    /// Reports `reason` beside the reasons already held, so one never hides another.
    pub fn add_error(&self, reason: String) {
        self.set_facts(|f| f.last_error = beside(f.last_error.take(), Some(reason)));
    }

    /// Reports a route that could not be added. The routing loop retries it on
    /// every wake, so the newest failure replaces the one before it.
    pub fn route_failed(&self, reason: String) {
        self.set_facts(|f| f.route_error = Some(reason));
    }

    /// No route is still failing: what was reported is over.
    pub fn routes_settled(&self) {
        self.set_facts(|f| f.route_error = None);
    }

    /// A routing run starts its attribution sources again: what the last run's
    /// reported is over, and is not said twice if it happens again.
    pub fn attribution_starts(&self) {
        self.set_facts(|f| f.attribution_error = None);
    }

    /// Reports an attribution source that failed or ended, beside any other of
    /// this run's: routing goes on with the owner tables alone.
    pub fn attribution_failed(&self, reason: String) {
        self.set_facts(|f| f.attribution_error = beside(f.attribution_error.take(), Some(reason)));
    }

    /// The encrypted DNS resolvers the engine holds.
    pub fn dns_upstreams(&self) -> DnsUpstreams {
        lock(&self.dns_upstreams).clone()
    }

    /// Builds the DNS service from the held list and the policy's mode and installs
    /// it, all under both locks: a list or a policy set on the pipe reaches either
    /// the build or the installed service, so what the pipe answers is what the
    /// service uses. Lock order: list, policy, service (as `set_policy` and
    /// `set_dns_upstreams` take theirs).
    pub fn start_dns_service(&self, build: impl FnOnce(Vec<Upstream>) -> Arc<Service>) -> Result<Arc<Service>, String> {
        let held = lock(&self.dns_upstreams);
        let policy = lock(&self.policy);
        let service = build(config::validate(&held)?);
        service.set_mode(Mode::of(&policy));
        *lock(&self.dns_service) = Some(service.clone());
        Ok(service)
    }

    pub fn stop_dns_service(&self) {
        *lock(&self.dns_service) = None;
    }

    /// Records this run's clean end (the service was asked to stop).
    pub fn stop_clean(&self) {
        self.exclusions.flush();
        let mut runs = lock(&self.runs);
        runs.stop_clean();
        if let Some(dir) = &self.dir {
            let _ = policy::save_runs(dir, &runs);
        }
    }

    /// Writes the Status to `status.json` beside the policy (admin-only), so
    /// the live check reads the engine's own facts and counters from an
    /// admin prompt (the pipe admits only the installed app). Best effort.
    pub fn write_status_file(&self) {
        #[cfg(feature = "attribution-diagnostics")]
        if let (Some(dir), Ok(json)) = (&self.dir, serde_json::to_vec_pretty(&*lock(&self.meters.attribution))) {
            let tmp = dir.join("attribution-diagnostics.tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, dir.join("attribution-diagnostics.json"));
            }
        }
        #[cfg(not(feature = "relay-experiments"))]
        let json = self.status_json();
        #[cfg(feature = "relay-experiments")]
        let json = self.experimental_status_json();
        if let (Some(dir), Ok(json)) = (&self.dir, json) {
            let tmp = dir.join(STATUS_FILE).with_extension("tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, dir.join(STATUS_FILE));
            }
        }
        self.write_dns_status_file();
    }

    /// The Status plus what stays local: the key exchange evidence (task D18) and
    /// the QUIC fallback evidence (slice 8) and what content filtering did
    /// (content task D7, D11). Counts only, no host. Only an answer on the pipe
    /// tells a person about a release, so this holds the plain update state.
    fn status_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        let mut status = serde_json::to_value(self.status_saying(self.updates.status()))?;
        status["dns_mode"] = serde_json::to_value(Mode::of(&self.policy()))?;
        status["https"] = self.meters.https.report();
        status["quic"] = self.meters.quic.report(crate::quic::REFUSAL);
        let local = |c: &std::sync::atomic::AtomicU64| serde_json::Value::from(c.load(std::sync::atomic::Ordering::Relaxed));
        status["counters"]["tun_write_dropped"] = local(&self.meters.tun_write_dropped);
        status["counters"]["udp_too_big"] = local(&self.meters.udp_too_big);
        status["counters"]["udp_too_big_unanswered"] = local(&self.meters.udp_too_big_unanswered);
        status["packet_path"] = lock(&self.beats.path).as_ref().map(|p| p.report()).unwrap_or(serde_json::Value::Null);
        self.validation.report(&mut status["https"]);
        status["content"] = self.meters.content.report();
        status["content"]["list_hits"] = serde_json::to_value(lock(&self.book).list_hits())?;
        Ok(status)
    }

    #[cfg(not(feature = "relay-experiments"))]
    fn status_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(&self.status_value()?)
    }

    /// Beside `status.json`: an empty list while nothing is up, so an old fact
    /// is never read as a current one. Best effort.
    fn write_dns_status_file(&self) {
        let Some(dir) = &self.dir else { return };
        if let Ok(json) = serde_json::to_vec_pretty(&self.dns_status_value()) {
            let _ = policy::write_report(&dir.join(DNS_STATUS_FILE), &json);
        }
    }

    /// `dns-status.json`'s content: the mode the user chose, and the sessions and
    /// counts while the service is up.
    fn dns_status_value(&self) -> serde_json::Value {
        // The policy first and on its own: `set_policy` holds it while it takes the service's lock.
        let mode = Mode::of(&self.policy());
        let (upstreams, counts) = lock(&self.dns_service).as_ref().map(|s| (s.report(), s.counts())).unwrap_or_default();
        serde_json::json!({ "mode": mode, "upstreams": upstreams, "answers": counts })
    }

    #[cfg(feature = "relay-experiments")]
    fn experimental_status_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut status = self.status_value()?;
        let mut experiments = serde_json::to_value(&self.experiments)?;
        let copy = self.experiments.settings.copy_buffer_bytes.unwrap_or(crate::experiments::DEFAULT_COPY_BYTES);
        experiments["copy_buffers"] = serde_json::json!({
            "app_to_upstream_bytes": copy,
            "upstream_to_app_bytes": copy,
            // Fixed: both relays share production's classifier read.
            "classifier_bytes": crate::flow::relay::CLASSIFIER_READ,
        });
        let workers = self.runtime_workers.load(std::sync::atomic::Ordering::Relaxed);
        // Before the runtime exists there is no effective worker count yet.
        experiments["runtime_worker_threads"] = if workers == 0 { serde_json::Value::Null } else { workers.into() };
        status["experiments"] = experiments;
        serde_json::to_vec_pretty(&status)
    }

    /// The next batch of changed flows and log rows, sent to every subscriber.
    pub fn publish_batch(&self) {
        let (batch, rows) = {
            let mut book = lock(&self.book);
            (book.take_batch(), book.take_log())
        };
        if !batch.is_empty() {
            let _ = self.flows.send(Arc::new(batch));
        }
        if !rows.is_empty() {
            let _ = self.log.send(Arc::new(rows));
        }
    }

    /// Whether a new flow can be decrypted: the slot, which the policy and the
    /// routing loop empty (`wanted`, `take_down`), and not the switch. A floor can
    /// still refuse any one flow, so this says nothing of a given site.
    #[cfg(windows)]
    fn decrypting(&self) -> bool {
        self.https.get().is_some()
    }

    #[cfg(not(windows))]
    fn decrypting(&self) -> bool {
        false
    }

    /// The Status, with the update state it reports. Only an answer on the pipe
    /// tells a person about a release, so the file writers pass the plain state.
    fn status_saying(&self, update: sieve_ipc::UpdateStatus) -> EngineStatus {
        let f = self.facts();
        let policy = self.policy();
        let blocker = if !policy.engine {
            None
        } else if let Some(starts) = self.crash_loop() {
            Some(Blocker::CrashLoop { starts })
        } else {
            f.blocker
        };
        // Read under one lock, released before the literal below.
        let (live, guests) = {
            let book = lock(&self.book);
            (book.live(), book.guests())
        };
        let dns_unreachable = lock(&self.dns_service).as_ref().is_some_and(|s| s.unreachable());
        EngineStatus {
            filtering: f.routes_up,
            routes_up: f.routes_up,
            blocking: f.routes_up && self.filter.get().blocks_anything(),
            flows: u32::try_from(live).unwrap_or(u32::MAX),
            decrypting: self.decrypting(),
            last_error: [f.dns_file_error, f.route_error, f.https_error, f.attribution_error, f.policy_save_error, self.lists.compile_error()].into_iter().fold(f.last_error, beside),
            policy,
            blocker,
            split_tunnels: f.split_tunnels,
            counters: self.meters.counters(),
            guests,
            filter: self.lists.facts(),
            dns_unreachable,
            dns_capture: if f.routes_up { f.dns_capture } else { None },
            wifi_sign_in: if f.routes_up { self.sign_in().report(std::time::Instant::now()) } else { None },
            update,
        }
    }
}

impl Backend for Engine {
    fn status(&self) -> EngineStatus {
        self.status_saying(self.updates.status_for_client())
    }

    /// The policy takes effect whether or not it reaches the disk: a file that
    /// cannot be written must not keep the engine routing after the user said
    /// off (fail-open). A failed save is reported, and the file keeps the last
    /// good one for the next start. It is saved under the lock, so the file
    /// never ends on an older policy than the engine holds, and its result is
    /// published under the lock, so the warning describes the policy in force
    /// and not whichever request finished last.
    fn set_policy(&self, asked: Policy) -> Result<EngineStatus, String> {
        {
            let mut current = lock(&self.policy);
            let next = policy::accept(&current, asked)?;
            if next.engine && !current.engine && lock(&self.crash_loop).take().is_some() {
                let mut runs = lock(&self.runs);
                runs.forgive();
                if let Some(dir) = &self.dir {
                    let _ = policy::save_runs(dir, &runs);
                }
            }
            self.apply_to_filter(&current, &next);
            if let Some(service) = lock(&self.dns_service).as_ref() {
                service.set_mode(Mode::of(&next));
            }
            let saved = self.dir.as_ref().map_or(Ok(()), |dir| policy::save(dir, &next));
            *current = next;
            self.set_facts(|f| f.policy_save_error = saved.err().map(|why| format!("the policy holds until a restart, which reads the last one saved: {why}")));
        }
        self.wake.notify_one();
        self.ca_wake.notify_one();
        Ok(self.status())
    }

    /// The user's click: refused unless routes are up, the capture is wanted and
    /// really holds (the status says it works), and the routing loop sees
    /// `network` as one that wants a sign-in now, with a pause left
    /// (`SignIn::pause`). The loop is woken to close the capture at once.
    fn pause_dns_capture(&self, network: &str) -> Result<EngineStatus, String> {
        let facts = self.facts();
        let wanted = facts.routes_up && crate::route::capture::wanted(&self.policy());
        let held = facts.dns_capture == Some(sieve_ipc::DnsCapture::Working);
        self.sign_in().pause(std::time::Instant::now(), network, wanted, held)?;
        self.wake.notify_one();
        Ok(self.status())
    }

    /// "Resume now": the loop is woken to open the capture again.
    fn resume_dns_capture(&self) -> EngineStatus {
        if self.sign_in().resume().is_some() {
            self.wake.notify_one();
        }
        self.status()
    }

    fn set_dns_upstreams(&self, asked: DnsUpstreams) -> Result<DnsUpstreams, String> {
        let next = {
            let mut held = lock(&self.dns_upstreams);
            let (next, endpoints) = config::accept(&held, asked)?;
            if let Some(dir) = &self.dir {
                config::save(dir, &next)?;
            }
            *held = next.clone();
            if let Some(service) = lock(&self.dns_service).as_ref() {
                service.set_list(endpoints);
            }
            // The file was just replaced, so its old reason no longer holds.
            self.set_facts(|f| f.dns_file_error = None);
            next
        };
        // With routing off nothing else rewrites the status file.
        self.write_status_file();
        Ok(next)
    }

    fn dns_upstreams(&self) -> DnsUpstreams {
        Engine::dns_upstreams(self)
    }

    fn subscribe(&self) -> Subscription {
        let book = lock(&self.book);
        // Subscribed under the book's lock: no batch slips between the two.
        Subscription { open: book.snapshot(), batches: self.flows.subscribe(), log: self.log.subscribe(), routes_up: self.routes_up.subscribe() }
    }

    fn lists(&self) -> (Vec<ListStatus>, Option<u64>) {
        self.lists.report()
    }

    fn lists_refresh(&self) {
        self.lists.refresh_now();
    }

    fn list_refresh(&self, id: &str) -> Result<(), String> {
        self.lists.refresh_one(id)
    }

    async fn list_import(&self, id: &str, text: String) -> Result<(u64, u64), String> {
        self.lists.import(id, text, policy::wall_ms()).await
    }

    fn list_rules(&self, id: &str, query: &str) -> Result<(Vec<String>, u64, u64), String> {
        self.lists.rules(id, query)
    }

    fn cert_status(&self) -> CertStatus {
        self.ca.get().map(|ca| ca.status(policy::wall_ms())).unwrap_or_default()
    }

    fn install_root(&self) -> Result<CertStatus, String> {
        if !self.policy().https {
            return Err(HTTPS_OFF.to_string());
        }
        if self.ca.get().is_none() {
            return Err(NO_CA.to_string());
        }
        self.reinstall.store(true, Ordering::SeqCst);
        self.ca_wake.notify_one();
        Ok(self.cert_status())
    }

    fn request_update(&self) -> Result<EngineStatus, String> {
        self.updates.request(crate::watchdog::monotonic_ms())?;
        Ok(self.status())
    }

    fn exclusions(&self) -> ExclusionsView {
        self.exclusions.view(policy::wall_ms())
    }

    fn try_decrypt_again(&self, retry: Retry) {
        self.heal.try_again(&retry, policy::wall_ms());
    }

    fn heal_notices(&self, after: u64) -> HealAnswer {
        let (revision, notices) = self.heal.notices(after);
        // An entry past its end (an app's day untouched) moves the revision the app
        // compares, with or without a flow to read the store.
        self.exclusions.get();
        HealAnswer { run: self.heal.run(), revision, exclusions_revision: self.exclusions.revision(), notices }
    }

    /// The book's revisions start at this run's start, as heal's do.
    fn issues(&self, session: u32) -> IssuesAnswer {
        let mut book = lock(&self.book);
        IssuesAnswer { run: self.heal.run(), revision: book.issues_revision(), apps: book.issues(session), dropped: book.issues_dropped() }
    }
}

/// The checks of `scripts/live/engine-route.ps1` that the live check
/// `live_engine_full_route_relays_and_restores` requires to have passed
/// (docs/live/engine-slice-3.md; plan slice 3 acceptance).
pub const LIVE_CHECKS: &[&str] = &[
    "the engine refuses while AdGuard runs (blocker adguard)",
    "the app offers to pause AdGuard",
    "routes on the Sieve adapter",
    "no Sieve route in the persistent store",
    "no DNS server set on the Sieve adapter",
    "LAN router UI reachable",
    "30 minutes of normal use without a failure",
    "attribution of at least 0.95 from the engine's counters",
    "network checked within 5 s of the kill",
    "no route on an interface named Sieve after the kill",
    "the watchdog removed the routes",
    "no route on an interface named Sieve after the reboot",
    "the crash-loop stop engaged after three unclean ends within the hour",
    "turning routing off and on ends the crash-loop stop",
    "idle CPU under 1 percent of one core",
    "relay CPU at most 15 percent of one core per 100 Mbit/s",
    "engine memory at most 300 MB",
];

/// Which required checks did not pass, reading the script's results: the
/// last line about each check decides.
pub fn live_failures(results: &str) -> Vec<&'static str> {
    LIVE_CHECKS
        .iter()
        .copied()
        .filter(|name| {
            let last = results.lines().rfind(|l| l.get(6..).is_some_and(|rest| rest.starts_with(name)));
            !last.is_some_and(|l| l.starts_with("PASS  "))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "relay-experiments")]
    #[test]
    fn status_records_effective_settings_read_result_and_runtime_workers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(crate::experiments::FILE);
        std::fs::write(&path, b"{\"tun_mtu\":9000,\"worker_threads\":2}").unwrap();
        let engine = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None);
        engine.runtime_workers.store(2, std::sync::atomic::Ordering::Relaxed);
        // Later edits are deliberately ignored until the next engine start.
        std::fs::write(&path, b"{\"tun_mtu\":1280}").unwrap();
        engine.write_status_file();
        let status: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.path().join(STATUS_FILE)).unwrap()).unwrap();
        assert_eq!(status["experiments"]["tun_mtu"], 9000);
        assert_eq!(status["experiments"]["tun_batch"], 1);
        assert_eq!(status["experiments"]["runtime_worker_threads"], 2);
        assert_eq!(status["experiments"]["file"]["result"], "ok");
        assert!(status["experiments"]["copy_buffer_bytes"].is_null());
        assert!(serde_json::to_value(engine.status()).unwrap().get("experiments").is_none(), "IPC protocol unchanged");
        std::fs::write(&path, b"{").unwrap();
        let engine = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None);
        let status: serde_json::Value = serde_json::from_slice(&engine.experimental_status_json().unwrap()).unwrap();
        assert_eq!(status["experiments"]["tun_mtu"], crate::tun::MTU);
        assert_eq!(status["experiments"]["file"]["result"], "refused");
        assert!(!status["experiments"]["file"]["reason"].as_str().unwrap().is_empty());
    }

    /// The live check of `filtering.engine` (registry `liveCheck`), run by
    /// the user only: it reads the evidence `scripts/live/engine-route.ps1`
    /// wrote (`SIEVE_LIVE_DIR`, default `C:\Users\Public\sieve-engine-live`)
    /// and passes when every required check passed. It changes nothing.
    #[test]
    #[ignore = "live: reads the user's evidence of scripts/live/engine-route.ps1"]
    fn live_engine_full_route_relays_and_restores() {
        let dir = std::env::var("SIEVE_LIVE_DIR").unwrap_or_else(|_| r"C:\Users\Public\sieve-engine-live".into());
        let path = std::path::Path::new(&dir).join("results-route.txt");
        let results = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e} (run the live check first)", path.display()));
        assert_eq!(live_failures(&results), Vec::<&str>::new(), "required checks without a PASS");
    }

    #[test]
    fn every_required_live_check_is_one_the_script_makes() {
        let script = include_str!("../../../../../scripts/live/engine-route.ps1");
        for name in LIVE_CHECKS {
            assert!(script.contains(&format!("Check \"{name}\"")), "{name}");
        }
    }

    #[test]
    fn the_last_line_about_a_check_decides() {
        let mut results = String::from("==== header\n");
        for name in LIVE_CHECKS {
            results.push_str(&format!("FAIL  {name}  (first try)\nPASS  {name}  (detail)\n"));
        }
        assert!(live_failures(&results).is_empty());
        results.push_str("FAIL  routes on the Sieve adapter\n");
        assert_eq!(live_failures(&results), ["routes on the Sieve adapter"]);
        assert_eq!(live_failures("").len(), LIVE_CHECKS.len());
    }

    fn engine(policy: Policy, crash: Option<u32>) -> Engine {
        Engine::new(None, PathBuf::from(r"C:\x\sieve-engine.exe"), policy, Runs::default(), crash)
    }

    #[test]
    fn the_default_engine_routes_nothing_and_says_so() {
        let s = engine(Policy::default(), None).status();
        assert!(!s.routes_up && !s.filtering && !s.policy.engine);
        assert_eq!(s.blocker, None);
    }

    /// The pause is no general off switch: refused with routes down, with the
    /// capture not holding, with nothing detected, for another network, and with
    /// the setting off; taken for the network the routing loop saw; said in the
    /// status only while routes are up. A restart forgets it even though the
    /// status file showed it: the engine started again on the same folder holds
    /// no pause and says nothing until its own routing loop sees the network.
    #[test]
    fn the_engine_pauses_only_a_detected_network_and_a_restart_forgets_it() {
        use crate::route::sign_in::{NO_SIGN_IN, NOT_HELD, NOT_WANTED, OTHER_NETWORK, Seen, Verdict};
        const HOTEL: &str = "{6f1c2a9e-0b7d-4c55-9a31-2f1d8e4b7c10}";
        const WIFI: u64 = 0x0047_0000_0000_0007;
        let dir = tempfile::tempdir().unwrap();
        let on = Policy { engine: true, ..Policy::default() };
        let start = || Engine::new(Some(dir.path().to_path_buf()), PathBuf::from(r"C:\x\sieve-engine.exe"), on.clone(), Runs::default(), None);
        let e = start();
        assert_eq!(e.pause_dns_capture(HOTEL), Err(NOT_WANTED.to_string()), "routes down");
        e.set_facts(|f| {
            f.routes_up = true;
            f.dns_capture = Some(sieve_ipc::DnsCapture::Off);
        });
        assert_eq!(e.pause_dns_capture(HOTEL), Err(NOT_HELD.to_string()), "wanted, but the capture does not hold");
        e.set_facts(|f| f.dns_capture = Some(sieve_ipc::DnsCapture::Working));
        assert_eq!(e.pause_dns_capture(HOTEL), Err(NO_SIGN_IN.to_string()));
        let hotel = Verdict { network: HOTEL.into(), luid: WIFI, hijacked: false };
        e.sign_in().observe(std::time::Instant::now(), Seen { wanted: true, held: true, network: Some(&hotel), unread: false, portal: true, encrypted_unreachable: true });
        assert_eq!(e.status().wifi_sign_in, Some(sieve_ipc::WifiSignIn { network: HOTEL.into(), paused_left_s: None, wifi: true }));
        assert_eq!(e.pause_dns_capture("{another}"), Err(OTHER_NETWORK.to_string()));
        let paused = e.pause_dns_capture(HOTEL).unwrap();
        assert!(paused.wifi_sign_in.and_then(|w| w.paused_left_s).is_some_and(|s| s > sieve_ipc::SIGN_IN_PAUSE_MAX_S - 5));
        assert!(e.sign_in().paused());
        e.write_status_file();
        let file: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.path().join(STATUS_FILE)).unwrap()).unwrap();
        assert_eq!(file["wifi_sign_in"]["network"], HOTEL, "the live check reads it");
        let restarted = start();
        restarted.set_facts(|f| {
            f.routes_up = true;
            f.dns_capture = Some(sieve_ipc::DnsCapture::Working);
        });
        assert!(!restarted.sign_in().paused() && restarted.status().wifi_sign_in.is_none(), "a restart reads nothing of it back");
        assert_eq!(restarted.pause_dns_capture(HOTEL), Err(NO_SIGN_IN.to_string()), "and takes no click for it until it sees the network itself");
        e.set_facts(|f| f.routes_up = false);
        assert_eq!(e.status().wifi_sign_in, None, "nothing to say while routes are down");
        e.set_facts(|f| f.routes_up = true);
        assert!(e.resume_dns_capture().wifi_sign_in.is_some_and(|w| w.paused_left_s.is_none()), "resumed; the notice stands");
        assert!(!e.sign_in().paused());
        e.set_policy(Policy { revision: 1, engine: true, skip_dns_capture: true, ..Policy::default() }).unwrap();
        assert_eq!(e.pause_dns_capture(HOTEL), Err(NOT_WANTED.to_string()), "the setting off is the off switch");
    }

    fn switches(revision: u64, engine: bool) -> Policy {
        Policy { revision, engine, ..Policy::default() }
    }

    #[tokio::test]
    async fn set_dns_upstreams_answers_the_held_list_persists_it_and_refuses_a_stale_or_bad_one() {
        use sieve_ipc::nonblocking::{read_frame, write_frame};
        use sieve_ipc::{ClientMessage, EngineMessage, PROTOCOL};

        let dir = tempfile::tempdir().unwrap();
        let engine = Arc::new(Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None));
        assert_eq!(engine.dns_upstreams(), config::defaults(), "no file: the defaults, and no error");
        assert_eq!(engine.status().last_error, None);
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        let backend = engine.clone();
        let task = tokio::spawn(async move { crate::ipc::serve_client(&mut server, 1, backend.as_ref()).await });
        write_frame(&mut client, &ClientMessage::Hello { protocol: PROTOCOL, app_version: "0.1.0".into(), capabilities: Vec::new() }).await.unwrap();
        let _: EngineMessage = read_frame(&mut client).await.unwrap();

        let good = DnsUpstreams { revision: 3, upstreams: vec!["tls://dns.example".into(), "quic://192.0.2.9".into()] };
        write_frame(&mut client, &ClientMessage::SetDnsUpstreams(good.clone())).await.unwrap();
        assert_eq!(read_frame::<_, EngineMessage>(&mut client).await.unwrap(), EngineMessage::DnsUpstreams(good.clone()));

        for (bad, why) in [
            (DnsUpstreams { revision: 3, upstreams: vec!["tls://other.example".into()] }, "stale"),
            (DnsUpstreams { revision: 9, upstreams: vec![] }, "empty"),
            (DnsUpstreams { revision: 9, upstreams: vec!["udp://1.1.1.1".into()] }, "udp://1.1.1.1"),
            (DnsUpstreams { revision: 9, upstreams: vec!["tls://a.example".to_string(); 9] }, "limit"),
        ] {
            write_frame(&mut client, &ClientMessage::SetDnsUpstreams(bad)).await.unwrap();
            let answer: EngineMessage = read_frame(&mut client).await.unwrap();
            assert!(matches!(&answer, EngineMessage::Error { message } if message.contains(why)), "{why}: {answer:?}");
        }
        drop(client);
        task.await.unwrap().unwrap();

        assert_eq!(engine.dns_upstreams(), good, "a refusal changes nothing");
        let reloaded = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None);
        assert_eq!(reloaded.dns_upstreams(), good, "it survives a restart");
    }

    #[test]
    fn a_bad_dns_file_reads_as_the_defaults_and_says_why() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(config::DNS_FILE), b"{\"revision\":1,\"upstreams\":[\"udp://1.1.1.1\"]}").unwrap();
        let e = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None);
        assert_eq!(e.dns_upstreams(), config::defaults());
        assert!(e.status().last_error.unwrap().contains("read as the defaults"));
    }

    fn engine_with_a_bad_dns_file(dir: &std::path::Path) -> Engine {
        std::fs::write(dir.join(config::DNS_FILE), b"{\"revision\":1,\"upstreams\":[\"udp://1.1.1.1\"]}").unwrap();
        let e = Engine::new(Some(dir.to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None);
        assert!(e.status().last_error.unwrap().contains("read as the defaults"));
        e
    }

    #[test]
    fn a_good_list_set_over_a_bad_file_ends_its_reason_and_no_other() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine_with_a_bad_dns_file(dir.path());
        e.add_error("policy.json: broken".into());
        e.route_failed("route 10.0.0.0/8: code 5".into());
        e.set_dns_upstreams(DnsUpstreams { revision: 1, upstreams: vec!["tls://dns.example".into()] }).unwrap();

        let on_disk: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.path().join(STATUS_FILE)).unwrap()).unwrap();
        for reported in [e.status().last_error.unwrap(), on_disk["last_error"].as_str().unwrap().to_string()] {
            assert!(!reported.contains("read as the defaults"), "{reported}");
            for held in ["policy.json: broken", "route 10.0.0.0/8: code 5"] {
                assert!(reported.contains(held), "{held} in {reported}");
            }
        }
    }

    #[test]
    fn a_good_list_set_over_a_bad_file_leaves_no_error_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine_with_a_bad_dns_file(dir.path());
        e.set_dns_upstreams(DnsUpstreams { revision: 1, upstreams: vec!["tls://dns.example".into()] }).unwrap();
        assert_eq!(e.status().last_error, None);
    }

    #[test]
    fn a_refused_list_leaves_the_bad_files_reason() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine_with_a_bad_dns_file(dir.path());
        e.set_dns_upstreams(DnsUpstreams { revision: 1, upstreams: vec!["udp://1.1.1.1".into()] }).unwrap_err();
        e.set_dns_upstreams(DnsUpstreams { revision: 0, upstreams: vec!["tls://dns.example".into()] }).unwrap_err();
        assert!(e.status().last_error.unwrap().contains("read as the defaults"));
    }

    #[test]
    fn a_list_that_could_not_be_saved_leaves_the_bad_files_reason() {
        let dir = tempfile::tempdir().unwrap();
        let held = dir.path().join("engine");
        std::fs::create_dir(&held).unwrap();
        let e = engine_with_a_bad_dns_file(&held);
        std::fs::remove_dir_all(&held).unwrap();
        e.set_dns_upstreams(DnsUpstreams { revision: 1, upstreams: vec!["tls://dns.example".into()] }).unwrap_err();
        assert!(e.status().last_error.unwrap().contains("read as the defaults"));
    }

    #[test]
    fn a_repeating_route_failure_replaces_itself_and_hides_no_other_reason() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(config::DNS_FILE), b"{\"revision\":1,\"upstreams\":[\"udp://1.1.1.1\"]}").unwrap();
        let e = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None);
        e.add_error("policy.json: broken".into());
        e.route_failed("route 10.0.0.0/8: code 5".into());
        e.route_failed("route 10.0.0.0/8: code 87".into());
        let reported = e.status().last_error.unwrap();
        for held in ["read as the defaults", "policy.json: broken", "route 10.0.0.0/8: code 87"] {
            assert!(reported.contains(held), "{held} in {reported}");
        }
        assert!(!reported.contains("code 5"), "{reported}");
    }

    /// The routing loop's sites (`control/routing.rs`) go through these two; a
    /// plain assignment there is what hid the reasons before.
    #[test]
    fn an_attribution_failure_hides_no_other_reason_and_is_not_repeated_by_the_next_run() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(config::DNS_FILE), b"{\"revision\":1,\"upstreams\":[\"udp://1.1.1.1\"]}").unwrap();
        let e = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None);
        e.add_error("policy.json: broken".into());
        e.add_error("certificate: no store".into());
        e.add_error("route changes are not watched: code 5".into());
        e.route_failed("route 10.0.0.0/8: code 5".into());

        e.attribution_starts();
        e.attribution_failed("attribution without ETW: code 5".into());
        e.attribution_failed("the consumer ended".into());
        let reported = e.status().last_error.unwrap();
        for held in ["read as the defaults", "policy.json: broken", "certificate: no store", "route changes are not watched", "route 10.0.0.0/8: code 5", "attribution without ETW: code 5", "the consumer ended"] {
            assert!(reported.contains(held), "{held} in {reported}");
        }

        e.attribution_starts();
        e.attribution_failed("attribution without ETW: code 5".into());
        let reported = e.status().last_error.unwrap();
        assert_eq!(reported.matches("attribution without ETW").count(), 1, "{reported}");
        assert!(!reported.contains("the consumer ended"), "the last run's is over: {reported}");
        assert!(reported.contains("policy.json: broken"), "{reported}");
    }

    #[test]
    fn nothing_in_the_routing_loop_assigns_the_kept_reasons() {
        let routing = include_str!("routing.rs");
        assert!(!routing.contains("f.last_error ="), "use add_error or attribution_failed: one reason never hides another");
    }

    #[test]
    fn a_route_failure_alone_is_the_whole_reason() {
        let e = engine(Policy::default(), None);
        e.route_failed("route 10.0.0.0/8: code 5".into());
        assert_eq!(e.status().last_error.as_deref(), Some("route 10.0.0.0/8: code 5"));
    }

    fn service_from(endpoints: Vec<Upstream>) -> Arc<Service> {
        use crate::route::table::fixtures::{HOME, load};
        let context = crate::dns::testing::Ca::new().context(Arc::default(), Vec::new());
        Arc::new(Service::new(endpoints, context, Arc::new(std::sync::RwLock::new(load(HOME))), Arc::default(), Arc::default(), usize::from(crate::tun::MTU), Box::new(|_| false)))
    }

    fn addresses(service: &Service) -> Vec<String> {
        service.report().into_iter().map(|r| r.address).collect()
    }

    /// How long the pipe's request gets to overtake a build, were it able to.
    const OVERTAKE: std::time::Duration = std::time::Duration::from_millis(100);

    #[test]
    fn a_list_set_while_the_dns_service_starts_reaches_the_service() {
        let e = Arc::new(engine(Policy::default(), None));
        let asked = DnsUpstreams { revision: 1, upstreams: vec!["tls://new.example".into()] };
        let (answered, answer) = std::sync::mpsc::channel();
        let service = e
            .start_dns_service(|endpoints| {
                let (pipe, list) = (e.clone(), asked.clone());
                std::thread::spawn(move || answered.send(pipe.set_dns_upstreams(list)));
                assert!(answer.recv_timeout(OVERTAKE).is_err(), "the pipe waits for the service to be installed");
                service_from(endpoints)
            })
            .unwrap();
        assert_eq!(answer.recv().unwrap().unwrap(), asked);
        assert_eq!(addresses(&service), asked.upstreams, "the service uses what the pipe answered");
    }

    #[test]
    fn a_list_set_before_the_dns_service_starts_is_the_one_it_starts_with() {
        let e = engine(Policy::default(), None);
        let asked = DnsUpstreams { revision: 1, upstreams: vec!["tls://new.example".into()] };
        e.set_dns_upstreams(asked.clone()).unwrap();
        assert_eq!(addresses(&e.start_dns_service(service_from).unwrap()), asked.upstreams);
    }

    #[test]
    fn a_held_list_that_does_not_validate_starts_no_service() {
        let e = engine(Policy::default(), None);
        lock(&e.dns_upstreams).upstreams.clear();
        let refused = e.start_dns_service(|_| panic!("nothing to build from")).err().unwrap();
        assert!(refused.contains("empty"), "{refused}");
        assert!(lock(&e.dns_service).is_none());
    }

    #[test]
    fn a_stopped_dns_service_no_longer_hears_the_list() {
        let e = engine(Policy::default(), None);
        let service = e.start_dns_service(service_from).unwrap();
        let before = addresses(&service);
        e.stop_dns_service();
        e.set_dns_upstreams(DnsUpstreams { revision: 1, upstreams: vec!["tls://new.example".into()] }).unwrap();
        assert_eq!(addresses(&service), before);
    }

    #[test]
    fn the_dns_status_file_holds_no_upstream_while_nothing_is_up() {
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None);
        e.write_status_file();
        let status: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.path().join(DNS_STATUS_FILE)).unwrap()).unwrap();
        assert_eq!(status["upstreams"], serde_json::json!([]));
        assert_eq!(status["answers"]["ech_stripped"], serde_json::json!(0), "counts sit beside the list, and start at nothing");
        assert_eq!(status["mode"], "encrypted", "the default, said");
    }

    /// "Also encrypt Windows' own lookups" off: the policy holds it and is saved, the
    /// routing loop is woken to close the capture (`routing::follow_capture`), and the
    /// status says the capture's state only while routes are up.
    #[tokio::test]
    async fn the_capture_switch_is_held_saved_wakes_routing_and_the_status_says_its_state() {
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None);
        assert!(!e.policy().skip_dns_capture, "on by default");
        e.set_policy(Policy { revision: 1, skip_dns_capture: true, ..Policy::default() }).unwrap();
        assert!(e.status().policy.skip_dns_capture);
        assert!(tokio::time::timeout(std::time::Duration::from_millis(50), e.wake.notified()).await.is_ok(), "routing is woken to follow it");
        let reloaded = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), policy::load(dir.path()).0, Runs::default(), None);
        assert!(reloaded.policy().skip_dns_capture, "saved");

        e.set_facts(|f| f.dns_capture = Some(sieve_ipc::DnsCapture::Off));
        assert_eq!(e.status().dns_capture, None, "nothing to say while routes are down");
        e.set_facts(|f| f.routes_up = true);
        assert_eq!(e.status().dns_capture, Some(sieve_ipc::DnsCapture::Off));
    }

    /// The app's switch over the pipe: SetPolicy reaches a running service at once,
    /// a service started later starts in it, and both status files say it.
    #[tokio::test]
    async fn the_plain_dns_switch_reaches_the_service_over_the_pipe_and_the_status_says_so() {
        use sieve_ipc::nonblocking::{read_frame, write_frame};
        use sieve_ipc::{ClientMessage, EngineMessage, PROTOCOL};

        let dir = tempfile::tempdir().unwrap();
        let e = Arc::new(Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None));
        let running = e.start_dns_service(service_from).unwrap();
        assert_eq!(running.mode(), Mode::Encrypted, "the default");
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        let backend = e.clone();
        let task = tokio::spawn(async move { crate::ipc::serve_client(&mut server, 1, backend.as_ref()).await });
        write_frame(&mut client, &ClientMessage::Hello { protocol: PROTOCOL, app_version: "0.1.0".into(), capabilities: Vec::new() }).await.unwrap();
        let _: EngineMessage = read_frame(&mut client).await.unwrap();

        write_frame(&mut client, &ClientMessage::SetPolicy(Policy { revision: 1, plain_dns: true, ..Policy::default() })).await.unwrap();
        let EngineMessage::Status(status) = read_frame(&mut client).await.unwrap() else { panic!("a status answers SetPolicy") };
        assert!(status.policy.plain_dns, "the pipe's status holds the mode");
        assert_eq!(running.mode(), Mode::Plain, "the running service took it");
        e.stop_dns_service();
        assert_eq!(e.start_dns_service(service_from).unwrap().mode(), Mode::Plain, "a new service starts in it");
        e.write_status_file();
        let read = |file: &str| serde_json::from_slice::<serde_json::Value>(&std::fs::read(dir.path().join(file)).unwrap()).unwrap();
        assert_eq!((read(DNS_STATUS_FILE)["mode"].clone(), read(STATUS_FILE)["dns_mode"].clone()), ("plain".into(), "plain".into()));

        write_frame(&mut client, &ClientMessage::SetPolicy(Policy { revision: 2, ..Policy::default() })).await.unwrap();
        let _: EngineMessage = read_frame(&mut client).await.unwrap();
        assert_eq!(lock(&e.dns_service).as_ref().unwrap().mode(), Mode::Encrypted, "and back");
        drop(client);
        task.await.unwrap().unwrap();
        let reloaded = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), policy::load(dir.path()).0, Runs::default(), None);
        assert!(!reloaded.policy().plain_dns, "the saved policy is the last one");
    }

    #[tokio::test]
    async fn the_status_says_when_no_encrypted_resolver_answers_and_the_mode_stays() {
        use crate::dns::service::{Asker, Transport, UNREACHABLE_AFTER};
        let e = engine(Policy::default(), None);
        e.set_dns_upstreams(DnsUpstreams { revision: 1, upstreams: vec!["tls://127.0.0.1:1".into()] }).unwrap();
        let service = e.start_dns_service(service_from).unwrap();
        let asker = Asker { may_decrypt: true, addressed: "203.0.113.53".parse().unwrap(), dns_client: false };
        assert!(!e.status().dns_unreachable);
        for id in 0..UNREACHABLE_AFTER as u16 {
            service.answer(&crate::dns::testing::client_query(id, "www.example"), Transport::Datagram, asker).await.unwrap();
        }
        let status = e.status();
        assert!(status.dns_unreachable && !status.policy.plain_dns, "said, and still encrypted");
        assert_eq!(service.mode(), Mode::Encrypted);
        e.set_policy(Policy { revision: 1, plain_dns: true, ..Policy::default() }).unwrap();
        assert!(!e.status().dns_unreachable, "the user's plain mode is no encrypted failure");
    }

    #[test]
    fn a_policy_set_while_the_dns_service_starts_reaches_its_mode() {
        let e = Arc::new(engine(Policy::default(), None));
        let (answered, answer) = std::sync::mpsc::channel();
        let service = e
            .start_dns_service(|endpoints| {
                let pipe = e.clone();
                std::thread::spawn(move || answered.send(pipe.set_policy(Policy { revision: 1, plain_dns: true, ..Policy::default() })));
                assert!(answer.recv_timeout(OVERTAKE).is_err(), "the policy waits for the service to be installed");
                service_from(endpoints)
            })
            .unwrap();
        assert!(answer.recv().unwrap().unwrap().policy.plain_dns);
        assert_eq!(service.mode(), Mode::Plain);
    }

    #[test]
    fn packet_path_status_names_the_waiting_stage_without_flow_data() {
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None);
        assert!(e.status_value().unwrap()["packet_path"].is_null());
        let progress = Arc::new(ipstack::Progress::default());
        let offered = Arc::new(crate::watchdog::Offered::default());
        let mut path = crate::watchdog::PathWatch::new(offered.clone(), progress);
        offered.admit();
        Meters::bump(&e.meters.tun_write_dropped);
        Meters::bump(&e.meters.udp_too_big);
        assert!(path.check(0).is_none());
        assert_eq!(path.check(crate::watchdog::STALL_MS).unwrap().what, "TUN to ipstack queue");
        *lock(&e.beats.path) = Some(path);
        e.write_status_file();
        let status: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.path().join(STATUS_FILE)).unwrap()).unwrap();
        let path = &status["packet_path"];
        assert_eq!(path["offered"], 1);
        assert_eq!(path["received"], 0);
        assert_eq!(path["waiting_stage"], "TUN to ipstack queue");
        assert!(path["exit_reason"].is_null(), "the worker has not ended");
        assert!(path.as_object().unwrap().iter().all(|(key, value)| ["waiting_stage", "exit_reason"].contains(&key.as_str()) || value.is_u64() || value.is_boolean()));
        assert_eq!(status["counters"]["tun_write_dropped"], 1);
        assert_eq!((&status["counters"]["udp_too_big"], &status["counters"]["udp_too_big_unanswered"]), (&1.into(), &0.into()));
        let ipc = serde_json::to_value(e.status()).unwrap();
        assert!(ipc.get("packet_path").is_none() && ipc["counters"].get("tun_write_dropped").is_none(), "IPC unchanged");
        assert!(ipc["counters"].get("udp_too_big").is_none(), "IPC unchanged");
    }

    #[test]
    fn a_stale_policy_is_refused_and_a_newer_one_wakes_the_loop() {
        let e = engine(switches(2, false), None);
        assert!(e.set_policy(switches(2, true)).unwrap_err().contains("stale"));
        assert!(!e.policy().engine);
        let s = e.set_policy(switches(3, true)).unwrap();
        assert_eq!(s.policy, switches(3, true));
    }

    /// An engine that routes and blocks, whose `policy.json` cannot be written:
    /// a directory sits where `policy::save` puts its temporary file, as a held
    /// or refused file would. Removing that directory lets the save work again.
    fn engine_that_cannot_save(dir: &std::path::Path) -> Engine {
        let on = saved_on();
        policy::save(dir, &on).unwrap();
        std::fs::create_dir(dir.join(policy::POLICY_FILE).with_extension("tmp")).unwrap();
        policy::save(dir, &on).unwrap_err();
        let e = Engine::new(Some(dir.to_path_buf()), PathBuf::new(), on, Runs::default(), None);
        e.set_facts(|f| f.routes_up = true);
        assert!(e.status().blocking);
        assert_eq!(e.status().last_error, None);
        e
    }

    fn saved_on() -> Policy {
        use sieve_ipc::{DomainList, DomainListKind};
        let user = vec![DomainList { kind: DomainListKind::Block, entries: vec!["ads.example".into()], enabled: true }];
        Policy { revision: 1, engine: true, sieving: true, domain_lists: user, ..Policy::default() }
    }

    /// Fail-open: a full disk or a locked file must not keep the engine routing
    /// after the user said off. What ends routing is `run`'s own read of the
    /// policy on the wake (`control/routing.rs`, Windows, and it touches routes,
    /// so it does not run here): the wake and the switch it reads are pinned.
    #[tokio::test]
    async fn the_engine_switch_ends_routing_when_the_policy_cannot_be_saved() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine_that_cannot_save(dir.path());
        let answered = e.set_policy(Policy { revision: 2, engine: false, ..saved_on() }).expect("an off switch is never refused for a file");
        assert!(!answered.policy.engine, "the answer says what the engine now holds");
        assert!(!e.policy().engine, "the routing loop reads this on the wake");
        tokio::time::timeout(std::time::Duration::from_secs(5), e.wake.notified()).await.expect("the routing loop is woken");
        let reported = answered.last_error.expect("the failed save is reported");
        assert!(reported.contains("policy.tmp"), "the reason names the file: {reported}");
        assert!(reported.contains("restart"), "and what it costs: {reported}");
    }

    #[test]
    fn sieving_off_and_an_apps_off_reach_the_decision_when_the_policy_cannot_be_saved() {
        use crate::flow::flows::Action;
        let dir = tempfile::tempdir().unwrap();
        let e = engine_that_cannot_save(dir.path());
        assert_eq!(sees(&e, "ads.example", "browser"), Action::Drop);
        e.set_policy(Policy { revision: 2, off_apps: vec!["browser".into()], ..saved_on() }).unwrap();
        assert_eq!(sees(&e, "ads.example", "browser"), Action::Pass);
        assert_eq!(sees(&e, "ads.example", "other"), Action::Drop);
        e.set_policy(Policy { revision: 3, sieving: false, ..saved_on() }).unwrap();
        assert_eq!(sees(&e, "ads.example", "other"), Action::Pass);
    }

    /// Only the newest failure stands: the text travels in every Status, so a
    /// failure per click on a full disk must not grow it.
    #[test]
    fn a_failed_save_replaces_itself_hides_no_other_reason_and_ends_with_the_next_good_save() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine_that_cannot_save(dir.path());
        e.add_error("policy.json: broken".into());
        e.set_policy(Policy { revision: 2, engine: false, ..saved_on() }).unwrap();
        let once = e.status().last_error.unwrap();
        e.set_policy(Policy { revision: 3, engine: false, ..saved_on() }).unwrap();
        assert_eq!(e.status().last_error.unwrap(), once, "the same failure, said once");
        assert!(once.contains("policy.json: broken"), "{once}");
        assert_eq!(policy::load(dir.path()).0, saved_on(), "the file still holds the last good save");

        std::fs::remove_dir(dir.path().join(policy::POLICY_FILE).with_extension("tmp")).unwrap();
        let newest = Policy { revision: 4, engine: false, ..saved_on() };
        e.set_policy(newest.clone()).unwrap();
        assert_eq!(e.status().last_error.as_deref(), Some("policy.json: broken"), "that save worked: its reason is over");
        assert_eq!(policy::load(dir.path()), (newest, None));
    }

    /// What is refused is still refused, and changes nothing, whatever the file.
    #[test]
    fn a_stale_or_oversized_policy_is_still_refused_when_the_policy_cannot_be_saved() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine_that_cannot_save(dir.path());
        let stale = Policy { revision: 1, engine: false, ..saved_on() };
        assert!(e.set_policy(stale).unwrap_err().contains("stale"));
        let big = Policy { revision: 2, engine: false, off_apps: vec!["a".repeat(policy::MAX_POLICY_BYTES)], ..saved_on() };
        assert!(e.set_policy(big).unwrap_err().contains("over the"));
        assert_eq!(e.policy(), saved_on());
        assert_eq!(e.status().last_error, None, "nothing was attempted");
    }

    fn sees(e: &Engine, host: &str, key: &str) -> crate::flow::flows::Action {
        use crate::domain::{Flow, Owner};
        let flow = Flow { dns: false, name: Some(host), remote: "192.0.2.1".parse().unwrap(), owner: Owner::App { key } };
        e.filter.get().decide(flow, &e.names, 0).action
    }

    /// The acceptance chain through the policy: the user's rule blocks a
    /// sieved app, an Off change alone relays it with no recompile, and the
    /// global switch relays everyone.
    #[test]
    fn a_policy_change_reaches_the_decision_without_a_recompile() {
        use crate::flow::flows::Action;
        use sieve_ipc::{DomainList, DomainListKind};
        let user = vec![DomainList { kind: DomainListKind::Block, entries: vec!["ads.example".into()], enabled: true }];
        let e = engine(Policy { revision: 1, sieving: true, domain_lists: user.clone(), ..Policy::default() }, None);
        assert_eq!(sees(&e, "ads.example", "browser"), Action::Drop);
        assert_eq!(sees(&e, "news.example", "browser"), Action::Pass);
        let compiled = e.filter.get().rules.user.clone();
        e.set_policy(Policy { revision: 2, sieving: true, domain_lists: user.clone(), off_apps: vec!["browser".into()], ..Policy::default() }).unwrap();
        assert_eq!(sees(&e, "ads.example", "browser"), Action::Pass);
        assert_eq!(sees(&e, "ads.example", "other"), Action::Drop);
        assert!(Arc::ptr_eq(&compiled, &e.filter.get().rules.user), "nothing recompiled");
        e.set_policy(Policy { revision: 3, sieving: false, domain_lists: user, ..Policy::default() }).unwrap();
        assert_eq!(sees(&e, "ads.example", "other"), Action::Pass);
        e.set_policy(Policy { revision: 4, sieving: true, ..Policy::default() }).unwrap();
        assert_eq!(sees(&e, "ads.example", "other"), Action::Pass, "the rule went with the list");
    }

    /// What ends a decrypted flow of an app turned Off is `FilterSlot::until_off`
    /// (`tls/tests.rs`): `SetPolicy` is what reaches it, also on a full disk.
    #[tokio::test]
    async fn set_policy_reaches_what_a_decrypted_flow_waits_on() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine_that_cannot_save(dir.path());
        let browser = crate::domain::Owner::App { key: "browser" };
        let mut waiting = Box::pin(e.filter.until_off(browser));
        let wait = std::time::Duration::from_millis(20);
        assert!(tokio::time::timeout(wait, &mut waiting).await.is_err());
        e.set_policy(Policy { revision: 2, off_apps: vec!["browser".into()], ..saved_on() }).unwrap();
        tokio::time::timeout(wait, &mut waiting).await.expect("the row turned Off");
    }

    /// C2: the rules the log's actions and the Filters editor write reach the
    /// decision through SetPolicy, and a change to them recompiles the user's
    /// engine. Exclusions go to the store and compile nothing.
    #[test]
    fn user_rules_and_exclusions_travel_in_the_policy() {
        use crate::flow::flows::Action;
        let ruled = |revision, rules: &[&str]| Policy { revision, sieving: true, user_rules: rules.iter().map(|r| r.to_string()).collect(), ..Policy::default() };
        let e = engine(ruled(1, &["||ads.example^", "@@||ok.ads.example^"]), None);
        assert_eq!(sees(&e, "ads.example", "browser"), Action::Drop, "from the file, at start");
        assert_eq!(sees(&e, "ok.ads.example", "browser"), Action::Pass);
        let compiled = e.filter.get().rules.user.clone();
        let excluded = Policy { exclusions: vec!["bank.example".into()], ..ruled(2, &["||ads.example^", "@@||ok.ads.example^"]) };
        let answered = e.set_policy(excluded.clone()).unwrap();
        assert_eq!(answered.policy, excluded, "held and answered back");
        assert!(Arc::ptr_eq(&compiled, &e.filter.get().rules.user), "an exclusion compiles nothing");
        e.set_policy(ruled(3, &["||other.example^"])).unwrap();
        assert_eq!(sees(&e, "other.example", "browser"), Action::Drop);
        assert_eq!(sees(&e, "ads.example", "browser"), Action::Pass, "the old rule went");
        assert_eq!(sees(&e, "other.example", "off"), Action::Drop);
        e.set_policy(Policy { off_apps: vec!["off".into()], ..ruled(4, &["||other.example^"]) }).unwrap();
        assert_eq!(sees(&e, "other.example", "off"), Action::Pass, "off apps win over the user's rules");
    }

    #[test]
    fn a_policys_exclusions_reach_the_store_and_the_status_file_counts_without_a_host() {
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None);
        let ip = "192.0.2.1".parse().unwrap();
        let found = |e: &Engine| e.exclusions.get().find(Some("www.bank.example"), ip, None, true).cloned();
        assert_eq!(found(&e), None);
        e.set_policy(Policy { revision: 1, exclusions: vec!["bank.example".into()], ..Policy::default() }).unwrap();
        assert_eq!(found(&e), Some(sieve_filter::exclusions::Source::User));
        crate::stack::Meters::bump(&e.meters.https.intercepted);
        e.meters.https.upstream_groups[0].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        e.write_status_file();
        let text = std::fs::read_to_string(dir.path().join(STATUS_FILE)).unwrap();
        let status: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(status["https"]["intercepted"], 1);
        assert_eq!(status["https"]["upstream_groups"]["X25519MLKEM768"], 1);
        assert_eq!(status["https"]["client_groups"]["X25519"], 0);
        assert!(serde_json::to_value(e.status()).unwrap().get("https").is_none(), "IPC protocol unchanged");
    }

    #[test]
    fn status_reports_the_arm_and_holds_no_host() {
        const HOST: &str = "refused.example";
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None);
        e.meters.quic.refused(42, HOST, 1_000);
        e.meters.quic.tcp_seen(42, HOST, 1_037);
        e.meters.quic.refused(42, HOST, 2_000);
        e.write_status_file();
        let text = std::fs::read_to_string(dir.path().join(STATUS_FILE)).unwrap();
        assert!(!text.contains(HOST), "no host on disk");
        let status: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(status["quic"]["refusal"], "version_negotiation");
        assert_eq!(status["quic"]["refused"], 2);
        assert_eq!(status["quic"]["replies"], 0);
        assert_eq!(status["quic"]["send_failed"], 0);
        assert_eq!(status["quic"]["raced"], 0);
        assert_eq!(status["quic"]["fallback_ms"], serde_json::json!([37]));
        assert!(serde_json::to_value(e.status()).unwrap().get("quic").is_none(), "IPC protocol unchanged");
    }

    #[test]
    fn status_json_content_holds_no_host() {
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None);
        crate::stack::Meters::bump(&e.meters.content.rewritten);
        crate::stack::Meters::bump(&e.meters.content.with_scriptlets);
        const HOST: &str = "secret-host.example";
        {
            let mut book = lock(&e.book);
            let event = sieve_ipc::FlowEvent {
                id: 0,
                pid: None,
                exe: None,
                session: None,
                proto: sieve_ipc::FlowProto::Tcp,
                local: "198.18.0.1:5000".into(),
                remote: "192.0.2.1:443".into(),
                kind: sieve_ipc::FlowKind::Tls,
                host: Some(HOST.into()),
                action: sieve_ipc::FlowAction::Relayed,
                bytes_up: 0,
                bytes_down: 0,
                open: true,
                reason: None,
                rule: None,
                list: None,
                forwarded: None,
            };
            let id = book.open(event).unwrap();
            let url = format!("https://{HOST}/a.js");
            let row = crate::stack::book::RequestRow { url: &url, request_type: "script", outcome: sieve_ipc::LogOutcome::Blocked, rule: Some("||secret-host.example^"), list: Some("adguard-dns"), changes: Vec::new() };
            book.log_request(id, row, 1);
        }
        e.write_status_file();
        let text = std::fs::read_to_string(dir.path().join(STATUS_FILE)).unwrap();
        let status: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(status["content"]["rewritten"], 1);
        assert_eq!(status["content"]["with_scriptlets"], 1);
        assert_eq!(status["content"]["with_procedural"], 0);
        assert_eq!(status["content"]["resets"], 0);
        assert_eq!(status["content"]["list_hits"]["adguard-dns"], 1);
        assert!(!text.contains(HOST), "{text}");
        assert!(serde_json::to_value(e.status()).unwrap().get("content").is_none(), "not on the pipe");
    }

    /// Off closes every decrypted flow at once: it does not wait for the routing
    /// loop's next wake.
    #[cfg(windows)]
    #[test]
    fn turning_https_off_empties_the_slot_at_once() {
        use crate::tls::active::Active;
        use crate::tls::intercept::{Interception, NoWatch};
        use crate::tls::upstream::{PlatformTrust, TRUST_TIMEOUT, Verifier};
        use crate::tls::verdict::VerdictCache;
        let on = Policy { revision: 1, sieving: true, https: true, ..Policy::default() };
        let e = Engine::new(None, PathBuf::new(), on.clone(), Runs::default(), None);
        let egress = Arc::new(crate::stack::egress::Egress::new(0, Arc::new(std::sync::RwLock::new(crate::route::table::NetTables::default()))));
        let interception = Interception {
            connector: egress,
            exclusions: e.exclusions.clone(),
            verifier: Arc::new(Verifier::new(crate::tls::public_roots(), Arc::new(PlatformTrust::new().unwrap()), TRUST_TIMEOUT, e.validation.clone()).unwrap()),
            verdicts: VerdictCache::default(),
            ech: Arc::new(crate::tls::ech::EchCache::new(service_from(Vec::new()))),
            active: Active::default(),
            minter: Box::new(|| None),
            filter: e.filter.clone(),
            names: e.names.clone(),
            book: e.book.clone(),
            meters: e.meters.clone(),
            watch: Arc::new(NoWatch),
            hook: Arc::new(crate::http::hook::NoRewrite),
            clock: policy::wall_ms,
        };
        e.https.set(Some(Arc::new(interception)));
        e.set_policy(Policy { revision: 2, ..on.clone() }).unwrap();
        assert!(e.https.get().is_some(), "still wanted");
        e.set_policy(Policy { revision: 3, https: false, ..on.clone() }).unwrap();
        assert!(e.https.get().is_none(), "the switch off");
    }

    /// The real wiring: routing hands the interception the engine's `Heal`, not the
    /// plain watch, and `Heal` writes to the store the flows read.
    #[test]
    fn production_wires_heal_not_nowatch() {
        let routing = include_str!("routing.rs");
        let production = &routing[..routing.find("#[cfg(test)]").unwrap_or(routing.len())];
        assert!(production.contains("watch: engine.heal.clone(),"));
        assert!(!production.contains("NoWatch"));
        let e = Engine::new(None, PathBuf::new(), Policy::default(), Runs::default(), None);
        let pair = crate::tls::intercept::Pair { exe: Some(r"C:\Apps\Client.exe".into()), host: "pin.example".into(), session: Some(1) };
        use crate::tls::intercept::ClientWatch;
        e.heal.handshake_failed(&pair, Some(rustls::AlertDescription::UnknownCA));
        let ip = "192.0.2.1".parse().unwrap();
        assert!(e.exclusions.get().find(Some("pin.example"), ip, Some(r"C:\Apps\Client.exe"), true).is_some());
        assert!(e.exclusions.get().find(Some("pin.example"), ip, Some(r"C:\Apps\Other.exe"), true).is_none());
        assert_eq!(e.meters.https.report()["healed"], 1);
        let answer = e.heal_notices(0);
        assert_eq!((answer.revision, answer.notices.len()), (1, 1));
        assert_eq!(answer.exclusions_revision, e.exclusions.revision());
        assert_eq!(answer.run, e.heal.run());
        assert_eq!(e.exclusions().rows.iter().filter(|r| r.reason == "auto:pinning").count(), 1);
        e.try_decrypt_again(Retry::One { pattern: sieve_filter::exclusions::Pattern::Exact("pin.example".into()), app: Some("client.exe".into()), reason: sieve_filter::exclusions::AutoReason::Pinning });
        assert_eq!(e.exclusions().rows.iter().filter(|r| r.reason == "auto:pinning").count(), 0);
    }

    #[test]
    fn a_policy_file_with_rules_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let on_disk = Policy { revision: 1, sieving: true, user_rules: vec!["||ads.example^".into()], exclusions: vec!["bank.example".into()], ..Policy::default() };
        Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy::default(), Runs::default(), None).set_policy(on_disk.clone()).unwrap();
        assert_eq!(policy::load(dir.path()), (on_disk, None));
    }

    /// C1: one batch carries flows and rows to subscribers, and a decision made
    /// with the switch off leaves no row.
    #[test]
    fn a_subscriber_gets_log_rows_with_the_batch() {
        use crate::domain::{Decision, Reason};
        use crate::flow::flows::Action;
        let e = engine(Policy::default(), None);
        let Subscription { log: mut rows, .. } = e.subscribe();
        let id = e.book.lock().unwrap().open(crate::stack::book::tests_event(Some(1))).unwrap();
        let decided = Decision { action: Action::Drop, reason: Reason::NamedBlock, rule: Some("||ads.example^".into()), list: Some("user".into()) };
        e.book.lock().unwrap().log_decision(id, &decided, 5);
        e.publish_batch();
        let batch = rows.try_recv().unwrap();
        assert_eq!(batch.iter().map(|r| (r.flow_id, r.t, r.list.as_deref())).collect::<Vec<_>>(), [(id, 5, Some("user"))]);
        e.publish_batch();
        assert!(rows.try_recv().is_err(), "no empty batch");
    }

    /// C1: what the Engine block and the report read. Nothing until the lists
    /// compiled, then each selected list with its counts, and what the app reads
    /// back through `lists` stays the same counts.
    #[tokio::test]
    async fn the_status_says_what_the_engine_filters_with() {
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::new(Some(dir.path().to_path_buf()), PathBuf::new(), Policy { revision: 1, sieving: true, lists: Some(vec!["adguard-dns".into()]), ..Policy::default() }, Runs::default(), None);
        assert_eq!(e.status().filter, None, "no compile yet: no facts");
        crate::lists::cache::Cache::new(dir.path()).write_text("adguard-dns", "! Version: 2026.11.1\n||ads.example^\n||b.example^\nnot/a/$bad-option\n").unwrap();
        e.lists.compile_and_swap().await;
        let facts = e.status().filter.unwrap();
        assert_eq!(facts.resource_pin, None, "no bundle in this folder");
        let [fact] = facts.lists.as_slice() else { panic!("{facts:?}") };
        assert_eq!((fact.id.as_str(), fact.version.as_deref(), fact.applied), ("adguard-dns", Some("2026.11.1"), 2));
        assert_eq!(fact.title, sieve_filter::catalogue::find("adguard-dns").unwrap().title);
        assert_eq!(fact.homepage, sieve_filter::catalogue::find("adguard-dns").unwrap().homepage);
        let (rows, _) = Backend::lists(&e);
        let row = rows.iter().find(|r| r.id == fact.id).unwrap();
        assert_eq!((row.network, row.skipped), (fact.applied, fact.skipped));
    }

    #[test]
    fn blocking_is_its_own_fact_and_routing_alone_does_not_claim_it() {
        use sieve_ipc::{DomainList, DomainListKind};
        let user = vec![DomainList { kind: DomainListKind::Block, entries: vec!["ads.example".into()], enabled: true }];
        let e = engine(Policy { revision: 1, sieving: true, ..Policy::default() }, None);
        e.set_facts(|f| f.routes_up = true);
        let s = e.status();
        assert!(s.filtering && !s.blocking, "routes up, but no rule yet");
        e.set_policy(Policy { revision: 2, sieving: true, domain_lists: user, ..Policy::default() }).unwrap();
        assert!(e.status().blocking);
        e.set_facts(|f| f.routes_up = false);
        assert!(!e.status().blocking, "no routes, nothing can be blocked");
    }

    #[test]
    fn the_report_lists_every_catalogue_row_and_the_users_rules() {
        let (rows, compile_ms) = Backend::lists(&engine(Policy::default(), None));
        assert_eq!(rows.len(), sieve_filter::catalogue::LISTS.len() + 1);
        assert_eq!(rows.last().unwrap().id, sieve_filter::rules::USER_LIST);
        assert_eq!(compile_ms, None);
    }

    #[test]
    fn a_crash_loop_blocks_until_the_user_turns_the_engine_on_again() {
        let e = engine(switches(1, true), Some(3));
        assert_eq!(e.status().blocker, Some(Blocker::CrashLoop { starts: 3 }));
        e.set_policy(switches(2, false)).unwrap();
        assert_eq!(e.status().blocker, None, "off: nothing to explain");
        assert_eq!(e.crash_loop(), Some(3), "turning off does not forgive");
        e.set_policy(switches(3, true)).unwrap();
        assert_eq!(e.crash_loop(), None);
        assert_eq!(e.status().blocker, None);
    }

    /// A build with no worker: nothing to report and nothing queued.
    #[test]
    fn an_engine_without_an_updater_answers_not_configured() {
        let e = engine(Policy::default(), None);
        assert_eq!(e.status().update, sieve_ipc::UpdateStatus::NotConfigured);
        assert_eq!(e.request_update().unwrap().update, sieve_ipc::UpdateStatus::NotConfigured);
    }

    /// `status.json` tells no one on the app's screen: only an answer on the pipe
    /// makes a release one the next request may install.
    #[test]
    fn only_an_answer_on_the_pipe_shows_a_release_to_the_user() {
        let e = engine(Policy::default(), None);
        let (jobs, queued) = std::sync::mpsc::channel();
        e.updates.attach(jobs);
        let available = sieve_ipc::UpdateStatus::Available { version: "0.2.0".into() };
        e.updates.set_status(available.clone());

        e.write_status_file();
        assert_eq!(e.request_update().unwrap().update, available, "unasked: the answer shows it");
        assert!(queued.try_recv().is_err(), "and nothing was queued");

        e.request_update().unwrap();
        assert_eq!(queued.try_recv(), Ok(crate::update::cycle::Job::Apply { shown: "0.2.0".into() }), "the answer above told the user");
    }

    #[test]
    fn a_routing_engine_reports_routes_and_split_tunnels() {
        let e = engine(switches(1, true), None);
        e.set_facts(|f| {
            f.routes_up = true;
            f.split_tunnels = vec!["Corp VPN".into()];
        });
        let s = e.status();
        assert!(s.routes_up && s.filtering && !s.decrypting);
        assert_eq!(s.split_tunnels, ["Corp VPN"]);
    }

    #[test]
    fn the_status_carries_the_books_guests() {
        let e = engine(Policy::default(), None);
        assert!(e.status().guests.is_empty(), "no forwarded traffic, no group");
        let guest = sieve_ipc::FlowEvent {
            pid: None,
            exe: None,
            forwarded: Some(sieve_ipc::Forwarded { vm: Some("DevBox".into()) }),
            ..crate::stack::book::tests_event(None)
        };
        e.book.lock().unwrap().open(guest).unwrap();
        let s = e.status();
        assert_eq!(s.flows, 1);
        assert_eq!(s.guests.iter().map(|g| (g.key.as_str(), g.open)).collect::<Vec<_>>(), [("vm:devbox", 1)]);
    }

    #[test]
    fn a_subscriber_gets_the_open_flows_then_every_batch() {
        let e = engine(Policy::default(), None);
        let first = e.book.lock().unwrap().open(crate::stack::book::tests_event(Some(1))).unwrap();
        let Subscription { open, batches: mut rx, routes_up, .. } = e.subscribe();
        assert!(!*routes_up.borrow());
        e.set_facts(|f| f.routes_up = true);
        assert!(*routes_up.borrow(), "subscribers see the routes come up");
        assert_eq!(open.iter().map(|f| f.id).collect::<Vec<_>>(), [first]);
        e.book.lock().unwrap().close(first, sieve_ipc::FlowAction::Relayed, 1, 2);
        e.publish_batch();
        let batch = rx.try_recv().unwrap();
        assert_eq!(batch.iter().map(|f| (f.id, f.open, f.bytes_down)).collect::<Vec<_>>(), [(first, false, 2)]);
    }
}
