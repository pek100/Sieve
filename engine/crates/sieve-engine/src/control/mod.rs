//! The running engine's state and the one place its facts come from
//! (plan 1.6): the policy it holds, why it does not route, the routes, the
//! flow book and the counters. The pipe reads it ([`crate::ipc::Backend`]);
//! the routing loop (`routing`, Windows) writes it.
//!
//! Turning the engine on through `SetPolicy` after a crash loop forgives
//! the earlier failures (the user's explicit act, plan 1.6.4).

#[cfg(windows)]
pub mod routing;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use sieve_filter::rules::{RuleEngine, RuleSet};
use sieve_ipc::{Blocker, DnsUpstreams, EngineStatus, FlowEvent, ListStatus, Policy};
use tokio::sync::{Notify, broadcast, watch};

use crate::dns::service::Service;
use crate::dns::upstream::Upstream;
use crate::dns::{NameMap, config};
use crate::domain::{DomainFilter, FilterSlot, user_engine};
use crate::ipc::{Backend, Subscription};
use crate::lists::Lists;
use crate::policy::{self, Runs};
use crate::stack::Meters;
use crate::stack::book::FlowBook;
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
    /// When the routes came up (monotonic ms), for the Stall test build.
    pub up_since: Option<u64>,
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
    pub flows: broadcast::Sender<Arc<Vec<FlowEvent>>>,
    /// Whether routes are up, for subscriptions (they end when it turns false).
    routes_up: watch::Sender<bool>,
    /// Wakes the routing loop: a policy change or a route change.
    pub wake: Arc<Notify>,
    pub beats: Arc<Beats>,
    pub arm: Arc<Arm>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
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
        let rules = RuleSet { user: Arc::new(user_engine(&policy)), lists: Arc::new(RuleEngine::empty()) };
        let filter = Arc::new(FilterSlot::new(DomainFilter::new(&policy, rules)));
        let lists = Arc::new(Lists::new(dir.as_deref(), filter.clone(), policy.lists.clone()));
        let (dns_upstreams, unused_dns_file) = dir.as_deref().map(config::load).unwrap_or_else(|| (config::defaults(), None));
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
            meters: Arc::default(),
            filter,
            lists,
            flows: broadcast::channel(FLOWS_BACKLOG).0,
            routes_up: watch::channel(false).0,
            wake: Arc::default(),
            beats: Arc::default(),
            arm: Arc::default(),
        }
    }

    pub fn policy(&self) -> Policy {
        lock(&self.policy).clone()
    }

    /// A changed policy reaches the decision: an Off-app or switch change
    /// recompiles nothing, the user's rules recompile their small engine, and
    /// a new list selection wakes the refresh task.
    fn apply_to_filter(&self, before: &Policy, now: &Policy) {
        let user = (before.domain_lists != now.domain_lists).then(|| Arc::new(user_engine(now)));
        self.filter.update(|f| {
            let rules = RuleSet { user: user.unwrap_or_else(|| f.rules.user.clone()), lists: f.rules.lists.clone() };
            DomainFilter::new(now, rules)
        });
        self.lists.set_selection(now.lists.clone());
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

    /// The encrypted DNS resolvers the engine holds.
    pub fn dns_upstreams(&self) -> DnsUpstreams {
        lock(&self.dns_upstreams).clone()
    }

    /// Builds the DNS service from the held list and installs it, all under the
    /// list's lock: a list set on the pipe reaches either the build or the
    /// installed service, so what the pipe answers is what the service uses.
    pub fn start_dns_service(&self, build: impl FnOnce(Vec<Upstream>) -> Arc<Service>) -> Result<Arc<Service>, String> {
        let held = lock(&self.dns_upstreams);
        let service = build(config::validate(&held)?);
        *lock(&self.dns_service) = Some(service.clone());
        Ok(service)
    }

    pub fn stop_dns_service(&self) {
        *lock(&self.dns_service) = None;
    }

    /// Records this run's clean end (the service was asked to stop).
    pub fn stop_clean(&self) {
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
        let json = serde_json::to_vec_pretty(&self.status());
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

    /// Beside `status.json`: an empty list while nothing is up, so an old fact
    /// is never read as a current one. Best effort.
    fn write_dns_status_file(&self) {
        let Some(dir) = &self.dir else { return };
        let upstreams = lock(&self.dns_service).as_ref().map(|s| s.report()).unwrap_or_default();
        if let Ok(json) = serde_json::to_vec_pretty(&serde_json::json!({ "upstreams": upstreams })) {
            let _ = policy::write_atomic(&dir.join(DNS_STATUS_FILE), &json);
        }
    }

    #[cfg(feature = "relay-experiments")]
    fn experimental_status_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut status = serde_json::to_value(self.status())?;
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

    /// The next batch of changed flows, sent to every subscriber.
    pub fn publish_batch(&self) {
        let batch = lock(&self.book).take_batch();
        if !batch.is_empty() {
            let _ = self.flows.send(Arc::new(batch));
        }
    }
}

impl Backend for Engine {
    fn status(&self) -> EngineStatus {
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
        EngineStatus {
            filtering: f.routes_up,
            routes_up: f.routes_up,
            blocking: f.routes_up && self.filter.get().blocks_anything(),
            flows: u32::try_from(live).unwrap_or(u32::MAX),
            decrypting: false,
            last_error: beside(beside(beside(f.last_error, f.dns_file_error), f.route_error), self.lists.compile_error()),
            policy,
            blocker,
            split_tunnels: f.split_tunnels,
            counters: self.meters.counters(),
            guests,
            filter: None,
        }
    }

    fn set_policy(&self, asked: Policy) -> Result<EngineStatus, String> {
        {
            let mut current = lock(&self.policy);
            let next = policy::accept(&current, asked)?;
            if let Some(dir) = &self.dir {
                policy::save(dir, &next)?;
            }
            if next.engine && !current.engine && lock(&self.crash_loop).take().is_some() {
                let mut runs = lock(&self.runs);
                runs.forgive();
                if let Some(dir) = &self.dir {
                    let _ = policy::save_runs(dir, &runs);
                }
            }
            self.apply_to_filter(&current, &next);
            *current = next;
        }
        self.wake.notify_one();
        Ok(self.status())
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

    fn subscribe(&self) -> Subscription {
        let book = lock(&self.book);
        // Subscribed under the book's lock: no batch slips between the two.
        Subscription { open: book.snapshot(), batches: self.flows.subscribe(), routes_up: self.routes_up.subscribe() }
    }

    fn lists(&self) -> (Vec<ListStatus>, Option<u64>) {
        self.lists.report()
    }

    fn lists_refresh(&self) {
        self.lists.refresh_now();
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
        write_frame(&mut client, &ClientMessage::Hello { protocol: PROTOCOL, app_version: "0.1.0".into() }).await.unwrap();
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

    #[test]
    fn a_route_failure_alone_is_the_whole_reason() {
        let e = engine(Policy::default(), None);
        e.route_failed("route 10.0.0.0/8: code 5".into());
        assert_eq!(e.status().last_error.as_deref(), Some("route 10.0.0.0/8: code 5"));
    }

    fn service_from(endpoints: Vec<Upstream>) -> Arc<Service> {
        use crate::route::table::fixtures::{HOME, load};
        let context = crate::dns::testing::Ca::new().context(Arc::default(), Vec::new());
        Arc::new(Service::new(endpoints, context, Arc::new(std::sync::RwLock::new(load(HOME))), Arc::default(), Arc::default(), usize::from(crate::tun::MTU)))
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
    }

    #[test]
    fn a_stale_policy_is_refused_and_a_newer_one_wakes_the_loop() {
        let e = engine(switches(2, false), None);
        assert!(e.set_policy(switches(2, true)).unwrap_err().contains("stale"));
        assert!(!e.policy().engine);
        let s = e.set_policy(switches(3, true)).unwrap();
        assert_eq!(s.policy, switches(3, true));
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
        let Subscription { open, batches: mut rx, routes_up } = e.subscribe();
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
