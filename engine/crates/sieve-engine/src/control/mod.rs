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

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use sieve_ipc::{Blocker, CertStatus, EngineStatus, FlowEvent, Policy};
use tokio::sync::{Notify, broadcast, watch};

use crate::ca::Ca;
use crate::dns::NameMap;
use crate::ipc::{Backend, Subscription};
use crate::policy::{self, Runs};
use crate::stack::Meters;
use crate::stack::book::FlowBook;
use crate::watchdog::{Arm, Beats};

/// Batches a slow client may fall behind by before it is disconnected (it
/// then reconnects and gets the open flows again).
pub const FLOWS_BACKLOG: usize = 64;

/// The engine's Status for an admin prompt (`scripts/live/engine-route.ps1`).
pub const STATUS_FILE: &str = "status.json";
/// While routes are up, `status.json` is rewritten this often.
pub const STATUS_FILE_EVERY_MS: u64 = 30_000;

/// What the routing loop reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    pub routes_up: bool,
    pub blocker: Option<Blocker>,
    pub split_tunnels: Vec<String>,
    pub last_error: Option<String>,
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
    pub book: Arc<Mutex<FlowBook>>,
    pub names: Arc<Mutex<NameMap>>,
    pub meters: Arc<Meters>,
    pub flows: broadcast::Sender<Arc<Vec<FlowEvent>>>,
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
}

/// `install_root`'s refusal while the switch is off (plan 7.3: no root
/// without the user's act, and the act here is the switch).
pub const HTTPS_OFF: &str = "HTTPS filtering is off, so there is no certificate to reinstall";
pub const NO_CA: &str = "the certificate service did not start";

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Engine {
    pub fn new(dir: Option<PathBuf>, exe: PathBuf, policy: Policy, runs: Runs, crash_loop: Option<u32>) -> Self {
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
            facts: Mutex::new(Facts::default()),
            book: Arc::default(),
            names: Arc::default(),
            meters: Arc::default(),
            flows: broadcast::channel(FLOWS_BACKLOG).0,
            routes_up: watch::channel(false).0,
            wake: Arc::default(),
            beats: Arc::default(),
            arm: Arc::default(),
            ca: OnceLock::new(),
            ca_wake: Notify::new(),
            reinstall: AtomicBool::new(false),
        }
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
        *lock(&self.policy)
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
        EngineStatus {
            filtering: f.routes_up,
            routes_up: f.routes_up,
            flows: u32::try_from(lock(&self.book).live()).unwrap_or(u32::MAX),
            decrypting: false,
            last_error: f.last_error,
            policy,
            blocker,
            split_tunnels: f.split_tunnels,
            counters: self.meters.counters(),
        }
    }

    fn set_policy(&self, asked: Policy) -> Result<EngineStatus, String> {
        {
            let mut current = lock(&self.policy);
            let next = policy::accept(*current, asked)?;
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
            *current = next;
        }
        self.wake.notify_one();
        self.ca_wake.notify_one();
        Ok(self.status())
    }

    fn subscribe(&self) -> Subscription {
        let book = lock(&self.book);
        // Subscribed under the book's lock: no batch slips between the two.
        Subscription { open: book.snapshot(), batches: self.flows.subscribe(), routes_up: self.routes_up.subscribe() }
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

    #[test]
    fn a_stale_policy_is_refused_and_a_newer_one_wakes_the_loop() {
        let e = engine(Policy { revision: 2, engine: false, ..Policy::default() }, None);
        assert!(e.set_policy(Policy { revision: 2, engine: true, ..Policy::default() }).unwrap_err().contains("stale"));
        assert!(!e.policy().engine);
        let s = e.set_policy(Policy { revision: 3, engine: true, ..Policy::default() }).unwrap();
        assert_eq!(s.policy, Policy { revision: 3, engine: true, ..Policy::default() });
    }

    #[test]
    fn a_crash_loop_blocks_until_the_user_turns_the_engine_on_again() {
        let e = engine(Policy { revision: 1, engine: true, ..Policy::default() }, Some(3));
        assert_eq!(e.status().blocker, Some(Blocker::CrashLoop { starts: 3 }));
        e.set_policy(Policy { revision: 2, engine: false, ..Policy::default() }).unwrap();
        assert_eq!(e.status().blocker, None, "off: nothing to explain");
        assert_eq!(e.crash_loop(), Some(3), "turning off does not forgive");
        e.set_policy(Policy { revision: 3, engine: true, ..Policy::default() }).unwrap();
        assert_eq!(e.crash_loop(), None);
        assert_eq!(e.status().blocker, None);
    }

    #[test]
    fn a_routing_engine_reports_routes_and_split_tunnels() {
        let e = engine(Policy { revision: 1, engine: true, ..Policy::default() }, None);
        e.set_facts(|f| {
            f.routes_up = true;
            f.split_tunnels = vec!["Corp VPN".into()];
        });
        let s = e.status();
        assert!(s.routes_up && s.filtering && !s.decrypting);
        assert_eq!(s.split_tunnels, ["Corp VPN"]);
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
