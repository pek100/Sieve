//! The engine: one running filter = rules (list plus user rules) + proxy +
//! an hourly refresher. Tauri-free, so tests drive the same start, status,
//! self check and stop the commands call. Time and the network come in as
//! `Clock` and `Fetcher`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::task::JoinHandle;

use super::DnsError;
use super::lists::{self, Fetcher};
use super::probe::{self, KNOWN_GOOD_NAME, SelfCheck};
use super::proxy::{Proxy, ProxyConfig, SharedRules, UPSTREAM_TIMEOUT_MS};
use super::rules::RuleSet;
use super::status::{Counters, DNS_STATUS_VERSION, DnsStatus, DomainCount, ListInfo};

/// How often the refresher looks at the list age. The list itself is only
/// downloaded when older than `lists::MAX_AGE_MS`; each check also re-reads
/// the user rules file.
pub const REFRESH_CHECK_MS: u64 = 60 * 60 * 1000;

/// Milliseconds since the Unix epoch.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The system clock (glue only; the engine takes any `Clock`).
pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    })
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Listen addresses (default `proxy::DEFAULT_BINDS`: 127.0.0.1:53 and [::1]:53).
    pub binds: Vec<SocketAddr>,
    pub upstreams: Vec<SocketAddr>,
    pub list_url: String,
    /// Where the list cache and `user-rules.txt` live.
    pub data_dir: PathBuf,
}

pub struct Engine {
    config: EngineConfig,
    proxy: Proxy,
    started_at: u64,
    list: Arc<Mutex<ListInfo>>,
    refresher: JoinHandle<()>,
}

impl Engine {
    pub async fn start(config: EngineConfig, fetch: Fetcher, clock: Clock) -> Result<Engine, DnsError> {
        let started_at = clock();
        let (rules, info) = load_rules(&config, started_at, &fetch).await;
        let proxy = Proxy::start(
            ProxyConfig {
                binds: config.binds.clone(),
                upstreams: config.upstreams.clone(),
                upstream_timeout: Duration::from_millis(UPSTREAM_TIMEOUT_MS),
            },
            rules,
        )
        .await?;
        let list = Arc::new(Mutex::new(info));
        let refresher = tokio::spawn(refresh_loop(
            config.clone(),
            proxy.rules(),
            list.clone(),
            fetch,
            clock,
        ));
        Ok(Engine { config, proxy, started_at, list, refresher })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.proxy.local_addr()
    }

    pub fn local_addrs(&self) -> &[SocketAddr] {
        self.proxy.local_addrs()
    }

    pub fn status(&self) -> DnsStatus {
        let s = self.proxy.stats();
        DnsStatus {
            v: DNS_STATUS_VERSION,
            running: true,
            pass_through: self.proxy.pass_through(),
            binds: self.proxy.local_addrs().iter().map(SocketAddr::to_string).collect(),
            started_at: Some(self.started_at),
            upstreams: self.config.upstreams.iter().map(SocketAddr::to_string).collect(),
            counters: Counters {
                queries: s.queries,
                blocked: s.blocked,
                forwarded: s.forwarded,
                failed: s.failed,
                untracked: s.untracked,
            },
            last_error: s.last_error,
            list: self.list.lock().unwrap_or_else(PoisonError::into_inner).clone(),
            top_blocked: s
                .top_blocked
                .into_iter()
                .map(|(domain, count)| DomainCount { domain, count })
                .collect(),
        }
    }

    /// Forward every lookup and block nothing (true), or filter again
    /// (false). The global Sieving switch off sets it; the proxy keeps
    /// answering, so Windows DNS pointed here keeps working.
    pub fn set_pass_through(&self, on: bool) {
        self.proxy.set_pass_through(on);
    }

    /// Asks the running proxy, on every listen address, for the canary
    /// (`rules::CANARY_NAME`) and for `KNOWN_GOOD_NAME`, and fails when no
    /// block rule is loaded. The canary is never counted; the good name is
    /// one forwarded lookup per listen address.
    pub async fn self_check(&self) -> SelfCheck {
        let block_rules = current(&self.proxy.rules()).counts().block;
        probe::self_check(self.proxy.local_addrs(), block_rules, KNOWN_GOOD_NAME).await
    }

    /// One refresh pass now (the refresher calls the same function).
    pub async fn refresh(&self, fetch: &Fetcher, now: u64) {
        refresh_once(&self.config, &self.proxy.rules(), &self.list, fetch, now).await;
    }

    pub async fn stop(self) {
        self.refresher.abort();
        self.proxy.stop().await;
    }
}

fn current(rules: &SharedRules) -> Arc<RuleSet> {
    rules.read().unwrap_or_else(PoisonError::into_inner).clone()
}

/// The one path from disk and network to rules plus their list info.
async fn load_rules(config: &EngineConfig, now: u64, fetch: &Fetcher) -> (RuleSet, ListInfo) {
    let load = lists::load(&config.data_dir, &config.list_url, now, fetch).await;
    let (user, user_error) = match lists::read_user_rules(&config.data_dir) {
        Ok(text) => (text, None),
        Err(e) => (String::new(), Some(e.to_string())),
    };
    let rules = lists::build_rules(load.list.as_ref().map(|c| c.text.as_str()), &user);
    let counts = rules.counts();
    let info = ListInfo {
        url: Some(config.list_url.clone()),
        fetched_at: load.list.as_ref().map(|c| c.fetched_at),
        rules: counts.block,
        allow: counts.allow,
        skipped: counts.skipped,
        user_rules: !user.trim().is_empty(),
        error: load.error.or(user_error),
    };
    (rules, info)
}

async fn refresh_once(
    config: &EngineConfig,
    rules: &SharedRules,
    list: &Mutex<ListInfo>,
    fetch: &Fetcher,
    now: u64,
) {
    let (next, info) = load_rules(config, now, fetch).await;
    *rules.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(next);
    *list.lock().unwrap_or_else(PoisonError::into_inner) = info;
}

async fn refresh_loop(
    config: EngineConfig,
    rules: SharedRules,
    list: Arc<Mutex<ListInfo>>,
    fetch: Fetcher,
    clock: Clock,
) {
    loop {
        tokio::time::sleep(Duration::from_millis(REFRESH_CHECK_MS)).await;
        refresh_once(&config, &rules, &list, &fetch, clock()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::super::lists::{MAX_AGE_MS, USER_RULES_FILE, write_cache};
    use super::super::probe::{CheckKind, is_block_answer, is_resolved, query_a};
    use super::super::proxy::DEFAULT_UPSTREAMS;
    use super::super::proxy::tests::FakeUpstream;
    use super::super::rules::CANARY_NAME;
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    const URL: &str = "https://lists.example.invalid/filter.txt";
    const FIXTURE: &str = "! Sieve test list\n||ads.sieve-test.invalid^\n||doubleclick.net^\n";
    const T0: u64 = 1_800_000_000_000;

    fn fetch_ok(text: &'static str) -> Fetcher {
        Arc::new(move |_| Box::pin(async move { Ok(text.to_owned()) }))
    }

    fn fetch_offline() -> Fetcher {
        Arc::new(|_| Box::pin(async { Err("offline (test)".to_owned()) }))
    }

    fn fixed_clock(t: u64) -> Clock {
        let now = Arc::new(AtomicU64::new(t));
        Arc::new(move || now.load(Ordering::SeqCst))
    }

    fn config(dir: &std::path::Path, upstreams: Vec<SocketAddr>) -> EngineConfig {
        EngineConfig {
            binds: vec!["127.0.0.1:0".parse().expect("addr")],
            upstreams,
            list_url: URL.to_owned(),
            data_dir: dir.to_path_buf(),
        }
    }

    #[tokio::test]
    async fn start_status_self_check_stop() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(USER_RULES_FILE), "||mine.example.org^\n").expect("write");
        let up = FakeUpstream::start(false).await;
        let engine = Engine::start(config(dir.path(), vec![up.addr]), fetch_ok(FIXTURE), fixed_clock(T0))
            .await
            .expect("start");
        let s = engine.status();
        assert!(s.running);
        assert_eq!(s.binds, vec![engine.local_addr().to_string()]);
        assert_eq!(s.started_at, Some(T0));
        assert_eq!(s.upstreams, vec![up.addr.to_string()]);
        assert_eq!(s.list.fetched_at, Some(T0));
        assert_eq!((s.list.rules, s.list.allow, s.list.skipped), (3, 0, 0));
        assert!(s.list.user_rules);
        assert_eq!(s.list.error, None);

        let check = engine.self_check().await;
        assert!(check.pass, "{check:?}");
        assert_eq!(check.checks[0].name, CANARY_NAME);
        let s = engine.status();
        assert_eq!(
            (s.counters.queries, s.counters.blocked, s.counters.forwarded),
            (1, 0, 1),
            "the canary is in no user-facing counter; the normal name is one forwarded lookup"
        );
        assert!(s.top_blocked.is_empty(), "the canary is not a top blocked domain");

        let addr = engine.local_addr();
        engine.stop().await;
        std::net::UdpSocket::bind(addr).expect("port free after stop");
    }

    #[tokio::test]
    async fn pass_through_forwards_a_blocked_name_and_says_so_in_the_status() {
        let dir = tempfile::tempdir().expect("tempdir");
        let up = FakeUpstream::start(false).await;
        let engine = Engine::start(config(dir.path(), vec![up.addr]), fetch_ok(FIXTURE), fixed_clock(T0))
            .await
            .expect("start");
        let addr = engine.local_addr();
        assert!(!engine.status().pass_through);
        let m = query_a(addr, "doubleclick.net").await.expect("answer");
        assert!(is_block_answer(&m), "filtering by default");

        engine.set_pass_through(true);
        let s = engine.status();
        assert!(s.running && s.pass_through, "still running, passing through");
        let blocked_before = s.counters.blocked;
        let m = query_a(addr, "doubleclick.net").await.expect("answer");
        assert!(is_resolved(&m), "a blocked name is forwarded while passing through");
        assert_eq!(engine.status().counters.blocked, blocked_before, "nothing counted as blocked");

        engine.set_pass_through(false);
        assert!(!engine.status().pass_through);
        let m = query_a(addr, "doubleclick.net").await.expect("answer");
        assert!(is_block_answer(&m), "filtering again");
        engine.stop().await;
    }

    #[tokio::test]
    async fn offline_start_uses_the_cache_and_reports_the_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_cache(dir.path(), URL, FIXTURE, T0).expect("write");
        let up = FakeUpstream::start(false).await;
        let engine = Engine::start(
            config(dir.path(), vec![up.addr]),
            fetch_offline(),
            fixed_clock(T0 + 2 * MAX_AGE_MS),
        )
        .await
        .expect("start");
        let s = engine.status();
        assert_eq!(s.list.fetched_at, Some(T0));
        assert_eq!(s.list.rules, 2);
        assert_eq!(s.list.error.as_deref(), Some("offline (test)"));
        engine.stop().await;
    }

    #[tokio::test]
    async fn offline_first_start_runs_without_a_list_and_self_check_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let up = FakeUpstream::start(false).await;
        let engine = Engine::start(config(dir.path(), vec![up.addr]), fetch_offline(), fixed_clock(T0))
            .await
            .expect("start");
        let s = engine.status();
        assert_eq!((s.list.fetched_at, s.list.rules), (None, 0));
        assert!(s.list.error.is_some());
        let check = engine.self_check().await;
        assert!(!check.pass);
        assert_eq!(check.checks[0].kind, CheckKind::Rules);
        assert_eq!(check.checks[0].got, "no block rule is loaded");
        engine.stop().await;
    }

    #[tokio::test]
    async fn refresh_swaps_in_a_newer_list_and_user_rule_edits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let up = FakeUpstream::start(false).await;
        let engine = Engine::start(config(dir.path(), vec![up.addr]), fetch_ok(FIXTURE), fixed_clock(T0))
            .await
            .expect("start");
        let addr = engine.local_addr();
        std::fs::write(dir.path().join(USER_RULES_FILE), "@@||doubleclick.net^\n").expect("write");
        let later = T0 + MAX_AGE_MS;
        engine.refresh(&fetch_ok("||example.com^\n"), later).await;
        let s = engine.status();
        assert_eq!(s.list.fetched_at, Some(later));
        assert_eq!((s.list.rules, s.list.allow), (1, 1));
        let m = query_a(addr, "example.com").await.expect("answer");
        assert!(is_block_answer(&m));
        let m = query_a(addr, "doubleclick.net").await.expect("answer");
        assert!(is_resolved(&m), "allowed by the user rule, forwarded");
        engine.stop().await;
    }

    /// Live check for the `filtering.dns` data switch. Starts the engine on
    /// 127.0.0.1:0 with a fixture list (never downloaded) and the real
    /// default upstreams, then asks it over UDP. Sends DNS queries to
    /// 1.1.1.1 and 9.9.9.9 only; changes nothing on the machine.
    #[tokio::test]
    #[ignore = "live: needs the network (DNS to 1.1.1.1 / 9.9.9.9)"]
    async fn live_dns_filter_resolves_blocked_domain() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_cache(dir.path(), URL, FIXTURE, T0).expect("write fixture list");
        let upstreams: Vec<SocketAddr> =
            DEFAULT_UPSTREAMS.iter().map(|u| u.parse().expect("default upstream")).collect();
        let engine = Engine::start(config(dir.path(), upstreams), fetch_offline(), fixed_clock(T0))
            .await
            .expect("start");
        let addr = engine.local_addr();
        println!("proxy on {addr}, list rules {}", engine.status().list.rules);

        for name in ["ads.sieve-test.invalid", "doubleclick.net", "stats.doubleclick.net"] {
            let m = query_a(addr, name).await.expect("blocked name answered");
            println!("{name} -> {}", probe::describe(&m));
            assert!(is_block_answer(&m), "{name} must get the block answer");
        }
        let m = query_a(addr, "example.com").await.expect("example.com answered");
        println!("example.com -> {}", probe::describe(&m));
        assert!(is_resolved(&m), "example.com must resolve through an upstream");

        let check = engine.self_check().await;
        println!("self check: {}", serde_json::to_string(&check).expect("json"));
        assert!(check.pass);
        let status = engine.status();
        println!("dns_status: {}", serde_json::to_string(&status).expect("json"));
        assert_eq!(status.counters.failed, 0);
        engine.stop().await;
    }
}
