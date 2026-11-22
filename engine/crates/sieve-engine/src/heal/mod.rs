//! Self-healing (plan 4.3, slice 7): a client that rejects Sieve's certificate
//! costs at most one failed request per (app, host) on strong evidence, and the
//! next connection of that pair passes through untouched. Self-healing can only
//! add pass-through, and "Try decrypting again" can only take back what the
//! engine wrote itself (S24).
//!
//! [`Heal`] is the production `ClientWatch`. `control::Engine` owns it, so it
//! outlives each `Interception`; with `filtering.https` off no `Interception`
//! exists, so nothing here runs on any flow.
//! - [`dials`]: every number, declared;
//! - [`score`]: the evidence, one quantity with one threshold;
//! - [`notices`]: one notice per app;
//! - [`trouble`]: the whole app through untouched for a while, when it refuses
//!   Sieve for several sites right after Sieve began decrypting it.
//!
//! A refusal from a process started before the root that minted the leaf was
//! installed is no evidence (2026-11-22): Firefox reads the Windows roots only at
//! its start, so one open when HTTPS filtering was turned on, or across a silent
//! rotation, refuses every leaf until it restarts. Such a refusal neither scores
//! nor excludes; the process is remembered (by pid and start, so a reused pid is
//! another process) and its next flows pass through by `floor:root-not-trusted`,
//! so its pages work undecrypted until it restarts; one log row says so, and the
//! status names it for the app's notice. A process whose start cannot be read
//! counts as before.

pub mod dials;
pub mod notices;
pub mod score;
pub mod trouble;

use std::sync::{Arc, Mutex, OnceLock};

use rustls::AlertDescription;
use sieve_filter::exclusions::{AutoReason, Pattern, exe_file_name};
use sieve_ipc::{HealNotice, LogOutcome, RestartApp};

use crate::exclusions::{AutoEntry, ExclusionSlot};
use crate::policy::wall_ms;
use crate::stack::Meters;
use crate::stack::book::FlowBook;
use crate::tls::intercept::{ClientWatch, Pair, Silence};

use notices::Notices;
use score::{Evidence, Ledger};

/// When a process started (ms since the Unix epoch), by pid; None when that cannot
/// be read or the process has exited.
pub type ProcessStart = Box<dyn Fn(u32) -> Option<u64> + Send + Sync>;

/// Processes remembered at once as needing a restart, oldest first out: one per
/// browser process a person has open, with room to spare. A forgotten one counts
/// its next refusal again, which only puts it back.
pub const MAX_UNTRUSTING: usize = 64;

/// The log reason of the one row per such process.
pub const RESTART_TO_TRUST: &str = "restart-to-trust";

/// A process that refused Sieve's certificate and started before the root.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Untrusting {
    pid: u32,
    started_ms: u64,
    /// Full path, as attribution read it.
    exe: String,
    session: u32,
}

#[cfg(windows)]
fn process_start() -> ProcessStart {
    Box::new(crate::flow::flows::os::started_ms)
}

#[cfg(not(windows))]
fn process_start() -> ProcessStart {
    Box::new(|_| None)
}

/// Evidence that can exclude: a refusal, or a connection the client ended unused.
fn could_exclude(evidence: Evidence) -> bool {
    matches!(evidence, Evidence::Refused(_) | Evidence::Ended(Some(_)))
}

/// The same connection with what it said taken away: a handshake it refused opened
/// nothing, and an end still closes its connection in the count.
fn without_evidence(evidence: Evidence) -> Option<Evidence> {
    match evidence {
        Evidence::Refused(_) => None,
        Evidence::Ended(Some(_)) => Some(Evidence::Ended(None)),
        other => Some(other),
    }
}

/// What "Try decrypting again" names. Only ever `auto:*` entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retry {
    /// One row: its pattern, its app (None for an entry of every app) and its reason.
    One { pattern: Pattern, app: Option<String>, reason: AutoReason },
    /// Every `auto:pinning` entry of this app.
    App { app: String },
}

#[derive(Default)]
struct State {
    ledger: Ledger,
    notices: Notices,
    trouble: trouble::Trouble,
    untrusting: Vec<Untrusting>,
}

pub struct Heal {
    exclusions: Arc<ExclusionSlot>,
    meters: Arc<Meters>,
    state: Mutex<State>,
    /// Names this run for the notices, whose revisions and ids start over with a new
    /// one: the time it started, which no other run of this engine shares.
    run: u64,
    started: ProcessStart,
    /// Where the one row per process that needs a restart goes; none in tests that do not read it.
    book: OnceLock<Arc<Mutex<FlowBook>>>,
}

impl Heal {
    pub fn new(exclusions: Arc<ExclusionSlot>, meters: Arc<Meters>) -> Self {
        Self { exclusions, meters, state: Mutex::default(), run: wall_ms(), started: process_start(), book: OnceLock::new() }
    }

    /// Processes' starts from the caller, not from Windows.
    pub fn with_process_start(self, started: impl Fn(u32) -> Option<u64> + Send + Sync + 'static) -> Self {
        Self { started: Box::new(started), ..self }
    }

    /// The log the rows of processes that need a restart go to (once, by the engine).
    pub fn log_to(&self, book: Arc<Mutex<FlowBook>>) {
        let _ = self.book.set(book);
    }

    pub fn run(&self) -> u64 {
        self.run
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// True when this evidence comes from a process that started before the root
    /// that minted its leaf: it is then no evidence. Remembers the process, and
    /// logs it the first time. Unknown pid, root or start: false, as before.
    fn before_root(&self, pair: &Pair, exe: &str, session: u32, evidence: Evidence) -> bool {
        let (Some(pid), Some(root_ms)) = (pair.pid, pair.root_ms) else { return false };
        if !could_exclude(evidence) {
            return false;
        }
        let Some(started_ms) = (self.started)(pid) else { return false };
        if started_ms >= root_ms {
            return false;
        }
        let process = Untrusting { pid, started_ms, exe: exe.to_string(), session };
        let new = {
            let mut state = self.state();
            // A pid seen with another start was another process: it is gone.
            state.untrusting.retain(|u| u.pid != pid || u.started_ms == started_ms);
            let new = !state.untrusting.contains(&process);
            if new {
                state.untrusting.push(process);
                let over = state.untrusting.len().saturating_sub(MAX_UNTRUSTING);
                state.untrusting.drain(..over);
            }
            new
        };
        if new && let Some(book) = self.book.get() {
            let outcome = LogOutcome::NotDecrypted { reason: RESTART_TO_TRUST.to_string() };
            book.lock().unwrap_or_else(|p| p.into_inner()).note_app(pid, exe, session, &pair.host.to_ascii_lowercase(), outcome);
        }
        true
    }

    /// The apps with a process open that needs a restart to trust Sieve's root, one
    /// row per exe file name and session. A process that exited, or whose pid now
    /// names another process, is forgotten here.
    pub fn restart_to_trust(&self) -> Vec<RestartApp> {
        let known: Vec<Untrusting> = self.state().untrusting.clone();
        let gone: Vec<(u32, u64)> = known.iter().filter(|u| (self.started)(u.pid) != Some(u.started_ms)).map(|u| (u.pid, u.started_ms)).collect();
        let mut state = self.state();
        state.untrusting.retain(|u| !gone.contains(&(u.pid, u.started_ms)));
        let mut apps: Vec<RestartApp> = state.untrusting.iter().map(|u| RestartApp { exe: exe_file_name(&u.exe), session: u.session }).collect();
        apps.sort_by(|a, b| (a.session, &a.exe).cmp(&(b.session, &b.exe)));
        apps.dedup();
        apps
    }

    /// One piece of evidence about a pair, at `now_ms`. A flow reaches the watch
    /// only with an exe and a session: `decrypt` passes everything else through.
    pub fn hear(&self, pair: &Pair, evidence: Evidence, now_ms: u64) {
        let (Some(exe), Some(session)) = (pair.exe.as_deref(), pair.session) else { return };
        let Some(evidence) = silence_only_for_apps(evidence, self.exclusions.in_scope(Some(exe))) else { return };
        // After the browser rule, so a process start is read only for what could still exclude.
        let evidence = if self.before_root(pair, exe, session, evidence) { without_evidence(evidence) } else { Some(evidence) };
        let Some(evidence) = evidence else { return };
        let mut state = self.state();
        let app = trouble::key(exe, session);
        state.trouble.heard(&app, now_ms);
        let excluded = state.ledger.hear(exe, &pair.host, evidence, now_ms);
        // The app's case is sites it refused with an alert, each one `score` took for
        // a refusal: never a client that only went away (P1-1).
        if excluded && refused_with_an_alert(evidence) && state.trouble.refused(&app, &pair.host, now_ms) {
            let until = now_ms.saturating_add(trouble::FAIL_OPEN_MS);
            state.trouble.opened(&app, until, now_ms);
            if self.exclusions.add_whole_app(exe, session, now_ms, until) {
                Meters::bump(&self.meters.https.failed_open);
            }
        }
        if !excluded {
            return;
        }
        // A second refusal of a held entry says nothing new, and raises no notice.
        if self.exclusions.add_auto(AutoEntry::for_app(&pair.host, exe, AutoReason::Pinning, now_ms), now_ms) {
            Meters::bump(&self.meters.https.healed);
            state.notices.push(session, &exe_file_name(exe), &pair.host.to_ascii_lowercase(), now_ms);
        }
    }

    /// Takes the named entries back, and seeds each score to 1: a client that still
    /// pins with silent closes is excluded by one more, not two. After a restart
    /// the seed is gone and it takes two, which is harmless. The app's notice groups
    /// close, so a refusal of what was tried is a notice of its own. The answer is how
    /// many entries were taken back.
    pub fn try_again(&self, retry: &Retry, now_ms: u64) -> usize {
        let mut state = self.state();
        match retry {
            Retry::One { app: Some(app), reason: AutoReason::Failing, .. } => {
                let taken = self.exclusions.try_again_whole_app(app, now_ms);
                for key in &taken {
                    state.trouble.rearm(key, now_ms);
                }
                taken.len()
            }
            Retry::One { pattern, app, reason } => {
                if !self.exclusions.try_again(pattern, app.as_deref(), *reason, now_ms) {
                    return 0;
                }
                if let Some(app) = app {
                    state.notices.close(app);
                    if let Pattern::Exact(host) = pattern {
                        state.ledger.seed(app, host, now_ms);
                    }
                }
                1
            }
            Retry::App { app } => {
                let hosts = self.exclusions.try_again_app(app, AutoReason::Pinning, now_ms);
                if !hosts.is_empty() {
                    state.notices.close(app);
                }
                for pattern in &hosts {
                    if let Pattern::Exact(host) = pattern {
                        state.ledger.seed(app, host, now_ms);
                    }
                }
                hosts.len()
            }
        }
    }

    pub fn notices(&self, after: u64) -> (u64, Vec<HealNotice>) {
        let state = self.state();
        (state.notices.revision(), state.notices.after(after))
    }
}

/// A browser's silence is no evidence, only its alerts (run 7, 2026-11-09). A browser
/// that refuses Sieve's certificate says so with an alert (measured: Firefox without
/// Sieve's root sent unknown_ca, in the handshake and right after it), which counts as
/// before; a handshake it gives up on, or closes at once, with no alert, is a tab or a
/// preconnect let go. The silent rules are for apps that check a pin after TLS and
/// drop the socket (`dials::QUIET_CLOSES`). Once the TCP stack read a client's FIN at
/// once, twelve minutes of Edge and Chrome excluded a video host for Edge; before, those
/// ends were heard 10 to 60 s late, mostly beside another open connection, and never
/// counted. A browser's silent end still closes its connection in the count (None for
/// a handshake, which opened none). `browser` is the registered-browser set's word,
/// the one decryption's scope reads.
fn silence_only_for_apps(evidence: Evidence, browser: bool) -> Option<Evidence> {
    match evidence {
        Evidence::Ended(Some(Silence { alert: None, .. })) if browser => Some(Evidence::Ended(None)),
        Evidence::Refused(None) if browser => None,
        other => Some(other),
    }
}
/// The client said no to Sieve's certificate: an alert in the handshake, or one on
/// a connection it never used. A handshake it only gave up on carries none.
fn refused_with_an_alert(evidence: Evidence) -> bool {
    matches!(evidence, Evidence::Refused(Some(_)) | Evidence::Ended(Some(Silence { alert: Some(_), .. })))
}

impl ClientWatch for Heal {
    fn handshake_failed(&self, pair: &Pair, alert: Option<AlertDescription>) {
        self.hear(pair, Evidence::Refused(alert), wall_ms());
    }

    fn accepted(&self, pair: &Pair) {
        self.hear(pair, Evidence::Accepted, wall_ms());
    }

    fn request_seen(&self, pair: &Pair) {
        self.hear(pair, Evidence::Used, wall_ms());
    }

    fn ended(&self, pair: &Pair, silence: Option<Silence>) {
        self.hear(pair, Evidence::Ended(silence), wall_ms());
    }

    /// A process remembered as needing a restart, still the same process. Windows
    /// is asked only for a pid that is remembered.
    fn distrusts(&self, pid: u32) -> bool {
        let Some(started_ms) = self.state().untrusting.iter().find(|u| u.pid == pid).map(|u| u.started_ms) else { return false };
        if (self.started)(pid) == Some(started_ms) {
            return true;
        }
        self.state().untrusting.retain(|u| u.pid != pid || u.started_ms != started_ms);
        false
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use sieve_filter::exclusions::Source as Src;

    use super::dials::{BURST_MS, FATAL_ALERTS, NOTICE_WINDOW_MS, QUIET_CLOSES, USED_QUIET_CLOSES};
    use super::*;

    const NOW: u64 = 1_793_000_000_000;
    const CLIENT: &str = r"C:\Apps\Client.exe";
    const OTHER: &str = r"C:\Apps\Other.exe";
    const HOST: &str = "pin.example";

    fn heal() -> Heal {
        Heal::new(Arc::new(ExclusionSlot::with_sources(None, &[], Vec::new(), NOW)), Arc::default())
    }

    fn pair(exe: &str, host: &str) -> Pair {
        Pair::of(Some(exe), host, Some(1))
    }

    fn refused() -> Evidence {
        Evidence::Refused(Some(FATAL_ALERTS[0]))
    }

    /// A connection that completes its handshake and is closed at once, unused.
    fn handshake_then_close(h: &Heal, exe: &str, host: &str, at: u64) {
        h.hear(&pair(exe, host), Evidence::Accepted, at);
        h.hear(&pair(exe, host), Evidence::Ended(Some(Silence { after: std::time::Duration::ZERO, alert: None })), at);
    }

    fn found(heal: &Heal, exe: &str, at: u64) -> Option<Src> {
        heal.exclusions.get_at(at).find(Some(HOST), "192.0.2.1".parse().unwrap(), Some(exe), true).cloned()
    }

    fn one_row() -> Retry {
        Retry::One { pattern: Pattern::Exact(HOST.into()), app: Some("client.exe".into()), reason: AutoReason::Pinning }
    }

    #[test]
    fn retry_removes_the_entry_and_a_refusal_restores_its_history() {
        let h = heal();
        h.hear(&pair(CLIENT, HOST), refused(), NOW);
        assert_eq!(found(&h, CLIENT, NOW), Some(Src::Auto(AutoReason::Pinning)));
        assert_eq!(h.try_again(&one_row(), NOW + 5), 1);
        assert_eq!(found(&h, CLIENT, NOW + 5), None, "the next connection is decrypted again");
        h.hear(&pair(CLIENT, HOST), refused(), NOW + 9);
        assert_eq!(found(&h, CLIENT, NOW + 9), Some(Src::Auto(AutoReason::Pinning)));
        let rows = h.exclusions.rows(NOW + 9);
        let row = rows.iter().find(|r| r.reason == "auto:pinning").unwrap();
        assert_eq!((row.created_ms, row.retries), (Some(NOW), 1), "its first date, and the try");
        let notices = h.notices(0).1;
        assert_eq!(notices.iter().map(|n| (n.id, n.total)).collect::<Vec<_>>(), [(1, 1), (2, 1)], "a new notice of one site, inside the window too; the first stands");
        assert_eq!(notices[1].hosts, [HOST]);
    }

    #[test]
    fn a_second_refusal_after_a_retry_keeps_the_first_date() {
        let h = heal();
        h.hear(&pair(CLIENT, HOST), refused(), NOW);
        h.try_again(&one_row(), NOW + 5);
        h.hear(&pair(CLIENT, HOST), refused(), NOW + 9);
        h.hear(&pair(CLIENT, HOST), refused(), NOW + 10);
        let rows = h.exclusions.rows(NOW + 10);
        let row = rows.iter().find(|r| r.reason == "auto:pinning").unwrap();
        assert_eq!((row.created_ms, row.retries), (Some(NOW), 1), "a client with two connections in flight loses nothing");
        assert_eq!(h.notices(0).1.len(), 2, "and the second refusal raises no notice");
    }

    #[test]
    fn a_refusal_after_the_window_raises_a_notice_of_its_own() {
        let h = heal();
        h.hear(&pair(CLIENT, HOST), refused(), NOW);
        h.try_again(&one_row(), NOW);
        h.hear(&pair(CLIENT, HOST), refused(), NOW + NOTICE_WINDOW_MS);
        assert_eq!(h.notices(0).1.len(), 2);
    }

    #[test]
    fn trying_all_again_does_not_double_the_count() {
        let h = heal();
        for host in ["a.example", "b.example"] {
            h.hear(&pair(CLIENT, host), refused(), NOW);
        }
        h.try_again(&Retry::App { app: "client.exe".into() }, NOW + 1);
        for host in ["a.example", "b.example"] {
            h.hear(&pair(CLIENT, host), refused(), NOW + 2);
        }
        assert_eq!(h.notices(0).1.iter().map(|n| (n.id, n.total)).collect::<Vec<_>>(), [(1, 2), (2, 2)]);
    }

    #[test]
    fn a_try_that_took_nothing_back_leaves_the_group_open() {
        let h = heal();
        h.hear(&pair(CLIENT, "a.example"), refused(), NOW);
        assert_eq!(h.try_again(&one_row(), NOW), 0);
        assert_eq!(h.try_again(&Retry::App { app: "other.exe".into() }, NOW), 0);
        h.hear(&pair(CLIENT, "b.example"), refused(), NOW);
        assert_eq!(h.notices(0).1.iter().map(|n| n.total).collect::<Vec<_>>(), [2]);
    }

    #[test]
    fn a_host_evicted_from_the_store_and_refused_again_counts_once() {
        let h = heal();
        h.hear(&pair(CLIENT, HOST), refused(), NOW);
        for i in 0..crate::exclusions::auto::MAX_PER_REASON {
            h.hear(&pair(OTHER, &format!("h{i}.example")), refused(), NOW);
        }
        assert_eq!(found(&h, CLIENT, NOW), None, "the control: the flood evicted it");
        h.hear(&pair(CLIENT, HOST), refused(), NOW + 1);
        assert_eq!(found(&h, CLIENT, NOW + 1), Some(Src::Auto(AutoReason::Pinning)));
        let notices = h.notices(0).1;
        assert_eq!(notices.iter().find(|n| n.exe == "client.exe").unwrap().total, 1);
    }

    #[test]
    fn retry_then_one_silent_close_excludes() {
        let h = heal();
        h.hear(&pair(CLIENT, HOST), refused(), NOW);
        h.try_again(&one_row(), NOW);
        handshake_then_close(&h, CLIENT, HOST, NOW);
        assert_eq!(found(&h, CLIENT, NOW), Some(Src::Auto(AutoReason::Pinning)));
    }

    /// Changed 2026-11-08 with the quiet-close rule: a pair that carried a request
    /// takes `USED_QUIET_CLOSES` closes, so what follows the request here is fewer
    /// closes, then refused handshakes, which the request's credit delays by one.
    #[test]
    fn retry_then_a_used_connection_stays_decrypted() {
        let burst = |n: u64| NOW + n * (BURST_MS + 1);
        let h = heal();
        h.hear(&pair(CLIENT, HOST), refused(), NOW);
        h.try_again(&one_row(), NOW);
        h.hear(&pair(CLIENT, HOST), Evidence::Used, NOW);
        assert_eq!(found(&h, CLIENT, NOW), None);
        for n in 1..u64::from(USED_QUIET_CLOSES) {
            handshake_then_close(&h, CLIENT, HOST, burst(n));
        }
        let at = burst(u64::from(USED_QUIET_CLOSES));
        assert_eq!(found(&h, CLIENT, at), None, "the seed's closes are gone, and a used pair takes more");
        for n in 0..2 {
            h.hear(&pair(CLIENT, HOST), Evidence::Refused(None), at + burst(n) - NOW);
        }
        assert_eq!(found(&h, CLIENT, at), None, "and it takes three refusals");
        h.hear(&pair(CLIENT, HOST), Evidence::Refused(None), at + burst(2) - NOW);
        assert_eq!(found(&h, CLIENT, at), Some(Src::Auto(AutoReason::Pinning)));
    }

    #[test]
    fn try_again_for_an_app_clears_only_its_pinning_entries() {
        let h = heal();
        for host in ["a.example", "b.example"] {
            h.hear(&pair(CLIENT, host), refused(), NOW);
        }
        h.hear(&pair(OTHER, "a.example"), refused(), NOW);
        h.exclusions.add_auto(AutoEntry::host("cert.example", AutoReason::ClientCert, NOW, None), NOW);
        assert_eq!(h.try_again(&Retry::App { app: "client.exe".into() }, NOW), 2);
        let rows = h.exclusions.rows(NOW);
        let lines: Vec<(&str, &[String])> = rows.iter().filter(|r| r.reason.starts_with("auto:")).map(|r| (r.line.as_str(), r.apps.as_slice())).collect();
        assert_eq!(lines, [("\"a.example\"", &["other.exe".to_string()][..]), ("\"cert.example\"", &[][..])]);
        handshake_then_close(&h, CLIENT, "b.example", NOW);
        assert_eq!(h.exclusions.rows(NOW).iter().filter(|r| r.line == "\"b.example\"").count(), 1, "seeded, as one row's try");
    }

    #[test]
    fn retry_of_nothing_takes_nothing_back() {
        assert_eq!(heal().try_again(&one_row(), NOW), 0);
        assert_eq!(heal().try_again(&Retry::App { app: "client.exe".into() }, NOW), 0);
    }

    #[test]
    fn an_entry_for_one_app_leaves_another_app_decrypted() {
        use sieve_filter::exclusions::{Decrypt, FlowFacts, PassReason, Scope, Switches, Transport, UpstreamVerdict, decrypt};
        let h = heal();
        h.hear(&pair(CLIENT, HOST), refused(), NOW);
        let alpn = vec!["h2".to_string()];
        let facts = |exe| FlowFacts {
            transport: Transport::Tcp,
            may_decrypt: true,
            exe: Some(exe),
            session: Some(1),
            host: Some(HOST),
            ip: "192.0.2.1".parse().unwrap(),
            port: 443,
            alpn: &alpn,
            ech: false,
            client_compatible: true,
            app_in_scope: true,
            app_off: false,
            upstream: Some(UpstreamVerdict::Eligible),
            root_not_trusted: false,
        };
        let switches = Switches { https: true, root_ready: true, lists_ready: true, skip_ev: true, scope: Scope::All };
        let store = h.exclusions.get_at(NOW);
        assert_eq!(decrypt(&facts(CLIENT), &store, &switches), Decrypt::PassThrough(PassReason::Stored(Src::Auto(AutoReason::Pinning))));
        assert_eq!(decrypt(&facts(OTHER), &store, &switches), Decrypt::Intercept);
    }

    #[test]
    fn client_cert_and_ev_raise_no_notice() {
        let h = heal();
        h.exclusions.add_auto(AutoEntry::host("cert.example", AutoReason::ClientCert, NOW, None), NOW);
        h.exclusions.add_auto(AutoEntry::host("ev.example", AutoReason::Ev, NOW, None), NOW);
        assert!(h.notices(0).1.is_empty());
        assert_eq!(h.exclusions.rows(NOW).iter().filter(|r| r.reason.starts_with("auto:")).count(), 2, "they appear as rows");
    }

    #[test]
    fn a_second_refusal_of_a_held_entry_raises_none() {
        let h = heal();
        h.hear(&pair(CLIENT, HOST), refused(), NOW);
        h.hear(&pair(CLIENT, HOST), refused(), NOW + 1);
        let (revision, notices) = h.notices(0);
        assert_eq!((revision, notices[0].total), (1, 1));
        assert_eq!(h.meters.https.healed.load(Ordering::Relaxed), 1);
    }

    /// The fail-open rule end to end: three sites refused right after the start
    /// let the whole app through, every site, for a day; another app stays
    /// decrypted; "Try decrypting again" takes it back like any `auto:*` entry.
    #[test]
    fn an_app_refusing_several_sites_goes_through_untouched_for_a_while() {
        use super::trouble::{FAIL_OPEN_MS, TROUBLE_HOSTS};
        let h = heal();
        let excluded = |at: u64, exe: &str, session: u32| h.exclusions.get_at(at).passes_app(Some(exe), Some(session));
        for i in 0..TROUBLE_HOSTS - 1 {
            h.hear(&pair(CLIENT, &format!("s{i}.example")), refused(), NOW + i as u64 * (BURST_MS + 1));
        }
        assert!(!excluded(NOW + 5_000, CLIENT, 1), "not yet the app's case");
        h.hear(&pair(CLIENT, "last.example"), refused(), NOW + 5_000);
        assert!(excluded(NOW + 5_000, CLIENT, 1), "every site of it passes");
        assert!(!excluded(NOW + 5_000, OTHER, 1) && !excluded(NOW + 5_000, CLIENT, 2), "another app, the same app of another user");
        assert!(!excluded(NOW + 5_000, r"C:\Elsewhere\client.exe", 1), "an exe named like it");
        assert!(!excluded(NOW + 5_000 + FAIL_OPEN_MS, CLIENT, 1), "a day later it is decrypted again");
        assert_eq!(h.meters.https.report()["failed_open"], 1);
        let row = h.exclusions.rows(NOW + 5_000).into_iter().find(|r| r.reason == "auto:failing").unwrap();
        assert_eq!((row.line.as_str(), row.apps.as_slice()), ("*", &["client.exe".to_string()][..]));
        let taken = h.try_again(&Retry::One { pattern: Pattern::Wildcard("*".into()), app: Some("client.exe".into()), reason: AutoReason::Failing }, NOW + 6_000);
        assert_eq!((taken, excluded(NOW + 6_000, CLIENT, 1)), (1, false));
    }

    /// P1-1 of the 2026-11-08 second review: a client that goes away mid handshake
    /// (a tab closed, sleep, the 10 s timeout) on many sites, often enough that
    /// `score` excludes each, never lets the whole app through.
    #[test]
    fn handshakes_given_up_on_many_sites_never_let_the_app_through() {
        let h = heal();
        let burst = |n: u64| NOW + n * (BURST_MS + 1);
        for i in 0..10u64 {
            let host = format!("s{i}.example");
            h.hear(&pair(CLIENT, &host), Evidence::Refused(None), burst(2 * i));
            h.hear(&pair(CLIENT, &host), Evidence::Refused(None), burst(2 * i + 1));
        }
        assert!(found_any(&h, "s9.example"), "the control: score took each site");
        assert!(!h.exclusions.get_at(burst(20)).passes_app(Some(CLIENT), Some(1)));
        assert_eq!(h.meters.https.report()["failed_open"], 0);
        // A weak alert counts once score takes the site for it.
        let weak = Evidence::Refused(Some(AlertDescription::HandshakeFailure));
        for i in 0..3u64 {
            let host = format!("w{i}.example");
            h.hear(&pair(OTHER, &host), weak, burst(2 * i));
            h.hear(&pair(OTHER, &host), weak, burst(2 * i + 1));
        }
        assert!(h.exclusions.get_at(burst(6)).passes_app(Some(OTHER), Some(1)));
    }

    fn found_any(h: &Heal, host: &str) -> bool {
        h.exclusions.rows(NOW).iter().any(|r| r.line == format!("\"{host}\"") && r.reason == "auto:pinning")
    }

    #[test]
    fn after_a_try_again_the_rule_arms_again() {
        use super::trouble::TROUBLE_HOSTS;
        let h = heal();
        let three = |at: u64| (0..TROUBLE_HOSTS).for_each(|i| h.hear(&pair(CLIENT, &format!("t{at}-{i}.example")), refused(), at + i as u64));
        three(NOW);
        assert!(h.exclusions.get_at(NOW + 5).passes_app(Some(CLIENT), Some(1)));
        let later = NOW + 3 * 60 * 60_000;
        assert_eq!(h.try_again(&Retry::One { pattern: Pattern::Wildcard("*".into()), app: Some("client.exe".into()), reason: AutoReason::Failing }, later), 1);
        three(later + 1);
        assert!(h.exclusions.get_at(later + 10).passes_app(Some(CLIENT), Some(1)), "hours after the run's start, armed from the try");
    }

    /// Run 7: with the client's FIN read at once, a browser's tab closes are quiet
    /// closes in time. For a registered browser they are no evidence; its alert is,
    /// and an app that is not a browser still heals by them.
    #[test]
    fn a_browsers_quiet_closes_never_exclude_and_its_alert_still_does() {
        use crate::exclusions::browsers::{BrowserRegistry, BrowserSet};
        struct One;
        impl BrowserRegistry for One {
            fn commands(&self) -> Vec<String> {
                vec![format!("\"{OTHER}\" -- \"%1\"")]
            }
        }
        let h = heal();
        h.exclusions.set_browsers(BrowserSet::read(&One), NOW);
        let burst = |n: u64| NOW + n * (BURST_MS + 1);
        for n in 0..u64::from(10 * USED_QUIET_CLOSES) {
            handshake_then_close(&h, OTHER, HOST, burst(n));
        }
        for n in 0..10u64 {
            h.hear(&pair(OTHER, HOST), Evidence::Refused(None), burst(30 + n));
        }
        assert_eq!(found(&h, OTHER, burst(100)), None, "a browser's tab closes, preconnects and handshakes given up");
        assert_eq!(h.meters.https.healed.load(Ordering::Relaxed), 0);
        h.hear(&pair(OTHER, HOST), refused(), burst(101));
        assert_eq!(found(&h, OTHER, burst(101)), Some(Src::Auto(AutoReason::Pinning)), "its refusal with an alert");
        // The control: an app that is not a browser heals by the same closes.
        for n in 0..u64::from(QUIET_CLOSES) {
            handshake_then_close(&h, CLIENT, HOST, burst(n));
        }
        assert_eq!(found(&h, CLIENT, burst(QUIET_CLOSES.into())), Some(Src::Auto(AutoReason::Pinning)));
    }

    #[test]
    fn a_pair_with_no_exe_or_session_is_not_scored() {
        let h = heal();
        h.hear(&Pair::of(None, HOST, Some(1)), refused(), NOW);
        h.hear(&Pair::of(Some(CLIENT), HOST, None), refused(), NOW);
        assert_eq!(found(&h, CLIENT, NOW), None);
        h.hear(&pair(CLIENT, HOST), refused(), NOW);
        assert_eq!(found(&h, CLIENT, NOW), Some(Src::Auto(AutoReason::Pinning)), "the control");
    }

    // A process started before the root (2026-11-22).

    /// The root that minted the leaves in these tests was installed at ROOT.
    const ROOT: u64 = NOW - 60_000;
    const OLD: u32 = 7;
    const NEW: u32 = 8;
    const UNKNOWN: u32 = 9;

    type Starts = Arc<Mutex<std::collections::HashMap<u32, u64>>>;

    /// OLD started a day before ROOT, NEW after it, UNKNOWN cannot be read.
    fn heal_with_starts() -> (Heal, Starts, Arc<Mutex<FlowBook>>) {
        let starts: Starts = Arc::new(Mutex::new([(OLD, ROOT - 86_400_000), (NEW, ROOT + 1)].into_iter().collect()));
        let read = starts.clone();
        let h = heal().with_process_start(move |pid| read.lock().unwrap().get(&pid).copied());
        let book = Arc::new(Mutex::new(FlowBook::default()));
        h.log_to(book.clone());
        (h, starts, book)
    }

    fn of(pid: u32, host: &str, root_ms: u64) -> Pair {
        Pair { pid: Some(pid), root_ms: Some(root_ms), ..pair(CLIENT, host) }
    }

    fn restart_rows(book: &Mutex<FlowBook>) -> Vec<(Option<u32>, String, Option<u32>)> {
        book.lock().unwrap().take_log().into_iter().filter(|r| r.outcome == LogOutcome::NotDecrypted { reason: RESTART_TO_TRUST.into() }).map(|r| (r.pid, r.host, r.session)).collect()
    }

    #[test]
    fn a_refusal_from_a_process_older_than_the_root_is_no_evidence() {
        let (h, _, book) = heal_with_starts();
        for (n, host) in ["youtube.example", "a.example", "b.example", "c.example"].into_iter().enumerate() {
            h.hear(&of(OLD, host, ROOT), refused(), NOW + n as u64);
            h.hear(&of(OLD, host, ROOT), Evidence::Ended(Some(Silence { after: std::time::Duration::ZERO, alert: Some(FATAL_ALERTS[0]) })), NOW + n as u64);
        }
        assert!(h.exclusions.rows(NOW + 10).is_empty(), "no Rejected row, and not the whole app either");
        assert!(h.notices(0).1.is_empty() && h.meters.https.healed.load(Ordering::Relaxed) == 0);
        assert!(h.distrusts(OLD) && !h.distrusts(NEW) && !h.distrusts(UNKNOWN), "its next flows pass through; others are judged");
        assert_eq!(restart_rows(&book), [(Some(OLD), "youtube.example".to_string(), Some(1))], "one row for the process, not one per flow");
        assert_eq!(h.restart_to_trust(), [RestartApp { exe: "client.exe".into(), session: 1 }]);
    }

    #[test]
    fn a_refusal_from_a_process_newer_than_the_root_counts_as_before() {
        let (h, _, book) = heal_with_starts();
        h.hear(&of(NEW, HOST, ROOT), refused(), NOW);
        assert_eq!(found(&h, CLIENT, NOW), Some(Src::Auto(AutoReason::Pinning)), "a real refusal");
        assert!(!h.distrusts(NEW) && restart_rows(&book).is_empty() && h.restart_to_trust().is_empty());
    }

    #[test]
    fn an_unknown_start_or_pid_or_root_counts_as_before() {
        for (n, p) in [of(UNKNOWN, "u.example", ROOT), Pair { pid: None, ..of(OLD, "p.example", ROOT) }, Pair { root_ms: None, ..of(OLD, "r.example", ROOT) }].into_iter().enumerate() {
            let (h, _, _) = heal_with_starts();
            h.hear(&p, refused(), NOW);
            assert!(h.exclusions.rows(NOW).iter().any(|r| r.reason == "auto:pinning"), "case {n}");
            assert!(h.restart_to_trust().is_empty(), "case {n}");
        }
    }

    /// Silent rotation: a process that trusted the old root does not trust the new
    /// one yet; one started after the new root does.
    #[test]
    fn after_a_rotation_the_new_roots_time_decides() {
        let (h, starts, _) = heal_with_starts();
        let rotated = NOW + 3_600_000;
        starts.lock().unwrap().insert(NEW, ROOT + 1);
        h.hear(&of(NEW, HOST, ROOT), Evidence::Accepted, NOW);
        h.hear(&of(NEW, HOST, ROOT), Evidence::Used, NOW);
        h.hear(&of(NEW, HOST, ROOT), Evidence::Ended(None), NOW);
        h.hear(&of(NEW, HOST, rotated), refused(), rotated + 1);
        assert_eq!(found(&h, CLIENT, rotated + 1), None, "older than the new root: no evidence");
        assert!(h.distrusts(NEW));
        starts.lock().unwrap().insert(10, rotated + 5);
        h.hear(&Pair { pid: Some(10), ..of(NEW, HOST, rotated) }, refused(), rotated + 10);
        assert_eq!(found(&h, CLIENT, rotated + 10), Some(Src::Auto(AutoReason::Pinning)), "newer than it: counted");
    }

    /// The notice's list goes once the process exited, or its pid names another
    /// process; that pid's flows are judged again.
    #[test]
    fn a_process_that_exits_or_whose_pid_is_reused_is_forgotten() {
        let (h, starts, book) = heal_with_starts();
        h.hear(&of(OLD, HOST, ROOT), refused(), NOW);
        assert_eq!(h.restart_to_trust().len(), 1);
        starts.lock().unwrap().insert(OLD, ROOT + 50);
        assert!(!h.distrusts(OLD), "the pid is another process now");
        assert!(h.restart_to_trust().is_empty());
        let (h, starts, _) = heal_with_starts();
        h.hear(&of(OLD, HOST, ROOT), refused(), NOW);
        starts.lock().unwrap().remove(&OLD);
        assert!(h.restart_to_trust().is_empty(), "exited");
        assert!(!h.distrusts(OLD));
        let _ = book;
    }

    #[test]
    fn two_processes_of_one_browser_are_one_row_and_the_list_is_bounded() {
        let (h, starts, _) = heal_with_starts();
        starts.lock().unwrap().insert(11, ROOT - 5);
        h.hear(&of(OLD, HOST, ROOT), refused(), NOW);
        h.hear(&Pair { pid: Some(11), ..of(OLD, HOST, ROOT) }, refused(), NOW);
        h.hear(&Pair { session: Some(2), ..of(OLD, HOST, ROOT) }, refused(), NOW);
        assert_eq!(h.restart_to_trust(), [RestartApp { exe: "client.exe".into(), session: 1 }, RestartApp { exe: "client.exe".into(), session: 2 }]);
        for pid in 100..100 + MAX_UNTRUSTING as u32 * 2 {
            starts.lock().unwrap().insert(pid, ROOT - 1);
            h.hear(&Pair { pid: Some(pid), ..of(OLD, HOST, ROOT) }, refused(), NOW);
        }
        assert_eq!(h.state().untrusting.len(), MAX_UNTRUSTING);
    }
}
