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
//! - [`notices`]: one notice per app.

pub mod dials;
pub mod notices;
pub mod score;

use std::sync::{Arc, Mutex};

use rustls::AlertDescription;
use sieve_filter::exclusions::{AutoReason, Pattern, exe_file_name};
use sieve_ipc::HealNotice;

use crate::exclusions::{AutoEntry, ExclusionSlot};
use crate::policy::wall_ms;
use crate::stack::Meters;
use crate::tls::intercept::{ClientWatch, Pair, Silence};

use notices::Notices;
use score::{Evidence, Ledger};

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
}

pub struct Heal {
    exclusions: Arc<ExclusionSlot>,
    meters: Arc<Meters>,
    state: Mutex<State>,
    /// Names this run for the notices, whose revisions and ids start over with a new
    /// one: the time it started, which no other run of this engine shares.
    run: u64,
}

impl Heal {
    pub fn new(exclusions: Arc<ExclusionSlot>, meters: Arc<Meters>) -> Self {
        Self { exclusions, meters, state: Mutex::default(), run: wall_ms() }
    }

    pub fn run(&self) -> u64 {
        self.run
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// One piece of evidence about a pair, at `now_ms`. A flow reaches the watch
    /// only with an exe and a session: `decrypt` passes everything else through.
    pub fn hear(&self, pair: &Pair, evidence: Evidence, now_ms: u64) {
        let (Some(exe), Some(session)) = (pair.exe.as_deref(), pair.session) else { return };
        let mut state = self.state();
        if !state.ledger.hear(exe, &pair.host, evidence, now_ms) {
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
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use sieve_filter::exclusions::Source as Src;

    use super::dials::{FATAL_ALERTS, NOTICE_WINDOW_MS};
    use super::*;

    const NOW: u64 = 1_793_000_000_000;
    const CLIENT: &str = r"C:\Apps\Client.exe";
    const OTHER: &str = r"C:\Apps\Other.exe";
    const HOST: &str = "pin.example";

    fn heal() -> Heal {
        Heal::new(Arc::new(ExclusionSlot::with_sources(None, &[], Vec::new(), NOW)), Arc::default())
    }

    fn pair(exe: &str, host: &str) -> Pair {
        Pair { exe: Some(exe.to_string()), host: host.to_string(), session: Some(1) }
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
    /// is no longer excluded by closes at all, so what follows the request here is
    /// refused handshakes, which the request's credit delays by one.
    #[test]
    fn retry_then_a_used_connection_stays_decrypted() {
        let h = heal();
        h.hear(&pair(CLIENT, HOST), refused(), NOW);
        h.try_again(&one_row(), NOW);
        h.hear(&pair(CLIENT, HOST), Evidence::Used, NOW);
        assert_eq!(found(&h, CLIENT, NOW), None);
        for _ in 0..10 {
            handshake_then_close(&h, CLIENT, HOST, NOW);
        }
        assert_eq!(found(&h, CLIENT, NOW), None, "closes say nothing now");
        for _ in 0..2 {
            h.hear(&pair(CLIENT, HOST), Evidence::Refused(None), NOW);
        }
        assert_eq!(found(&h, CLIENT, NOW), None, "and it takes three refusals");
        h.hear(&pair(CLIENT, HOST), Evidence::Refused(None), NOW);
        assert_eq!(found(&h, CLIENT, NOW), Some(Src::Auto(AutoReason::Pinning)));
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

    #[test]
    fn a_pair_with_no_exe_or_session_is_not_scored() {
        let h = heal();
        h.hear(&Pair { exe: None, host: HOST.into(), session: Some(1) }, refused(), NOW);
        h.hear(&Pair { exe: Some(CLIENT.into()), host: HOST.into(), session: None }, refused(), NOW);
        assert_eq!(found(&h, CLIENT, NOW), None);
        h.hear(&pair(CLIENT, HOST), refused(), NOW);
        assert_eq!(found(&h, CLIENT, NOW), Some(Src::Auto(AutoReason::Pinning)), "the control");
    }
}
