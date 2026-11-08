//! The evidence about one (app, host) pair (plan 4.3, task D1). Pure; every
//! "now" is passed in (S15).
//!
//! ```text
//! a fatal alert, during or after the handshake: excluded at once
//! a refusal (a handshake that did not complete, or any other alert after one on a
//!     connection that carried no request), no other connection of the pair open,
//!     one per BURST: v = v * 0.5^(dt / HALF_LIFE) + 1; excluded when v >= EXCLUDE_AT
//! a quiet close (see QUIET_CLOSES), one per BURST: excluded at QUIET_CLOSES within
//!     QUIET_WINDOW, or for a pair used this run at USED_QUIET_CLOSES within
//!     USED_QUIET_WINDOW
//! a used connection: v = max(min(decayed, 0) - 1, -MAX_CREDIT), quiet count reset
//! try again: one more refusal or quiet close excludes
//! ```
//!
//! A connection open past its handshake while another of the same pair fails says
//! the client accepts the leaf: a browser drops the losers of a race once one
//! connection is up. Scores live in memory only: losing one costs one more attempt.

use std::collections::HashMap;

use rustls::AlertDescription;
use sieve_filter::exclusions::exe_file_name;

use super::dials::{BURST_MS, EXCLUDE_AT, FATAL_ALERTS, HALF_LIFE_MS, MAX_CREDIT, MAX_PAIRS, QUIET_CLOSES, QUIET_WINDOW_MS, SILENT_CLOSE_MS, USED_QUIET_CLOSES, USED_QUIET_WINDOW_MS};
use crate::lru::Lru;
use crate::tls::intercept::Silence;

/// What the watch heard (the table in task D3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// The local handshake did not complete, with the client's alert if it sent one.
    Refused(Option<AlertDescription>),
    /// The local handshake completed: a connection of the pair is open.
    Accepted,
    /// An open connection of the pair carried a request.
    Used,
    /// An open connection ended, with how the client ended it if it sent nothing.
    Ended(Option<Silence>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Score {
    /// Refused handshakes, decaying; below 0 is credit.
    value: f64,
    at_ms: u64,
    /// A connection of the pair carried a request this run: quiet closes then take
    /// [`USED_QUIET_CLOSES`] (P1 of the 2026-11-08 review). Not a lapse after a time:
    /// the unpinned half of an app keeps its pair used, so only a higher bound lets
    /// the pinned half, or the same app after an update, heal at all.
    used: bool,
    /// Quiet closes since `quiet_from_ms`.
    quiet: u32,
    quiet_from_ms: u64,
    /// When the burst of the last counted refusal, and of quiet close, began.
    refused_burst: Option<u64>,
    quiet_burst: Option<u64>,
}

/// True when evidence at `now_ms` opens a burst of its own, which `anchor` then
/// marks; false when it falls within [`BURST_MS`] of the one marked, either way
/// (a clock that went back a little is the same burst).
fn new_burst(anchor: &mut Option<u64>, now_ms: u64) -> bool {
    if anchor.is_some_and(|at| at.abs_diff(now_ms) <= BURST_MS) {
        return false;
    }
    *anchor = Some(now_ms);
    true
}

impl Score {
    const NONE: Self = Self { value: 0.0, at_ms: 0, used: false, quiet: 0, quiet_from_ms: 0, refused_burst: None, quiet_burst: None };

    /// A clock that went backwards decays nothing.
    fn decayed(self, now_ms: u64) -> f64 {
        let elapsed = now_ms.saturating_sub(self.at_ms) as f64;
        self.value * 0.5_f64.powf(elapsed / HALF_LIFE_MS as f64)
    }

    fn set(&mut self, value: f64, now_ms: u64) {
        self.value = value;
        self.at_ms = now_ms.max(self.at_ms);
    }

    /// One more refusal; true when it reaches [`EXCLUDE_AT`].
    fn refusal(&mut self, now_ms: u64) -> bool {
        if !new_burst(&mut self.refused_burst, now_ms) {
            return false;
        }
        self.set(self.decayed(now_ms) + 1.0, now_ms);
        self.value >= EXCLUDE_AT
    }

    /// One more quiet close; true when it makes the pair's bound in its window.
    fn quiet_close(&mut self, now_ms: u64) -> bool {
        if !new_burst(&mut self.quiet_burst, now_ms) {
            return false;
        }
        let (closes, window) = if self.used { (USED_QUIET_CLOSES, USED_QUIET_WINDOW_MS) } else { (QUIET_CLOSES, QUIET_WINDOW_MS) };
        if self.quiet == 0 || now_ms.saturating_sub(self.quiet_from_ms) > window {
            (self.quiet, self.quiet_from_ms) = (0, now_ms);
        }
        self.quiet += 1;
        self.quiet >= closes
    }
}

/// (exe file name, host), both lower case.
type Key = (String, String);

/// Every pair's score, bounded, and the connections of each that are open now.
pub struct Ledger {
    scores: Lru<Key, Score>,
    /// Bounded by the connections open at once; a pair leaves at 0.
    open: HashMap<Key, usize>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self::with_capacity(MAX_PAIRS)
    }
}

fn fatal(alert: Option<AlertDescription>) -> bool {
    alert.is_some_and(|a| FATAL_ALERTS.contains(&a))
}

impl Ledger {
    fn with_capacity(capacity: usize) -> Self {
        Self { scores: Lru::new(capacity), open: HashMap::new() }
    }

    fn key(exe: &str, host: &str) -> Key {
        (exe_file_name(exe), host.to_ascii_lowercase())
    }

    fn get(&mut self, key: &Key) -> Score {
        self.scores.get(key, |_| true).unwrap_or(Score::NONE)
    }

    fn others_open(&self, key: &Key) -> bool {
        self.open.get(key).is_some_and(|n| *n > 0)
    }

    /// Changes the pair's score; `judge` answers whether it is now excluded.
    fn with_score(&mut self, key: &Key, judge: impl FnOnce(&mut Score) -> bool) -> bool {
        let mut score = self.get(key);
        let excluded = judge(&mut score);
        self.scores.insert(key.clone(), score);
        excluded
    }

    /// True when this evidence excludes the pair. An excluded pair's score is gone:
    /// the next one starts from what "try again" seeds.
    pub fn hear(&mut self, exe: &str, host: &str, evidence: Evidence, now_ms: u64) -> bool {
        let key = Self::key(exe, host);
        let excluded = match evidence {
            Evidence::Refused(alert) if fatal(alert) => true,
            Evidence::Refused(_) => self.refused(&key, now_ms),
            Evidence::Accepted => {
                *self.open.entry(key.clone()).or_default() += 1;
                false
            }
            Evidence::Used => self.with_score(&key, |s| {
                s.set((s.decayed(now_ms).min(0.0) - 1.0).max(-MAX_CREDIT), now_ms);
                (s.used, s.quiet) = (true, 0);
                false
            }),
            Evidence::Ended(silence) => {
                if let Some(n) = self.open.get_mut(&key) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        self.open.remove(&key);
                    }
                }
                match silence {
                    Some(s) if fatal(s.alert) => true,
                    // Any other alert from the client on a connection it never used, however late.
                    Some(Silence { alert: Some(_), .. }) => self.refused(&key, now_ms),
                    Some(s) if s.after.as_millis() <= u128::from(SILENT_CLOSE_MS) && !self.others_open(&key) => self.with_score(&key, |score| score.quiet_close(now_ms)),
                    _ => false,
                }
            }
        };
        if excluded {
            self.scores.remove(&key);
        }
        excluded
    }

    /// A refusal, which says nothing while another connection of the pair is open.
    fn refused(&mut self, key: &Key, now_ms: u64) -> bool {
        !self.others_open(key) && self.with_score(key, |s| s.refusal(now_ms))
    }

    /// "Try decrypting again": one more refusal or quiet close excludes the pair.
    pub fn seed(&mut self, exe: &str, host: &str, now_ms: u64) {
        let seeded = Score { value: 1.0, at_ms: now_ms, quiet: QUIET_CLOSES - 1, quiet_from_ms: now_ms, ..Score::NONE };
        self.scores.insert(Self::key(exe, host), seeded);
    }

    pub fn len(&self) -> usize {
        self.scores.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }

    #[cfg(test)]
    fn value(&mut self, exe: &str, host: &str, now_ms: u64) -> f64 {
        self.get(&Self::key(exe, host)).decayed(now_ms)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use proptest::prelude::*;

    use super::*;

    const EXE: &str = r"C:\Apps\Client.exe";
    const HOST: &str = "pin.example";
    const NOW: u64 = 1_793_000_000_000;
    /// Chromium's idle timeout for a socket it never used: what an unused
    /// preconnect waits before it closes.
    const PRECONNECT_IDLE: Duration = Duration::from_secs(10);

    fn refused() -> Evidence {
        Evidence::Refused(None)
    }

    fn quiet(after: Duration) -> Evidence {
        Evidence::Ended(Some(Silence { after, alert: None }))
    }

    fn hear(ledger: &mut Ledger, evidence: Evidence, at: u64) -> bool {
        ledger.hear(EXE, HOST, evidence, at)
    }

    /// The start of the `n`th burst after NOW: each its own piece of evidence.
    fn burst(n: u64) -> u64 {
        NOW + n * (BURST_MS + 1)
    }

    /// One connection that completes its handshake and is closed by the client
    /// `after` it, with no request: what intercept reports for it.
    fn handshake_then_close(ledger: &mut Ledger, after: Duration, at: u64) -> bool {
        hear(ledger, Evidence::Accepted, at);
        hear(ledger, quiet(after), at)
    }

    /// One connection that carries a request: the end then has no silence.
    fn used_connection(ledger: &mut Ledger, at: u64) -> bool {
        [Evidence::Accepted, Evidence::Used, Evidence::Ended(None)].into_iter().any(|e| hear(ledger, e, at))
    }

    #[test]
    fn the_plans_numbers_could_not_do_what_it_said() {
        // Task F1: one half-life apart, the plan's threshold is out of reach.
        let two_refusals = 0.5_f64.powf(1.0) + 1.0;
        assert!(two_refusals < 2.0);
        assert!(two_refusals >= EXCLUDE_AT);
    }

    #[test]
    fn one_fatal_alert_excludes() {
        for alert in FATAL_ALERTS {
            assert!(Ledger::default().hear(EXE, HOST, Evidence::Refused(Some(alert)), NOW), "{alert:?} in the handshake");
            let mut after = Ledger::default();
            hear(&mut after, Evidence::Accepted, NOW);
            assert!(hear(&mut after, Evidence::Ended(Some(Silence { after: PRECONNECT_IDLE, alert: Some(alert) })), NOW), "{alert:?} after it, however late");
        }
        assert_eq!(FATAL_ALERTS.len(), 7);
    }

    #[test]
    fn a_fatal_certificate_alert_excludes_on_the_first_whatever_came_before() {
        let mut ledger = Ledger::default();
        for _ in 0..10 {
            used_connection(&mut ledger, NOW);
        }
        hear(&mut ledger, Evidence::Accepted, NOW);
        assert!(hear(&mut ledger, Evidence::Refused(Some(AlertDescription::BadCertificate)), NOW), "credit and an open connection do not matter");
    }

    #[test]
    fn a_real_ech_taken_for_grease_excludes_on_its_first_refusal() {
        assert!(Ledger::default().hear(EXE, HOST, Evidence::Refused(Some(AlertDescription::EncryptedClientHelloRequired)), NOW));
    }

    #[test]
    fn another_alert_or_none_is_weak_evidence() {
        for weak in [Some(AlertDescription::HandshakeFailure), Some(AlertDescription::UserCanceled), None] {
            let mut ledger = Ledger::default();
            assert!(!hear(&mut ledger, Evidence::Refused(weak), NOW), "{weak:?}: one is not enough");
            assert!(hear(&mut ledger, Evidence::Refused(weak), burst(1)), "{weak:?}: two are");
        }
    }

    #[test]
    fn any_alert_after_the_handshake_on_an_unused_connection_is_a_refusal() {
        let alerted = |alert| Evidence::Ended(Some(Silence { after: PRECONNECT_IDLE, alert: Some(alert) }));
        for weak in [AlertDescription::HandshakeFailure, AlertDescription::InternalError, AlertDescription::UserCanceled] {
            let mut ledger = Ledger::default();
            hear(&mut ledger, Evidence::Accepted, NOW);
            assert!(!hear(&mut ledger, alerted(weak), NOW), "{weak:?}: one is not enough, however late");
            hear(&mut ledger, Evidence::Accepted, burst(1));
            assert!(hear(&mut ledger, alerted(weak), burst(1)), "{weak:?}: two are");
        }
        // The control: the same late closes with no alert say nothing.
        let mut ledger = Ledger::default();
        for n in 0..10 {
            assert!(!handshake_then_close(&mut ledger, PRECONNECT_IDLE, burst(n)));
        }
    }

    #[test]
    fn an_alert_beside_an_open_connection_of_the_pair_is_no_evidence() {
        let mut ledger = Ledger::default();
        hear(&mut ledger, Evidence::Accepted, NOW);
        for n in 0..10 {
            hear(&mut ledger, Evidence::Accepted, burst(n));
            assert!(!hear(&mut ledger, Evidence::Ended(Some(Silence { after: Duration::ZERO, alert: Some(AlertDescription::HandshakeFailure) })), burst(n)), "{n}");
        }
    }

    /// A browser exiting, or a tab closing, with several handshakes to one host in
    /// flight gives them all up at once: one decision, one piece of evidence.
    #[test]
    fn parallel_handshakes_given_up_together_count_once() {
        let mut ledger = Ledger::default();
        for socket in 0..10 {
            assert!(!hear(&mut ledger, refused(), NOW + socket * BURST_MS / 10), "socket {socket}");
        }
        assert!(hear(&mut ledger, refused(), burst(1)), "the control: a second burst excludes");
    }

    #[test]
    fn a_client_closing_during_the_handshake_again_and_again_is_excluded() {
        for gap in [BURST_MS + 1, HALF_LIFE_MS] {
            let mut ledger = Ledger::default();
            assert!(!hear(&mut ledger, refused(), NOW), "one never excludes");
            assert!(hear(&mut ledger, refused(), NOW + gap), "gap {gap}");
        }
    }

    #[test]
    fn two_refusals_past_the_half_life_do_not() {
        let mut ledger = Ledger::default();
        hear(&mut ledger, refused(), NOW);
        assert!(!hear(&mut ledger, refused(), NOW + HALF_LIFE_MS + 1));
    }

    #[test]
    fn a_refusal_beside_an_open_connection_of_the_pair_is_no_evidence() {
        // A browser races connections and drops the losers once one is up.
        let mut ledger = Ledger::default();
        hear(&mut ledger, Evidence::Accepted, NOW);
        for loser in 0..10 {
            assert!(!hear(&mut ledger, refused(), NOW), "loser {loser}");
        }
        hear(&mut ledger, Evidence::Ended(None), NOW);
        assert!(!hear(&mut ledger, refused(), NOW), "the control: alone, the first counts");
        assert!(hear(&mut ledger, refused(), burst(1)), "and the second excludes");
    }

    #[test]
    fn a_request_clears_the_refusals_before_it() {
        let mut ledger = Ledger::default();
        hear(&mut ledger, refused(), NOW);
        used_connection(&mut ledger, NOW);
        assert!(!hear(&mut ledger, refused(), burst(1)));
        assert!(!hear(&mut ledger, refused(), burst(2)), "the first refusal is gone, and one credit stands");
        assert!(hear(&mut ledger, refused(), burst(3)), "the control: a third");
    }

    #[test]
    fn a_handshake_then_a_close_counts_only_when_it_repeats_soon() {
        let mut ledger = Ledger::default();
        for close in 1..u64::from(QUIET_CLOSES) {
            assert!(!handshake_then_close(&mut ledger, Duration::ZERO, burst(close)), "close {close}");
        }
        assert!(handshake_then_close(&mut ledger, Duration::ZERO, burst(1) + QUIET_WINDOW_MS), "the last at the window's edge excludes");
        // Spread past the window, the same closes never add up.
        let mut ledger = Ledger::default();
        let mut at = NOW;
        for close in 0..1000 {
            assert!(!handshake_then_close(&mut ledger, Duration::ZERO, at), "close {close}");
            at += QUIET_WINDOW_MS / u64::from(QUIET_CLOSES - 1) + 1;
        }
    }

    #[test]
    fn a_close_after_the_window_is_no_evidence() {
        let late = Duration::from_millis(SILENT_CLOSE_MS + 1);
        let edge = Duration::from_millis(SILENT_CLOSE_MS);
        let mut ledger = Ledger::default();
        for n in 0..u64::from(10 * QUIET_CLOSES) {
            assert!(!handshake_then_close(&mut ledger, late, burst(n)), "an idle connection says nothing");
        }
        let from = u64::from(10 * QUIET_CLOSES);
        for n in 1..u64::from(QUIET_CLOSES) {
            assert!(!handshake_then_close(&mut ledger, edge, burst(from + n)));
        }
        assert!(handshake_then_close(&mut ledger, edge, burst(from + u64::from(QUIET_CLOSES))), "the control: at the edge they count");
    }

    /// A pinning app that tries again on its own schedule, a minute or two apart.
    #[test]
    fn a_pinning_app_that_retries_slowly_is_excluded() {
        const RETRY: u64 = 2 * 60_000;
        let mut ledger = Ledger::default();
        for close in 1..u64::from(QUIET_CLOSES) {
            assert!(!handshake_then_close(&mut ledger, Duration::ZERO, NOW + close * RETRY), "close {close}");
        }
        assert!(handshake_then_close(&mut ledger, Duration::ZERO, NOW + u64::from(QUIET_CLOSES) * RETRY));
    }

    /// Parallel sockets of one client closed one after another within a burst, each
    /// with nothing else open (the next one's handshake not yet done).
    #[test]
    fn quiet_closes_in_one_burst_count_once() {
        let mut ledger = Ledger::default();
        for socket in 0..10 {
            assert!(!handshake_then_close(&mut ledger, Duration::ZERO, NOW + socket * BURST_MS / 10), "socket {socket}");
        }
        for n in 1..u64::from(QUIET_CLOSES) - 1 {
            assert!(!handshake_then_close(&mut ledger, Duration::ZERO, burst(n)));
        }
        assert!(handshake_then_close(&mut ledger, Duration::ZERO, burst(u64::from(QUIET_CLOSES) - 1)), "the control: separate bursts add up");
    }

    /// P1 of the 2026-11-08 review: an app that updates mid-run to start pinning, or
    /// the pinned half of an app whose unpinned half shares its exe.
    #[test]
    fn a_used_pair_that_then_drops_connection_after_connection_is_excluded() {
        let mut ledger = Ledger::default();
        used_connection(&mut ledger, NOW);
        for n in 1..u64::from(USED_QUIET_CLOSES) {
            assert!(!handshake_then_close(&mut ledger, Duration::ZERO, burst(n)), "close {n}: a used pair takes more");
        }
        assert!(handshake_then_close(&mut ledger, Duration::ZERO, burst(u64::from(USED_QUIET_CLOSES))));
        // Spread past the shorter window, or with a request between, they never add up.
        let mut ledger = Ledger::default();
        used_connection(&mut ledger, NOW);
        for n in 1..1000 {
            assert!(!handshake_then_close(&mut ledger, Duration::ZERO, NOW + n * (USED_QUIET_WINDOW_MS / u64::from(USED_QUIET_CLOSES - 1) + 1)), "close {n}");
        }
        let mut ledger = Ledger::default();
        for n in 0..1000 {
            if n % u64::from(USED_QUIET_CLOSES - 1) == 0 {
                used_connection(&mut ledger, burst(n));
            }
            assert!(!handshake_then_close(&mut ledger, Duration::ZERO, burst(n)), "close {n}");
        }
    }

    #[test]
    fn a_close_beside_an_open_connection_of_the_pair_is_no_evidence() {
        // A browser holds one preconnect and drops the redundant one at once.
        let mut ledger = Ledger::default();
        hear(&mut ledger, Evidence::Accepted, NOW);
        for close in 0..1000 {
            assert!(!handshake_then_close(&mut ledger, Duration::ZERO, NOW), "close {close}");
        }
    }

    /// The Edge and Chrome 157 patterns that excluded a search engine, a photo CDN
    /// and a chat app's CDN under the old rule (plan 4.3, 2026-11-08): rounds of
    /// several handshakes, one held idle and closed later, the rest dropped at once,
    /// none carrying a request, on hosts the user never opens and on hosts they use.
    #[test]
    fn edge_like_preconnects_never_exclude() {
        const ROUNDS: u64 = 1000;
        const SOCKETS: usize = 3;
        for gap in [0, 1, SILENT_CLOSE_MS, QUIET_WINDOW_MS / 4, QUIET_WINDOW_MS, HALF_LIFE_MS] {
            for with_requests in [false, true] {
                let mut ledger = Ledger::default();
                let mut at = NOW;
                for round in 0..ROUNDS {
                    for _ in 0..SOCKETS {
                        hear(&mut ledger, Evidence::Accepted, at);
                    }
                    if with_requests && round % 3 == 0 {
                        assert!(!hear(&mut ledger, Evidence::Used, at));
                    }
                    for dropped in 1..SOCKETS {
                        assert!(!hear(&mut ledger, quiet(Duration::from_millis(dropped as u64)), at), "gap {gap}, round {round}: a dropped one");
                    }
                    // A losing handshake cancelled while the held one is up.
                    assert!(!hear(&mut ledger, refused(), at), "gap {gap}, round {round}: a cancelled one");
                    at += gap;
                    assert!(!hear(&mut ledger, if with_requests && round % 3 == 0 { Evidence::Ended(None) } else { quiet(PRECONNECT_IDLE) }, at), "gap {gap}, round {round}: the held one");
                    at += gap;
                }
            }
        }
    }

    #[test]
    fn preconnects_later_used_never_exclude() {
        const ROUNDS: u64 = 1000;
        for gap in [0, 1, SILENT_CLOSE_MS, 60_000, HALF_LIFE_MS, 10 * HALF_LIFE_MS] {
            let mut ledger = Ledger::default();
            let mut at = NOW;
            for round in 0..ROUNDS {
                assert!(!handshake_then_close(&mut ledger, Duration::ZERO, at), "gap {gap}, round {round}");
                at += gap;
                assert!(!used_connection(&mut ledger, at));
                at += gap;
            }
        }
    }

    #[test]
    fn credit_is_bounded_and_decays() {
        let mut ledger = Ledger::default();
        for _ in 0..10 {
            used_connection(&mut ledger, NOW);
        }
        assert_eq!(ledger.value(EXE, HOST, NOW), -MAX_CREDIT);
        assert_eq!(ledger.value(EXE, HOST, NOW + HALF_LIFE_MS), -MAX_CREDIT / 2.0);
        // The bound holds: full credit buys two refusals more, no further.
        for refusal in 1..=3 {
            assert!(!hear(&mut ledger, refused(), NOW + refusal * (BURST_MS + 1)), "refusal {refusal}");
        }
        assert!(hear(&mut ledger, refused(), burst(4)), "the fourth");
    }

    #[test]
    fn a_clock_going_backwards_decays_nothing() {
        let mut ledger = Ledger::default();
        hear(&mut ledger, refused(), NOW);
        assert_eq!(ledger.value(EXE, HOST, NOW - HALF_LIFE_MS), 1.0);
        assert!(!hear(&mut ledger, refused(), NOW - 1), "a little back is the same burst");
        assert!(hear(&mut ledger, refused(), NOW - BURST_MS - 1), "and the next refusal still adds up");
        let mut ledger = Ledger::default();
        for n in 1..u64::from(QUIET_CLOSES) {
            handshake_then_close(&mut ledger, Duration::ZERO, burst(n));
        }
        assert!(handshake_then_close(&mut ledger, Duration::ZERO, NOW - QUIET_WINDOW_MS), "nor does it open a new quiet window");
    }

    #[test]
    fn a_used_connection_counts_once_however_many_requests() {
        // The ledger hears connections, one `Used` each: `http::serve::handle` tells
        // it once per connection, pinned by `tls::tests`. Two connections, two credits.
        let mut ledger = Ledger::default();
        used_connection(&mut ledger, NOW);
        assert_eq!(ledger.value(EXE, HOST, NOW), -1.0);
        used_connection(&mut ledger, NOW);
        assert_eq!(ledger.value(EXE, HOST, NOW), -2.0);
    }

    #[test]
    fn pairs_are_separate() {
        let mut ledger = Ledger::default();
        assert!(!ledger.hear(r"C:\a\one.exe", HOST, refused(), NOW));
        assert!(!ledger.hear(r"C:\a\two.exe", HOST, refused(), NOW), "another exe");
        assert!(!ledger.hear(r"C:\a\one.exe", "other.example", refused(), NOW), "another host");
        ledger.hear(r"C:\a\two.exe", HOST, Evidence::Accepted, NOW);
        assert!(ledger.hear(r"D:\elsewhere\ONE.EXE", "PIN.example", refused(), burst(1)), "the same pair, case folded, by file name; another exe's open connection is not its own");
    }

    #[test]
    fn the_ledger_stays_bounded() {
        let mut ledger = Ledger::default();
        for i in 0..MAX_PAIRS * 3 {
            let host = format!("h{i}.example");
            ledger.hear(EXE, &host, refused(), NOW);
            ledger.hear(EXE, &host, Evidence::Accepted, NOW);
            ledger.hear(EXE, &host, Evidence::Ended(None), NOW);
        }
        assert_eq!(ledger.len(), MAX_PAIRS);
        assert!(ledger.open.is_empty(), "a pair with nothing open leaves the open count");
    }

    #[test]
    fn an_excluded_pair_leaves_the_ledger() {
        let mut ledger = Ledger::default();
        hear(&mut ledger, refused(), NOW);
        hear(&mut ledger, refused(), burst(1));
        assert!(ledger.is_empty());
    }

    #[test]
    fn a_seeded_pair_is_excluded_by_one_more_attempt() {
        let mut ledger = Ledger::default();
        ledger.seed(EXE, HOST, NOW);
        assert!(hear(&mut ledger, refused(), NOW), "a refusal");
        ledger.seed(EXE, HOST, NOW);
        assert!(handshake_then_close(&mut ledger, Duration::ZERO, NOW), "or a quiet close");
    }

    proptest! {
        /// No cliff: more time passed never means more score, for evidence or credit.
        #[test]
        fn score_is_monotonic_in_elapsed_time(refusals in 0..3u8, used in 0..3u8, a in 0..(100 * HALF_LIFE_MS), b in 0..(100 * HALF_LIFE_MS)) {
            let mut ledger = Ledger::default();
            for _ in 0..used {
                used_connection(&mut ledger, NOW);
            }
            for _ in 0..refusals {
                hear(&mut ledger, refused(), NOW);
            }
            let (early, late) = (a.min(b), a.max(b));
            let (at_early, at_late) = (ledger.value(EXE, HOST, NOW + early), ledger.value(EXE, HOST, NOW + late));
            prop_assert!(at_early.abs() >= at_late.abs(), "{} then {}", at_early, at_late);
        }
    }
}
