//! The evidence about one (app, host) pair (plan 4.3, task D1): one quantity with
//! one threshold, its law written directly. Pure; every "now" is passed in (S15).
//!
//! ```text
//! decayed(v, dt) = v * 0.5^(dt / HALF_LIFE)     // credit decays toward 0 too
//! a failed attempt: v = decayed + 1; excluded when v >= EXCLUDE_AT
//! a used connection: v = max(decayed - 1, -MAX_CREDIT)
//! a fatal alert: excluded at once
//! try again: v = 1 at now
//! ```
//!
//! Scores live in memory only: losing one costs one more close.

use rustls::AlertDescription;

use super::dials::{EXCLUDE_AT, FATAL_ALERTS, HALF_LIFE_MS, MAX_CREDIT, MAX_PAIRS, SILENT_CLOSE_MS};
use crate::lru::Lru;

/// What the watch heard (the table in task D3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// The client refused our handshake or ended right after it, with this alert
    /// if it sent one.
    Refused(Option<AlertDescription>),
    /// The client closed this long after the handshake, with no request.
    Closed { after_ms: u64 },
    /// A connection of the pair carried a request.
    Used,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Score {
    value: f64,
    at_ms: u64,
}

impl Score {
    const NONE: Self = Self { value: 0.0, at_ms: 0 };

    /// A clock that went backwards decays nothing.
    fn decayed(self, now_ms: u64) -> f64 {
        let elapsed = now_ms.saturating_sub(self.at_ms) as f64;
        self.value * 0.5_f64.powf(elapsed / HALF_LIFE_MS as f64)
    }

    fn set(&mut self, value: f64, now_ms: u64) {
        *self = Self { value, at_ms: now_ms.max(self.at_ms) };
    }
}

/// (exe file name, host), both lower case.
type Key = (String, String);

/// Every pair's score, bounded.
pub struct Ledger {
    scores: Lru<Key, Score>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self::with_capacity(MAX_PAIRS)
    }
}

/// `exe` as an exclusion compares it: the file name, lower case.
pub fn exe_name(exe: &str) -> String {
    exe.rsplit(['\\', '/']).next().unwrap_or(exe).to_ascii_lowercase()
}

impl Ledger {
    fn with_capacity(capacity: usize) -> Self {
        Self { scores: Lru::new(capacity) }
    }

    fn key(exe: &str, host: &str) -> Key {
        (exe_name(exe), host.to_ascii_lowercase())
    }

    fn get(&mut self, key: &Key) -> Score {
        self.scores.get(key, |_| true).unwrap_or(Score::NONE)
    }

    /// True when this evidence excludes the pair. An excluded pair's score is gone:
    /// the next one starts from what "try again" seeds.
    pub fn hear(&mut self, exe: &str, host: &str, evidence: Evidence, now_ms: u64) -> bool {
        let key = Self::key(exe, host);
        let excluded = match evidence {
            Evidence::Refused(Some(alert)) if FATAL_ALERTS.contains(&alert) => true,
            Evidence::Closed { after_ms } if after_ms > SILENT_CLOSE_MS => false,
            Evidence::Refused(_) | Evidence::Closed { .. } => {
                let mut score = self.get(&key);
                score.set(score.decayed(now_ms) + 1.0, now_ms);
                self.scores.insert(key.clone(), score);
                score.value >= EXCLUDE_AT
            }
            Evidence::Used => {
                let mut score = self.get(&key);
                score.set((score.decayed(now_ms) - 1.0).max(-MAX_CREDIT), now_ms);
                self.scores.insert(key.clone(), score);
                false
            }
        };
        if excluded {
            self.scores.remove(&key);
        }
        excluded
    }

    /// "Try decrypting again": one more failed attempt excludes the pair.
    pub fn seed(&mut self, exe: &str, host: &str, now_ms: u64) {
        self.scores.insert(Self::key(exe, host), Score { value: 1.0, at_ms: now_ms });
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
    use proptest::prelude::*;

    use super::*;

    const EXE: &str = r"C:\Apps\Client.exe";
    const HOST: &str = "pin.example";
    const NOW: u64 = 1_793_000_000_000;

    fn closed() -> Evidence {
        Evidence::Closed { after_ms: 0 }
    }

    fn hear(ledger: &mut Ledger, evidence: Evidence, at: u64) -> bool {
        ledger.hear(EXE, HOST, evidence, at)
    }

    #[test]
    fn the_plans_numbers_could_not_do_what_it_said() {
        // Task F1: one half-life apart, the plan's threshold is out of reach.
        let two_closes = 0.5_f64.powf(1.0) + 1.0;
        assert!(two_closes < 2.0);
        assert!(two_closes >= EXCLUDE_AT);
    }

    #[test]
    fn one_fatal_alert_excludes() {
        for alert in FATAL_ALERTS {
            assert!(Ledger::default().hear(EXE, HOST, Evidence::Refused(Some(alert)), NOW), "{alert:?}");
        }
        assert_eq!(FATAL_ALERTS.len(), 6);
    }

    #[test]
    fn a_fatal_alert_ignores_any_credit() {
        let mut ledger = Ledger::default();
        for _ in 0..10 {
            hear(&mut ledger, Evidence::Used, NOW);
        }
        assert!(hear(&mut ledger, Evidence::Refused(Some(AlertDescription::UnknownCA)), NOW));
    }

    #[test]
    fn another_alert_or_none_is_weak_evidence() {
        for weak in [Some(AlertDescription::HandshakeFailure), Some(AlertDescription::UserCanceled), None] {
            let mut ledger = Ledger::default();
            assert!(!hear(&mut ledger, Evidence::Refused(weak), NOW), "{weak:?}: one is not enough");
            assert!(hear(&mut ledger, Evidence::Refused(weak), NOW), "{weak:?}: two are");
        }
    }

    #[test]
    fn two_silent_closes_within_the_half_life_exclude() {
        for gap in [0, 1, HALF_LIFE_MS] {
            let mut ledger = Ledger::default();
            assert!(!hear(&mut ledger, closed(), NOW), "one close never excludes");
            assert!(hear(&mut ledger, closed(), NOW + gap), "gap {gap}");
        }
    }

    #[test]
    fn two_silent_closes_past_the_half_life_do_not() {
        let mut ledger = Ledger::default();
        hear(&mut ledger, closed(), NOW);
        assert!(!hear(&mut ledger, closed(), NOW + HALF_LIFE_MS + 1));
    }

    #[test]
    fn a_close_after_the_window_is_no_evidence() {
        let mut ledger = Ledger::default();
        hear(&mut ledger, Evidence::Closed { after_ms: SILENT_CLOSE_MS + 1 }, NOW);
        assert_eq!(ledger.value(EXE, HOST, NOW), 0.0, "nothing was added");
        assert!(!hear(&mut ledger, Evidence::Closed { after_ms: SILENT_CLOSE_MS }, NOW), "at the edge it counts");
        assert_eq!(ledger.value(EXE, HOST, NOW), 1.0);
        assert!(!hear(&mut ledger, Evidence::Closed { after_ms: SILENT_CLOSE_MS + 1 }, NOW), "and a late one still does not");
        assert!(hear(&mut ledger, Evidence::Closed { after_ms: SILENT_CLOSE_MS }, NOW), "the control");
    }

    #[test]
    fn preconnects_later_used_never_exclude() {
        const ROUNDS: u64 = 1000;
        for gap in [0, 1, SILENT_CLOSE_MS, 60_000, HALF_LIFE_MS, 10 * HALF_LIFE_MS] {
            let mut ledger = Ledger::default();
            let mut at = NOW;
            for round in 0..ROUNDS {
                assert!(!hear(&mut ledger, closed(), at), "gap {gap}, round {round}");
                at += gap;
                assert!(!hear(&mut ledger, Evidence::Used, at));
                at += gap;
            }
        }
    }

    #[test]
    fn used_then_redundant_closes_do_not_exclude() {
        let mut ledger = Ledger::default();
        hear(&mut ledger, Evidence::Used, NOW);
        assert!(!hear(&mut ledger, closed(), NOW));
        assert!(!hear(&mut ledger, closed(), NOW), "two redundant sockets on a pair that carried requests");
        // The bound holds: full credit buys two closes more, no further.
        let mut ledger = Ledger::default();
        for _ in 0..10 {
            hear(&mut ledger, Evidence::Used, NOW);
        }
        for close in 1..=3 {
            assert!(!hear(&mut ledger, closed(), NOW), "close {close}");
        }
        assert!(hear(&mut ledger, closed(), NOW), "the fourth");
    }

    #[test]
    fn credit_is_bounded_and_decays() {
        let mut ledger = Ledger::default();
        for _ in 0..10 {
            hear(&mut ledger, Evidence::Used, NOW);
        }
        assert_eq!(ledger.value(EXE, HOST, NOW), -MAX_CREDIT);
        assert_eq!(ledger.value(EXE, HOST, NOW + HALF_LIFE_MS), -MAX_CREDIT / 2.0);
    }

    #[test]
    fn a_clock_going_backwards_decays_nothing() {
        let mut ledger = Ledger::default();
        hear(&mut ledger, closed(), NOW);
        assert_eq!(ledger.value(EXE, HOST, NOW - HALF_LIFE_MS), 1.0);
        assert!(hear(&mut ledger, closed(), NOW - 1), "and the next close still adds up");
    }

    #[test]
    fn a_used_connection_counts_once_however_many_requests() {
        // The ledger hears connections, one `Used` each: `http::serve::handle` tells
        // it once per connection, pinned by `tls::tests`. Two connections, two credits.
        let mut ledger = Ledger::default();
        hear(&mut ledger, Evidence::Used, NOW);
        assert_eq!(ledger.value(EXE, HOST, NOW), -1.0);
        hear(&mut ledger, Evidence::Used, NOW);
        assert_eq!(ledger.value(EXE, HOST, NOW), -2.0);
    }

    #[test]
    fn pairs_are_separate() {
        let mut ledger = Ledger::default();
        assert!(!ledger.hear(r"C:\a\one.exe", HOST, closed(), NOW));
        assert!(!ledger.hear(r"C:\a\two.exe", HOST, closed(), NOW), "another exe");
        assert!(!ledger.hear(r"C:\a\one.exe", "other.example", closed(), NOW), "another host");
        assert!(ledger.hear(r"D:\elsewhere\ONE.EXE", "PIN.example", closed(), NOW), "the same pair, case folded, by file name");
    }

    #[test]
    fn the_ledger_stays_bounded() {
        let mut ledger = Ledger::default();
        for i in 0..MAX_PAIRS * 3 {
            ledger.hear(EXE, &format!("h{i}.example"), closed(), NOW);
        }
        assert_eq!(ledger.len(), MAX_PAIRS);
    }

    #[test]
    fn an_excluded_pair_leaves_the_ledger() {
        let mut ledger = Ledger::default();
        hear(&mut ledger, closed(), NOW);
        hear(&mut ledger, closed(), NOW);
        assert!(ledger.is_empty());
    }

    proptest! {
        /// No cliff: more time passed never means more score, for evidence or credit.
        #[test]
        fn score_is_monotonic_in_elapsed_time(closes in 0..3u8, used in 0..3u8, a in 0..(100 * HALF_LIFE_MS), b in 0..(100 * HALF_LIFE_MS)) {
            let mut ledger = Ledger::default();
            for _ in 0..used {
                hear(&mut ledger, Evidence::Used, NOW);
            }
            for _ in 0..closes {
                hear(&mut ledger, closed(), NOW);
            }
            let (early, late) = (a.min(b), a.max(b));
            let (at_early, at_late) = (ledger.value(EXE, HOST, NOW + early), ledger.value(EXE, HOST, NOW + late));
            prop_assert!(at_early.abs() >= at_late.abs(), "{} then {}", at_early, at_late);
        }
    }
}
