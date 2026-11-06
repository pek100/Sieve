//! The measurement behind `REFUSAL` (plan section 3, slice 8): from the first
//! datagram of a refused flow to the first TCP flow of the same (pid, host). The
//! numbers are counts and raw values in `status.json`; no host leaves memory and
//! nothing goes on the pipe (plan 7.1).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::Refusal;
use crate::lru::Lru;
use crate::stack::Meters;

/// Pairs waiting for their TCP flow.
pub const TRACKED: usize = 256;
/// Raw fallback times kept, newest last. The runbook takes the percentiles (S4).
pub const SAMPLES: usize = 256;
/// A TCP flow later than this is a later visit, not a fallback. Bounds the
/// measurement only: no decision reads it.
pub const FALLBACK_WINDOW: Duration = Duration::from_secs(10);

const WINDOW_MS: u64 = FALLBACK_WINDOW.as_millis() as u64;

type PairKey = (u32, String);

struct Fallback {
    /// The first datagram's time, per pair.
    waiting: Lru<PairKey, u64>,
    samples: VecDeque<u64>,
}

impl Default for Fallback {
    fn default() -> Self {
        Self { waiting: Lru::new(TRACKED), samples: VecDeque::with_capacity(SAMPLES) }
    }
}

impl std::fmt::Debug for Fallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fallback").field("waiting", &self.waiting.len()).field("samples", &self.samples.len()).finish()
    }
}

#[derive(Debug, Default)]
pub struct QuicMeters {
    pub refused: AtomicU64,
    pub replies: AtomicU64,
    /// Version Negotiation packets sent to blocked flows (`quic::negotiate`).
    pub blocked_replies: AtomicU64,
    pub send_failed: AtomicU64,
    /// A TCP flow accepted before the Initial: a race, never a sample of 0 (S17).
    pub raced: AtomicU64,
    fallback: Mutex<Fallback>,
}

impl QuicMeters {
    fn fallback(&self) -> std::sync::MutexGuard<'_, Fallback> {
        self.fallback.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A flow of this pair was refused; the clock started at its first datagram.
    /// A second flow while the first still waits keeps the first's clock.
    pub fn refused(&self, pid: u32, host: &str, first_datagram_ms: u64) {
        Meters::bump(&self.refused);
        let key = (pid, host.to_string());
        let mut fallback = self.fallback();
        let waiting = fallback.waiting.get(&key, |&at| first_datagram_ms.saturating_sub(at) <= WINDOW_MS).is_some();
        if !waiting {
            fallback.waiting.insert(key, first_datagram_ms);
        }
    }

    /// A TCP flow of this pair was accepted at `accepted_ms`. The first one takes
    /// the entry.
    pub fn tcp_seen(&self, pid: u32, host: &str, accepted_ms: u64) {
        let key = (pid, host.to_string());
        let mut fallback = self.fallback();
        let Some(first) = fallback.waiting.get(&key, |_| true) else { return };
        fallback.waiting.remove(&key);
        if accepted_ms < first {
            Meters::bump(&self.raced);
            return;
        }
        let waited = accepted_ms - first;
        if waited > WINDOW_MS {
            return;
        }
        if fallback.samples.len() == SAMPLES {
            fallback.samples.pop_front();
        }
        fallback.samples.push_back(waited);
    }

    /// The `quic` section of `status.json`: which arm this build is, so the
    /// evidence labels itself.
    pub fn report(&self, refusal: Refusal) -> serde_json::Value {
        let l = |c: &AtomicU64| c.load(Ordering::Relaxed);
        serde_json::json!({
            "refusal": refusal.word(),
            "refused": l(&self.refused),
            "replies": l(&self.replies),
            "blocked_replies": l(&self.blocked_replies),
            "send_failed": l(&self.send_failed),
            "raced": l(&self.raced),
            "fallback_ms": self.fallback().samples.iter().collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PID: u32 = 42;
    const HOST: &str = "site.example";
    const T0: u64 = 1_000_000;

    fn samples(m: &QuicMeters) -> Vec<u64> {
        m.fallback().samples.iter().copied().collect()
    }

    #[test]
    fn fallback_is_measured_from_the_first_datagram_to_the_first_tcp_flow() {
        let m = QuicMeters::default();
        m.refused(PID, HOST, T0);
        m.tcp_seen(PID, HOST, T0 + 37);
        assert_eq!(samples(&m), [37]);
        assert_eq!(m.refused.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_second_tcp_flow_is_no_sample() {
        let m = QuicMeters::default();
        m.refused(PID, HOST, T0);
        m.tcp_seen(PID, HOST, T0 + 5);
        m.tcp_seen(PID, HOST, T0 + 6);
        assert_eq!(samples(&m), [5]);
    }

    #[test]
    fn a_second_refused_flow_keeps_the_first_clock() {
        let m = QuicMeters::default();
        m.refused(PID, HOST, T0);
        m.refused(PID, HOST, T0 + 100);
        m.tcp_seen(PID, HOST, T0 + 150);
        assert_eq!(samples(&m), [150]);
        assert_eq!(m.refused.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_tcp_flow_first_counts_a_race_not_a_zero() {
        let m = QuicMeters::default();
        m.refused(PID, HOST, T0);
        m.tcp_seen(PID, HOST, T0 - 1);
        assert_eq!(samples(&m), Vec::<u64>::new());
        assert_eq!(m.raced.load(Ordering::Relaxed), 1);
        m.tcp_seen(PID, HOST, T0 + 1);
        assert_eq!(samples(&m), Vec::<u64>::new(), "the race took the entry");
    }

    #[test]
    fn past_the_window_is_no_sample() {
        let m = QuicMeters::default();
        m.refused(PID, HOST, T0);
        m.tcp_seen(PID, HOST, T0 + WINDOW_MS);
        assert_eq!(samples(&m), [WINDOW_MS], "the window itself still counts");
        m.refused(PID, HOST, T0);
        m.tcp_seen(PID, HOST, T0 + WINDOW_MS + 1);
        assert_eq!(samples(&m), [WINDOW_MS], "one past it does not");
        assert_eq!(m.raced.load(Ordering::Relaxed), 0);
        // A refusal past the window starts a new clock.
        m.refused(PID, HOST, T0);
        m.refused(PID, HOST, T0 + WINDOW_MS + 1);
        m.tcp_seen(PID, HOST, T0 + WINDOW_MS + 2);
        assert_eq!(samples(&m), [WINDOW_MS, 1]);
    }

    #[test]
    fn samples_and_tracked_pairs_are_bounded() {
        let m = QuicMeters::default();
        for i in 0..(TRACKED as u64 + 10) {
            m.refused(PID, &format!("h{i}.example"), T0);
        }
        assert_eq!(m.fallback().waiting.len(), TRACKED);
        m.tcp_seen(PID, "h0.example", T0 + 1);
        assert_eq!(samples(&m), Vec::<u64>::new(), "the oldest pair went first");
        for i in 0..(SAMPLES as u64 + 5) {
            m.refused(PID, HOST, T0 + i);
            m.tcp_seen(PID, HOST, T0 + i + i);
        }
        let held = samples(&m);
        assert_eq!(held.len(), SAMPLES);
        assert_eq!(held.last(), Some(&(SAMPLES as u64 + 4)), "the newest stays");
    }

    #[test]
    fn another_pid_is_another_pair() {
        let m = QuicMeters::default();
        m.refused(PID, HOST, T0);
        m.tcp_seen(PID + 1, HOST, T0 + 1);
        m.tcp_seen(PID, "other.example", T0 + 1);
        assert_eq!(samples(&m), Vec::<u64>::new());
        m.tcp_seen(PID, HOST, T0 + 2);
        assert_eq!(samples(&m), [2]);
    }
}
