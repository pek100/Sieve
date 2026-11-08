//! Follow admitted adapter packets through the stack, independently of pings.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use ipstack::{Progress, ProgressSnapshot};
use super::{STALL_MS, Stall};

const WORKER_EXITED: &str = "ipstack worker exited";

/// One routing run's adapter arrivals the stack should receive: admitted
/// packets less those dropped as too large. Owned by that run's reader, so a
/// previous run's reader still draining the ring cannot count here.
#[derive(Debug, Default)]
pub struct Offered {
    admitted: AtomicU64,
    dropped: AtomicU64,
}

impl Offered {
    pub fn admit(&self) { self.admitted.fetch_add(1, Ordering::Relaxed); }
    pub fn drop_oversized(&self) { self.dropped.fetch_add(1, Ordering::Relaxed); }

    /// Admitted is read first, so a racing drop can only make this low for one sample.
    pub fn get(&self) -> u64 {
        let admitted = self.admitted.load(Ordering::Relaxed);
        admitted.saturating_sub(self.dropped.load(Ordering::Relaxed))
    }
}

/// A stage with work outstanding must complete something within STALL_MS.
/// Reuse the existing watchdog outage budget: these are local queue/dispatch/
/// device operations, not remote DNS or TCP response deadlines. A slow stage
/// that keeps completing work resets its timer, regardless of queue depth.
#[derive(Debug, Default)]
struct Waiting {
    completed: u64,
    since: Option<u64>,
}

impl Waiting {
    fn check(&mut self, pending: bool, completed: u64, now: u64, what: &'static str) -> Option<Stall> {
        if !pending {
            self.since = None;
        } else if self.since.is_none() || completed != self.completed {
            self.since = Some(now);
        }
        self.completed = completed;
        let ms = now.saturating_sub(self.since?);
        (ms >= STALL_MS).then_some(Stall { what, ms, detail: None })
    }
}

#[derive(Debug, Default)]
struct Stages {
    input: Waiting,
    dispatch: Waiting,
    output: Waiting,
    exited: Waiting,
}

impl Stages {
    fn check(&mut self, offered: u64, p: ProgressSnapshot, now: u64) -> Option<Stall> {
        // Evaluate every stage even when another has tripped. More specific
        // downstream failures take precedence over the backlog they cause.
        let exited = self.exited.check(p.exited, 0, now, WORKER_EXITED);
        let output = self.output.check(p.writes_started > p.writes_finished, p.writes_finished, now, "ipstack to TUN write");
        let dispatch = self.dispatch.check(p.received > p.dispatched, p.dispatched, now, "ipstack dispatch");
        let input = self.input.check(offered > p.received, p.received, now, "TUN to ipstack queue");
        exited.or(output).or(dispatch).or(input)
    }

    fn waiting_stage(&self) -> Option<&'static str> {
        if self.exited.since.is_some() { Some(WORKER_EXITED) }
        else if self.output.since.is_some() { Some("ipstack to TUN write") }
        else if self.dispatch.since.is_some() { Some("ipstack dispatch") }
        else if self.input.since.is_some() { Some("TUN to ipstack queue") }
        else { None }
    }
}

#[derive(Debug)]
pub struct PathWatch {
    offered: Arc<Offered>,
    progress: Arc<Progress>,
    stages: Stages,
}

impl PathWatch {
    /// Both sides belong to one routing run: its TUN device's arrivals and its stack.
    pub fn new(offered: Arc<Offered>, progress: Arc<Progress>) -> Self {
        Self { offered, progress, stages: Stages::default() }
    }

    /// A worker exit names the worker's own error, so the trip's record keeps it.
    pub fn check(&mut self, now: u64) -> Option<Stall> {
        let stall = self.stages.check(self.offered.get(), self.progress.snapshot(), now)?;
        let detail = if stall.what == WORKER_EXITED { self.progress.exit_reason() } else { None };
        Some(Stall { detail, ..stall })
    }

    /// Counts, plus the worker's device error. ipstack's worker fails only on
    /// device reads and writes, whose errors carry no flow address.
    /// `waiting_stage` is the watchdog's last sample, not a cause.
    pub fn report(&self) -> serde_json::Value {
        let p = self.progress.snapshot();
        serde_json::json!({
            "offered": self.offered.get(),
            "received": p.received,
            "dispatched": p.dispatched,
            "writes_started": p.writes_started,
            "writes_finished": p.writes_finished,
            "worker_exited": p.exited,
            "exit_reason": self.progress.exit_reason(),
            "waiting_stage": self.stages.waiting_stage(),
            "stall_ms": STALL_MS,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offered_input_stalls_below_queue_capacity_even_if_pings_work() {
        let mut stages = Stages::default();
        let p = ProgressSnapshot::default();
        assert_eq!(stages.check(1, p, 0), None);
        assert_eq!(stages.check(2, p, STALL_MS - 1), None);
        assert_eq!(stages.check(3, p, STALL_MS).unwrap().what, "TUN to ipstack queue");
    }

    #[test]
    fn idle_and_silent_processed_packets_need_no_reply() {
        let mut stages = Stages::default();
        assert_eq!(stages.check(0, ProgressSnapshot::default(), u64::MAX), None);
        let p = ProgressSnapshot { received: 1, dispatched: 1, ..Default::default() };
        assert_eq!(stages.check(1, p, 0), None);
        assert_eq!(stages.check(1, p, STALL_MS * 2), None);
    }

    #[test]
    fn slow_progress_resets_each_stage_despite_backlog() {
        let mut stages = Stages::default();
        // Span more than the stall budget, always completing just before it.
        for step in 0..=2 {
            let p = ProgressSnapshot { received: step + 1, dispatched: step, writes_started: step + 1, writes_finished: step, exited: false };
            assert_eq!(stages.check(step + 2, p, step * (STALL_MS - 1)), None);
        }
    }

    #[test]
    fn downstream_stages_are_named_and_unrelated_progress_cannot_mask_them() {
        for (p, expected) in [
            (ProgressSnapshot { received: 1, ..Default::default() }, "ipstack dispatch"),
            (ProgressSnapshot { writes_started: 1, ..Default::default() }, "ipstack to TUN write"),
            (ProgressSnapshot { exited: true, ..Default::default() }, WORKER_EXITED),
        ] {
            let mut stages = Stages::default();
            assert_eq!(stages.check(1, p, 0), None);
            assert_eq!(stages.check(2, p, STALL_MS).unwrap().what, expected);
        }
    }
}
