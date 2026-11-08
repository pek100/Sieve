//! Follow admitted adapter packets through the stack, independently of pings.

use std::sync::Arc;
use ipstack::{Progress, ProgressSnapshot};
use crate::stack::Meters;
use super::{STALL_MS, Stall};

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
        (ms >= STALL_MS).then_some(Stall { what, ms })
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
        let exited = self.exited.check(p.exited, 0, now, "ipstack worker exited");
        let output = self.output.check(p.writes_started > p.writes_finished, p.writes_finished, now, "ipstack to TUN write");
        let dispatch = self.dispatch.check(p.received > p.dispatched, p.dispatched, now, "ipstack dispatch");
        let input = self.input.check(offered > p.received, p.received, now, "TUN to ipstack queue");
        exited.or(output).or(dispatch).or(input)
    }

    fn waiting_stage(&self) -> Option<&'static str> {
        if self.exited.since.is_some() { Some("ipstack worker exited") }
        else if self.output.since.is_some() { Some("ipstack to TUN write") }
        else if self.dispatch.since.is_some() { Some("ipstack dispatch") }
        else if self.input.since.is_some() { Some("TUN to ipstack queue") }
        else { None }
    }
}

#[derive(Debug)]
pub struct PathWatch {
    meters: Arc<Meters>,
    progress: Arc<Progress>,
    baseline: u64,
    stages: Stages,
}

impl PathWatch {
    /// Capture baseline BEFORE starting this run's TUN reader. Counters are
    /// process-wide, but ipstack's counters belong to just this routing run.
    pub fn new(meters: Arc<Meters>, progress: Arc<Progress>, baseline: u64) -> Self {
        Self { meters, progress, baseline, stages: Stages::default() }
    }

    fn offered(&self) -> u64 { self.meters.stack_offered().saturating_sub(self.baseline) }

    pub fn check(&mut self, now: u64) -> Option<Stall> {
        self.stages.check(self.offered(), self.progress.snapshot(), now)
    }

    /// Counts only. `waiting_stage` is the watchdog's last sample, not a cause.
    pub fn report(&self) -> serde_json::Value {
        let p = self.progress.snapshot();
        serde_json::json!({
            "offered": self.offered(),
            "received": p.received,
            "dispatched": p.dispatched,
            "writes_started": p.writes_started,
            "writes_finished": p.writes_finished,
            "worker_exited": p.exited,
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
            (ProgressSnapshot { exited: true, ..Default::default() }, "ipstack worker exited"),
        ] {
            let mut stages = Stages::default();
            assert_eq!(stages.check(1, p, 0), None);
            assert_eq!(stages.check(2, p, STALL_MS).unwrap().what, expected);
        }
    }
}
