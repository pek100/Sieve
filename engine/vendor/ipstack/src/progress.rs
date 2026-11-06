//! Packet-loop progress, independent of the executor and flow tasks.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct Progress {
    pub(crate) received: AtomicU64,
    pub(crate) dispatched: AtomicU64,
    pub(crate) writes_started: AtomicU64,
    pub(crate) writes_finished: AtomicU64,
    exited: AtomicBool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProgressSnapshot {
    pub received: u64,
    pub dispatched: u64,
    pub writes_started: u64,
    pub writes_finished: u64,
    pub exited: bool,
}

impl Progress {
    pub fn snapshot(&self) -> ProgressSnapshot {
        ProgressSnapshot {
            received: self.received.load(Ordering::Relaxed),
            dispatched: self.dispatched.load(Ordering::Relaxed),
            writes_started: self.writes_started.load(Ordering::Relaxed),
            writes_finished: self.writes_finished.load(Ordering::Relaxed),
            exited: self.exited.load(Ordering::Acquire),
        }
    }
}

// Captured before spawning, so cancellation before the first poll counts too.
pub(crate) struct ExitGuard(pub Arc<Progress>);

impl Drop for ExitGuard {
    fn drop(&mut self) {
        self.0.exited.store(true, Ordering::Release);
    }
}
