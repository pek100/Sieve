//! Admission for connections that have not authenticated yet (a listening
//! hub, a device waiting for its hub to dial in, a device waiting to pair).
//!
//! Silent sockets must not lock everyone out, so:
//!
//! - each source (an IPv4 address, or an IPv6 /64) may have at most
//!   `per_source` connections waiting or handshaking at once; more are
//!   closed at once;
//! - at most `slots` handshakes run at once; a new connection WAITS up to
//!   `wait` for a slot instead of being dropped, and at most `queue`
//!   connections wait;
//! - the handshake itself has a short limit (the callers' `accept_timeout`,
//!   about 3 s), so a silent socket holds a slot for seconds, not ten.
//!
//! Nothing here is unbounded: one spawned task per admitted connection, and
//! admitted connections are capped by `queue` + `slots`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Copy, Debug)]
pub struct GateConfig {
    pub slots: usize,
    pub per_source: usize,
    pub queue: usize,
    pub wait: Duration,
}

impl GateConfig {
    /// A listening hub.
    pub fn hub() -> Self {
        GateConfig { slots: 64, per_source: 4, queue: 256, wait: Duration::from_secs(2) }
    }

    /// A device waiting for its hub (one peer expected).
    pub fn device() -> Self {
        GateConfig { slots: 8, per_source: 4, queue: 32, wait: Duration::from_secs(2) }
    }
}

pub struct Gate {
    cfg: GateConfig,
    slots: Arc<Semaphore>,
    queue: Arc<Semaphore>,
    sources: Mutex<HashMap<IpAddr, usize>>,
}

/// The source key: an IPv4 address, or the /64 an IPv6 address sits in
/// (one subscriber usually has a whole /64).
fn source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
        v4 => v4,
    }
}

/// Counts one connection against its source until dropped.
struct SourceHold {
    gate: Arc<Gate>,
    key: IpAddr,
}

impl Drop for SourceHold {
    fn drop(&mut self) {
        let mut m = self.gate.sources.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// Admitted, waiting for a handshake slot.
pub struct Ticket {
    hold: SourceHold,
    _queued: OwnedSemaphorePermit,
}

/// Holding a handshake slot.
pub struct Pass {
    _hold: SourceHold,
    _slot: OwnedSemaphorePermit,
}

impl Gate {
    pub fn new(cfg: GateConfig) -> Arc<Self> {
        Arc::new(Gate { cfg, slots: Arc::new(Semaphore::new(cfg.slots)), queue: Arc::new(Semaphore::new(cfg.queue)), sources: Mutex::new(HashMap::new()) })
    }

    /// Refuses at once a source that already has `per_source` connections in
    /// progress, or when `queue` connections are already waiting.
    pub fn admit(self: &Arc<Self>, ip: IpAddr) -> Option<Ticket> {
        let key = source_key(ip);
        {
            let mut m = self.sources.lock().unwrap_or_else(|e| e.into_inner());
            let n = m.entry(key).or_insert(0);
            if *n >= self.cfg.per_source {
                return None;
            }
            *n += 1;
        }
        let hold = SourceHold { gate: self.clone(), key };
        let queued = self.queue.clone().try_acquire_owned().ok()?;
        Some(Ticket { hold, _queued: queued })
    }

    /// Handshake slots free right now.
    pub fn free_slots(&self) -> usize {
        self.slots.available_permits()
    }
}

impl Ticket {
    /// Waits up to the gate's `wait` for a handshake slot.
    pub async fn enter(self) -> Option<Pass> {
        let gate = self.hold.gate.clone();
        let slot = tokio::time::timeout(gate.cfg.wait, gate.slots.clone().acquire_owned()).await.ok()?.ok()?;
        Some(Pass { _hold: self.hold, _slot: slot })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn one_source_cannot_take_every_slot() {
        let g = Gate::new(GateConfig { slots: 8, per_source: 2, queue: 16, wait: Duration::from_millis(100) });
        let a = g.admit(ip("203.0.113.1")).unwrap().enter().await.unwrap();
        let _b = g.admit(ip("203.0.113.1")).unwrap().enter().await.unwrap();
        assert!(g.admit(ip("203.0.113.1")).is_none(), "third from one source refused");
        // The same /64 is one source; another /64 is not.
        let _c = g.admit(ip("2a01:4f8:1:2::1")).unwrap();
        let _d = g.admit(ip("2a01:4f8:1:2::ffff")).unwrap();
        assert!(g.admit(ip("2a01:4f8:1:2:1::1")).is_none());
        assert!(g.admit(ip("2a01:4f8:1:3::1")).is_some());
        // A finished handshake frees the source.
        drop(a);
        assert!(g.admit(ip("203.0.113.1")).is_some());
    }

    #[tokio::test]
    async fn a_new_connection_waits_for_a_slot() {
        let g = Gate::new(GateConfig { slots: 1, per_source: 4, queue: 4, wait: Duration::from_secs(2) });
        let held = g.admit(ip("198.51.100.1")).unwrap().enter().await.unwrap();
        let t = g.admit(ip("198.51.100.2")).unwrap();
        let waiter = tokio::spawn(t.enter());
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(held);
        assert!(waiter.await.unwrap().is_some(), "the waiting connection got the freed slot");
        // With nothing freed, the wait ends empty-handed.
        let g = Gate::new(GateConfig { slots: 1, per_source: 4, queue: 4, wait: Duration::from_millis(50) });
        let _held = g.admit(ip("198.51.100.1")).unwrap().enter().await.unwrap();
        assert!(g.admit(ip("198.51.100.2")).unwrap().enter().await.is_none());
    }

    #[tokio::test]
    async fn the_queue_is_bounded() {
        let g = Gate::new(GateConfig { slots: 1, per_source: 100, queue: 2, wait: Duration::from_secs(1) });
        let _a = g.admit(ip("192.0.2.1")).unwrap();
        let _b = g.admit(ip("192.0.2.2")).unwrap();
        assert!(g.admit(ip("192.0.2.3")).is_none());
    }
}
