//! The flows that are or may become intercepted, by host, each with a close
//! signal (plan 2.6, task D17). A verdict of revoked closes that host's flows;
//! turning the switch off closes all of them. Revocation is learned only at a
//! handshake: no timer polls.
//!
//! A flow registers before it reads the verdict cache, so no close can fall in
//! the gap before it decrypts. `close_all` is latched: this set belongs to one
//! `Interception`, which is retired for good when the switch goes off, and a flow
//! that took it just before still registers afterwards. `close_host` needs no
//! latch: its caller stored the revoked verdict first, so a flow registering
//! later reads that from the cache (one owner of the fact, S29).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

struct Flows {
    next: u64,
    closed: bool,
    by_host: HashMap<String, HashMap<u64, watch::Sender<bool>>>,
}

#[derive(Clone)]
pub struct Active(Arc<Mutex<Flows>>);

impl Default for Active {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Flows { next: 0, closed: false, by_host: HashMap::new() })))
    }
}

/// One flow on its way to interception, or in it. It deregisters when dropped,
/// which a flow that passes through does before its splice.
pub struct Registered {
    active: Active,
    host: String,
    id: u64,
    closed: watch::Receiver<bool>,
}

impl Registered {
    pub fn host(&self) -> &str {
        &self.host
    }

    /// True once this flow must not decrypt, or must end.
    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    /// Resolves when this flow must end.
    pub async fn closed(&self) {
        let _ = self.closed.clone().wait_for(|c| *c).await;
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        let mut flows = self.active.lock();
        if let Some(of_host) = flows.by_host.get_mut(&self.host) {
            of_host.remove(&self.id);
            if of_host.is_empty() {
                flows.by_host.remove(&self.host);
            }
        }
    }
}

impl Active {
    fn lock(&self) -> std::sync::MutexGuard<'_, Flows> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn register(&self, host: &str) -> Registered {
        let mut flows = self.lock();
        let (tx, closed) = watch::channel(flows.closed);
        flows.next += 1;
        let id = flows.next;
        flows.by_host.entry(host.to_string()).or_default().insert(id, tx);
        Registered { active: self.clone(), host: host.to_string(), id, closed }
    }

    pub fn close_host(&self, host: &str) {
        for tx in self.lock().by_host.get(host).into_iter().flat_map(HashMap::values) {
            let _ = tx.send(true);
        }
    }

    /// Every flow, and every flow registered from now on.
    pub fn close_all(&self) {
        let mut flows = self.lock();
        flows.closed = true;
        for tx in flows.by_host.values().flat_map(HashMap::values) {
            let _ = tx.send(true);
        }
    }

    /// True once `close_all` ran.
    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }

    pub fn len(&self) -> usize {
        self.lock().by_host.values().map(HashMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const SHORT: Duration = Duration::from_millis(20);

    #[tokio::test]
    async fn a_host_closes_alone_and_all_closes_the_rest() {
        let active = Active::default();
        let (a, b) = (active.register("a.example"), active.register("b.example"));
        assert_eq!(active.len(), 2);
        active.close_host("a.example");
        tokio::time::timeout(SHORT, a.closed()).await.expect("a closed");
        assert!(a.is_closed());
        assert!(tokio::time::timeout(SHORT, b.closed()).await.is_err(), "b did not");
        assert!(!b.is_closed() && !active.is_closed());
        active.close_all();
        tokio::time::timeout(SHORT, b.closed()).await.expect("b closed");
        drop((a, b));
        assert!(active.is_empty(), "each flow deregisters");
    }

    #[tokio::test]
    async fn close_all_holds_for_flows_registered_after_it_and_a_host_close_does_not() {
        let active = Active::default();
        active.close_host("a.example");
        assert!(!active.register("a.example").is_closed(), "the verdict cache holds a revocation, not this set");
        active.close_all();
        let late = active.register("b.example");
        assert!(late.is_closed() && active.is_closed());
        tokio::time::timeout(SHORT, late.closed()).await.expect("at once");
    }
}
