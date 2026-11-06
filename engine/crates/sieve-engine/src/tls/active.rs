//! The intercepted flows, by host, each with a close signal (plan 2.6, task D17).
//! A verdict of revoked closes that host's flows; turning the switch off closes
//! all of them. Revocation is learned only at a handshake: no timer polls.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

struct Flows {
    next: u64,
    by_host: HashMap<String, HashMap<u64, watch::Sender<bool>>>,
}

#[derive(Clone)]
pub struct Active(Arc<Mutex<Flows>>);

impl Default for Active {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Flows { next: 0, by_host: HashMap::new() })))
    }
}

/// One intercepted flow. It deregisters when dropped.
pub struct Registered {
    active: Active,
    host: String,
    id: u64,
    closed: watch::Receiver<bool>,
}

impl Registered {
    /// Resolves when this flow must end.
    pub async fn closed(&mut self) {
        let _ = self.closed.wait_for(|c| *c).await;
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
        let (tx, closed) = watch::channel(false);
        let mut flows = self.lock();
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

    pub fn close_all(&self) {
        for tx in self.lock().by_host.values().flat_map(HashMap::values) {
            let _ = tx.send(true);
        }
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
        let (mut a, mut b) = (active.register("a.example"), active.register("b.example"));
        assert_eq!(active.len(), 2);
        active.close_host("a.example");
        tokio::time::timeout(SHORT, a.closed()).await.expect("a closed");
        assert!(tokio::time::timeout(SHORT, b.closed()).await.is_err(), "b did not");
        active.close_all();
        tokio::time::timeout(SHORT, b.closed()).await.expect("b closed");
        drop((a, b));
        assert!(active.is_empty(), "each flow deregisters");
    }
}
