//! The engine's flow book: every flow the stack relays, as the app sees it
//! (sieve-ipc `FlowEvent`), and the batch of changes since the last one
//! (plan 1.3: `Flows` every 250 ms). Pure: the relay tasks write, the batch
//! task reads, the pipe sends each client only its own session's flows and
//! the services' (session 0).
//!
//! Bytes are reported when a flow closes (the relay counts them then); an
//! open flow's event says 0 until its last event.

use std::collections::{BTreeSet, HashMap};

use sieve_ipc::{FlowAction, FlowEvent};

/// The flows the engine holds at most (plan 6, flow caps): past it a new
/// flow is closed at once and counted.
pub const MAX_FLOWS: usize = 10_000;

/// Who a client is: its Windows session (plan 1.3, session scoping).
pub fn visible_to(event: &FlowEvent, session: u32) -> bool {
    matches!(event.session, Some(s) if s == session || s == 0)
}

#[derive(Debug, Default)]
pub struct FlowBook {
    next_id: u64,
    open: HashMap<u64, FlowEvent>,
    /// Flows changed since the last batch, by id (closed ones included).
    changed: BTreeSet<u64>,
    /// Last events of flows that closed since the last batch.
    closed: HashMap<u64, FlowEvent>,
}

impl FlowBook {
    /// Registers a new flow (its `id` is set here); None at the cap.
    pub fn open(&mut self, mut event: FlowEvent) -> Option<u64> {
        if self.open.len() >= MAX_FLOWS {
            return None;
        }
        self.next_id += 1;
        event.id = self.next_id;
        event.open = true;
        self.changed.insert(event.id);
        self.open.insert(event.id, event);
        Some(self.next_id)
    }

    /// Fills in what the first bytes said (kind, host) once decided.
    pub fn update(&mut self, id: u64, f: impl FnOnce(&mut FlowEvent)) {
        if let Some(e) = self.open.get_mut(&id) {
            f(e);
            self.changed.insert(id);
        }
    }

    /// The flow ended with these totals.
    pub fn close(&mut self, id: u64, action: FlowAction, bytes_up: u64, bytes_down: u64) {
        if let Some(mut e) = self.open.remove(&id) {
            e.open = false;
            e.action = action;
            e.bytes_up = bytes_up;
            e.bytes_down = bytes_down;
            self.closed.insert(id, e);
            self.changed.insert(id);
        }
    }

    /// Ends every open flow (the routes went down; their tasks are gone).
    pub fn close_all(&mut self) {
        let ids: Vec<u64> = self.open.keys().copied().collect();
        for id in ids {
            self.close(id, FlowAction::Relayed, 0, 0);
        }
    }

    pub fn live(&self) -> usize {
        self.open.len()
    }

    /// Every event that changed since the last batch, in id order; a flow
    /// that opened and closed in between is sent once, closed.
    pub fn take_batch(&mut self) -> Vec<FlowEvent> {
        let ids = std::mem::take(&mut self.changed);
        let mut closed = std::mem::take(&mut self.closed);
        ids.into_iter().filter_map(|id| closed.remove(&id).or_else(|| self.open.get(&id).cloned())).collect()
    }

    /// Every open flow, for a client that subscribes now.
    pub fn snapshot(&self) -> Vec<FlowEvent> {
        let mut v: Vec<FlowEvent> = self.open.values().cloned().collect();
        v.sort_by_key(|e| e.id);
        v
    }
}

/// A flow event for tests elsewhere in the crate.
#[cfg(test)]
pub(crate) fn tests_event(session: Option<u32>) -> FlowEvent {
    tests::event(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sieve_ipc::{FlowKind, FlowProto};

    pub(super) fn event(session: Option<u32>) -> FlowEvent {
        FlowEvent {
            id: 0,
            pid: Some(42),
            exe: Some(r"C:\a.exe".into()),
            session,
            proto: FlowProto::Tcp,
            local: "198.18.0.1:5000".into(),
            remote: "93.184.215.14:443".into(),
            kind: FlowKind::Other,
            host: None,
            action: FlowAction::Relayed,
            bytes_up: 0,
            bytes_down: 0,
            open: false,
            reason: None,
            rule: None,
            list: None,
        }
    }

    #[test]
    fn a_batch_carries_opens_updates_and_closes_once() {
        let mut b = FlowBook::default();
        let a = b.open(event(Some(1))).unwrap();
        let c = b.open(event(Some(1))).unwrap();
        b.update(a, |e| {
            e.kind = FlowKind::Tls;
            e.host = Some("example.com".into());
        });
        let batch = b.take_batch();
        assert_eq!(batch.iter().map(|e| (e.id, e.open)).collect::<Vec<_>>(), [(a, true), (c, true)]);
        assert_eq!(batch[0].host.as_deref(), Some("example.com"));
        assert!(b.take_batch().is_empty(), "nothing changed since");
        b.close(c, FlowAction::Relayed, 10, 20);
        let batch = b.take_batch();
        assert_eq!(batch.len(), 1);
        assert_eq!((batch[0].id, batch[0].open, batch[0].bytes_up, batch[0].bytes_down), (c, false, 10, 20));
        assert_eq!(b.live(), 1);
        assert_eq!(b.snapshot().iter().map(|e| e.id).collect::<Vec<_>>(), [a]);
    }

    #[test]
    fn a_flow_that_opened_and_closed_between_batches_is_sent_once_closed() {
        let mut b = FlowBook::default();
        let id = b.open(event(Some(1))).unwrap();
        b.close(id, FlowAction::Failed, 0, 0);
        let batch = b.take_batch();
        assert_eq!(batch.len(), 1);
        assert!(!batch[0].open && batch[0].action == FlowAction::Failed);
    }

    #[test]
    fn closing_all_ends_every_open_flow_in_the_next_batch() {
        let mut b = FlowBook::default();
        let ids = [b.open(event(Some(1))).unwrap(), b.open(event(Some(0))).unwrap()];
        b.take_batch();
        b.close_all();
        assert_eq!(b.live(), 0);
        assert_eq!(b.take_batch().iter().map(|e| (e.id, e.open)).collect::<Vec<_>>(), [(ids[0], false), (ids[1], false)]);
    }

    #[test]
    fn the_book_refuses_flows_past_its_cap() {
        let mut b = FlowBook::default();
        for _ in 0..MAX_FLOWS {
            assert!(b.open(event(Some(1))).is_some());
        }
        assert!(b.open(event(Some(1))).is_none());
    }

    #[test]
    fn a_client_sees_its_session_and_the_services_only() {
        assert!(visible_to(&event(Some(1)), 1));
        assert!(visible_to(&event(Some(0)), 1), "services are machine-wide");
        assert!(!visible_to(&event(Some(2)), 1), "another user's flows never reach this one");
        assert!(!visible_to(&event(None), 1), "an unattributed flow could be anyone's");
    }
}
