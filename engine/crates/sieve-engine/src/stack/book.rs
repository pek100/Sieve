//! The engine's flow book: every flow the stack relays, as the app sees it
//! (sieve-ipc `FlowEvent`), and the batch of changes since the last one
//! (plan 1.3: `Flows` every 250 ms). Pure: the relay tasks write, the batch
//! task reads, the pipe sends each client only its own session's flows and
//! the services' (session 0).
//!
//! Bytes are reported when a flow closes (the relay counts them then); an
//! open flow's event says 0 until its last event.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use sieve_ipc::{FlowAction, FlowEvent, Forwarded, Guest, MAX_GUESTS, vm_key};

/// The flows the engine holds at most (plan 6, flow caps): past it a new
/// flow is closed at once and counted.
pub const MAX_FLOWS: usize = 10_000;

/// Who a client is: its Windows session (plan 1.3, session scoping). A guest's
/// flow belongs to the machine, as a service's does (the pipe's DACL already
/// limits clients to the owner and admins); an unknown flow could be anyone's.
pub fn visible_to(event: &FlowEvent, session: u32) -> bool {
    event.forwarded.is_some() || matches!(event.session, Some(s) if s == session || s == 0)
}

#[derive(Debug, Default)]
pub struct FlowBook {
    next_id: u64,
    open: HashMap<u64, FlowEvent>,
    /// Flows changed since the last batch, by id (closed ones included).
    changed: BTreeSet<u64>,
    /// Last events of flows that closed since the last batch.
    closed: HashMap<u64, FlowEvent>,
    /// VMs seen since the engine started, by key.
    guests: BTreeMap<String, Guest>,
}

impl FlowBook {
    /// The row a guest's flow counts in. Past [`MAX_GUESTS`] a new name folds
    /// into the unidentified row (one slot stays reserved for it), and since
    /// rows are never removed, a folded name folds for this whole run.
    fn guest_mut(&mut self, forwarded: &Forwarded) -> &mut Guest {
        let named = vm_key(forwarded.vm.as_deref());
        let room = self.guests.keys().filter(|k| **k != vm_key(None)).count() < MAX_GUESTS - 1;
        let vm = if self.guests.contains_key(&named) || room { forwarded.vm.as_deref() } else { None };
        let key = vm_key(vm);
        self.guests.entry(key.clone()).or_insert_with(|| Guest { key, vm: vm.map(str::to_string), seen: 0, open: 0 })
    }

    /// Named rows by key, then the unidentified row.
    pub fn guests(&self) -> Vec<Guest> {
        let (unnamed, mut rows): (Vec<Guest>, Vec<Guest>) = self.guests.values().cloned().partition(|g| g.vm.is_none());
        rows.extend(unnamed);
        rows
    }

    /// Registers a new flow (its `id` is set here); None at the cap.
    pub fn open(&mut self, mut event: FlowEvent) -> Option<u64> {
        if self.open.len() >= MAX_FLOWS {
            return None;
        }
        if let Some(forwarded) = &event.forwarded {
            let guest = self.guest_mut(forwarded);
            guest.seen += 1;
            guest.open = guest.open.saturating_add(1);
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
            if let Some(forwarded) = &e.forwarded {
                let guest = self.guest_mut(forwarded);
                guest.open = guest.open.saturating_sub(1);
            }
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
            forwarded: None,
        }
    }

    fn guest_event(vm: Option<&str>) -> FlowEvent {
        FlowEvent { pid: None, exe: None, session: None, forwarded: Some(Forwarded { vm: vm.map(str::to_string) }), ..event(None) }
    }

    #[test]
    fn a_host_flow_makes_no_guest() {
        let mut b = FlowBook::default();
        b.open(event(Some(1))).unwrap();
        assert!(b.guests().is_empty());
    }

    #[test]
    fn guests_appear_on_first_sight_and_stay_after_close() {
        let mut b = FlowBook::default();
        let id = b.open(guest_event(Some("DevBox"))).unwrap();
        b.open(guest_event(None)).unwrap();
        b.open(guest_event(Some("alpha"))).unwrap();
        let keys: Vec<String> = b.guests().into_iter().map(|g| g.key).collect();
        assert_eq!(keys, ["vm:alpha", "vm:devbox", "vm:unidentified"], "named rows first, the unidentified row last");
        b.close(id, FlowAction::Relayed, 1, 1);
        let dev = b.guests().into_iter().find(|g| g.key == "vm:devbox").unwrap();
        assert_eq!((dev.vm.as_deref(), dev.seen, dev.open), (Some("DevBox"), 1, 0), "seen since the engine started");
    }

    #[test]
    fn open_counts_follow_open_and_close_all() {
        let mut b = FlowBook::default();
        let id = b.open(guest_event(Some("DevBox"))).unwrap();
        b.open(guest_event(Some("DevBox"))).unwrap();
        b.open(guest_event(None)).unwrap();
        assert_eq!(b.guests()[0].open, 2);
        b.close(id, FlowAction::Relayed, 0, 0);
        assert_eq!(b.guests()[0].open, 1);
        b.close_all();
        assert!(b.guests().iter().all(|g| g.open == 0));
        assert_eq!(b.guests()[0].seen, 2);
    }

    #[test]
    fn guests_are_capped_into_the_unidentified_row() {
        let mut b = FlowBook::default();
        let mut ids = Vec::new();
        for i in 0..MAX_GUESTS + 5 {
            ids.push(b.open(guest_event(Some(&format!("vm{i:02}")))).unwrap());
        }
        let rows = b.guests();
        assert_eq!(rows.len(), MAX_GUESTS);
        let last = rows.last().unwrap();
        assert_eq!((last.key.as_str(), last.vm.as_deref(), last.seen, last.open), ("vm:unidentified", None, 6, 6));
        // A name already held keeps its row; a folded flow closes in the row it opened in.
        b.open(guest_event(Some("vm00"))).unwrap();
        assert_eq!(b.guests()[0].seen, 2);
        for id in ids {
            b.close(id, FlowAction::Relayed, 0, 0);
        }
        assert_eq!(b.guests().last().unwrap().open, 0);
    }

    #[test]
    fn a_client_sees_forwarded_flows_but_not_unknown_ones() {
        assert!(visible_to(&guest_event(Some("DevBox")), 1));
        assert!(visible_to(&guest_event(None), 7), "a VM belongs to the machine");
        let unknown = FlowEvent { pid: None, exe: None, ..event(None) };
        assert!(!visible_to(&unknown, 1));
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
