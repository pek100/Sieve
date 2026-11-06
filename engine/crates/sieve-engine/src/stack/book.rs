//! The engine's flow book: every flow the stack relays, as the app sees it
//! (sieve-ipc `FlowEvent`), and the batch of changes since the last one
//! (plan 1.3: `Flows` every 250 ms). Pure: the relay tasks write, the batch
//! task reads, the pipe sends each client only its own session's flows and
//! the services' (session 0).
//!
//! Bytes are reported when a flow closes (the relay counts them then); an
//! open flow's event says 0 until its last event.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use sieve_ipc::{FlowAction, FlowEvent, Forwarded, Guest, LOG_RULE_MAX, LogOutcome, LogRow, MAX_GUESTS, cap_text, vm_key};

use crate::domain::{Decision, Reason};

/// The flows the engine holds at most (plan 6, flow caps): past it a new
/// flow is closed at once and counted.
pub const MAX_FLOWS: usize = 10_000;
/// Log rows held between two batches at most; a burst past it loses the excess,
/// never a flow. Rows are per flow, so this is far above any real 250 ms.
pub const MAX_PENDING_LOG: usize = 4_000;

/// Who a client is: its Windows session (plan 1.3, session scoping). A guest's
/// flow belongs to the machine, as a service's does (the pipe's DACL already
/// limits clients to the owner and admins); an unknown flow could be anyone's.
pub fn visible_to(event: &FlowEvent, session: u32) -> bool {
    event.forwarded.is_some() || matches!(event.session, Some(s) if s == session || s == 0)
}

/// [`visible_to`] for a log row: a row shows no more than its flow does.
pub fn log_visible_to(row: &LogRow, session: u32) -> bool {
    row.forwarded.is_some() || matches!(row.session, Some(s) if s == session || s == 0)
}

/// What a decision says in the log; None when nothing was decided. With the
/// switch off the engine sieves nothing, and a lookup is never a decision.
pub fn log_outcome(decision: &Decision) -> Option<LogOutcome> {
    let passed = |reason: &str| Some(LogOutcome::Passed { reason: reason.to_string() });
    match decision.reason {
        Reason::Disabled | Reason::Dns => None,
        Reason::NamedBlock | Reason::AllResolvedNamesBlocked => Some(LogOutcome::Blocked),
        Reason::AppExempt => passed("app_off"),
        Reason::NamedAllow => passed("exception"),
        Reason::NamedNoRule => passed("no_rule"),
        Reason::MixedResolvedNames => passed("mixed_names"),
        Reason::UnknownDomain => passed("no_name"),
    }
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
    next_log_id: u64,
    /// Log rows since the last batch.
    log: Vec<LogRow>,
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

    /// The host-level log row (plan 8.3, slice 4) of an open flow just decided.
    /// `url` and `request_type` wait for decryption (slice 6). `t` is the wall clock.
    pub fn log_decision(&mut self, id: u64, decision: &Decision, t: u64) {
        let Some(outcome) = log_outcome(decision) else { return };
        let Some(e) = self.open.get(&id) else { return };
        if self.log.len() >= MAX_PENDING_LOG {
            return;
        }
        let ip = || e.remote.parse::<std::net::SocketAddr>().map_or_else(|_| e.remote.clone(), |a| a.ip().to_string());
        let row = LogRow {
            id: self.next_log_id + 1,
            t,
            flow_id: id,
            pid: e.pid,
            exe: e.exe.clone(),
            session: e.session,
            kind: e.kind,
            host: e.host.clone().unwrap_or_else(ip),
            remote: e.remote.clone(),
            url: None,
            request_type: None,
            outcome,
            rule: decision.rule.as_deref().map(|r| cap_text(r, LOG_RULE_MAX).to_string()),
            list: decision.list.clone(),
            forwarded: e.forwarded.clone(),
        };
        self.next_log_id += 1;
        self.log.push(row);
    }

    /// The log rows since the last batch.
    pub fn take_log(&mut self) -> Vec<LogRow> {
        std::mem::take(&mut self.log)
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

    fn decided(reason: Reason, rule: Option<&str>, list: Option<&str>) -> Decision {
        let action = if rule.is_some() && reason != Reason::NamedAllow { crate::flow::flows::Action::Drop } else { crate::flow::flows::Action::Pass };
        Decision { action, reason, rule: rule.map(str::to_string), list: list.map(str::to_string) }
    }

    #[test]
    fn a_decided_flow_logs_one_host_level_row_with_the_app_contract_slugs() {
        let mut b = FlowBook::default();
        let id = b.open(event(Some(1))).unwrap();
        b.update(id, |e| e.kind = FlowKind::Tls);
        b.log_decision(id, &decided(Reason::NamedBlock, Some("||ads.example^"), Some("adguard-dns")), 77);
        let rows = b.take_log();
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!((r.id, r.t, r.flow_id, r.pid, r.session, r.kind), (1, 77, id, Some(42), Some(1), FlowKind::Tls));
        assert_eq!((r.host.as_str(), r.remote.as_str()), ("93.184.215.14", "93.184.215.14:443"), "no name: the remote IP");
        assert_eq!((r.url.clone(), r.request_type.clone()), (None, None), "host level");
        assert_eq!(r.outcome, LogOutcome::Blocked);
        assert_eq!((r.rule.as_deref(), r.list.as_deref()), (Some("||ads.example^"), Some("adguard-dns")));
        assert!(b.take_log().is_empty(), "taken once");
        for (reason, slug) in [(Reason::AppExempt, "app_off"), (Reason::NamedAllow, "exception"), (Reason::NamedNoRule, "no_rule"), (Reason::MixedResolvedNames, "mixed_names"), (Reason::UnknownDomain, "no_name")] {
            assert_eq!(log_outcome(&decided(reason, None, None)), Some(LogOutcome::Passed { reason: slug.into() }));
        }
        assert_eq!(log_outcome(&decided(Reason::AllResolvedNamesBlocked, Some("||x^"), None)), Some(LogOutcome::Blocked));
    }

    #[test]
    fn nothing_is_logged_with_the_switch_off_or_for_a_lookup_or_a_closed_flow() {
        let mut b = FlowBook::default();
        let id = b.open(event(Some(1))).unwrap();
        b.log_decision(id, &decided(Reason::Disabled, None, None), 1);
        b.log_decision(id, &decided(Reason::Dns, None, None), 1);
        assert!(b.take_log().is_empty());
        b.close(id, FlowAction::Relayed, 0, 0);
        b.log_decision(id, &decided(Reason::NamedNoRule, None, None), 1);
        assert!(b.take_log().is_empty());
    }

    #[test]
    fn a_rows_name_rule_cap_guest_and_session_follow_its_flow() {
        let mut b = FlowBook::default();
        let named = b.open(event(Some(2))).unwrap();
        b.update(named, |e| e.host = Some("news.example".into()));
        b.log_decision(named, &decided(Reason::NamedBlock, Some(&"r".repeat(LOG_RULE_MAX + 10)), None), 1);
        let guest = b.open(guest_event(Some("DevBox"))).unwrap();
        b.log_decision(guest, &decided(Reason::AppExempt, None, None), 2);
        let rows = b.take_log();
        assert_eq!(rows[0].host, "news.example");
        assert_eq!(rows[0].rule.as_ref().map(String::len), Some(LOG_RULE_MAX));
        assert_eq!(rows[1].forwarded, Some(Forwarded { vm: Some("DevBox".into()) }));
        assert!(rows[1].pid.is_none() && rows[1].exe.is_none());
        assert_eq!((rows[0].id, rows[1].id), (1, 2));
        assert!(log_visible_to(&rows[0], 2) && !log_visible_to(&rows[0], 1), "another user's history never reaches this one");
        assert!(log_visible_to(&rows[1], 1), "a VM belongs to the machine");
        assert!(!log_visible_to(&LogRow { session: None, forwarded: None, ..rows[0].clone() }, 1));
    }

    #[test]
    fn a_burst_past_the_cap_loses_rows_and_not_flows() {
        let mut b = FlowBook::default();
        let id = b.open(event(Some(1))).unwrap();
        for _ in 0..MAX_PENDING_LOG + 5 {
            b.log_decision(id, &decided(Reason::NamedNoRule, None, None), 1);
        }
        assert_eq!(b.take_log().len(), MAX_PENDING_LOG);
        assert_eq!(b.live(), 1);
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
