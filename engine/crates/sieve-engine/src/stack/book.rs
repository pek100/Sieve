//! The engine's flow book: every flow the stack relays, as the app sees it
//! (sieve-ipc `FlowEvent`), and the batch of changes since the last one
//! (plan 1.3: `Flows` every 250 ms). Pure: the relay tasks write, the batch
//! task reads, the pipe sends each client only its own session's flows and
//! the services' (session 0).
//!
//! Bytes are reported when a flow closes (the relay counts them then); an
//! open flow's event says 0 until its last event.
//!
//! Every flow ends here, so the book also feeds each app's problems
//! ([`crate::issues`]): a relay task names a flow's problem ([`FlowBook::problem`])
//! before it closes it, and a close says what no task named (a block, a failure).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use sieve_ipc::{AppIssues, FlowAction, FlowEvent, Forwarded, Guest, LOG_RULE_MAX, LOG_URL_MAX, LogChange, LogOutcome, LogRow, MAX_GUESTS, MAX_LOG_CHANGES, RetryHow, Signal, cap_text, vm_key};

use crate::domain::{Decision, Reason};
use crate::issues::{AppId, Issues};

/// The flows the engine holds at most (plan 6, flow caps): past it a new
/// flow is closed at once and counted.
pub const MAX_FLOWS: usize = 10_000;
/// Log rows held between two batches at most; a burst past it loses the excess,
/// never a flow, and the row ids count through the loss, so it shows as a gap.
/// Rows are per flow, so this takes about 16,000 new flows a second; the number
/// is a design, not a measurement.
pub const MAX_PENDING_LOG: usize = 4_000;

/// Who a client is: its Windows session (plan 1.3, session scoping). A guest's
/// flow belongs to the machine, as a service's does (the pipe's DACL already
/// limits clients to the owner and admins); an unknown flow could be anyone's.
pub fn visible_to(event: &FlowEvent, session: u32) -> bool {
    event.forwarded.is_some() || matches!(event.session, Some(s) if s == session || s == 0)
}

/// The address part of a flow's `remote`, what a row with no name shows.
fn remote_ip(remote: &str) -> String {
    remote.parse::<std::net::SocketAddr>().map_or_else(|_| remote.to_string(), |a| a.ip().to_string())
}

/// [`visible_to`] for a log row: a row shows no more than its flow does.
pub fn log_visible_to(row: &LogRow, session: u32) -> bool {
    row.forwarded.is_some() || matches!(row.session, Some(s) if s == session || s == 0)
}

/// [`visible_to`] for a self-healing notice: a client gets its own session's.
pub fn notice_visible_to(notice: &sieve_ipc::HealNotice, session: u32) -> bool {
    notice.session == session || notice.session == 0
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

/// What the log keeps of one decrypted request.
#[derive(Debug, Clone)]
pub struct RequestRow<'a> {
    pub url: &'a str,
    pub request_type: &'a str,
    pub outcome: LogOutcome,
    pub rule: Option<&'a str>,
    pub list: Option<&'a str>,
    /// What tracking protection changed (plan 2026-11-09).
    pub changes: Vec<LogChange>,
}

/// Whose an open flow is, for its problems: the app, its exe's file name, and
/// whether a task already named the flow's problem.
#[derive(Debug)]
struct Owned {
    app: AppId,
    exe: Option<String>,
    named: bool,
}

#[derive(Debug)]
pub struct FlowBook {
    /// The wall clock, in ms (S15): what problems and their rows are dated by.
    clock: fn() -> u64,
    /// Open flows that belong to an app or a VM row.
    owners: HashMap<u64, Owned>,
    issues: Issues,
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
    /// Connections and decrypted requests a list's rule acted on since the engine
    /// started, by list id: what a live check can read of the rules without a log on
    /// disk (plan 7.1).
    list_hits: BTreeMap<String, u64>,
}

impl Default for FlowBook {
    fn default() -> Self {
        Self::with_clock(crate::policy::wall_ms)
    }
}

impl FlowBook {
    pub fn with_clock(clock: fn() -> u64) -> Self {
        Self {
            clock,
            owners: HashMap::new(),
            issues: Issues::default(),
            next_id: 0,
            open: HashMap::new(),
            changed: BTreeSet::new(),
            closed: HashMap::new(),
            guests: BTreeMap::new(),
            next_log_id: 0,
            log: Vec::new(),
            list_hits: BTreeMap::new(),
        }
    }

    /// Names the app or VM row an open flow belongs to (its `apps.levels` key);
    /// None for an unknown flow, which has no app to have problems.
    pub fn own(&mut self, id: u64, key: Option<String>) {
        let (Some(key), Some(e)) = (key, self.open.get(&id)) else { return };
        // A VM's row is the machine's (None); a host flow with no session is no
        // client's, as in `visible_to`.
        let session = match (&e.forwarded, e.session) {
            (Some(_), _) => None,
            (None, Some(s)) => Some(s),
            (None, None) => return,
        };
        let exe = e.exe.as_deref().map(sieve_filter::exclusions::exe_file_name);
        let app = AppId { key, session };
        self.issues.seen(&app, exe.as_deref(), (self.clock)());
        self.owners.insert(id, Owned { app, exe, named: false });
    }

    /// The problem of an open flow: counted for its app, and a log row unless
    /// Sieve meant it (a block has its decision's row already).
    pub fn problem(&mut self, id: u64, signal: Signal) {
        let Some(e) = self.open.get(&id) else { return };
        let now = (self.clock)();
        if let Some(o) = self.owners.get_mut(&id) {
            o.named = true;
            let host = e.host.clone().unwrap_or_else(|| remote_ip(&e.remote));
            self.issues.problem(&o.app, o.exe.as_deref(), signal, Some(&host), now);
        }
        if !signal.intended() {
            self.push_row(id, now, None, LogOutcome::Problem { signal, cause: signal.cause() }, None, None, Vec::new());
        }
    }

    /// Sieve tried an open flow's connect again (`stack::retry`): a row, so a
    /// retry is never silent, and a count for the app.
    pub fn retried(&mut self, id: u64, how: RetryHow, recovered: bool) {
        let now = (self.clock)();
        if let Some(o) = self.owners.get(&id) {
            self.issues.retried(&o.app, o.exe.as_deref(), recovered, now);
        }
        self.push_row(id, now, None, LogOutcome::Retried { how, recovered }, None, None, Vec::new());
    }

    /// The apps of `session` (and the services' and VMs') with recent problems.
    pub fn issues(&self, session: u32) -> Vec<AppIssues> {
        self.issues.view(|s| s.is_none_or(|s| s == session || s == 0), (self.clock)())
    }

    /// Moves when a problem grew old too, so the app hears that it is gone.
    pub fn issues_revision(&mut self) -> u64 {
        self.issues.age((self.clock)());
        self.issues.revision()
    }

    pub fn issues_dropped(&self) -> u64 {
        self.issues.dropped()
    }
    /// The VM name of the row a guest's flow counts in, which is also the row
    /// whose Off applies to it. Past [`MAX_GUESTS`] a new name folds into the
    /// unidentified row (one slot stays reserved for it), and since rows are never
    /// removed, a folded name folds for this whole run.
    pub fn guest_row<'a>(&self, forwarded: &'a Forwarded) -> Option<&'a str> {
        let named = vm_key(forwarded.vm.as_deref());
        let room = self.guests.keys().filter(|k| **k != vm_key(None)).count() < MAX_GUESTS - 1;
        if self.guests.contains_key(&named) || room { forwarded.vm.as_deref() } else { None }
    }

    fn guest_mut(&mut self, forwarded: &Forwarded) -> &mut Guest {
        let vm = self.guest_row(forwarded);
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

    /// One row about an open flow, with what the flow's event already says.
    #[allow(clippy::too_many_arguments)]
    fn push_row(&mut self, id: u64, t: u64, request: Option<(&str, &str)>, outcome: LogOutcome, rule: Option<&str>, list: Option<&str>, mut changes: Vec<LogChange>) {
        let Some(e) = self.open.get(&id) else { return };
        if self.log.len() >= MAX_PENDING_LOG {
            self.next_log_id += 1;
            return;
        }
        let ip = || remote_ip(&e.remote);
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
            url: request.map(|(url, _)| cap_text(url, LOG_URL_MAX).to_string()),
            request_type: request.map(|(_, kind)| kind.to_string()),
            outcome,
            rule: rule.map(|r| cap_text(r, LOG_RULE_MAX).to_string()),
            list: list.map(str::to_string),
            forwarded: e.forwarded.clone(),
            changes: {
                changes.truncate(MAX_LOG_CHANGES);
                changes
            },
        };
        self.next_log_id += 1;
        self.log.push(row);
    }

    /// The host-level log row (plan 8.3, slice 4) of an open flow just decided.
    /// A decrypted request has its own row ([`FlowBook::log_request`]). `t` is
    /// the wall clock.
    pub fn log_decision(&mut self, id: u64, decision: &Decision, t: u64) {
        let Some(outcome) = log_outcome(decision) else { return };
        self.count_hit(&outcome, decision.list.as_deref());
        self.push_row(id, t, None, outcome, decision.rule.as_deref(), decision.list.as_deref(), Vec::new());
    }

    /// One decrypted request (task D13). Only what `RequestRow` holds reaches
    /// the log: bodies, cookies and auth headers never do (plan 7.1).
    pub fn log_request(&mut self, id: u64, request: RequestRow<'_>, t: u64) {
        self.count_hit(&request.outcome, request.list);
        self.push_row(id, t, Some((request.url, request.request_type)), request.outcome, request.rule, request.list, request.changes);
    }

    fn count_hit(&mut self, outcome: &LogOutcome, list: Option<&str>) {
        if matches!(outcome, LogOutcome::Blocked | LogOutcome::Redirected | LogOutcome::ParamsRemoved)
            && let Some(list) = list
        {
            *self.list_hits.entry(list.to_string()).or_default() += 1;
        }
    }

    /// A flow that goes on undecrypted, and why (plan 4.1).
    pub fn log_not_decrypted(&mut self, id: u64, reason: &str, t: u64) {
        self.push_row(id, t, None, LogOutcome::NotDecrypted { reason: reason.to_string() }, None, None, Vec::new());
    }

    pub fn list_hits(&self) -> &BTreeMap<String, u64> {
        &self.list_hits
    }

    /// The log rows since the last batch.
    pub fn take_log(&mut self) -> Vec<LogRow> {
        std::mem::take(&mut self.log)
    }

    /// The flow ended with these totals. What no task named is named here: a
    /// block is the rule's, a failure with no other word is a lost connection.
    pub fn close(&mut self, id: u64, action: FlowAction, bytes_up: u64, bytes_down: u64) {
        if self.owners.get(&id).is_some_and(|o| !o.named) {
            match action {
                FlowAction::Blocked => self.problem(id, Signal::Blocked),
                FlowAction::Failed => self.problem(id, Signal::ConnectionLost),
                FlowAction::Relayed => {}
            }
        }
        if let Some(o) = self.owners.remove(&id) {
            self.issues.ended(&o.app, (self.clock)());
        }
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

    /// Ends every open flow (the routes went down; their tasks are gone). The
    /// apps' problems stay; when Sieve began filtering each starts over.
    pub fn close_all(&mut self) {
        let ids: Vec<u64> = self.open.keys().copied().collect();
        for id in ids {
            self.close(id, FlowAction::Relayed, 0, 0);
        }
        self.issues.restart();
    }

    /// An open flow's event.
    pub fn snapshot_of(&self, id: u64) -> Option<FlowEvent> {
        self.open.get(&id).cloned()
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
        b.log_decision(id, &decided(Reason::NamedNoRule, None, None), 1);
        assert_eq!(b.take_log()[0].id, MAX_PENDING_LOG as u64 + 6, "the five lost rows are a gap in the ids");
    }

    #[test]
    fn list_hits_count_acted_requests_by_list() {
        let mut b = FlowBook::default();
        let id = b.open(event(Some(1))).unwrap();
        let row = |outcome, list| RequestRow { url: "https://x.example/a", request_type: "script", outcome, rule: None, list, changes: Vec::new() };
        for outcome in [LogOutcome::Blocked, LogOutcome::Redirected, LogOutcome::ParamsRemoved] {
            b.log_request(id, row(outcome, Some("a")), 1);
        }
        b.log_request(id, row(LogOutcome::Blocked, Some("b")), 1);
        b.log_request(id, row(LogOutcome::Blocked, None), 1);
        b.log_request(id, row(LogOutcome::Passed { reason: "exception".into() }, Some("a")), 1);
        assert_eq!(b.list_hits().iter().map(|(k, v)| (k.as_str(), *v)).collect::<Vec<_>>(), [("a", 3), ("b", 1)]);
        assert_eq!(b.take_log().len(), 6, "the rows are the log's whatever is counted");
        assert_eq!(b.list_hits().len(), 2, "taking the log leaves the counts");
    }

    /// A plain `||host^` is blocked at the connection and never reaches `log_request`.
    #[test]
    fn list_hits_count_a_connection_a_list_blocked() {
        let mut b = FlowBook::default();
        let id = b.open(event(Some(1))).unwrap();
        b.log_decision(id, &decided(Reason::NamedBlock, Some("||ads.example^"), Some("a")), 1);
        b.log_decision(id, &decided(Reason::AllResolvedNamesBlocked, Some("||ads.example^"), Some("a")), 1);
        b.log_decision(id, &decided(Reason::NamedBlock, Some("||ads.example^"), None), 1);
        b.log_decision(id, &decided(Reason::NamedAllow, Some("@@||ads.example^"), Some("a")), 1);
        b.log_decision(id, &decided(Reason::NamedNoRule, None, None), 1);
        b.log_decision(id, &decided(Reason::Disabled, None, Some("a")), 1);
        assert_eq!(b.list_hits().iter().map(|(k, v)| (k.as_str(), *v)).collect::<Vec<_>>(), [("a", 2)]);
    }

    const T: u64 = 1_793_000_000_000;

    fn clocked() -> FlowBook {
        FlowBook::with_clock(|| T)
    }

    fn owned(b: &mut FlowBook, key: &str) -> u64 {
        let id = b.open(event(Some(1))).unwrap();
        b.own(id, Some(key.into()));
        id
    }

    #[test]
    fn a_close_names_what_no_task_named_and_a_named_problem_counts_once() {
        let mut b = clocked();
        let blocked = owned(&mut b, "a");
        b.update(blocked, |e| e.host = Some("ads.example".into()));
        b.close(blocked, FlowAction::Blocked, 0, 0);
        let failed = owned(&mut b, "a");
        b.close(failed, FlowAction::Failed, 0, 0);
        let timed_out = owned(&mut b, "a");
        b.problem(timed_out, Signal::ConnectTimeout);
        b.close(timed_out, FlowAction::Failed, 0, 0);
        let fine = owned(&mut b, "a");
        b.close(fine, FlowAction::Relayed, 1, 1);
        let rows: Vec<LogOutcome> = b.take_log().into_iter().map(|r| r.outcome).collect();
        assert_eq!(rows, [LogOutcome::Problem { signal: Signal::ConnectionLost, cause: sieve_ipc::Cause::Unknown }, LogOutcome::Problem { signal: Signal::ConnectTimeout, cause: sieve_ipc::Cause::Network }], "a block's row is its decision's");
        let a = &b.issues(1)[0];
        assert_eq!((a.key.as_str(), a.exe.as_deref(), a.flows, a.since_ms), ("a", Some("a.exe"), 4, T));
        let mut signals: Vec<(Signal, Option<&str>, u32)> = a.problems.iter().map(|p| (p.signal, p.host.as_deref(), p.count)).collect();
        signals.sort();
        assert_eq!(signals, [(Signal::ConnectTimeout, Some("93.184.215.14"), 1), (Signal::ConnectionLost, Some("93.184.215.14"), 1), (Signal::Blocked, Some("ads.example"), 1)]);
    }

    #[test]
    fn an_unknown_flows_problem_is_logged_but_belongs_to_no_app() {
        let mut b = clocked();
        let id = b.open(event(Some(1))).unwrap();
        b.own(id, None);
        b.problem(id, Signal::Stall);
        b.close(id, FlowAction::Relayed, 0, 0);
        assert_eq!(b.take_log().len(), 1);
        assert!(b.issues(1).is_empty());
        let no_session = b.open(event(None)).unwrap();
        b.own(no_session, Some("a".into()));
        b.problem(no_session, Signal::Stall);
        assert!(b.issues(1).is_empty() && b.issues(0).is_empty(), "a flow of no session is no client's");
    }

    #[test]
    fn a_retry_is_a_row_and_a_count() {
        let mut b = clocked();
        let id = owned(&mut b, "a");
        b.retried(id, RetryHow::NextAddress, true);
        b.problem(id, Signal::ConnectRefused);
        assert_eq!(b.take_log()[0].outcome, LogOutcome::Retried { how: RetryHow::NextAddress, recovered: true });
        assert_eq!((b.issues(1)[0].retried, b.issues(1)[0].recovered), (1, 1));
    }

    #[test]
    fn a_guests_problems_are_the_machines_and_another_sessions_are_not_mine() {
        let mut b = clocked();
        let guest = b.open(guest_event(Some("DevBox"))).unwrap();
        b.own(guest, Some(vm_key(Some("DevBox"))));
        b.problem(guest, Signal::Stall);
        let other = b.open(event(Some(2))).unwrap();
        b.own(other, Some("theirs".into()));
        b.problem(other, Signal::Stall);
        assert_eq!(b.issues(1).iter().map(|a| a.key.as_str()).collect::<Vec<_>>(), ["vm:devbox"]);
        assert_eq!(b.issues(1)[0].session, None);
    }

    #[test]
    fn routes_coming_down_start_since_over_and_keep_problems() {
        let mut b = clocked();
        let id = owned(&mut b, "a");
        b.problem(id, Signal::Stall);
        b.close_all();
        assert_eq!((b.issues(1)[0].flows, b.issues(1)[0].problems.len()), (0, 1));
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
