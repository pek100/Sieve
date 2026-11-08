//! What a flow is, from exact evidence only (docs/tasks/2026-11-02-attribution.md,
//! D1, D5, D9). [`decide`] is the one decision, pure:
//!
//! | Owner tables and ETW | NAT         | Result                     |
//! |----------------------|-------------|----------------------------|
//! | PID                  | none        | host, that PID             |
//! | none                 | exact match | forwarded                  |
//! | PID                  | exact match | unknown: both cannot be    |
//! | disagree             | not asked   | unknown                    |
//! | none                 | none        | unknown                    |
//!
//! Nothing is guessed, and a conflict is never resolved in favour of either
//! side: a forwarded flow must not borrow a host app's exemption, and a host
//! flow must not pass as a guest's. The loop guard, [`is_own`], is asked of the
//! raw owner and not of this decision, which can hide the PID it needs.

use sieve_ipc::Forwarded;

use super::Meters;
use super::book::FlowBook;
use crate::flow::flows::Owner;

/// Why a flow has no origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unproven {
    /// No source answered.
    NoAnswer,
    /// ETW and the owner tables disagreed, or ETW saw two PIDs.
    Disagreed,
    /// A host owner and an exact NAT match both answered.
    OwnerAndNat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribution {
    Host {
        pid: u32,
        /// Only the ETW witness gave this PID.
        witness_only: bool,
    },
    Forwarded(Forwarded),
    Unknown(Unproven),
}

/// The decision of the table above. `nat` is the match the caller holds; it is
/// not read for a disagreement.
pub fn decide(owner: Owner, nat: Option<Forwarded>) -> Attribution {
    let host = |pid, witness_only| match &nat {
        Some(_) => Attribution::Unknown(Unproven::OwnerAndNat),
        None => Attribution::Host { pid, witness_only },
    };
    match owner {
        Owner::Pid(pid) => host(pid, false),
        Owner::WitnessOnly(pid) => host(pid, true),
        Owner::Disagreed { .. } => Attribution::Unknown(Unproven::Disagreed),
        Owner::Unknown | Owner::Pending => match nat {
            Some(forwarded) => Attribution::Forwarded(forwarded),
            None => Attribution::Unknown(Unproven::NoAnswer),
        },
    }
}

/// Whether any source named the engine itself. Relaying such a flow can loop,
/// so it is refused even when a NAT match or a contradiction leaves the flow
/// unknown: the guard errs toward refusing, attribution toward not guessing.
pub fn is_own(owner: Owner, own_pid: u32) -> bool {
    match owner {
        Owner::Pid(pid) | Owner::WitnessOnly(pid) => pid == own_pid,
        Owner::Disagreed { table } => table == Some(own_pid),
        Owner::Unknown | Owner::Pending => false,
    }
}

/// Plain HTTP: where CryptoAPI fetches CRLs, OCSP answers and missing intermediates.
pub const HTTP_PORT: u16 = 80;

/// What the loop guard does with a TCP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    /// Not the engine's: the relay's own path.
    Admit,
    /// The engine's own plain HTTP, copied to an `Egress` socket with no decision.
    RelayOwn,
    Refuse,
}

/// The engine's own TCP flows are refused, except plain HTTP. Upstream validation
/// runs CryptoAPI in this process, and its revocation and AIA fetches use unpinned
/// sockets that the adapter's routes catch. Refused, revocation soft-fails to
/// unknown and a revoked certificate is intercepted (task F4, Q3; live U5,
/// 2026-11-08: `own_refused` grew by 2 while revoked.badssl.com was minted a leaf).
/// The copy's upstream is an `Egress` socket, pinned outside Sieve's routes, so it
/// cannot come back to the adapter.
pub fn guard_tcp(own: bool, remote_port: u16) -> Guard {
    match (own, remote_port) {
        (false, _) => Guard::Admit,
        (true, HTTP_PORT) => Guard::RelayOwn,
        (true, _) => Guard::Refuse,
    }
}

/// Who a flow belongs to, for the length of its decision. The attribution says
/// what kind of flow it is, so a guest never reaches an app's row, and a host
/// flow's key comes from its process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeldOwner {
    App(String),
    Forwarded(Option<String>),
    Unknown,
}

impl HeldOwner {
    /// As the decision reads it.
    pub fn as_owner(&self) -> crate::domain::Owner<'_> {
        use crate::domain::Owner;
        match self {
            Self::App(key) => Owner::App { key },
            Self::Forwarded(vm) => Owner::Forwarded { vm: vm.as_deref() },
            Self::Unknown => Owner::Unknown,
        }
    }
}

impl Attribution {
    /// The owner the decision asks about. `app` is the key of the host flow's
    /// process; it says nothing about any other kind of flow.
    pub fn owner(&self, app: Option<String>) -> HeldOwner {
        match self {
            Attribution::Host { .. } => app.map_or(HeldOwner::Unknown, HeldOwner::App),
            Attribution::Forwarded(f) => HeldOwner::Forwarded(f.vm.clone()),
            Attribution::Unknown(_) => HeldOwner::Unknown,
        }
    }

    /// [`Self::owner`] for a flow already in the book: a guest answers to the row
    /// it counts in, so a name folded past the cap answers to the row that reads Off.
    pub fn row_owner(&self, app: Option<String>, book: &FlowBook) -> HeldOwner {
        match self {
            Attribution::Forwarded(f) => HeldOwner::Forwarded(book.guest_row(f).map(str::to_string)),
            _ => self.owner(app),
        }
    }

    /// The process of a host flow.
    pub fn pid(&self) -> Option<u32> {
        match self {
            Attribution::Host { pid, .. } => Some(*pid),
            _ => None,
        }
    }

    /// The flow event's `pid` and `forwarded`: the one constructor of the
    /// pair, so the illegal state of both being Some cannot be built.
    pub fn event_fields(&self) -> (Option<u32>, Option<Forwarded>) {
        match self {
            Attribution::Host { pid, .. } => (Some(*pid), None),
            Attribution::Forwarded(f) => (None, Some(f.clone())),
            Attribution::Unknown(_) => (None, None),
        }
    }

    /// Counts one admitted flow. A forwarded flow is attributed only when an
    /// exact match named its VM; it stays in the denominator either way.
    pub fn count(&self, meters: &Meters) {
        Meters::bump(&meters.flows);
        match self {
            Attribution::Host { witness_only, .. } => {
                Meters::bump(&meters.attributed);
                if *witness_only {
                    Meters::bump(&meters.etw_found);
                }
            }
            Attribution::Forwarded(f) => {
                Meters::bump(&meters.forwarded);
                if f.vm.is_some() {
                    Meters::bump(&meters.attributed);
                    Meters::bump(&meters.forwarded_named);
                }
            }
            Attribution::Unknown(Unproven::Disagreed) => Meters::bump(&meters.etw_disagreed),
            Attribution::Unknown(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named() -> Forwarded {
        Forwarded { vm: Some("DevBox".into()) }
    }

    fn unnamed() -> Forwarded {
        Forwarded { vm: None }
    }

    /// Live U5: the engine's CryptoAPI fetches of revocation are its own port 80
    /// flows, and refusing them let a revoked certificate be intercepted.
    #[test]
    fn the_engines_own_plain_http_is_relayed_and_the_rest_refused() {
        assert_eq!(guard_tcp(true, HTTP_PORT), Guard::RelayOwn);
        for port in [443, 53, 8080, 0] {
            assert_eq!(guard_tcp(true, port), Guard::Refuse, "{port}");
        }
        for port in [HTTP_PORT, 443] {
            assert_eq!(guard_tcp(false, port), Guard::Admit, "{port}");
        }
    }

    #[test]
    fn decide_matches_the_table_of_d5() {
        assert_eq!(decide(Owner::Pid(7), None), Attribution::Host { pid: 7, witness_only: false });
        assert_eq!(decide(Owner::WitnessOnly(7), None), Attribution::Host { pid: 7, witness_only: true });
        assert_eq!(decide(Owner::Unknown, Some(named())), Attribution::Forwarded(named()));
        assert_eq!(decide(Owner::Unknown, Some(unnamed())), Attribution::Forwarded(unnamed()));
        assert_eq!(decide(Owner::Pid(7), Some(named())), Attribution::Unknown(Unproven::OwnerAndNat));
        assert_eq!(decide(Owner::WitnessOnly(7), Some(unnamed())), Attribution::Unknown(Unproven::OwnerAndNat));
        assert_eq!(decide(Owner::Disagreed { table: Some(7) }, Some(named())), Attribution::Unknown(Unproven::Disagreed));
        assert_eq!(decide(Owner::Disagreed { table: None }, None), Attribution::Unknown(Unproven::Disagreed));
        assert_eq!(decide(Owner::Unknown, None), Attribution::Unknown(Unproven::NoAnswer));
    }

    /// `decide` has no PID left in the first two cases: the guard must not ask it.
    #[test]
    fn the_engines_own_flow_is_seen_through_nat_and_conflict() {
        const OWN: u32 = 999;
        assert_eq!(decide(Owner::Pid(OWN), Some(named())).pid(), None);
        assert!(is_own(Owner::Pid(OWN), OWN), "own PID and a NAT match");
        assert_eq!(decide(Owner::Disagreed { table: Some(OWN) }, None).pid(), None);
        assert!(is_own(Owner::Disagreed { table: Some(OWN) }, OWN), "the table said own PID, ETW said another");
        assert!(is_own(Owner::WitnessOnly(OWN), OWN));
        for other in [Owner::Pid(7), Owner::WitnessOnly(7), Owner::Disagreed { table: Some(7) }, Owner::Disagreed { table: None }, Owner::Unknown, Owner::Pending] {
            assert!(!is_own(other, OWN), "{other:?}");
        }
    }

    /// A NAT table whose one session lasts for this many reads.
    fn table_with_session_for(reads: usize) -> crate::flow::nat::NatTable {
        use crate::flow::nat::{NatSession, NatSource, NatTable, NoDirectory, VmDirectory};
        use crate::flow::packet::Proto;

        struct Ending(usize);
        impl NatSource for Ending {
            fn read(&mut self) -> Result<Vec<NatSession>, String> {
                let live = self.0 > 0;
                self.0 = self.0.saturating_sub(1);
                Ok(live
                    .then(|| NatSession {
                        proto: Proto::Udp,
                        internal_source: "172.17.83.30:36099".parse().unwrap(),
                        external_source: "198.18.0.1:62049".parse().unwrap(),
                        external_destination: "185.125.190.57:123".parse().unwrap(),
                    })
                    .into_iter()
                    .collect())
            }
        }
        NatTable::spawn(move || {
            let sources: Vec<Box<dyn NatSource>> = vec![Box::new(Ending(reads))];
            let directory: Box<dyn VmDirectory> = Box::new(NoDirectory);
            (sources, directory)
        })
    }

    fn session_flow() -> crate::flow::flows::FiveTuple {
        use crate::flow::packet::Proto;
        crate::flow::flows::FiveTuple { proto: Proto::Udp, local: "198.18.0.1:62049".parse().unwrap(), remote: "185.125.190.57:123".parse().unwrap() }
    }

    /// Later than any read asked before it, so it shares none.
    const LATER_MS: u64 = 60_000;

    /// A forwarded UDP flow whose external port equals a host wildcard-bound
    /// port matches that owner row: a NAT session still there must overrule it,
    /// or the flow borrows that app's exemption.
    #[tokio::test]
    async fn a_udp_owner_with_a_live_nat_match_is_unknown() {
        let (table, flow) = (table_with_session_for(usize::MAX), session_flow());
        assert_eq!(decide(Owner::Pid(7), table.confirmed_match(&flow, 0).await), Attribution::Host { pid: 7, witness_only: false }, "nothing held yet");
        assert_eq!(table.stats().reads, 0, "and a flow with nothing held costs no read");
        assert!(table.fresh_match(&flow, 1_000).await.is_some());
        assert_eq!(decide(Owner::Pid(7), table.confirmed_match(&flow, LATER_MS).await), Attribution::Unknown(Unproven::OwnerAndNat));
    }

    /// A guest's session ended and a host app reuses its exact tuple: what is held
    /// is out of date, and only a read can say so.
    #[tokio::test]
    async fn a_stale_held_match_does_not_turn_a_host_flow_unknown() {
        let (table, flow) = (table_with_session_for(1), session_flow());
        assert!(table.fresh_match(&flow, 1_000).await.is_some());
        assert!(table.held_match(&flow).is_some(), "the index still claims it");
        assert_eq!(decide(Owner::Pid(7), table.confirmed_match(&flow, LATER_MS).await), Attribution::Host { pid: 7, witness_only: false });
    }

    /// The row's Off has to reach the flows the row counts: the 32nd name reads
    /// under the unidentified row, so that row's Off exempts it, and no other does.
    #[test]
    fn a_guest_folded_past_the_cap_answers_to_the_row_it_counts_in() {
        use crate::domain::{DomainFilter, Flow, Reason};
        use sieve_filter::rules::{ListText, RuleEngine, RuleSet};
        use sieve_ipc::{MAX_GUESTS, Policy, vm_key};
        use std::sync::{Arc, Mutex};

        let mut book = FlowBook::default();
        let guest = |vm: &str| decide(Owner::Unknown, Some(Forwarded { vm: Some(vm.to_string()) }));
        let open = |book: &mut FlowBook, vm: &str| {
            let (_, forwarded) = guest(vm).event_fields();
            book.open(sieve_ipc::FlowEvent { pid: None, exe: None, session: None, forwarded, ..crate::stack::book::tests_event(None) }).unwrap();
        };
        for i in 0..MAX_GUESTS - 1 {
            open(&mut book, &format!("vm{i:02}"));
        }
        let (held, folded) = ("vm00", "one too many");
        open(&mut book, folded);
        assert_eq!(guest(held).row_owner(None, &book), HeldOwner::Forwarded(Some(held.to_string())));
        assert_eq!(guest(folded).row_owner(None, &book), HeldOwner::Forwarded(None));

        let lists = RuleEngine::compile(&[ListText { id: "test", text: "||ads.example^\n", trusted: false }]);
        let rules = RuleSet { user: Arc::new(RuleEngine::empty()), lists: Arc::new(lists) };
        let row_off = DomainFilter::new(&Policy { sieving: true, off_apps: vec![vm_key(None)], ..Policy::default() }, rules);
        let names = Mutex::default();
        let reason = |owner: HeldOwner| row_off.decide(Flow { dns: false, name: Some("ads.example"), remote: "192.0.2.1".parse().unwrap(), owner: owner.as_owner() }, &names, 0).reason;
        assert_eq!(reason(guest(folded).row_owner(None, &book)), Reason::AppExempt);
        assert_ne!(reason(guest(held).row_owner(None, &book)), Reason::AppExempt);
    }

    #[test]
    fn a_forwarded_flow_has_no_pid_exe_or_session() {
        let (pid, forwarded) = decide(Owner::Unknown, Some(named())).event_fields();
        assert_eq!((pid, forwarded), (None, Some(named())));
        assert_eq!(decide(Owner::Unknown, Some(named())).pid(), None, "so no exe or session is looked up");
    }

    /// The join of attribution and domain policy: a VM's row exempts that VM
    /// alone, an unnamed guest answers to the unidentified row, and neither can
    /// reach an app's row. A guest is filtered by domain and never decrypted.
    #[test]
    fn a_forwarded_flow_answers_to_its_vm_row_and_is_never_decrypted() {
        use crate::dns::NameMap;
        use crate::domain::{DomainFilter, Flow, Reason};
        use crate::flow::flows::Action;
        use sieve_filter::rules::{ListText, RuleEngine, RuleSet};
        use sieve_ipc::{Policy, vm_key};
        use std::sync::{Arc, Mutex};

        const BLOCKED: &str = "ads.example";
        let rules = || {
            let lists = RuleEngine::compile(&[ListText { id: "test", text: "||ads.example^\n", trusted: false }]);
            RuleSet { user: Arc::new(RuleEngine::empty()), lists: Arc::new(lists) }
        };
        let filter = |off: Vec<String>| DomainFilter::new(&Policy { sieving: true, off_apps: off, ..Policy::default() }, rules());
        let names = Mutex::new(NameMap::default());
        let decide_for = |f: &DomainFilter, owner: &HeldOwner| f.decide(Flow { dns: false, name: Some(BLOCKED), remote: "192.0.2.1".parse().unwrap(), owner: owner.as_owner() }, &names, 0);

        let dev = decide(Owner::Unknown, Some(named())).owner(None);
        let bare = decide(Owner::Unknown, Some(unnamed())).owner(None);
        assert_eq!(dev, HeldOwner::Forwarded(Some("DevBox".into())));
        assert!(!dev.as_owner().may_decrypt() && !bare.as_owner().may_decrypt());

        let vm_row_off = filter(vec![vm_key(Some("DevBox"))]);
        let got = decide_for(&vm_row_off, &dev);
        assert_eq!((got.action, got.reason), (Action::Pass, Reason::AppExempt), "its own row");
        assert_eq!(decide_for(&vm_row_off, &bare).action, Action::Drop, "another guest's row");

        let unnamed_off = filter(vec![vm_key(None)]);
        assert_eq!(decide_for(&unnamed_off, &bare).reason, Reason::AppExempt);
        assert_eq!(decide_for(&unnamed_off, &dev).action, Action::Drop);

        // An app sharing the VM's name, or any key the process table could give, is not its row.
        let app_row_off = filter(vec!["devbox".into()]);
        assert_eq!(decide_for(&app_row_off, &dev).action, Action::Drop, "filtered by domain only");
    }

    /// A host flow alone reads its app key: a guest or a contradiction that
    /// was somehow handed one still gets no app's exemption.
    #[test]
    fn only_a_host_flow_is_an_app() {
        let app = || Some("browser".to_string());
        assert_eq!(decide(Owner::Pid(7), None).owner(app()), HeldOwner::App("browser".into()));
        assert_eq!(decide(Owner::Pid(7), None).owner(None), HeldOwner::Unknown, "a hidden exe has no key");
        assert_eq!(decide(Owner::Unknown, Some(named())).owner(app()), HeldOwner::Forwarded(Some("DevBox".into())));
        assert_eq!(decide(Owner::Pid(7), Some(named())).owner(app()), HeldOwner::Unknown, "both answered");
        assert_eq!(decide(Owner::Disagreed { table: Some(7) }, None).owner(app()), HeldOwner::Unknown);
    }

    #[test]
    fn event_fields_cannot_say_both() {
        for a in [
            decide(Owner::Pid(7), None),
            decide(Owner::Pid(7), Some(named())),
            decide(Owner::Unknown, Some(named())),
            decide(Owner::Unknown, None),
            decide(Owner::Disagreed { table: None }, None),
        ] {
            let (pid, forwarded) = a.event_fields();
            assert!(pid.is_none() || forwarded.is_none(), "{a:?}");
        }
    }

    #[test]
    fn counters_give_both_rates() {
        // forwarded_unnamed_is_a_miss: 100 flows, 90 host, 5 named, 5 unnamed.
        let m = Meters::default();
        for _ in 0..90 {
            decide(Owner::Pid(7), None).count(&m);
        }
        for _ in 0..5 {
            decide(Owner::Unknown, Some(named())).count(&m);
            decide(Owner::Unknown, Some(unnamed())).count(&m);
        }
        let c = m.counters();
        assert_eq!((c.flows, c.attributed, c.forwarded, c.forwarded_named), (100, 95, 10, 5));
        let all = c.attributed as f64 / c.flows as f64;
        let host = (c.attributed - c.forwarded_named) as f64 / (c.flows - c.forwarded) as f64;
        assert_eq!((all, host), (0.95, 1.0));
    }

    #[test]
    fn counters_name_what_etw_did_and_a_conflict_is_a_miss() {
        let m = Meters::default();
        decide(Owner::WitnessOnly(7), None).count(&m);
        decide(Owner::Disagreed { table: Some(7) }, None).count(&m);
        decide(Owner::Pid(7), Some(named())).count(&m);
        decide(Owner::Unknown, None).count(&m);
        let c = m.counters();
        assert_eq!((c.flows, c.attributed, c.etw_found, c.etw_disagreed, c.forwarded), (4, 1, 1, 1, 0));
    }
}
