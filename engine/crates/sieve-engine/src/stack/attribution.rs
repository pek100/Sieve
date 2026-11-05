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
//! flow must not pass as a guest's.

use sieve_ipc::Forwarded;

use super::Meters;
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
        Owner::Disagreed => Attribution::Unknown(Unproven::Disagreed),
        Owner::Unknown | Owner::Pending => match nat {
            Some(forwarded) => Attribution::Forwarded(forwarded),
            None => Attribution::Unknown(Unproven::NoAnswer),
        },
    }
}

impl Attribution {
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

    #[test]
    fn decide_matches_the_table_of_d5() {
        assert_eq!(decide(Owner::Pid(7), None), Attribution::Host { pid: 7, witness_only: false });
        assert_eq!(decide(Owner::WitnessOnly(7), None), Attribution::Host { pid: 7, witness_only: true });
        assert_eq!(decide(Owner::Unknown, Some(named())), Attribution::Forwarded(named()));
        assert_eq!(decide(Owner::Unknown, Some(unnamed())), Attribution::Forwarded(unnamed()));
        assert_eq!(decide(Owner::Pid(7), Some(named())), Attribution::Unknown(Unproven::OwnerAndNat));
        assert_eq!(decide(Owner::WitnessOnly(7), Some(unnamed())), Attribution::Unknown(Unproven::OwnerAndNat));
        assert_eq!(decide(Owner::Disagreed, Some(named())), Attribution::Unknown(Unproven::Disagreed));
        assert_eq!(decide(Owner::Disagreed, None), Attribution::Unknown(Unproven::Disagreed));
        assert_eq!(decide(Owner::Unknown, None), Attribution::Unknown(Unproven::NoAnswer));
    }

    /// A forwarded UDP flow whose external port equals a host wildcard-bound
    /// port matches that owner row: the NAT state already held must overrule
    /// it, or the flow borrows that app's exemption. No read may be issued.
    #[tokio::test]
    async fn a_udp_owner_with_a_held_nat_match_is_unknown() {
        use crate::flow::flows::FiveTuple;
        use crate::flow::nat::{NatSession, NatSource, NatTable, NoDirectory, VmDirectory};
        use crate::flow::packet::Proto;

        struct OneSession;
        impl NatSource for OneSession {
            fn read(&mut self) -> Result<Vec<NatSession>, String> {
                Ok(vec![NatSession {
                    proto: Proto::Udp,
                    internal_source: "172.17.83.30:36099".parse().unwrap(),
                    external_source: "198.18.0.1:62049".parse().unwrap(),
                    external_destination: "185.125.190.57:123".parse().unwrap(),
                }])
            }
        }
        let table = NatTable::spawn(|| {
            let sources: Vec<Box<dyn NatSource>> = vec![Box::new(OneSession)];
            let directory: Box<dyn VmDirectory> = Box::new(NoDirectory);
            (sources, directory)
        });
        let flow = FiveTuple { proto: Proto::Udp, local: "198.18.0.1:62049".parse().unwrap(), remote: "185.125.190.57:123".parse().unwrap() };
        assert_eq!(decide(Owner::Pid(7), table.held_match(&flow)), Attribution::Host { pid: 7, witness_only: false }, "nothing held yet");
        assert!(table.fresh_match(&flow, 1_000).await.is_some());
        let reads = table.stats().reads;
        assert_eq!(decide(Owner::Pid(7), table.held_match(&flow)), Attribution::Unknown(Unproven::OwnerAndNat));
        assert_eq!(table.stats().reads, reads, "the check reads only what is held");
    }

    #[test]
    fn a_forwarded_flow_has_no_pid_exe_or_session() {
        let (pid, forwarded) = decide(Owner::Unknown, Some(named())).event_fields();
        assert_eq!((pid, forwarded), (None, Some(named())));
        assert_eq!(decide(Owner::Unknown, Some(named())).pid(), None, "so no exe or session is looked up");
    }

    #[test]
    fn event_fields_cannot_say_both() {
        for a in [
            decide(Owner::Pid(7), None),
            decide(Owner::Pid(7), Some(named())),
            decide(Owner::Unknown, Some(named())),
            decide(Owner::Unknown, None),
            decide(Owner::Disagreed, None),
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
        decide(Owner::Disagreed, None).count(&m);
        decide(Owner::Pid(7), Some(named())).count(&m);
        decide(Owner::Unknown, None).count(&m);
        let c = m.counters();
        assert_eq!((c.flows, c.attributed, c.etw_found, c.etw_disagreed, c.forwarded), (4, 1, 1, 1, 0));
    }
}
