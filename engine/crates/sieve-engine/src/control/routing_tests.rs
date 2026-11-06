//! `routing.rs`'s switch and its reasons, with no OS and no socket. In a file of its
//! own: laws read `routing.rs` as text to see what production wires.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use sieve_ipc::Policy;

use super::Engine;
use super::routing::sync_https_by;
use crate::http::hook::NoRewrite;
use crate::ipc::Backend;
use crate::policy::{Runs, wall_ms};
use crate::route::table::NetTables;
use crate::stack::egress::Egress;
use crate::tls::active::Active;
use crate::tls::ech::EchCache;
use crate::tls::ech::testing::FakeLookup;
use crate::tls::intercept::Interception;
use crate::tls::tests::{FakeTrust, Pki};
use crate::tls::upstream::{TRUST_TIMEOUT, TrustAnswer, Verifier};
use crate::tls::verdict::VerdictCache;

const ROUTE_FAILURE: &str = "route 10.0.0.0/8: code 5";
const BUILD_FAILURE: &str = "the DNS service is not running";

/// One switch turned off.
type Off = fn(&mut Policy);

const OFF_SWITCHES: [(&str, Off); 3] = [("https", |p| p.https = false), ("sieving", |p| p.sieving = false), ("engine", |p| p.engine = false)];

fn engine() -> Engine {
    let on = Policy { revision: 1, engine: true, sieving: true, https: true, ..Policy::default() };
    Engine::new(None, PathBuf::from(r"C:\x\sieve-engine.exe"), on, Runs::default(), None)
}

/// What `build_interception` makes.
fn built(engine: &Engine) -> Interception<Egress> {
    let tables = Arc::new(RwLock::new(NetTables::default()));
    Interception {
        connector: Arc::new(Egress::new(0, tables)),
        exclusions: engine.exclusions.clone(),
        verifier: Arc::new(Verifier::new(Pki::new("Test Public Root").roots(), FakeTrust::says(TrustAnswer::Trusted), TRUST_TIMEOUT, engine.validation.clone()).unwrap()),
        verdicts: VerdictCache::default(),
        ech: Arc::new(EchCache::new(FakeLookup::none())),
        active: Active::default(),
        minter: Box::new(|| None),
        filter: engine.filter.clone(),
        names: engine.names.clone(),
        book: engine.book.clone(),
        meters: engine.meters.clone(),
        watch: engine.heal.clone(),
        hook: Arc::new(NoRewrite),
        clock: wall_ms,
    }
}

/// The switches a test turns, at the next revision.
fn turn(engine: &Engine, change: Off) {
    let mut next = engine.policy();
    next.revision += 1;
    change(&mut next);
    engine.set_policy(next).unwrap();
}

#[test]
fn a_switch_turned_off_while_building_publishes_nothing() {
    for (name, off) in OFF_SWITCHES {
        let e = engine();
        sync_https_by(&e, || {
            turn(&e, off);
            Ok(built(&e))
        });
        assert!(e.https.get().is_none(), "{name}: a new flow would decrypt");
    }
    // The control: the same build with the switch left on.
    let e = engine();
    sync_https_by(&e, || Ok(built(&e)));
    assert!(e.https.get().is_some());
}

#[test]
fn a_held_interception_is_not_built_again_and_off_takes_it_away() {
    let e = engine();
    sync_https_by(&e, || Ok(built(&e)));
    sync_https_by(&e, || panic!("the slot is full"));
    turn(&e, |p| p.https = false);
    assert!(e.https.get().is_none());
    sync_https_by(&e, || panic!("the switch is off"));
}

#[test]
fn a_failed_build_is_reported_until_a_later_one_works() {
    let e = engine();
    e.route_failed(ROUTE_FAILURE.into());
    sync_https_by(&e, || Err("first".into()));
    sync_https_by(&e, || Err(BUILD_FAILURE.into()));
    let reported = e.status().last_error.unwrap();
    assert!(reported.contains(BUILD_FAILURE) && reported.contains(ROUTE_FAILURE) && !reported.contains("first"), "{reported}");

    sync_https_by(&e, || Ok(built(&e)));
    assert_eq!(e.status().last_error.as_deref(), Some(ROUTE_FAILURE), "and no other reason goes with it");
}

#[test]
fn a_failed_build_is_not_reported_after_the_switch_goes_off() {
    for (name, off) in OFF_SWITCHES {
        let e = engine();
        sync_https_by(&e, || Err(BUILD_FAILURE.into()));
        assert!(e.status().last_error.unwrap().contains(BUILD_FAILURE), "{name}");
        turn(&e, off);
        assert_eq!(e.status().last_error, None, "{name}: off ends it");

        let e = engine();
        sync_https_by(&e, || {
            turn(&e, off);
            Err(BUILD_FAILURE.into())
        });
        assert_eq!(e.status().last_error, None, "{name}: off during the build");
    }
}
