//! `routing.rs`'s switch and its reasons, with no OS and no socket. In a file of its
//! own: laws read `routing.rs` as text to see what production wires.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use sieve_ipc::Policy;

use super::Engine;
use super::routing::{add_missing, sync_https_by};
use crate::http::hook::NoRewrite;
use crate::ipc::Backend;
use crate::policy::{Runs, wall_ms};
use crate::route::prefix::Prefix;
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

/// The slot's sync with nothing to load.
async fn sync(engine: &Engine, build: impl FnOnce() -> Result<Interception<Egress>, String>) {
    sync_https_by(engine, async {}, build).await;
}

#[tokio::test]
async fn a_switch_turned_off_while_building_publishes_nothing() {
    for (name, off) in OFF_SWITCHES {
        let e = engine();
        sync(&e, || {
            turn(&e, off);
            Ok(built(&e))
        })
        .await;
        assert!(e.https.get().is_none(), "{name}: a new flow would decrypt");
    }
    // The control: the same build with the switch left on.
    let e = engine();
    sync(&e, || Ok(built(&e))).await;
    assert!(e.https.get().is_some());
}

/// A flow reads the slot when it arrives, and its verdict lasts as long as it does.
#[tokio::test]
async fn no_flow_finds_interception_before_its_validation_data() {
    let e = engine();
    let (loaded, read) = tokio::sync::oneshot::channel::<()>();
    let sync = sync_https_by(
        &e,
        async {
            let _ = read.await;
        },
        || Ok(built(&e)),
    );
    tokio::pin!(sync);
    assert!(tokio::time::timeout(std::time::Duration::from_millis(50), &mut sync).await.is_err(), "it waits for the data");
    assert!(e.https.get().is_none(), "a flow arriving now passes as with the switch off");
    loaded.send(()).unwrap();
    sync.await;
    assert!(e.https.get().is_some());
}

#[tokio::test]
async fn a_switch_turned_off_while_loading_publishes_nothing() {
    for (name, off) in OFF_SWITCHES {
        let e = engine();
        sync_https_by(&e, async { turn(&e, off) }, || Ok(built(&e))).await;
        assert!(e.https.get().is_none(), "{name}: a new flow would decrypt");
    }
}

#[tokio::test]
async fn nothing_is_loaded_for_a_slot_that_needs_nothing() {
    let e = engine();
    sync(&e, || Ok(built(&e))).await;
    sync_https_by(&e, async { panic!("the slot is full") }, || panic!("the slot is full")).await;
    turn(&e, |p| p.https = false);
    sync_https_by(&e, async { panic!("the switch is off") }, || panic!("the switch is off")).await;
}

#[tokio::test]
async fn a_held_interception_is_not_built_again_and_off_takes_it_away() {
    let e = engine();
    sync(&e, || Ok(built(&e))).await;
    sync(&e, || panic!("the slot is full")).await;
    turn(&e, |p| p.https = false);
    assert!(e.https.get().is_none());
    sync(&e, || panic!("the switch is off")).await;
}

#[tokio::test]
async fn a_failed_build_is_reported_until_a_later_one_works() {
    let e = engine();
    e.route_failed(ROUTE_FAILURE.into());
    sync(&e, || Err("first".into())).await;
    sync(&e, || Err(BUILD_FAILURE.into())).await;
    let reported = e.status().last_error.unwrap();
    assert!(reported.contains(BUILD_FAILURE) && reported.contains(ROUTE_FAILURE) && !reported.contains("first"), "{reported}");

    sync(&e, || Ok(built(&e))).await;
    assert_eq!(e.status().last_error.as_deref(), Some(ROUTE_FAILURE), "and no other reason goes with it");
}

#[tokio::test]
async fn a_failed_build_is_not_reported_after_the_switch_goes_off() {
    for (name, off) in OFF_SWITCHES {
        let e = engine();
        sync(&e, || Err(BUILD_FAILURE.into())).await;
        assert!(e.status().last_error.unwrap().contains(BUILD_FAILURE), "{name}");
        turn(&e, off);
        assert_eq!(e.status().last_error, None, "{name}: off ends it");

        let e = engine();
        sync(&e, || {
            turn(&e, off);
            Err(BUILD_FAILURE.into())
        })
        .await;
        assert_eq!(e.status().last_error, None, "{name}: off during the build");
    }
}

#[test]
fn a_route_failure_is_reported_until_a_later_pass_adds_it() {
    let e = engine();
    let route: Prefix = Prefix::new("10.0.0.0".parse().unwrap(), 8).unwrap();
    let other: Prefix = Prefix::new("172.16.0.0".parse().unwrap(), 12).unwrap();
    e.add_error("policy.json: broken".into());
    assert_eq!(add_missing(&e, [route, other].into_iter(), |p| if p == route { Err(ROUTE_FAILURE.into()) } else { Ok(()) }), [other]);
    assert!(e.status().last_error.unwrap().contains(ROUTE_FAILURE));
    assert_eq!(add_missing(&e, [route].into_iter(), |_| Ok(())), [route]);
    assert_eq!(e.status().last_error.as_deref(), Some("policy.json: broken"), "over, and it takes no other reason with it");

    add_missing(&e, [route].into_iter(), |_| Err(ROUTE_FAILURE.into()));
    assert_eq!(add_missing(&e, std::iter::empty(), |_| panic!("nothing is missing")), []);
    assert!(!e.status().last_error.unwrap().contains(ROUTE_FAILURE), "a route no longer planned is not failing either");
}
