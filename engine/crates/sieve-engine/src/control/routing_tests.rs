//! `routing.rs`'s switch and its reasons, with no OS and no socket. In a file of its
//! own: laws read `routing.rs` as text to see what production wires.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use sieve_ipc::Policy;

use super::Engine;
use super::routing::{ADDRESSES_READY_WITHIN, AdapterOps, add_addresses, add_missing, adapter_addresses, route_adapter, sync_https_by};
use crate::route::apply::AddressState;
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

/// The Status says what new flows get, not what the switch asks for: wanted but
/// unbuilt, or built and then any switch off, is no decrypting (task D8).
#[tokio::test]
async fn the_status_reports_decrypting_only_while_the_slot_holds_it() {
    let e = engine();
    assert!(e.policy().https && !e.status().decrypting, "wanted, not built yet");
    sync(&e, || Ok(built(&e))).await;
    assert!(e.status().decrypting, "built");
    // What `take_down` does, for the engine switch and for a blocker.
    e.https.set(None);
    assert!(!e.status().decrypting, "routes down");
    for (name, off) in [OFF_SWITCHES[0], OFF_SWITCHES[1]] {
        let e = engine();
        sync(&e, || Ok(built(&e))).await;
        turn(&e, off);
        assert!(!e.status().decrypting, "{name}: off");
    }
}

#[tokio::test]
async fn a_failed_build_says_nothing_is_decrypting() {
    let e = engine();
    sync(&e, || Err(BUILD_FAILURE.to_string())).await;
    assert!(!e.status().decrypting);
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

/// The adapter as duplicate address detection leaves it: each address is
/// tentative until `ready_at` (tokio's paused clock), then preferred or `then`.
struct FakeAdapter {
    start: tokio::time::Instant,
    ready_at: std::time::Duration,
    then: AddressState,
    /// What was done, and when, in milliseconds since `start`.
    log: Vec<(u128, String)>,
    fail_route: Option<Prefix>,
}

impl FakeAdapter {
    fn new(ready_at: std::time::Duration, then: AddressState) -> Self {
        Self { start: tokio::time::Instant::now(), ready_at, then, log: Vec::new(), fail_route: None }
    }

    fn note(&mut self, what: String) {
        let at = self.start.elapsed().as_millis();
        self.log.push((at, what));
    }

    fn routes_added(&self) -> Vec<u128> {
        self.log.iter().filter(|(_, w)| w.starts_with("route ")).map(|(t, _)| *t).collect()
    }
}

impl AdapterOps for FakeAdapter {
    fn add_address(&mut self, ip: std::net::IpAddr) -> Result<(), String> {
        self.note(format!("address {ip}"));
        Ok(())
    }

    fn address_state(&mut self, _: std::net::IpAddr) -> Result<AddressState, String> {
        Ok(if self.start.elapsed() < self.ready_at { AddressState::Tentative } else { self.then })
    }

    fn add_route(&mut self, prefix: Prefix) -> Result<(), String> {
        if self.fail_route == Some(prefix) {
            return Err(ROUTE_FAILURE.into());
        }
        self.note(format!("route {prefix}"));
        Ok(())
    }

    fn delete_route(&mut self, prefix: Prefix) {
        self.note(format!("delete {prefix}"));
    }

    fn forget_routes(&mut self) {
        self.note("journal emptied".into());
    }
}

fn routes() -> Vec<Prefix> {
    ["0.0.0.0/5", "2000::/4"].iter().map(|p| p.parse().unwrap()).collect()
}

/// Live on a Windows Server 2025 VM (2026-11-09): routes added while 198.18.0.1 was
/// still tentative made every lookup fail with "host unreachable" for 3.0 s.
#[tokio::test(start_paused = true)]
async fn no_route_points_at_the_adapter_before_its_addresses_may_be_a_source() {
    let mut adapter = FakeAdapter::new(std::time::Duration::from_secs(3), AddressState::Preferred);
    let addresses = adapter_addresses(&routes());
    assert_eq!(addresses.len(), 2, "IPv6 is routed, so the adapter takes both addresses");
    add_addresses(&mut adapter, &addresses).unwrap();
    let added = route_adapter(&mut adapter, &addresses, &routes()).await.unwrap();
    assert_eq!(added, routes());
    let at = adapter.routes_added();
    assert_eq!(at.len(), 2);
    assert!(at.iter().all(|t| *t >= 3_000), "a route went in while an address was tentative: {:?}", adapter.log);
    assert!(at[0] < 3_000 + 100, "and soon after it settled: {:?}", adapter.log);
}

#[tokio::test(start_paused = true)]
async fn an_address_that_never_settles_routes_nothing() {
    let mut adapter = FakeAdapter::new(ADDRESSES_READY_WITHIN * 2, AddressState::Preferred);
    let addresses = adapter_addresses(&routes());
    let failed = route_adapter(&mut adapter, &addresses, &routes()).await.unwrap_err();
    assert!(failed.contains("still tentative"), "{failed}");
    assert!(adapter.routes_added().is_empty());
    assert!(adapter.start.elapsed() >= ADDRESSES_READY_WITHIN && adapter.start.elapsed() < ADDRESSES_READY_WITHIN + std::time::Duration::from_secs(1));

    let mut duplicate = FakeAdapter::new(std::time::Duration::ZERO, AddressState::Unusable(2));
    let failed = route_adapter(&mut duplicate, &addresses, &routes()).await.unwrap_err();
    assert!(failed.contains("cannot use its address"), "{failed}");
    assert!(duplicate.routes_added().is_empty());
    assert_eq!(duplicate.start.elapsed(), std::time::Duration::ZERO, "no wait for an address that is never usable");
}

#[tokio::test(start_paused = true)]
async fn a_failed_route_takes_out_the_ones_before_it_and_empties_the_journal() {
    let mut adapter = FakeAdapter::new(std::time::Duration::ZERO, AddressState::Preferred);
    adapter.fail_route = Some(routes()[1]);
    let addresses = adapter_addresses(&routes());
    assert_eq!(route_adapter(&mut adapter, &addresses, &routes()).await.unwrap_err(), ROUTE_FAILURE);
    let done: Vec<&str> = adapter.log.iter().map(|(_, w)| w.as_str()).collect();
    assert_eq!(done, ["route 0.0.0.0/5", "delete 0.0.0.0/5", "journal emptied"]);
}

#[test]
fn an_ipv4_only_plan_gives_the_adapter_no_ipv6_address() {
    let v4: Vec<Prefix> = vec!["0.0.0.0/5".parse().unwrap()];
    assert_eq!(adapter_addresses(&v4), [std::net::IpAddr::V4(crate::tun::TUN_V4)]);
}