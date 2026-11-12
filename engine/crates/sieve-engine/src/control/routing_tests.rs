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
    /// What it reads before `ready_at`.
    before: AddressState,
    /// What was done, and when, in milliseconds since `start`.
    log: Vec<(u128, String)>,
    fail_route: Option<Prefix>,
}

impl FakeAdapter {
    fn new(ready_at: std::time::Duration, then: AddressState) -> Self {
        Self { start: tokio::time::Instant::now(), ready_at, then, before: AddressState::Tentative, log: Vec::new(), fail_route: None }
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
        Ok(if self.start.elapsed() < self.ready_at { self.before } else { self.then })
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
    let added = route_adapter(&mut adapter, &addresses, &routes(), &|| true).await.unwrap();
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
    let failed = route_adapter(&mut adapter, &addresses, &routes(), &|| true).await.unwrap_err();
    assert!(failed.contains("still tentative"), "{failed}");
    assert!(adapter.routes_added().is_empty());
    assert!(adapter.start.elapsed() >= ADDRESSES_READY_WITHIN && adapter.start.elapsed() < ADDRESSES_READY_WITHIN + std::time::Duration::from_secs(1));

    let mut deprecated = FakeAdapter::new(std::time::Duration::ZERO, AddressState::Unusable(3));
    let failed = route_adapter(&mut deprecated, &addresses, &routes(), &|| true).await.unwrap_err();
    assert!(failed.contains("cannot use its address"), "{failed}");
    assert!(deprecated.routes_added().is_empty());
    assert_eq!(deprecated.start.elapsed(), std::time::Duration::ZERO, "no wait for an address that is never usable");
}

/// Another VPN or TUN on 198.18.0.0/15: the blocker says what to do.
#[tokio::test(start_paused = true)]
async fn a_duplicate_address_says_another_adapter_has_sieves_range() {
    let mut duplicate = FakeAdapter::new(std::time::Duration::ZERO, AddressState::Duplicate);
    let addresses = adapter_addresses(&routes());
    let failed = route_adapter(&mut duplicate, &addresses, &routes(), &|| true).await.unwrap_err();
    assert!(failed.contains("198.18.0.0/15") && failed.contains("another VPN") && failed.contains("turn Sieve on again"), "{failed}");
    assert!(duplicate.routes_added().is_empty());
}

/// Right after the address is added Windows may read it as not yet set
/// (`IpDadStateInvalid`): that is waited on, not a failure.
#[tokio::test(start_paused = true)]
async fn an_address_not_yet_set_is_waited_on() {
    let mut adapter = FakeAdapter::new(std::time::Duration::from_millis(500), AddressState::Preferred);
    adapter.before = AddressState::NotYet;
    let addresses = adapter_addresses(&routes());
    assert_eq!(route_adapter(&mut adapter, &addresses, &routes(), &|| true).await.unwrap(), routes());
    assert!(adapter.routes_added().iter().all(|t| *t >= 500));
}

/// A stop or the switch going off ends the wait at once: no route goes in, and
/// it is no Setup blocker (`NO_LONGER_WANTED`).
#[tokio::test(start_paused = true)]
async fn a_stop_during_the_wait_ends_it_at_once() {
    let mut adapter = FakeAdapter::new(std::time::Duration::from_secs(3), AddressState::Preferred);
    let addresses = adapter_addresses(&routes());
    let start = tokio::time::Instant::now();
    let asked = std::sync::atomic::AtomicUsize::new(0);
    let wanted = || asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 3;
    let failed = route_adapter(&mut adapter, &addresses, &routes(), &wanted).await.unwrap_err();
    assert_eq!(failed, super::routing::NO_LONGER_WANTED);
    assert!(start.elapsed() < std::time::Duration::from_millis(500), "{:?}", start.elapsed());
    assert!(adapter.routes_added().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_failed_route_takes_out_the_ones_before_it_and_empties_the_journal() {
    let mut adapter = FakeAdapter::new(std::time::Duration::ZERO, AddressState::Preferred);
    adapter.fail_route = Some(routes()[1]);
    let addresses = adapter_addresses(&routes());
    assert_eq!(route_adapter(&mut adapter, &addresses, &routes(), &|| true).await.unwrap_err(), ROUTE_FAILURE);
    let done: Vec<&str> = adapter.log.iter().map(|(_, w)| w.as_str()).collect();
    assert_eq!(done, ["route 0.0.0.0/5", "delete 0.0.0.0/5", "journal emptied"]);
}

#[test]
fn an_ipv4_only_plan_gives_the_adapter_no_ipv6_address() {
    let v4: Vec<Prefix> = vec!["0.0.0.0/5".parse().unwrap()];
    assert_eq!(adapter_addresses(&v4), [std::net::IpAddr::V4(crate::tun::TUN_V4)]);
}

mod sign_in_pass {
    use std::time::{Duration, Instant};

    use super::super::routing::{Outstanding, SignInFacts, Unread, capture_wanted, sign_in_pass, verdict_of};
    use super::engine;
    use crate::ipc::Backend;
    use crate::route::sign_in::{self, Ended, PROBE_EVERY, Seen, Verdict};

    const HOTEL: &str = "{6f1c2a9e-0b7d-4c55-9a31-2f1d8e4b7c10}";

    fn hotel() -> Verdict {
        Verdict { network: HOTEL.into(), luid: 0x0047_0000_0000_0001, hijacked: false }
    }

    /// A pass on the portal, with the capture as given.
    fn pass(v: Option<&Verdict>, held: bool) -> Seen<'_> {
        Seen { wanted: true, held, network: v, unread: false, portal: true, encrypted_unreachable: true }
    }

    /// The engine with a notice shown, then paused by the user's click.
    fn paused_at(t0: Instant) -> crate::control::Engine {
        let e = engine();
        e.sign_in().observe(t0, pass(Some(&hotel()), true));
        e.sign_in().pause(t0, HOTEL, true, true).unwrap();
        e
    }

    async fn never_asked() -> bool {
        panic!("no encrypted lookup is due")
    }

    #[tokio::test]
    async fn the_capture_is_held_as_none_while_paused_and_comes_back_when_it_ends() {
        let t0 = Instant::now();
        let e = engine();
        assert!(capture_wanted(&e), "the setting on: wanted");
        let e = paused_at(t0);
        assert!(!capture_wanted(&e), "paused: the capture step closes it");
        assert_eq!(sign_in_pass(&e, t0 + Duration::from_secs(1), pass(Some(&hotel()), false), never_asked).await, None);
        assert!(!capture_wanted(&e), "still paused");
        assert_eq!(e.sign_in().resume(), Some(Ended::User));
        assert!(capture_wanted(&e), "resumed: wanted again");
    }

    /// Windows' word that cannot be read: reported once while it keeps failing;
    /// for a moment the last good word stands and the pause holds; past the bound
    /// a pause ends in the same pass, so the capture step after it opens the
    /// capture again, and it is not counted.
    #[tokio::test]
    async fn a_verdict_that_cannot_be_read_ends_a_pause_only_past_the_bound() {
        let t0 = Instant::now();
        let e = paused_at(t0);
        let mut facts = SignInFacts::default();
        let mut last = None;
        let why = "Windows did not say within 5 s which network this is";
        fn pass_with(heard: &sign_in::Heard) -> Seen<'_> {
            Seen { unread: heard.unread, ..pass(heard.verdict.as_ref(), false) }
        }
        let (heard, _) = facts.heard(t0, verdict_of(&e, Ok(Some(hotel())), &mut last), None);
        assert_eq!(sign_in_pass(&e, t0, pass_with(&heard), never_asked).await, None);
        for s in [1, 2] {
            let read = verdict_of(&e, Err(why.into()), &mut last);
            assert_eq!(read, None);
            let (heard, _) = facts.heard(t0 + Duration::from_secs(s), read, None);
            assert_eq!(heard.verdict, Some(hotel()), "miss {s}: the last good word stands");
            assert_eq!(sign_in_pass(&e, t0 + Duration::from_secs(s), pass_with(&heard), never_asked).await, None);
            assert!(!capture_wanted(&e), "still paused");
        }
        let (heard, _) = facts.heard(t0 + Duration::from_secs(3), verdict_of(&e, Err(why.into()), &mut last), None);
        assert!(heard.unread);
        assert_eq!(sign_in_pass(&e, t0 + Duration::from_secs(3), pass_with(&heard), never_asked).await, Some(Ended::Unread));
        assert!(capture_wanted(&e), "the capture comes back in this very pass");
        let reported = e.facts().last_error.unwrap_or_default();
        assert_eq!(reported.matches(why).count(), 1, "said once while it keeps failing the same way: {reported}");
        assert_eq!(verdict_of(&e, Ok(Some(hotel())), &mut last), Some(Some(hotel())));
        assert_eq!(last, None, "a read that works ends it");
    }

    /// The glue of `follow_sign_in`: the portal check's answer is stamped with the
    /// network id and adapter Windows named in the same pass, counts only for
    /// them, and a moved network clears it and makes the check due at once.
    #[test]
    fn the_portal_answer_is_stamped_with_its_network_and_cleared_when_it_moves() {
        let t0 = Instant::now();
        let mut facts = SignInFacts::default();
        assert!(facts.portal_due(t0), "the first check is due");
        assert!(!facts.portal_due(t0 + Duration::from_secs(1)), "counted as started");
        let (heard, portal) = facts.heard(t0, Some(Some(hotel())), Some(true));
        assert_eq!(heard.verdict, Some(hotel()));
        assert!(portal, "found on the network Windows named");
        let (_, portal) = facts.heard(t0 + Duration::from_secs(5), Some(Some(hotel())), None);
        assert!(portal, "no check this pass: the last answer stands while fresh");
        let cafe = Verdict { network: "{0d4b7e21-5a3c-4e8f-b1d2-9c6a5f3e8b47}".into(), ..hotel() };
        let (_, portal) = facts.heard(t0 + Duration::from_secs(6), Some(Some(cafe)), None);
        assert!(!portal, "another network on the same adapter: the answer was not for it");
        let ethernet = Verdict { luid: 0x0006_0000_0000_0002, ..hotel() };
        assert!(!facts.heard(t0 + Duration::from_secs(7), Some(Some(ethernet.clone())), None).1, "another adapter");
        let (heard, portal) = facts.heard(t0 + Duration::from_secs(8), None, Some(true));
        assert_eq!(heard.verdict, Some(ethernet), "a missed read: the last good word stands");
        assert!(portal, "and the check is stamped with that word");
        assert!(!facts.heard(t0 + Duration::from_secs(9), Some(Some(hotel())), None).1, "so it is not hotel's");
        let mut facts = SignInFacts::default();
        facts.portal_due(t0);
        facts.heard(t0, Some(Some(hotel())), Some(true));
        facts.moved();
        assert!(facts.portal_due(t0 + Duration::from_secs(1)), "moved: due at once");
        let (heard, portal) = facts.heard(t0 + Duration::from_secs(1), None, None);
        assert!(heard.unread && !portal, "moved: neither the answer nor Windows' last word is kept");
        let (_, portal) = facts.heard(t0 + Duration::from_secs(2), Some(Some(hotel())), None);
        assert!(!portal, "moved: the old answer is gone even for the same network");
    }

    /// While paused, the encrypted lookup runs on its schedule, and its answer ends
    /// the pause in the same pass: the capture step after it opens the capture.
    #[tokio::test]
    async fn an_encrypted_answer_reopens_the_capture_in_the_same_pass() {
        let t0 = Instant::now();
        let e = paused_at(t0);
        let early = t0 + PROBE_EVERY - Duration::from_secs(1);
        assert_eq!(sign_in_pass(&e, early, pass(Some(&hotel()), false), never_asked).await, None, "not due yet: nothing asked");
        let due = t0 + PROBE_EVERY;
        assert_eq!(sign_in_pass(&e, due, pass(Some(&hotel()), false), || async { false }).await, None, "asked, no answer: still paused");
        assert!(!capture_wanted(&e));
        e.set_facts(|f| f.routes_up = true);
        assert!(e.status().wifi_sign_in.is_some_and(|w| w.paused_left_s.is_some()), "the status says paused");
        let next = due + PROBE_EVERY;
        assert_eq!(sign_in_pass(&e, next, pass(Some(&hotel()), false), || async { true }).await, Some(Ended::Answered));
        assert!(capture_wanted(&e), "opened again in the same pass");
        assert_eq!(e.status().wifi_sign_in, None, "and nothing to say");
    }

    /// A read that hangs costs one thread, never one per pass: while it runs, the
    /// next pass starts none, and once it ends late its answer is dropped as stale.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hung_read_is_not_started_again_while_it_runs() {
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (release, hold) = std::sync::mpsc::channel::<()>();
        let hold = std::sync::Arc::new(std::sync::Mutex::new(hold));
        let mut read: Outstanding<u32> = Outstanding::default();
        let start = |answer: u32| {
            let (started, hold) = (started.clone(), hold.clone());
            move || {
                tokio::task::spawn_blocking(move || {
                    started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = hold.lock().unwrap().recv_timeout(Duration::from_secs(10));
                    answer
                })
            }
        };
        assert_eq!(read.read(Duration::from_millis(50), start(1)).await, Err(Unread::TimedOut));
        for _ in 0..3 {
            assert_eq!(read.read(Duration::from_millis(50), start(2)).await, Err(Unread::StillRunning));
        }
        assert_eq!(started.load(std::sync::atomic::Ordering::SeqCst), 1, "one thread, not one per pass");
        release.send(()).unwrap();
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while read.read(Duration::from_secs(5), start(3)).await == Err(Unread::StillRunning) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(started.load(std::sync::atomic::Ordering::SeqCst), 2, "the next read started only after the hung one ended");
    }
}