//! Slice 11 through `Verifier` and through `tls::intercept::run`: the two local
//! chain checks and upstream ECH, on the harness of `tls::tests`. Lists here are
//! built in memory, so they carry no real signature (`ct` tests the real one).

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use clubcard_crlite::Encoding;
use rustls::RootCertStore;
use rustls::client::EchConfig;
use rustls::pki_types::CertificateDer;
use sieve_filter::exclusions::UpstreamVerdict;
use sieve_ipc::FlowAction;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::crlite::testing::filter;
use super::crlite::{Crlite, encode_bundle};
use super::ct::testing::{MemoryLog, USABLE, list_json, ocsp_with, ocsp_with_status, sct_list_value, status_revoked};
use super::ct::{self, CtAnswer, LogList, MAX_LIST_AGE_MS};
use super::ech::ECH_HANDSHAKE_TIMEOUT;
use super::ech::testing::{FakeLookup, config_list};
use super::ech::usable_config;
use super::tests::{Arm, FakeTrust, GOOD, HOST, Pki, Rig, RigOpts, TestDial, arms, cert_server_with, client_tls, connect, echo, echo_dial, expect_real, flow_opts, raw, round_trip, server_tls, server_tls_no_tickets, shown_is_sieves, tls_server};
use super::upstream::{Chain, HandshakeEnd, TRUST_TIMEOUT, TrustAnswer, Verifier, handshake, leaf_facts};
use super::validation::{KIND_CRLITE, ValidationSlot};
use crate::dns::HttpsRecord;
use crate::flow::Progress;
use crate::flow::sni::{Hello, parse_tls_stream};
use crate::policy::wall_ms;
use crate::stack::Meters;
use crate::update::{Kind, data_path};

const PUBLIC_NAME: &str = "public.example";
const X25519MLKEM768: u16 = 0x11ec;
/// The raw serial of `Pki::leaf_with_scts`.
const SERIAL: &[u8] = &[0x51, 0x1e, 0x7e];

/// Two logs under two operators, in a fresh list, and the time their SCTs carry.
struct World {
    logs: [MemoryLog; 2],
    at_ms: u64,
}

impl World {
    fn new() -> Self {
        Self { logs: [MemoryLog::new(), MemoryLog::new()], at_ms: wall_ms() - 60_000 }
    }

    fn list(&self, age_ms: u64) -> LogList {
        let text = list_json("2026-01-01T00:00:00Z", &[vec![self.logs[0].json(USABLE)], vec![self.logs[1].json(USABLE)]]);
        let mut list = LogList::parse(text.as_bytes()).unwrap();
        list.timestamp_ms = wall_ms() - age_ms;
        list
    }

    /// A filter over this root's leaves: `SERIAL` revoked.
    fn revoking(&self, pki: &Pki) -> Crlite {
        let bundle = encode_bundle(&[self.filter(pki)]).unwrap();
        Crlite::from_bundle(&bundle).unwrap()
    }

    fn filter(&self, pki: &Pki) -> Vec<u8> {
        let issuer = ct::spki_hash(X509Certificate::from_der(&pki.der).unwrap().1.public_key().raw);
        filter(&issuer, &[SERIAL], &[&[0x7f]], &self.logs[0].id, self.at_ms - 1_000, self.at_ms + 1_000, Encoding::V3)
    }

    /// A chain with an SCT from each log: compliant.
    fn compliant(&self, pki: &Pki) -> (Vec<CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>) {
        pki.leaf_with_scts(HOST, GOOD, &[&self.logs[0], &self.logs[1]], self.at_ms)
    }

    /// One SCT only: violates, and is still in a filter's coverage.
    fn violating(&self, pki: &Pki) -> (Vec<CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>) {
        pki.leaf_with_scts(HOST, GOOD, &[&self.logs[0]], self.at_ms)
    }
}

fn chain_of(certs: Vec<CertificateDer<'static>>) -> Chain {
    Chain { end_entity: certs[0].clone(), intermediates: certs[1..].to_vec(), ocsp: Vec::new() }
}

fn count(c: &AtomicU64) -> u64 {
    c.load(Ordering::Relaxed)
}

struct Stack {
    verifier: Verifier,
    slot: Arc<ValidationSlot>,
    meters: Arc<Meters>,
    trust: Arc<FakeTrust>,
}

fn stack(roots: Arc<RootCertStore>, list: Option<LogList>, crlite: Option<Crlite>) -> Stack {
    let meters: Arc<Meters> = Arc::default();
    let slot = Arc::new(ValidationSlot::new(meters.clone()));
    slot.install(list, crlite);
    let trust = FakeTrust::says(TrustAnswer::Trusted);
    let verifier = Verifier::new(roots, trust.clone(), TRUST_TIMEOUT, slot.clone()).unwrap();
    Stack { verifier, slot, meters, trust }
}

fn trust_calls(trust: &FakeTrust) -> usize {
    trust.calls.load(Ordering::Relaxed)
}

// ---- The stack, through `Verifier`.

#[tokio::test]
async fn unknown_root_never_reaches_validation() {
    let (public, private, world) = (Pki::new("Test Public Root"), Pki::new("A Corporate Proxy"), World::new());
    let s = stack(public.roots(), Some(world.list(0)), Some(world.revoking(&public)));
    let (certs, _) = private.leaf(HOST, GOOD);
    let asked = s.verifier.verify(&chain_of(certs), HOST, false, wall_ms()).await;
    assert_eq!(asked, UpstreamVerdict::NonPublicRoot);
    assert_eq!(trust_calls(&s.trust), 0);
    let https = &s.meters.https;
    assert_eq!(count(&https.ct_compliant) + count(&https.ct_violating) + count(&https.ct_skipped_no_list) + count(&https.crlite_revoked), 0, "no local check ran");
}

#[tokio::test]
async fn revoked_beats_ct_violation() {
    let (pki, world) = (Pki::new("Test Public Root"), World::new());
    let s = stack(pki.roots(), Some(world.list(0)), Some(world.revoking(&pki)));
    let chain = chain_of(world.violating(&pki).0);
    assert_eq!(s.verifier.verify(&chain, HOST, false, wall_ms()).await, UpstreamVerdict::Revoked);
    assert_eq!(trust_calls(&s.trust), 0);
    assert_eq!(count(&s.meters.https.crlite_revoked), 1);
}

#[tokio::test]
async fn ct_violation_gives_no_transparency_and_never_asks_trust() {
    let (pki, world) = (Pki::new("Test Public Root"), World::new());
    let s = stack(pki.roots(), Some(world.list(0)), None);
    let chain = chain_of(world.violating(&pki).0);
    assert_eq!(s.verifier.verify(&chain, HOST, false, wall_ms()).await, UpstreamVerdict::NoTransparency);
    assert_eq!(trust_calls(&s.trust), 0);
    assert_eq!(count(&s.meters.https.ct_violating), 1);
    // No SCTs at all is the same answer.
    let bare = chain_of(pki.leaf(HOST, GOOD).0);
    assert_eq!(s.verifier.verify(&bare, HOST, false, wall_ms()).await, UpstreamVerdict::NoTransparency);
}

#[tokio::test]
async fn compliant_chain_asks_trust_once() {
    let (pki, world) = (Pki::new("Test Public Root"), World::new());
    let s = stack(pki.roots(), Some(world.list(0)), None);
    let chain = chain_of(world.compliant(&pki).0);
    assert_eq!(s.verifier.verify(&chain, HOST, false, wall_ms()).await, UpstreamVerdict::Eligible);
    assert_eq!(trust_calls(&s.trust), 1);
    assert_eq!(count(&s.meters.https.ct_compliant), 1);
}

/// A staple with status revoked is still read, so the chain reaches trust, whose
/// `Revoked` is the verdict that closes open flows.
#[tokio::test]
async fn scts_in_a_revoked_staple_count_and_trust_is_asked() {
    let (pki, world) = (Pki::new("Test Public Root"), World::new());
    let s = stack(pki.roots(), Some(world.list(0)), None);
    let mut chain = chain_of(pki.leaf(HOST, GOOD).0);
    let entry = ct::SignedEntry::X509 { leaf: chain.end_entity.as_ref() };
    let scts = sct_list_value(&[world.logs[0].sct(world.at_ms, entry), world.logs[1].sct(world.at_ms, entry)]);
    chain.ocsp = ocsp_with_status(&status_revoked(), false, &scts);
    s.verifier.verify(&chain, HOST, false, wall_ms()).await;
    assert_eq!(count(&s.meters.https.ct_compliant), 1);
    assert_eq!(count(&s.meters.https.ct_violating), 0);
    assert_eq!(trust_calls(&s.trust), 1);
}

#[tokio::test]
async fn known_leaf_still_runs_local_checks_and_skips_trust() {
    let (pki, world) = (Pki::new("Test Public Root"), World::new());
    let s = stack(pki.roots(), Some(world.list(0)), None);
    let compliant = chain_of(world.compliant(&pki).0);
    assert_eq!(s.verifier.verify(&compliant, HOST, true, wall_ms()).await, UpstreamVerdict::Eligible);
    assert_eq!(count(&s.meters.https.ct_compliant), 1, "ran");
    assert_eq!(trust_calls(&s.trust), 0, "skipped");
    // A filter that arrived later reaches the same known leaf.
    s.slot.install(Some(world.list(0)), Some(world.revoking(&pki)));
    assert_eq!(s.verifier.verify(&compliant, HOST, true, wall_ms()).await, UpstreamVerdict::Revoked);
}

#[tokio::test]
async fn no_data_behaves_as_slice_6() {
    let pki = Pki::new("Test Public Root");
    let s = stack(pki.roots(), None, None);
    let chain = chain_of(pki.leaf(HOST, GOOD).0);
    assert_eq!(s.verifier.verify(&chain, HOST, false, wall_ms()).await, UpstreamVerdict::Eligible);
    assert_eq!(trust_calls(&s.trust), 1, "the fake trust was called");
    assert_eq!(count(&s.meters.https.ct_skipped_no_list), 1);
}

const RECORDED_ISSUER: &[u8] = include_bytes!("../../fixtures/validation/issuer.der");

fn spki_of(der: &[u8]) -> ct::SpkiHash {
    ct::spki_hash(X509Certificate::from_der(der).unwrap().1.public_key().raw)
}

#[tokio::test]
async fn issuer_hash_of_an_intermediate_matches_the_recorded_issuer() {
    // A path: the leaf's direct issuer is the hash, not the one above it.
    let root = Pki::new("Test Public Root");
    let upper = root.child("Upper");
    let lower = upper.child("Lower");
    let s = stack(root.roots(), None, None);
    let mut chain = chain_of(lower.leaf(HOST, GOOD).0);
    chain.intermediates = vec![lower.der.clone(), upper.der.clone()];
    assert_eq!(s.verifier.issuer_hash(&chain, wall_ms()), Some(spki_of(&lower.der)));
    // The recorded issuer has no root to chain to here, so its path cannot be
    // built; webpki's own rewrap of it is what the intermediate arm hashes, and
    // the hash of it is the one the recorded SCTs verify under (`ct` tests).
    let recorded = CertificateDer::from(RECORDED_ISSUER);
    let cert = webpki::EndEntityCert::try_from(&recorded).unwrap();
    assert_eq!(ct::spki_hash(cert.subject_public_key_info().as_ref()), spki_of(RECORDED_ISSUER));
}

#[tokio::test]
async fn issuer_hash_of_an_anchor_is_over_the_full_spki() {
    let root = Pki::new("Test Public Root");
    let s = stack(root.roots(), None, None);
    let chain = chain_of(root.leaf(HOST, GOOD).0);
    assert_eq!(s.verifier.issuer_hash(&chain, wall_ms()), Some(spki_of(&root.der)));
    // Task F12's witness: the anchor's own bytes hash differently.
    let store = root.roots();
    assert_ne!(ct::spki_hash(store.roots[0].subject_public_key_info.as_ref()), spki_of(&root.der));
}

#[tokio::test]
async fn issuer_is_found_when_the_server_sends_the_chain_out_of_order() {
    let root = Pki::new("Test Public Root");
    let upper = root.child("Upper");
    let lower = upper.child("Lower");
    let s = stack(root.roots(), None, None);
    let mut chain = chain_of(lower.leaf(HOST, GOOD).0);
    chain.intermediates = vec![upper.der.clone(), lower.der.clone()];
    assert_eq!(s.verifier.issuer_hash(&chain, wall_ms()), Some(spki_of(&lower.der)));
}

/// Evidence, not a gate: on the recorded leaf with a builder-made filter, in
/// memory, the second path build included. `--ignored --nocapture`.
#[tokio::test]
#[ignore = "a timing report, not a law"]
async fn bench_validation_local_checks() {
    use super::validation::tests::{NOW, chain, envelope, recorded_filter};
    const ROUNDS: u32 = 2_000;
    let mut store = RootCertStore::empty();
    store.add(CertificateDer::from(RECORDED_ISSUER)).unwrap();
    let list = LogList::from_envelope(&envelope(), ct::LOG_LIST_KEY).unwrap();
    let crlite = Crlite::from_bundle(&encode_bundle(&[recorded_filter(false)]).unwrap()).unwrap();
    let s = stack(Arc::new(store), Some(list), Some(crlite));
    let chain = chain();
    let start = std::time::Instant::now();
    for _ in 0..ROUNDS {
        let checked = s.slot.check(&chain, NOW, || s.verifier.issuer_hash(&chain, NOW));
        assert_eq!(checked.ct, CtAnswer::Compliant);
    }
    println!("bench_validation_local_checks: {:?} per connection, in memory, {ROUNDS} rounds", start.elapsed() / ROUNDS);
    // The worst a server can staple: a listed log's id on signatures that fail.
    const FLOOD: usize = 539;
    let leaf = chain.end_entity.as_ref();
    let forger = MemoryLog { key: rcgen::KeyPair::generate().unwrap(), id: *ct::scts_of(&X509Certificate::from_der(leaf).unwrap().1)[0].id.key_id };
    let forged = forger.sct(NOW - 1, ct::SignedEntry::X509 { leaf });
    let flooded = Chain { ocsp: ocsp_with(&sct_list_value(&vec![forged; FLOOD])), ..chain.clone() };
    let start = std::time::Instant::now();
    for _ in 0..ROUNDS {
        assert_eq!(s.slot.check(&flooded, NOW, || s.verifier.issuer_hash(&flooded, NOW)).ct, CtAnswer::Compliant);
    }
    println!("bench_validation_local_checks: {:?} per connection with a {}-byte staple", start.elapsed() / ROUNDS, flooded.ocsp.len());
}

// ---- End to end, through `tls::intercept::run`.

fn ct_rig(arm: Arm, configs: Vec<Arc<rustls::ServerConfig>>, pki: &Pki) -> (Rig, Arc<AtomicUsize>) {
    let (dial, shaken) = echo_dial(arm, configs);
    (Rig::new(dial, RigOpts::new(pki.roots())), shaken)
}

arms!(ct_violation_passes_through_with_client_hello_intact, |arm| async move {
    let (pki, world) = (Pki::new("Test Public Root"), World::new());
    let (rig, shaken) = ct_rig(arm, vec![server_tls_no_tickets(world.violating(&pki))], &pki);
    rig.validation.install(Some(world.list(0)), None);
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    expect_real(&shown, &rig);
    round_trip(&mut tls).await;
    assert_eq!(shaken.load(Ordering::Relaxed), 2, "our handshake on the first socket, the client's own on the fresh one");
    let sent = tls.get_ref().0.written.bytes();
    let arrived = rig.deps.connector.seen(1);
    let shared = sent.len().min(arrived.len());
    assert_eq!(arrived[..shared], sent[..shared], "the client's bytes reached the real server unchanged");
    tls.shutdown().await.unwrap();
    drop(tls);
    assert_eq!(task.await.unwrap().action, FlowAction::Relayed);
    assert_eq!(rig.reasons(), ["floor:upstream-ct"]);
    assert_eq!(rig.trust.calls.load(Ordering::Relaxed), 0);
});

arms!(ct_compliant_chain_is_intercepted, |arm| async move {
    let (pki, world) = (Pki::new("Test Public Root"), World::new());
    let (rig, _) = ct_rig(arm, vec![server_tls(world.compliant(&pki), &[], None)], &pki);
    rig.validation.install(Some(world.list(0)), None);
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig));
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(count(&rig.deps.meters.https.ct_compliant), 1);
    assert_eq!(rig.trust.calls.load(Ordering::Relaxed), 1);
});

arms!(stale_list_intercepts_and_counts_skipped, |arm| async move {
    let (pki, world) = (Pki::new("Test Public Root"), World::new());
    let (rig, _) = ct_rig(arm, vec![server_tls(world.violating(&pki), &[], None)], &pki);
    rig.validation.install(Some(world.list(MAX_LIST_AGE_MS + 60_000)), None);
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig), "a violation nobody can judge is no violation");
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(count(&rig.deps.meters.https.ct_skipped_stale), 1);
    assert_eq!(count(&rig.deps.meters.https.ct_violating), 0);
});

arms!(crlite_revoked_passes_through_and_closes_open_flows_to_that_host, |arm| async move {
    let (pki, world) = (Pki::new("Test Public Root"), World::new());
    let (rig, _) = ct_rig(arm, vec![server_tls(world.compliant(&pki), &[], None)], &pki);
    let (app, first_task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut first = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig));
    round_trip(&mut first).await;
    rig.validation.install(None, Some(world.revoking(&pki)));
    let (app, second_task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut second = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    expect_real(&shown, &rig);
    round_trip(&mut second).await;
    tokio::time::timeout(Duration::from_secs(10), first_task).await.expect("the open flow closed").unwrap();
    let mut rest = Vec::new();
    let _ = first.read_to_end(&mut rest).await;
    assert!(rest.is_empty());
    drop(second);
    second_task.await.unwrap();
    assert_eq!(rig.reasons(), ["floor:upstream-revoked"]);
    assert_eq!(count(&rig.deps.meters.https.crlite_revoked), 1);
});

// The cached Revoked skips the handshake from here on, so the connection that
// found it is the only one that can close the flows already open.
arms!(crlite_revoked_on_a_certificate_request_closes_open_flows_to_that_host, |arm| async move {
    let (pki, clients, world) = (Pki::new("Test Public Root"), Pki::new("Clients"), World::new());
    let (rig, _) = ct_rig(arm, vec![server_tls(world.compliant(&pki), &[], None), cert_server_with(world.compliant(&pki), &clients, false)], &pki);
    let (app, first_task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut first = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig));
    round_trip(&mut first).await;
    rig.validation.install(None, Some(world.revoking(&pki)));
    let (app, second_task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut second = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    expect_real(&shown, &rig);
    round_trip(&mut second).await;
    tokio::time::timeout(Duration::from_secs(10), first_task).await.expect("the open flow closed").unwrap();
    let mut rest = Vec::new();
    let _ = first.read_to_end(&mut rest).await;
    assert!(rest.is_empty());
    drop(second);
    second_task.await.unwrap();
    assert_eq!(rig.reasons(), ["floor:upstream-revoked"]);
    assert_eq!(rig.deps.verdicts.get(HOST, 443, wall_ms()).unwrap().verdict, UpstreamVerdict::Revoked);
    assert_eq!(count(&rig.deps.meters.https.crlite_revoked), 1);
});

arms!(crlite_revocation_arriving_later_reaches_a_known_leaf, |arm| async move {
    let (pki, world) = (Pki::new("Test Public Root"), World::new());
    let (rig, _) = ct_rig(arm, vec![server_tls(world.compliant(&pki), &[], None)], &pki);
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig));
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.trust.calls.load(Ordering::Relaxed), 1);
    // The update cycle leaves a file; the hourly wake reloads it.
    let dir = tempfile::tempdir().unwrap();
    let path = data_path(dir.path(), &Kind::List(KIND_CRLITE.into())).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, encode_bundle(&[world.filter(&pki)]).unwrap()).unwrap();
    rig.validation.reload(dir.path()).await;
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    expect_real(&shown, &rig);
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.trust.calls.load(Ordering::Relaxed), 1, "no second trust call: the local check said it");
    assert_eq!(rig.reasons(), ["floor:upstream-revoked"]);
});

arms!(ct_violation_is_cached_and_skips_the_next_handshake, |arm| async move {
    let (pki, world) = (Pki::new("Test Public Root"), World::new());
    let (rig, shaken) = ct_rig(arm, vec![server_tls_no_tickets(world.violating(&pki))], &pki);
    rig.validation.install(Some(world.list(0)), None);
    for round in 0..2 {
        let (app, task) = rig.flow(flow_opts()).await;
        let (client, shown) = client_tls(&[], None);
        let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
        expect_real(&shown, &rig);
        round_trip(&mut tls).await;
        drop(tls);
        task.await.unwrap();
        assert_eq!(rig.deps.verdicts.get(HOST, 443, wall_ms()).unwrap().verdict, UpstreamVerdict::NoTransparency, "round {round}");
    }
    assert_eq!(shaken.load(Ordering::Relaxed), 3, "ours once, the client's own twice");
    assert_eq!(rig.deps.connector.count(), 3, "the cached round used its SYN-time socket");
    assert_eq!(count(&rig.deps.meters.https.ct_violating), 1);
    assert_eq!(rig.reasons(), ["floor:upstream-ct", "floor:upstream-ct"]);
});

fn config_rig(arm: Arm, configs: Vec<Arc<rustls::ServerConfig>>, pki: &Pki, lookup: Arc<FakeLookup>) -> (Rig, Arc<AtomicUsize>) {
    let (dial, shaken) = echo_dial(arm, configs);
    (Rig::new(dial, RigOpts { ech: lookup, ..RigOpts::new(pki.roots()) }), shaken)
}

arms!(forwarded_flow_runs_no_validation_and_no_ech_lookup, |arm| async move {
    let (pki, world) = (Pki::new("Test Public Root"), World::new());
    let lookup = FakeLookup::with_config(config_list(PUBLIC_NAME));
    let (rig, _) = config_rig(arm, vec![server_tls(world.violating(&pki), &[], None)], &pki, lookup.clone());
    rig.validation.install(Some(world.list(0)), None);
    let (app, task) = rig.flow(super::tests::FlowOpts { may_decrypt: false, ..flow_opts() }).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    expect_real(&shown, &rig);
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(lookup.calls(), 0);
    assert_eq!(count(&rig.deps.meters.https.ct_violating) + count(&rig.deps.meters.https.ct_compliant), 0);
    assert_eq!(rig.reasons(), ["floor:forwarded"]);
});

arms!(pass_through_by_floor_runs_no_ech_lookup, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let lookup = FakeLookup::with_config(config_list(PUBLIC_NAME));
    let (rig, _) = config_rig(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)], &pki, lookup.clone());
    let (app, task) = rig.flow(super::tests::FlowOpts { session: Some(0), ..flow_opts() }).await;
    let (client, _) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(lookup.calls(), 0);
    assert_eq!(rig.reasons(), ["floor:service"]);
});

// ---- ECH.

/// The first hello of a handshake with this config, as a recording stream saw it.
async fn hello_with(ech: Option<EchConfig>) -> (Hello, Vec<u8>) {
    let (near, mut far) = tokio::io::duplex(1 << 16);
    let shaking = tokio::spawn(handshake(near, HOST, vec![b"h2".to_vec()], ech));
    let mut seen = Vec::new();
    let mut buffer = [0u8; 4096];
    let hello = loop {
        let n = far.read(&mut buffer).await.unwrap();
        seen.extend_from_slice(&buffer[..n]);
        match parse_tls_stream(&seen) {
            Progress::Done(hello) => break hello,
            Progress::NeedMore => {}
            _ => panic!("not a hello"),
        }
    };
    shaking.abort();
    (hello, seen)
}

fn holds(bytes: &[u8], needle: &str) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
}

fn sni_on(bytes: &[u8]) -> Option<String> {
    match parse_tls_stream(bytes) {
        Progress::Done(hello) => hello.sni,
        _ => None,
    }
}

#[tokio::test]
async fn ech_hello_hides_the_real_name() {
    let (hello, seen) = hello_with(usable_config(&config_list(PUBLIC_NAME))).await;
    assert_eq!(hello.sni.as_deref(), Some(PUBLIC_NAME));
    assert!(hello.ech);
    assert!(!holds(&seen, HOST), "the real name appears nowhere in the hello");
    // The control: the same recording with no config shows it.
    let (_, plain) = hello_with(None).await;
    assert!(holds(&plain, HOST));
}

#[tokio::test]
async fn no_config_offers_no_ech() {
    let (hello, _) = hello_with(None).await;
    assert!(!hello.ech, "no GREASE");
    assert_eq!(hello.sni.as_deref(), Some(HOST));
}

#[tokio::test]
async fn ech_changes_nothing_about_the_key_exchange_order() {
    let (with_ech, _) = hello_with(usable_config(&config_list(PUBLIC_NAME))).await;
    let (without, _) = hello_with(None).await;
    assert_eq!(with_ech.offer.groups.first(), Some(&X25519MLKEM768));
    assert_eq!(with_ech.offer.groups, without.offer.groups);
}

/// A rustls server ignoring the extension (task F8), for the public name on the
/// first socket and the real one after.
fn rejecting(arm: Arm, pki: &Pki, lookup: Arc<FakeLookup>) -> (Rig, Arc<AtomicUsize>) {
    let public = server_tls_no_tickets(pki.leaf(PUBLIC_NAME, GOOD));
    let real = server_tls(pki.leaf(HOST, GOOD), &[], None);
    config_rig(arm, vec![public, real], pki, lookup)
}

arms!(rejected_ech_retries_plain_on_a_fresh_socket_and_intercepts, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let lookup = FakeLookup::with_config(config_list(PUBLIC_NAME));
    let (rig, _) = rejecting(arm, &pki, lookup);
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig), "intercepted after the retry");
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.deps.connector.count(), 2);
    assert_eq!(sni_on(&rig.deps.connector.seen(0)).as_deref(), Some(PUBLIC_NAME));
    assert!(!holds(&rig.deps.connector.seen(0), HOST), "the first connection never named the host");
    assert_eq!(sni_on(&rig.deps.connector.seen(1)).as_deref(), Some(HOST), "the second gets the real name");
    assert_eq!(rig.deps.verdicts.get(HOST, 443, wall_ms()).unwrap().verdict, UpstreamVerdict::Eligible, "not Protocol");
    assert_eq!(rig.trust.calls.load(Ordering::Relaxed), 1, "the public name's chain was not judged");
    let https = &rig.deps.meters.https;
    assert_eq!((count(&https.ech_offered), count(&https.ech_failed), count(&https.ech_accepted)), (1, 1, 0));
    assert!(rig.reasons().is_empty());
});

arms!(rejected_ech_caches_no_verdict_and_marks_the_host_negative, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let lookup = FakeLookup::with_config(config_list(PUBLIC_NAME));
    let real = pki.leaf(HOST, GOOD);
    let real_hash = leaf_facts(&real.0[0]).unwrap().hash;
    let public = server_tls_no_tickets(pki.leaf(PUBLIC_NAME, GOOD));
    let (rig, _) = config_rig(arm, vec![public, server_tls(real, &[], None)], &pki, lookup.clone());
    for _ in 0..2 {
        let (app, task) = rig.flow(flow_opts()).await;
        let (client, _) = client_tls(&[], None);
        let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
        round_trip(&mut tls).await;
        drop(tls);
        task.await.unwrap();
    }
    let cached = rig.deps.verdicts.get(HOST, 443, wall_ms()).unwrap();
    assert_eq!((cached.verdict, cached.leaf), (UpstreamVerdict::Eligible, Some(real_hash)), "only the real host's verdict");
    assert_eq!(lookup.calls(), 1, "the host is remembered negative");
    assert_eq!(count(&rig.deps.meters.https.ech_offered), 1, "no second offer");
});

/// The first socket does `first`; the rest answer TLS for the real name.
async fn ech_failure_retries(arm: Arm, hangs: bool) {
    let pki = Pki::new("Test Public Root");
    let real = tls_server(vec![server_tls(pki.leaf(HOST, GOOD), &[], None)], Arc::default(), |_, tls| echo(tls));
    let handler = raw(move |conn, mut stream| {
        let real = real.clone();
        async move {
            if conn > 0 {
                return real(conn, stream).await;
            }
            let mut first = [0u8; 16];
            let _ = stream.read(&mut first).await;
            if hangs {
                tokio::time::sleep(ECH_HANDSHAKE_TIMEOUT * 2).await;
            }
        }
    });
    let lookup = FakeLookup::with_config(config_list(PUBLIC_NAME));
    let rig = Rig::new(TestDial::new(arm, handler), RigOpts { ech: lookup, ..RigOpts::new(pki.roots()) });
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig));
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.deps.connector.count(), 2);
    assert_eq!(count(&rig.deps.meters.https.ech_failed), 1);
}

arms!(ech_reset_and_ech_timeout_retry_plain, |arm| async move {
    ech_failure_retries(arm, false).await;
    ech_failure_retries(arm, true).await;
});

arms!(failed_retry_dial_closes_the_app_side_and_the_book_says_failed, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let lookup = FakeLookup::with_config(config_list(PUBLIC_NAME));
    let (rig, _) = rejecting(arm, &pki, lookup);
    rig.deps.connector.allow.store(1, Ordering::Relaxed);
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, _) = client_tls(&[], None);
    assert!(connect(app, client, HOST).await.is_err(), "the app side closed");
    assert_eq!(task.await.unwrap().action, FlowAction::Failed);
    assert_eq!(rig.reasons(), ["floor:upstream-unavailable"]);
    assert!(rig.deps.verdicts.get(HOST, 443, wall_ms()).is_none(), "Unavailable is not cached");
});

arms!(a_config_rustls_cannot_use_goes_on_without_ech, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let junk = FakeLookup::says(Ok(vec![HttpsRecord { priority: 1, ech: Some(vec![0, 3, 1, 2, 3]), ttl: 300 }]), Duration::ZERO);
    let (rig, _) = config_rig(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)], &pki, junk.clone());
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig));
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(junk.calls(), 1);
    assert_eq!(count(&rig.deps.meters.https.ech_offered), 0);
    assert_eq!(rig.deps.connector.count(), 1);
});

/// A handshake ending other than `Done` under ECH says nothing about the server.
#[tokio::test]
async fn an_ech_handshake_that_ends_early_is_an_ech_failure() {
    let (near, far) = tokio::io::duplex(1 << 16);
    drop(far);
    assert!(matches!(handshake(near, HOST, Vec::new(), usable_config(&config_list(PUBLIC_NAME))).await, HandshakeEnd::EchFailed));
    let (near, far) = tokio::io::duplex(1 << 16);
    drop(far);
    assert!(matches!(handshake(near, HOST, Vec::new(), None).await, HandshakeEnd::Failed(UpstreamVerdict::Unavailable)), "without ECH, as slice 6");
}

// ---- Live checks: docs/live/engine-slice-11.md. Never run offline. Decryption is
// for browsers (`exclusions::SCOPE`), so the test process cannot be the client:
// each reads status.json's counts around a browser step the person performs.

/// How long each wait of a live check lasts: long enough for a person to act and
/// for several rewrites of status.json, so a correct run cannot miss one.
const LIVE_WAIT: Duration = Duration::from_millis(4 * crate::control::STATUS_FILE_EVERY_MS);
/// Looks per wait.
const POLLS: u32 = 100;

fn status_count(path: &Path, meter: &str) -> Option<u64> {
    let status: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    status["https"][meter].as_u64()
}

fn poll_for<T>(wait: Duration, mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + wait;
    loop {
        if let Some(found) = probe() {
            return Some(found);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(wait / POLLS);
    }
}

/// A count before and after `browser_step`. The first is read from a rewrite that
/// came after this began, so what happened before the step is not taken for growth.
fn count_around(path: &Path, meter: &str, wait: Duration, browser_step: impl FnOnce()) -> Result<(u64, u64), String> {
    let modified = || std::fs::metadata(path).and_then(|m| m.modified()).ok();
    let written = modified();
    let before = poll_for(wait, || modified().filter(|m| Some(*m) != written).and_then(|_| status_count(path, meter))).ok_or_else(|| format!("{} was not rewritten with {meter}: is the engine running?", path.display()))?;
    browser_step();
    let after = poll_for(wait, || status_count(path, meter).filter(|n| *n > before)).ok_or_else(|| format!("{meter} stayed at {before}"))?;
    Ok((before, after))
}

fn live_count_grows(meter: &str) {
    let host = std::env::var("SIEVE_LIVE_HOST").expect("SIEVE_LIVE_HOST names the host (docs/live/engine-slice-11.md)");
    let path = std::env::var("SIEVE_LIVE_STATUS").expect("SIEVE_LIVE_STATUS names status.json (docs/live/engine-slice-11.md)");
    println!("Waiting for a fresh status.json, up to {LIVE_WAIT:?}.");
    let step = || println!("Now load {host} in a browser, and nothing else, within {LIVE_WAIT:?}.");
    let (before, after) = count_around(Path::new(&path), meter, LIVE_WAIT, step).unwrap_or_else(|why| panic!("{why}"));
    println!("{meter} grew from {before} to {after}");
}

#[test]
fn the_live_reader_passes_only_on_growth_after_a_rewrite() {
    const METER: &str = "ct_violating";
    const SHORT: Duration = Duration::from_millis(300);
    const LONG: Duration = Duration::from_secs(60);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    let write = |n: u64| {
        let _ = std::fs::write(&path, serde_json::json!({ "https": { (METER): n } }).to_string());
    };
    write(3);
    let stepped = AtomicBool::new(false);
    let unwritten = count_around(&path, METER, SHORT, || stepped.store(true, Ordering::Relaxed));
    assert!(unwritten.is_err(), "nothing rewrote it");
    assert!(!stepped.load(Ordering::Relaxed), "no step without a fresh count");

    let (value, stop) = (AtomicU64::new(3), AtomicBool::new(false));
    let (flat, grew) = std::thread::scope(|scope| {
        scope.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                write(value.load(Ordering::Relaxed));
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let flat = count_around(&path, METER, SHORT, || {});
        let grew = count_around(&path, METER, LONG, || value.store(4, Ordering::Relaxed));
        stop.store(true, Ordering::Relaxed);
        (flat, grew)
    });
    assert!(flat.is_err(), "a count that did not grow fails the check");
    assert_eq!(grew, Ok((3, 4)));
}

#[test]
#[ignore = "live: docs/live/engine-slice-11.md U1"]
fn live_ct_violating_endpoint_passes_through() {
    live_count_grows("ct_violating");
}

#[test]
#[ignore = "live: docs/live/engine-slice-11.md U2"]
fn live_crlite_revoked_passes_through() {
    live_count_grows("crlite_revoked");
}

#[test]
#[ignore = "live: docs/live/engine-slice-11.md U3"]
fn live_upstream_ech_used() {
    live_count_grows("ech_accepted");
}
