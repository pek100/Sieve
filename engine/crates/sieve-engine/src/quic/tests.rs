//! Slice 8's offline acceptance. The base flow is a browser in session 1, in
//! scope, on `h3`, with a real root, an empty store and no cached verdict: it is
//! refused, which keeps every "relayed" row from being vacuous. No test opens a
//! raw socket and no real ICMP is sent: packets end at [`FakeSink`].

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use etherparse::PacketBuilder;
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use sieve_filter::exclusions::{AutoReason, Decrypt, FlowFacts, Transport, UpstreamVerdict, decrypt};
use sieve_ipc::{FlowAction, LogOutcome};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use super::fallback::QuicMeters;
use super::icmp::tests::assert_answers;
use super::{PacketSink, QUIC_REFUSED, REFUSAL, Refusal, Reply, UdpPath, close_refused, path, refuse};
use crate::exclusions::AutoEntry;
use crate::exclusions::lists::{Origin, Source};
use crate::flow::classify::{Decoded, Kind, UdpClassifier};
use crate::flow::flows::Action;
use crate::flow::quic::{MIN_INITIAL_DATAGRAM, VERSION_1, crypto_frame, seal_client_initial};
use crate::flow::sni::{TlsOffer, build};
use crate::policy::wall_ms;
use crate::tls::intercept::{HttpsSlot, Who};
use crate::tls::tests::{Arm, BROWSER, BROWSER_KEY, CHROME, HOST, Pki, Rig, RigOpts, TestDial, echo, flow_opts, raw, turn_off};

const REMOTE: &str = "192.0.2.1:443";
const CURL: &str = r"C:\Tools\curl.exe";
const LOCAL: &str = "198.18.0.2:50000";
const IDLE: Duration = Duration::from_secs(30);
const BUF: usize = 65_535;
const DAY_MS: u64 = 86_400_000;
const DCID: [u8; 8] = [9; 8];
/// TLS 1.3, its first suite, X25519, ECDSA P-256: what a browser's QUIC hello always offers.
const TLS13: u16 = 0x0304;
const AES128_GCM_SHA256: u16 = 0x1301;
const X25519: u16 = 0x001d;
const ECDSA_P256: u16 = 0x0403;

fn good_offer() -> TlsOffer {
    TlsOffer { versions: vec![TLS13], suites: vec![AES128_GCM_SHA256], groups: vec![X25519], schemes: vec![ECDSA_P256] }
}

fn h3(host: &str) -> Decoded {
    Decoded { kind: Some(Kind::Quic), domain: Some(host.into()), alpn: vec!["h3".into()], ech: false, failure: None, offer: good_offer() }
}

/// One flow's facts: the base flow until a row changes them.
#[derive(Clone)]
struct Case {
    remote: SocketAddr,
    exe: Option<&'static str>,
    session: Option<u32>,
    may_decrypt: bool,
    app_off: bool,
    decoded: Decoded,
}

impl Case {
    fn base() -> Self {
        Self { remote: REMOTE.parse().unwrap(), exe: Some(CHROME), session: Some(1), may_decrypt: true, app_off: false, decoded: h3(HOST) }
    }

    fn who(&self) -> Who<'static> {
        Who { remote: self.remote, exe: self.exe, session: self.session, may_decrypt: self.may_decrypt, app_off: self.app_off, names_now_ms: 0 }
    }
}

fn dial() -> TestDial {
    TestDial::new(Arm::Duplex, raw(|_, stream| echo(stream)))
}

fn rig_with(edit: impl FnOnce(&mut RigOpts)) -> Rig {
    let mut opts = RigOpts::new(Pki::new("Test Public Root").roots());
    edit(&mut opts);
    Rig::new(dial(), opts)
}

fn rig() -> Rig {
    rig_with(|_| {})
}

fn slot_of(rig: &Rig) -> HttpsSlot<TestDial> {
    let slot = HttpsSlot::default();
    slot.set(Some(rig.deps.clone()));
    slot
}

/// The path of `case` on `rig`, and the reasons logged for it.
fn judged(rig: &Rig, case: &Case) -> (UdpPath, Vec<String>) {
    let id = rig.open_flow();
    let answer = path(Action::Pass, &slot_of(rig), &case.decoded, &case.who(), id);
    (answer, rig.reasons())
}

fn auto(rig: &Rig, reason: AutoReason) {
    let now = wall_ms();
    rig.deps.exclusions.add_auto(AutoEntry::host(HOST, reason, now, Some(now + DAY_MS)), now);
}

const fn seeded(id: &'static str, seed: &'static str) -> Source {
    Source { id, origin: Origin::Seed(seed), enabled: true }
}

// ---- Refused exactly when `decrypt` says Intercept.

#[test]
fn the_base_flow_is_refused() {
    let rig = rig();
    assert_eq!(judged(&rig, &Case::base()), (UdpPath::Refuse(REFUSAL), vec![QUIC_REFUSED.to_string()]));
    assert_eq!(rig.deps.meters.https.passed.load(Ordering::Relaxed), 0, "a refusal is not a pass-through");
    assert_eq!(rig.deps.connector.count(), 0, "nothing was dialled");
}

#[test]
fn relayed_table() {
    fn no_change(_: &mut RigOpts) {}
    fn no_prep(_: &Rig) {}
    type Row = (&'static str, fn(&mut RigOpts), fn(&Rig), fn(&mut Case));
    const LISTED: &str = "listed.example\n";
    let rows: [Row; 18] = [
        ("app_off", no_change, no_prep, |c| c.app_off = true),
        ("user", no_change, |r| r.deps.exclusions.set_user(&[HOST.to_string()], wall_ms()), |_| {}),
        ("list:sensitive", |o| o.sources = vec![seeded("sensitive", LISTED)], no_prep, |c| c.decoded = h3("www.listed.example")),
        ("auto:pinning", no_change, |r| auto(r, AutoReason::Pinning), |_| {}),
        ("auto:client-cert", no_change, |r| auto(r, AutoReason::ClientCert), |_| {}),
        ("auto:ev", no_change, |r| auto(r, AutoReason::Ev), |_| {}),
        ("floor:alpn", no_change, no_prep, |c| c.decoded.alpn = vec!["h2".into()]),
        ("floor:alpn", no_change, no_prep, |c| c.decoded.alpn = vec!["doq".into()]),
        ("floor:alpn", no_change, no_prep, |c| c.decoded.alpn = Vec::new()),
        ("floor:ech", no_change, no_prep, |c| c.decoded.ech = true),
        ("floor:service", no_change, no_prep, |c| c.session = Some(0)),
        ("floor:forwarded", no_change, no_prep, |c| c.may_decrypt = false),
        ("floor:unknown-app", no_change, no_prep, |c| c.exe = None),
        ("floor:unknown-app", no_change, no_prep, |c| c.session = None),
        ("floor:app-scope", no_change, no_prep, |c| c.exe = Some(CURL)),
        ("floor:restricted-suffix", no_change, no_prep, |c| c.decoded = h3("agency.gov")),
        ("floor:no-root", |o| o.minter = false, no_prep, |_| {}),
        ("floor:no-exclusion-list", |o| o.sources = vec![Source { id: "hx-banks", origin: Origin::Fetched("banks.txt"), enabled: true }], no_prep, |_| {}),
    ];
    for (slug, opts, prepare, change) in rows {
        let rig = rig_with(opts);
        prepare(&rig);
        let mut case = Case::base();
        change(&mut case);
        assert_eq!(judged(&rig, &case), (UdpPath::Relay, vec![slug.to_string()]), "{slug}");
        assert_eq!(rig.deps.meters.https.passed.load(Ordering::Relaxed), 1, "{slug}: the one counter of a pass-through");
    }
}

#[test]
fn refused_iff_decrypt_intercepts() {
    const HOSTS: [Option<&str>; 5] = [Some(HOST), Some("excluded.example"), Some("pinned.example"), Some("agency.gov"), None];
    const ALPNS: [&[&str]; 4] = [&["h3"], &["h3", "h3-29"], &["h2"], &[]];
    const EXES: [Option<&str>; 3] = [Some(CHROME), Some(CURL), None];
    const SESSIONS: [Option<u32>; 3] = [Some(1), Some(0), None];
    const VERDICTS: [Option<UpstreamVerdict>; 7] = [None, Some(UpstreamVerdict::Eligible), Some(UpstreamVerdict::NonPublicRoot), Some(UpstreamVerdict::Invalid), Some(UpstreamVerdict::Revoked), Some(UpstreamVerdict::Unavailable), Some(UpstreamVerdict::Protocol)];
    // (rig, root ready): the switches a slot can read.
    let rigs = [(rig(), true), (rig_with(|o| o.minter = false), false), (rig_with(|o| o.sources = vec![Source { id: "hx-banks", origin: Origin::Fetched("banks.txt"), enabled: true }]), true), (rig(), true)];
    rigs[3].0.deps.active.close_all();
    for (rig, _) in &rigs {
        let now = wall_ms();
        rig.deps.exclusions.add_auto(AutoEntry::host("pinned.example", AutoReason::Pinning, now, None), now);
    }
    let ids: Vec<u64> = rigs.iter().map(|(rig, _)| rig.open_flow()).collect();
    let slots: Vec<HttpsSlot<TestDial>> = rigs.iter().map(|(rig, _)| slot_of(rig)).collect();
    let (refused, relayed) = (AtomicUsize::new(0), AtomicUsize::new(0));
    // A port per case: a revocation in the cache stands against a later verdict.
    let next_port = AtomicUsize::new(1_000);

    // Weighted to the base flow: uniform choices almost never reach `Intercept`.
    let index = |n: usize| prop_oneof![4 => Just(0usize), 1 => 0..n];
    let strategy = (
        (index(rigs.len()), index(HOSTS.len()), index(ALPNS.len()), index(EXES.len()), index(SESSIONS.len()), index(VERDICTS.len())),
        (prop::bool::weighted(0.1), prop::bool::weighted(0.9), prop::bool::weighted(0.1), prop::bool::weighted(0.9), prop::bool::weighted(0.1)),
    );
    let mut runner = TestRunner::new(Config { cases: 512, failure_persistence: None, ..Config::default() });
    runner
        .run(&strategy, |((which, host, alpn, exe, session, verdict), (ech, may_decrypt, app_off, compatible, excluded))| {
            let (rig, root_ready) = &rigs[which];
            let deps = &rig.deps;
            let now = wall_ms();
            let lines = if excluded { vec!["excluded.example".to_string()] } else { Vec::new() };
            deps.exclusions.set_user(&lines, now);
            let port = u16::try_from(next_port.fetch_add(1, Ordering::Relaxed)).unwrap();
            if let (Some(h), Some(v)) = (HOSTS[host], VERDICTS[verdict]) {
                deps.verdicts.put(h, port, v, None, None, now);
            }
            let alpn: Vec<String> = ALPNS[alpn].iter().map(ToString::to_string).collect();
            let decoded = Decoded { kind: Some(Kind::Quic), domain: HOSTS[host].map(str::to_string), alpn: alpn.clone(), ech, failure: None, offer: if compatible { good_offer() } else { TlsOffer::default() } };
            let remote = SocketAddr::new(REMOTE.parse::<SocketAddr>().unwrap().ip(), port);
            let who = Who { remote, exe: EXES[exe], session: SESSIONS[session], may_decrypt, app_off, names_now_ms: 0 };

            // The same inputs, written out by hand, to the one function.
            let upstream = match (HOSTS[host], VERDICTS[verdict]) {
                // `Eligible` does not stand in for a handshake, `Unavailable` is never cached.
                (Some(_), Some(v)) if v != UpstreamVerdict::Eligible && v != UpstreamVerdict::Unavailable => Some(v),
                _ => None,
            };
            let facts = FlowFacts {
                transport: Transport::Quic,
                may_decrypt,
                exe: EXES[exe],
                session: SESSIONS[session],
                host: HOSTS[host],
                ip: remote.ip(),
                port,
                alpn: &alpn,
                ech,
                client_compatible: compatible,
                app_in_scope: EXES[exe] == Some(CHROME),
                app_off,
                upstream,
            };
            let store = deps.exclusions.get_at(now);
            let switches = deps.exclusions.switches(!deps.active.is_closed(), *root_ready);
            let intercept = decrypt(&facts, &store, &switches) == Decrypt::Intercept;

            let answer = path(Action::Pass, &slots[which], &decoded, &who, ids[which]);
            prop_assert_eq!(matches!(answer, UdpPath::Refuse(_)), intercept);
            prop_assert_eq!(answer == UdpPath::Relay, !intercept);
            (if intercept { &refused } else { &relayed }).fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();
    // The law could not fail on one side alone.
    assert!(refused.load(Ordering::Relaxed) > 0, "nothing was refused");
    assert!(relayed.load(Ordering::Relaxed) > 0, "nothing was relayed");
}

#[test]
fn a_grease_ech_with_a_resolved_name_is_refused() {
    let rig = rig();
    let mut case = Case::base();
    case.decoded.ech = true;
    assert_eq!(judged(&rig, &case), (UdpPath::Relay, vec!["floor:ech".to_string()]), "unresolved: a real ECH cannot be ruled out");
    rig.deps.names.lock().unwrap().record(HOST, case.remote.ip(), 300, 0);
    assert_eq!(judged(&rig, &case).0, UdpPath::Refuse(REFUSAL), "the engine's DNS answered it: the extension is GREASE");
}

#[test]
fn a_cached_rejection_relays_and_a_cached_eligible_refuses() {
    let rig = rig();
    let case = Case::base();
    let now = wall_ms();
    rig.deps.verdicts.put(HOST, case.remote.port(), UpstreamVerdict::Eligible, None, None, now);
    assert_eq!(judged(&rig, &case).0, UdpPath::Refuse(REFUSAL));
    rig.deps.verdicts.put(HOST, case.remote.port(), UpstreamVerdict::NonPublicRoot, None, None, now);
    assert_eq!(judged(&rig, &case), (UdpPath::Relay, vec!["floor:non-public-root".to_string()]));
}

/// A TCP hello the first look takes, offering what a browser does over TCP.
fn tcp_hello() -> Vec<u8> {
    let groups = (0x000a_u16, vec![0, 2, 0, 0x1d]);
    let versions = (0x002b_u16, vec![2, 3, 4]);
    let schemes = (0x000d_u16, vec![0, 2, 4, 3]);
    build::records(&build::handshake(&[build::sni_ext(HOST), build::alpn_ext(&["h2"]), groups, versions, schemes]), 1 << 14)
}

/// Each verdict through the real TCP path: a first look that passes uses the
/// SYN-time socket alone; one that goes on to the upstream fails against the
/// echo peer and dials a fresh socket (two dials).
#[tokio::test]
async fn tcp_and_quic_agree_on_every_verdict() {
    use UpstreamVerdict::{Eligible, Invalid, NonPublicRoot, Protocol, Revoked, Unavailable};
    let case = Case::base();
    for verdict in [Eligible, NonPublicRoot, Invalid, Revoked, Unavailable, Protocol] {
        let rig = rig();
        rig.deps.verdicts.put(HOST, case.remote.port(), verdict, None, None, wall_ms());
        // QUIC first: TCP's handshake against the echo peer writes its own verdict.
        let (quic, reasons) = judged(&rig, &case);
        let (mut app, task) = rig.flow(flow_opts()).await;
        app.write_all(&tcp_hello()).await.unwrap();
        let settled = async {
            while rig.deps.connector.count() < 2 && rig.deps.meters.https.passed.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(20), settled).await.expect("the first look ended");
        drop(app);
        let _ = tokio::time::timeout(Duration::from_secs(20), task).await;
        let tcp = rig.reasons();
        let tcp_went_on = rig.deps.connector.count() == 2;
        assert_eq!(quic == UdpPath::Refuse(REFUSAL), tcp_went_on, "{verdict:?}: TCP's reasons {tcp:?}");
        if !tcp_went_on {
            assert_eq!(reasons, tcp, "{verdict:?}: the same reason");
        }
    }
}

#[test]
fn the_quic_port_is_not_special() {
    let rig = rig();
    let mut case = Case::base();
    case.remote = "192.0.2.1:8443".parse().unwrap();
    assert_eq!(judged(&rig, &case).0, UdpPath::Refuse(REFUSAL), "h3 on 8443: ALPN decides, not a port list");
    rig.deps.exclusions.set_user(&[HOST.to_string()], wall_ms());
    assert_eq!(judged(&rig, &Case::base()), (UdpPath::Relay, vec!["user".to_string()]), "h3 on 443, excluded");
}

// ---- Never wholesale.

static CLOCK_CALLS: AtomicUsize = AtomicUsize::new(0);

fn counting_clock() -> u64 {
    CLOCK_CALLS.fetch_add(1, Ordering::Relaxed);
    wall_ms()
}

#[test]
fn no_slot_relays_and_asks_nothing() {
    let rig = rig_with(|o| o.clock = counting_clock);
    let case = Case::base();
    let id = rig.open_flow();
    let empty = HttpsSlot::<TestDial>::default();
    assert_eq!(path(Action::Pass, &empty, &case.decoded, &case.who(), id), UdpPath::Relay);
    assert_eq!(CLOCK_CALLS.load(Ordering::Relaxed), 0, "nothing was asked");
    assert_eq!(rig.reasons(), Vec::<String>::new());
    assert!(!empty.refuses(BROWSER));
    // The control: the same flow with the slot there reads the clock.
    assert_eq!(path(Action::Pass, &slot_of(&rig), &case.decoded, &case.who(), id), UdpPath::Refuse(REFUSAL));
    assert!(CLOCK_CALLS.load(Ordering::Relaxed) > 0);
}

#[test]
fn a_blocked_host_drops_and_is_not_refused() {
    let rig = rig();
    let case = Case::base();
    let id = rig.open_flow();
    assert_eq!(path(Action::Drop, &slot_of(&rig), &case.decoded, &case.who(), id), UdpPath::Drop);
    assert_eq!(rig.reasons(), Vec::<String>::new(), "no row of its own");
    assert_eq!(path(Action::Drop, &HttpsSlot::<TestDial>::default(), &case.decoded, &case.who(), id), UdpPath::Drop, "and off too");
}

fn classified(datagrams: &[Vec<u8>]) -> Decoded {
    let mut classifier = UdpClassifier::new();
    datagrams.iter().find_map(|d| classifier.push(d)).expect("decided")
}

/// Relayed, with `Decoded.kind` not QUIC: no row at all.
fn assert_relayed_silently(decoded: Decoded) {
    let rig = rig();
    let mut case = Case::base();
    case.decoded = decoded;
    assert_eq!(judged(&rig, &case), (UdpPath::Relay, Vec::new()));
    assert_eq!(rig.deps.meters.https.passed.load(Ordering::Relaxed), 0);
}

#[test]
fn not_quic_on_443_is_relayed_and_logs_nothing() {
    let decoded = classified(&[b"\x00\x01 not quic, some game's protocol".to_vec()]);
    assert_eq!(decoded.kind, None);
    assert_relayed_silently(decoded);
}

#[test]
fn an_unknown_version_is_relayed() {
    let mut datagram = seal_client_initial(VERSION_1, &DCID, &[], 0, 1, &[0; 1100]);
    datagram[1..5].copy_from_slice(&0x5a5a_5a5a_u32.to_be_bytes());
    let decoded = classified(&[datagram]);
    assert_eq!(decoded.domain, None);
    assert_relayed_silently(decoded);
}

#[test]
fn a_short_header_first_datagram_is_relayed() {
    // A live connection back after idling past `UDP_IDLE`: never refused for it.
    let mut datagram = vec![0x40];
    datagram.extend_from_slice(&[7; 1200]);
    assert_relayed_silently(classified(&[datagram]));
}

#[test]
fn a_cap_or_a_broken_initial_is_relayed() {
    let hello = build::handshake(&[build::sni_ext(HOST), build::alpn_ext(&["h3"]), (0x0033, vec![1; 4000])]);
    // Always the same early part of a hello that never completes.
    let mut frames = crypto_frame(0, &hello[..600]);
    frames.resize(1100, 0);
    let capped: Vec<Vec<u8>> = (0..crate::flow::classify::MAX_UDP_DATAGRAMS).map(|pn| seal_client_initial(VERSION_1, &DCID, &[], pn, 1, &frames)).collect();
    let mut broken = crypto_frame(0, &[0xff; 200]);
    broken.resize(1100, 0);
    for decoded in [classified(&capped), classified(&[seal_client_initial(VERSION_1, &DCID, &[], 0, 1, &broken)])] {
        assert_eq!((decoded.kind, decoded.domain.as_deref()), (Some(Kind::Quic), None), "{decoded:?}");
        let rig = rig();
        let mut case = Case::base();
        case.decoded = decoded;
        assert_eq!(judged(&rig, &case), (UdpPath::Relay, vec!["floor:no-sni".to_string()]));
    }
}

// ---- The flow.

#[derive(Default)]
pub(crate) struct FakeSink {
    pub(crate) sent: Mutex<Vec<Vec<u8>>>,
    fails: AtomicBool,
    pub(crate) tried: AtomicUsize,
}

impl PacketSink for FakeSink {
    fn send(&self, ip_packet: &[u8]) -> std::io::Result<()> {
        self.tried.fetch_add(1, Ordering::Relaxed);
        if self.fails.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("ring full"));
        }
        self.sent.lock().unwrap().push(ip_packet.to_vec());
        Ok(())
    }
}

impl FakeSink {
    pub(crate) fn count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
}

struct FlowRig {
    sink: Arc<FakeSink>,
    meters: Arc<QuicMeters>,
    on: Arc<AtomicBool>,
    app: tokio::io::DuplexStream,
    task: tokio::task::JoinHandle<Vec<Vec<u8>>>,
}

fn spawn_flow(refusal: Refusal, held: Vec<Vec<u8>>) -> FlowRig {
    let (sink, meters, on) = (Arc::new(FakeSink::default()), Arc::new(QuicMeters::default()), Arc::new(AtomicBool::new(true)));
    let (app, mut stack) = tokio::io::duplex(BUF);
    let (s, m, o) = (sink.clone(), meters.clone(), on.clone());
    let task = tokio::spawn(async move {
        let ends = (LOCAL.parse().unwrap(), REMOTE.parse().unwrap());
        let reply = Reply { ends, refusal, sink: &*s, meters: &m };
        let mut buf = vec![0u8; BUF];
        refuse(&mut stack, &reply, held, &mut buf, IDLE, || o.load(Ordering::Relaxed)).await
    });
    FlowRig { sink, meters, on, app, task }
}

/// One write per datagram: the duplex keeps no boundaries, so each is awaited.
async fn send_datagram(flow: &mut FlowRig, datagram: &[u8]) {
    flow.app.write_all(datagram).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1)).await;
}

#[tokio::test(start_paused = true)]
async fn each_held_and_later_datagram_gets_one_reply() {
    let mut flow = spawn_flow(Refusal::PortUnreachable, vec![vec![1; 200], vec![2; 300]]);
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(flow.sink.count(), 2, "one per held datagram");
    send_datagram(&mut flow, &[3; 400]).await;
    send_datagram(&mut flow, &[4; 500]).await;
    let sent = flow.sink.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 4);
    let (local, remote) = (LOCAL.parse().unwrap(), REMOTE.parse().unwrap());
    for (packet, (byte, size)) in sent.iter().zip([(1u8, 200usize), (2, 300), (3, 400), (4, 500)]) {
        let quote = assert_answers(packet, local, remote);
        assert_eq!(usize::from(u16::from_be_bytes([quote[24], quote[25]])), 8 + size, "the quote is of this datagram");
        assert!(quote[28..].iter().all(|b| *b == byte));
    }
    assert_eq!(flow.meters.replies.load(Ordering::Relaxed), 4);
    flow.task.abort();
}

#[tokio::test(start_paused = true)]
async fn silent_drop_replies_nothing_and_still_swallows() {
    let mut flow = spawn_flow(Refusal::SilentDrop, vec![vec![1; 200]]);
    send_datagram(&mut flow, &[2; 200]).await;
    assert_eq!(flow.sink.tried.load(Ordering::Relaxed), 0);
    assert_eq!(flow.meters.replies.load(Ordering::Relaxed), 0);
    assert!(!flow.task.is_finished(), "the flow is remembered until idle");
    let mut none = [0u8; 8];
    assert!(tokio::time::timeout(Duration::from_millis(1), flow.app.read(&mut none)).await.is_err(), "nothing back");
    flow.task.abort();
}

/// The VN arm answers through the app's stream, never the packet sink: each Initial,
/// held or later, gets its Version Negotiation; any other datagram is swallowed.
#[tokio::test(start_paused = true)]
async fn version_negotiation_answers_each_initial_through_the_stream() {
    const SCID: [u8; 4] = [5; 4];
    let initial = || {
        let mut frames = crypto_frame(0, &[1, 0, 0, 0]);
        frames.resize(MIN_INITIAL_DATAGRAM, 0);
        seal_client_initial(VERSION_1, &DCID, &SCID, 0, 1, &frames)
    };
    let expected = super::negotiate::version_negotiation(&initial()).unwrap();
    let mut flow = spawn_flow(Refusal::VersionNegotiation, vec![initial(), vec![2; 200]]);
    let mut got = vec![0u8; expected.len()];
    flow.app.read_exact(&mut got).await.unwrap();
    assert_eq!(got, expected, "the held Initial is answered");
    send_datagram(&mut flow, &[3; 400]).await;
    let mut none = [0u8; 8];
    assert!(tokio::time::timeout(Duration::from_millis(1), flow.app.read(&mut none)).await.is_err(), "no answer to what is no Initial");
    send_datagram(&mut flow, &initial()).await;
    flow.app.read_exact(&mut got).await.unwrap();
    assert_eq!(got, expected, "a later Initial is answered");
    assert_eq!(flow.sink.tried.load(Ordering::Relaxed), 0, "no ICMP");
    assert_eq!(flow.meters.replies.load(Ordering::Relaxed), 2);
    assert!(!flow.task.is_finished(), "the flow is remembered until idle");
    flow.task.abort();
}

/// Pins today's arm. A build for the live drop arm is expected to fail here, and
/// the runbook says so: a flip cannot land unnoticed.
#[test]
fn the_declared_constant_is_the_version_negotiation_arm() {
    assert_eq!(REFUSAL, Refusal::VersionNegotiation);
}

#[tokio::test(start_paused = true)]
async fn a_refused_flow_ends_when_idle() {
    let flow = spawn_flow(Refusal::PortUnreachable, vec![vec![1; 200]]);
    let started = tokio::time::Instant::now();
    tokio::time::sleep(IDLE - Duration::from_secs(1)).await;
    assert!(!flow.task.is_finished());
    flow.task.await.unwrap();
    assert_eq!(tokio::time::Instant::now() - started, IDLE);
    drop(flow.app);
}

#[tokio::test(start_paused = true)]
async fn a_retransmit_keeps_it_and_is_answered() {
    let mut flow = spawn_flow(Refusal::PortUnreachable, vec![vec![1; 200]]);
    for _ in 0..3 {
        tokio::time::sleep(IDLE - Duration::from_secs(1)).await;
        send_datagram(&mut flow, &[1; 200]).await;
    }
    assert!(!flow.task.is_finished(), "retransmits keep the flow");
    assert_eq!(flow.sink.count(), 4);
    let last = tokio::time::Instant::now();
    flow.task.await.unwrap();
    assert!(tokio::time::Instant::now() - last <= IDLE);
    drop(flow.app);
}

#[tokio::test(start_paused = true)]
async fn an_app_turned_off_ends_its_refused_flow_and_no_other() {
    let rig = rig();
    let slot = Arc::new(slot_of(&rig));
    let (sink, meters) = (FakeSink::default(), QuicMeters::default());
    let (mut app, mut stack) = tokio::io::duplex(BUF);
    let ends = (LOCAL.parse().unwrap(), REMOTE.parse().unwrap());
    let reply = Reply { ends, refusal: Refusal::PortUnreachable, sink: &sink, meters: &meters };
    let held = vec![vec![1u8; 200]];
    let mut buf = vec![0u8; BUF];
    let on = slot.clone();
    let flow = refuse(&mut stack, &reply, held, &mut buf, IDLE, move || on.refuses(BROWSER));
    tokio::pin!(flow);
    tokio::select! {
        _ = &mut flow => panic!("not Off: the flow goes on"),
        () = tokio::time::sleep(Duration::from_millis(1)) => {}
    }
    assert_eq!(sink.count(), 1);
    turn_off(&rig, BROWSER_KEY);
    assert!(!slot.refuses(BROWSER));
    assert!(slot.refuses(crate::domain::Owner::App { key: "other" }), "another app's flow stays refused");
    assert!(slot.refuses(crate::domain::Owner::Unknown), "and an unattributed one");
    assert!(!rig.deps.active.is_closed(), "the switch itself stayed on");
    app.write_all(&[2; 200]).await.unwrap();
    let started = tokio::time::Instant::now();
    assert_eq!(flow.await, [vec![2u8; 200]], "that datagram is the new flow's, not lost");
    assert_eq!(tokio::time::Instant::now(), started, "ended on that datagram, not by idling");
    assert_eq!(sink.count(), 1, "and no reply went");
    // What the new flow is told: relayed, for the reason the log gives.
    let who = Who { remote: REMOTE.parse().unwrap(), exe: Some(CHROME), session: Some(1), may_decrypt: true, app_off: true, names_now_ms: 0 };
    assert_eq!(path(Action::Pass, &slot, &h3(HOST), &who, rig.open_flow()), UdpPath::Relay);
}

#[tokio::test(start_paused = true)]
async fn the_switch_going_off_ends_a_refused_flow() {
    // Through the real slot: emptied, it reads as off for a flow on its way.
    let rig = rig();
    let slot = Arc::new(slot_of(&rig));
    assert!(slot.refuses(BROWSER));
    let (sink, meters) = (FakeSink::default(), QuicMeters::default());
    let (mut app, mut stack) = tokio::io::duplex(BUF);
    let ends = (LOCAL.parse().unwrap(), REMOTE.parse().unwrap());
    let reply = Reply { ends, refusal: Refusal::PortUnreachable, sink: &sink, meters: &meters };
    let held = vec![vec![1u8; 200]];
    let mut buf = vec![0u8; BUF];
    let on = slot.clone();
    let flow = refuse(&mut stack, &reply, held, &mut buf, IDLE, move || on.refuses(BROWSER));
    tokio::pin!(flow);
    tokio::select! {
        _ = &mut flow => panic!("still on: the flow goes on"),
        () = tokio::time::sleep(Duration::from_millis(1)) => {}
    }
    assert_eq!(sink.count(), 1);
    slot.set(None);
    assert!(!slot.refuses(BROWSER));
    assert!(rig.deps.active.is_closed(), "the closed set says so too (F9)");
    app.write_all(&[2; 200]).await.unwrap();
    let started = tokio::time::Instant::now();
    assert_eq!(flow.await, [vec![2u8; 200]], "that datagram is the new flow's, not lost");
    assert_eq!(tokio::time::Instant::now(), started, "ended on that datagram, not by idling");
    assert_eq!(sink.count(), 1, "and no reply went");
}

#[tokio::test(start_paused = true)]
async fn a_switch_off_before_the_held_datagrams_answers_none() {
    let flow = spawn_flow(Refusal::PortUnreachable, vec![vec![1; 200]]);
    flow.on.store(false, Ordering::Relaxed);
    // The task has not run yet: it starts after the switch went off.
    assert_eq!(flow.task.await.unwrap(), [vec![1u8; 200]], "they go on to the new flow");
    assert_eq!(flow.sink.count(), 0);
    drop(flow.app);
}

#[tokio::test]
async fn a_closed_stack_ends_the_flow_at_once() {
    let flow = spawn_flow(Refusal::PortUnreachable, Vec::new());
    drop(flow.app);
    assert!(tokio::time::timeout(Duration::from_secs(5), flow.task).await.expect("ended").unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_failed_send_is_counted_and_the_flow_goes_on() {
    let mut flow = spawn_flow(Refusal::PortUnreachable, Vec::new());
    flow.sink.fails.store(true, Ordering::Relaxed);
    send_datagram(&mut flow, &[1; 200]).await;
    assert_eq!(flow.meters.send_failed.load(Ordering::Relaxed), 1);
    assert_eq!(flow.meters.replies.load(Ordering::Relaxed), 0);
    assert!(!flow.task.is_finished());
    flow.sink.fails.store(false, Ordering::Relaxed);
    send_datagram(&mut flow, &[1; 200]).await;
    assert_eq!(flow.meters.replies.load(Ordering::Relaxed), 1);
    flow.task.abort();
}

// ---- Through a real stack, in memory (the device of `examples/bench.rs`).

pub(crate) struct MemDevice {
    pub(crate) rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pub(crate) tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl AsyncRead for MemDevice {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if let Some(p) = ready!(self.rx.poll_recv(cx)) {
            buf.put_slice(&p);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MemDevice {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let _ = self.tx.send(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// `host`'s `h3` hello, split over two sealed Initials as a post-quantum one is.
pub(crate) fn sealed_initials(host: &str) -> [Vec<u8>; 2] {
    sealed_initials_of(VERSION_1, &DCID, &[], host)
}

/// The same, with the version and connection IDs a test names.
pub(crate) fn sealed_initials_of(version: u32, dcid: &[u8], scid: &[u8], host: &str) -> [Vec<u8>; 2] {
    let groups = (0x000a_u16, vec![0, 2, 0, 0x1d]);
    let versions = (0x002b_u16, vec![2, 3, 4]);
    let schemes = (0x000d_u16, vec![0, 2, 4, 3]);
    let hello = build::handshake(&[build::sni_ext(host), build::alpn_ext(&["h3"]), groups, versions, schemes, (0x0033, vec![1; 1300])]);
    let (first, second) = hello.split_at(800);
    // Padded past the 1200-byte floor, as a real client's are.
    let mut f1 = crypto_frame(0, first);
    f1.resize(MIN_INITIAL_DATAGRAM, 0);
    let mut f2 = crypto_frame(800, second);
    f2.resize(MIN_INITIAL_DATAGRAM, 0);
    [seal_client_initial(version, dcid, scid, 0, 1, &f1), seal_client_initial(version, dcid, scid, 1, 1, &f2)]
}

pub(crate) fn udp_packet(local: SocketAddr, remote: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    match (local, remote) {
        (SocketAddr::V4(l), SocketAddr::V4(r)) => PacketBuilder::ipv4(l.ip().octets(), r.ip().octets(), 64).udp(l.port(), r.port()).write(&mut out, payload).unwrap(),
        (SocketAddr::V6(l), SocketAddr::V6(r)) => PacketBuilder::ipv6(l.ip().octets(), r.ip().octets(), 64).udp(l.port(), r.port()).write(&mut out, payload).unwrap(),
        _ => panic!("one family"),
    }
    out
}

pub(crate) const FLOWS: [(&str, &str); 2] = [(LOCAL, REMOTE), ("[fd00::2]:50000", "[2001:db8::1]:443")];

struct StackRun {
    answer: UdpPath,
    sink: FakeSink,
    from_stack: mpsc::UnboundedReceiver<Vec<u8>>,
}

/// The app's two Initials into a real `IpStack`, through `UdpClassifier`, `path`
/// and, when refused, `refuse` with `arm`, so every arm meets the real stack.
async fn through_the_stack(rig: &Rig, local: SocketAddr, remote: SocketAddr, arm: Refusal) -> StackRun {
    let (to_stack, rx) = mpsc::unbounded_channel();
    let (tx, from_stack) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut config = IpStackConfig::default();
    config.mtu(1500).unwrap();
    let mut stack = IpStack::new(config, MemDevice { rx, tx });
    for initial in sealed_initials(HOST) {
        to_stack.send(udp_packet(local, remote, &initial)).unwrap();
    }
    let Ok(IpStackStream::Udp(mut app)) = stack.accept().await else { panic!("no UDP stream") };
    assert_eq!((app.local_addr(), app.peer_addr()), (local, remote), "the stack's view of the flow");

    let mut classifier = UdpClassifier::new();
    let mut held = Vec::new();
    let mut buf = vec![0u8; BUF];
    let decoded = loop {
        let n = app.read(&mut buf).await.unwrap();
        held.push(buf[..n].to_vec());
        if let Some(d) = classifier.push(&buf[..n]) {
            break d;
        }
    };
    assert_eq!(held.len(), 2, "the hello spans both datagrams");
    assert_eq!((decoded.kind, decoded.domain.as_deref()), (Some(Kind::Quic), Some(HOST)), "{decoded:?}");

    let slot = slot_of(rig);
    let id = rig.open_flow();
    let who = Who { remote, exe: Some(CHROME), session: Some(1), may_decrypt: true, app_off: false, names_now_ms: 0 };
    let answer = path(Action::Pass, &slot, &decoded, &who, id);
    let sink = FakeSink::default();
    if let UdpPath::Refuse(_) = answer {
        let meters = QuicMeters::default();
        let reply = Reply { ends: (app.local_addr(), app.peer_addr()), refusal: arm, sink: &sink, meters: &meters };
        assert!(refuse(&mut app, &reply, held, &mut buf, Duration::from_millis(50), || slot.refuses(BROWSER)).await.is_empty(), "it idled out");
    }
    StackRun { answer, sink, from_stack }
}

#[tokio::test]
async fn a_sealed_initial_through_ipstack_comes_out_as_icmp() {
    for (local, remote) in FLOWS {
        let (local, remote): (SocketAddr, SocketAddr) = (local.parse().unwrap(), remote.parse().unwrap());
        let rig = rig();
        let mut run = through_the_stack(&rig, local, remote, Refusal::PortUnreachable).await;
        assert_eq!(run.answer, UdpPath::Refuse(REFUSAL), "{local}");
        let sent = run.sink.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 2, "one answer per datagram");
        for packet in &sent {
            assert_answers(packet, local, remote);
        }
        assert!(run.from_stack.try_recv().is_err(), "the stack itself wrote nothing back");
        assert_eq!(rig.deps.connector.count(), 0, "nothing went upstream");
    }
}

/// The default arm: each Initial comes back out of the stack as a UDP datagram from
/// the server's address, holding its Version Negotiation packet, and no ICMP is sent.
#[tokio::test]
async fn a_sealed_initial_through_ipstack_is_answered_by_version_negotiation() {
    for (local, remote) in FLOWS {
        let (local, remote): (SocketAddr, SocketAddr) = (local.parse().unwrap(), remote.parse().unwrap());
        let rig = rig();
        let mut run = through_the_stack(&rig, local, remote, Refusal::VersionNegotiation).await;
        assert_eq!(run.answer, UdpPath::Refuse(REFUSAL), "{local}");
        assert_eq!(run.sink.tried.load(Ordering::Relaxed), 0, "no ICMP");
        for initial in sealed_initials(HOST) {
            let packet = run.from_stack.try_recv().expect("one answer per Initial");
            let headers = etherparse::SlicedPacket::from_ip(&packet).unwrap();
            let Some(etherparse::TransportSlice::Udp(udp)) = headers.transport else { panic!("not UDP: {headers:?}") };
            let from = match headers.net {
                Some(etherparse::NetSlice::Ipv4(ip)) => std::net::IpAddr::from(ip.header().source_addr()),
                Some(etherparse::NetSlice::Ipv6(ip)) => std::net::IpAddr::from(ip.header().source_addr()),
                _ => panic!("no IP header"),
            };
            assert_eq!((SocketAddr::new(from, udp.source_port()), udp.destination_port()), (remote, local.port()), "from the server to the app");
            assert_eq!(udp.payload(), super::negotiate::version_negotiation(&initial).unwrap(), "{local}");
        }
        assert!(run.from_stack.try_recv().is_err(), "nothing else");
        assert_eq!(rig.deps.connector.count(), 0, "nothing went upstream");
    }
}

#[tokio::test]
async fn a_relayed_flow_gets_no_reply() {
    for (local, remote) in FLOWS {
        let rig = rig();
        rig.deps.exclusions.set_user(&[HOST.to_string()], wall_ms());
        let mut run = through_the_stack(&rig, local.parse().unwrap(), remote.parse().unwrap(), REFUSAL).await;
        assert_eq!(run.answer, UdpPath::Relay);
        assert_eq!(run.sink.tried.load(Ordering::Relaxed), 0);
        assert!(run.from_stack.try_recv().is_err());
        assert_eq!(rig.reasons(), ["user"]);
    }
}

// ---- The row.

#[test]
fn a_refused_flow_logs_not_decrypted_and_counts_no_block() {
    let rig = rig();
    let case = Case::base();
    let id = rig.open_flow();
    assert_eq!(path(Action::Pass, &slot_of(&rig), &case.decoded, &case.who(), id), UdpPath::Refuse(REFUSAL));
    close_refused(&rig.deps.book, id);
    let rows = rig.deps.book.lock().unwrap().take_log();
    assert_eq!(rows.len(), 1);
    assert!(matches!(&rows[0].outcome, LogOutcome::NotDecrypted { reason } if reason == QUIC_REFUSED), "{:?}", rows[0].outcome);
    assert_eq!(rig.deps.meters.counters().blocked, 0, "this is not a block");
    let batch = rig.deps.book.lock().unwrap().take_batch();
    let event = batch.iter().find(|e| e.id == id).expect("the flow's event");
    assert_eq!((event.action, event.bytes_up, event.bytes_down, event.open), (FlowAction::Relayed, 0, 0, false));
}

/// `reasonWords` in `src/core/log.ts` (tested by `src/core/log.test.ts`) shows a
/// slug it does not know with its underscores as spaces.
#[test]
fn the_slug_reads_as_words() {
    assert_eq!(QUIC_REFUSED.replace('_', " "), "quic refused");
    assert!(QUIC_REFUSED.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
}

/// Slice 8's live check (`docs/live/engine-slice-8.md`), run by the user: U1 to
/// U9. Offline it cannot pass and claims nothing.
#[test]
#[ignore = "live: docs/live/engine-slice-8.md, run by the user with the switch driven by scripts/live/engine-ca.ps1"]
fn live_quic_refused_falls_back_to_tcp() {
    panic!("this check is the runbook: docs/live/engine-slice-8.md");
}
