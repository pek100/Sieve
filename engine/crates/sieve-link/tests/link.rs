//! Loopback integration tests. Every socket is on 127.0.0.0/8 with an
//! ephemeral port (other 127.x addresses stand in for other sources); names
//! resolve through a fixed map, never DNS; the hub's own network comes from
//! a fixed interface list.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sieve_link::audit::AuditConfig;
use sieve_link::device::{PairVia, pair};
use sieve_link::hub::{read_status, revoke_at};
use sieve_link::mux::{self, Mode};
use sieve_link::netif::{FixedInterfaces, HostNet, IfAddr, InterfaceSource};
use sieve_link::resolve::StaticResolver;
use sieve_link::store::HubStore;
use sieve_link::tls::{self, PeerPolicy, Pinned};
use sieve_link::wire::{Message, Status, read_msg, write_msg};
use sieve_link::{Fingerprint, Hub, HubConfig, HubRoute, Identity, LinkClient, LinkConfig, LinkError, Limits, OnHubDown, PairingCode, Rules};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;

const T: Duration = Duration::from_secs(10);

fn resolver() -> StaticResolver {
    let mut m: HashMap<String, Vec<IpAddr>> = HashMap::new();
    m.insert("echo.test".into(), vec!["127.0.0.1".parse().unwrap()]);
    m.insert("blocked.test".into(), vec!["127.0.0.1".parse().unwrap()]);
    m.insert("private.test".into(), vec!["10.0.0.1".parse().unwrap()]);
    // The hub's own network (see `fake_net`).
    m.insert("nas.test".into(), vec!["2a01:4f8:1:2::20".parse().unwrap()]);
    m.insert("me.test".into(), vec!["2a01:4f8:1:2::10".parse().unwrap()]);
    m.insert("gw.test".into(), vec!["2a01:4f8:1:2::1".parse().unwrap()]);
    m.insert("neighbour.test".into(), vec!["81.2.69.170".parse().unwrap()]);
    StaticResolver(m)
}

/// A home network: private IPv4, a global IPv6 /64 from the ISP (inside its
/// /56), a public /28, the gateways, and a route to a VPN subnet.
fn fake_net() -> HostNet {
    let a = |s: &str, prefix: u8| IfAddr { addr: s.parse().unwrap(), prefix };
    HostNet {
        addrs: vec![a("192.168.1.10", 24), a("2a01:4f8:1:2::10", 64), a("fe80::10", 64), a("81.2.69.163", 28)],
        gateways: vec!["192.168.1.1".parse().unwrap(), "fe80::1".parse().unwrap()],
        routes: vec!["0.0.0.0/0".parse().unwrap(), "45.10.20.0/24".parse().unwrap()],
    }
}

struct TestHub {
    _dir: tempfile::TempDir,
    hub: Hub,
    addr: SocketAddr,
}

impl Drop for TestHub {
    fn drop(&mut self) {
        self.hub.shutdown();
    }
}

fn test_cfg(dir: &std::path::Path, dead_after: Duration) -> HubConfig {
    let mut cfg = HubConfig::new(dir);
    cfg.resolver = Arc::new(resolver());
    cfg.interfaces = Arc::new(FixedInterfaces(fake_net()));
    cfg.dead_after = dead_after;
    cfg.reload_every = Duration::from_millis(100);
    cfg.connect_timeout = Duration::from_secs(3);
    cfg
}

async fn start_hub_cfg(listen: bool, tweak: impl FnOnce(&mut HubConfig)) -> TestHub {
    let dir = tempfile::tempdir().unwrap();
    Hub::init(dir.path(), "test-hub").unwrap();
    let mut cfg = test_cfg(dir.path(), Duration::from_secs(5));
    tweak(&mut cfg);
    let hub = Hub::open(cfg).unwrap();
    let addr = if listen { hub.listen("127.0.0.1:0".parse().unwrap()).await.unwrap() } else { "127.0.0.1:9".parse().unwrap() };
    TestHub { _dir: dir, hub, addr }
}

async fn start_hub_with(dead_after: Duration, listen: bool) -> TestHub {
    start_hub_cfg(listen, |c| c.dead_after = dead_after).await
}

async fn start_hub() -> TestHub {
    start_hub_with(Duration::from_secs(5), true).await
}

/// A TCP connection to `to` from the loopback address `from` (another
/// "source" as far as the hub's per-source limits go).
async fn connect_from(from: &str, to: SocketAddr) -> TcpStream {
    let s = TcpSocket::new_v4().unwrap();
    s.bind(format!("{from}:0").parse().unwrap()).unwrap();
    s.connect(to).await.unwrap()
}

/// An echo server on loopback; returns its port.
async fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

/// A port with nothing listening on it.
async fn dead_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

async fn pair_new(h: &TestHub, name: &str) -> Identity {
    let code = h.hub.create_pairing_code(60, Some(h.addr.to_string()), name).unwrap();
    let id = Identity::generate().unwrap();
    let hub_name = pair(&id, &code, name, PairVia::Dial(h.addr.to_string()), T).await.unwrap();
    assert_eq!(hub_name, "test-hub");
    id
}

/// The echo servers run on this machine's loopback: reaching them is
/// reaching the hub itself, which takes `allow_self`.
fn allow_loopback(h: &TestHub, id: &Identity) {
    let rules = Rules { allow_self: vec!["127.0.0.1/32".parse().unwrap()], ..Default::default() };
    h.hub.set_rules(&id.fingerprint().short(), rules).unwrap();
}

fn link_cfg(hub: Fingerprint, route: HubRoute) -> LinkConfig {
    let mut c = LinkConfig::new(hub, route);
    c.keepalive = Duration::from_millis(300);
    c.dead_after = Duration::from_secs(3);
    c.hub_wait = Duration::from_secs(3);
    c.handshake_timeout = Duration::from_secs(5);
    c
}

async fn client(h: &TestHub, id: &Identity) -> LinkClient {
    let c = LinkClient::start(id, link_cfg(h.hub.fingerprint(), HubRoute::Dial(h.addr.to_string()))).await.unwrap();
    assert!(c.wait_up(T).await, "link did not come up");
    c
}

async fn echo_once<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: &mut S, msg: &[u8]) {
    s.write_all(msg).await.unwrap();
    let mut back = vec![0u8; msg.len()];
    tokio::time::timeout(T, s.read_exact(&mut back)).await.expect("echo timed out").unwrap();
    assert_eq!(back, msg);
}

fn audit_rows(h: &TestHub) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(h.hub.audit_path()).unwrap_or_default();
    text.lines().map(|l| serde_json::from_str(l).expect("audit line is JSON")).collect()
}

async fn wait_audit(h: &TestHub, pred: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
    for _ in 0..100 {
        if let Some(r) = audit_rows(h).into_iter().find(|r| pred(r)) {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no matching audit row; rows: {:#?}", audit_rows(h));
}

fn refused_status(r: Result<sieve_link::LinkStream, LinkError>) -> Status {
    match r {
        Err(LinkError::Refused { status, .. }) => status,
        Err(e) => panic!("expected a refusal, got {e}"),
        Ok(_) => panic!("expected a refusal, got a stream"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_then_relay_echo_and_audit() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let id = pair_new(&h, "laptop").await;
    allow_loopback(&h, &id);
    let c = client(&h, &id).await;

    let mut s = c.open("127.0.0.1", echo).await.unwrap();
    assert!(!s.is_direct());
    echo_once(&mut s, b"hello through the hub").await;
    // A name resolved at the hub.
    let mut s2 = c.open("echo.test", echo).await.unwrap();
    echo_once(&mut s2, &vec![7u8; 200_000]).await;
    drop(s);
    s2.shutdown().await.unwrap();
    drop(s2);

    let fp = id.fingerprint().short();
    wait_audit(&h, |r| r["event"] == "paired" && r["device"] == fp.as_str() && r["name"] == "laptop").await;
    let up = wait_audit(&h, |r| r["event"] == "link_up").await;
    assert_eq!(up["outcome"], "X25519MLKEM768", "post-quantum hybrid key exchange expected");
    let row = wait_audit(&h, |r| r["event"] == "stream" && r["target"] == format!("echo.test:{echo}")).await;
    assert_eq!(row["addr"], format!("127.0.0.1:{echo}"));
    assert_eq!(row["up"], 200_000);
    assert_eq!(row["down"], 200_000);
    assert_eq!(row["device"], fp.as_str());
    // The open row came first, with the same id.
    let open = wait_audit(&h, |r| r["event"] == "stream_open" && r["sid"] == row["sid"]).await;
    assert_eq!(open["addr"], row["addr"]);
    // Never payload: the audit file holds no relayed bytes.
    let text = std::fs::read_to_string(h.hub.audit_path()).unwrap();
    assert!(!text.contains("hello through the hub"));
    c.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_dial_pairs_and_relays() {
    // The hub never listens: it dials OUT to the device, and is still the hub.
    let h = start_hub_with(Duration::from_secs(5), false).await;
    let echo = echo_server().await;
    let device_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let device_addr = device_listener.local_addr().unwrap();
    let code = h.hub.create_pairing_code(60, None, "vm").unwrap();
    assert!(code.addr.is_none());
    let id = Identity::generate().unwrap();
    h.hub.dial(device_addr.to_string());
    let name = pair(&id, &code, "vm", PairVia::Listener(&device_listener), T).await.unwrap();
    assert_eq!(name, "test-hub");
    allow_loopback(&h, &id);

    let c = LinkClient::start_with_listener(&id, link_cfg(h.hub.fingerprint(), HubRoute::Listen(device_addr)), device_listener).unwrap();
    assert!(c.wait_up(T).await, "the hub did not dial back in");
    let mut s = c.open("127.0.0.1", echo).await.unwrap();
    echo_once(&mut s, b"reverse").await;
    let row = wait_audit(&h, |r| r["event"] == "link_up").await;
    assert_eq!(row["device"], id.fingerprint().short().as_str());
    c.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unpaired_device_is_refused() {
    let h = start_hub().await;
    let stranger = Identity::generate().unwrap();
    // No code outstanding: the handshake itself fails.
    let c = LinkClient::start(&stranger, link_cfg(h.hub.fingerprint(), HubRoute::Dial(h.addr.to_string()))).await.unwrap();
    assert!(!c.wait_up(Duration::from_secs(1)).await);
    assert!(matches!(c.open("echo.test", 1).await, Err(LinkError::HubDown)));
    wait_audit(&h, |r| r["event"] == "handshake_refused").await;
    c.shutdown();

    // A code outstanding lets an unknown key finish TLS, but it can only pair.
    let _code = h.hub.create_pairing_code(60, None, "other").unwrap();
    let cfg = tls::client_config(&stranger, Arc::new(Pinned(h.hub.fingerprint()))).unwrap();
    let est = tls::dial(&h.addr.to_string(), cfg, T).await.unwrap();
    let stop = CancellationToken::new();
    let (mh, _task) = mux::spawn(est.io.compat(), Mode::Client, |_| {}, stop.clone());
    let mut s = mh.open().await.unwrap();
    write_msg(&mut s, &Message::Connect { host: "echo.test".into(), port: 7 }).await.unwrap();
    match read_msg(&mut s).await.unwrap() {
        Message::Response { status, .. } => assert_eq!(status, Status::BadRequest),
        other => panic!("unexpected {other:?}"),
    }
    stop.cancel();
    wait_audit(&h, |r| r["event"] == "pair_refused").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoke_cuts_off_mid_stream_and_refuses_after() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let a = pair_new(&h, "a").await;
    let b = pair_new(&h, "b").await;
    allow_loopback(&h, &a);
    allow_loopback(&h, &b);
    let ca = client(&h, &a).await;
    let cb = client(&h, &b).await;
    let mut sa = ca.open("127.0.0.1", echo).await.unwrap();
    let mut sb = cb.open("127.0.0.1", echo).await.unwrap();
    echo_once(&mut sa, b"before").await;

    h.hub.revoke(&a.fingerprint().short()).unwrap();
    // A's open stream ends promptly.
    let mut buf = [0u8; 16];
    let _ = sa.write_all(b"after").await;
    let n = tokio::time::timeout(T, sa.read(&mut buf)).await.expect("stream was not cut");
    assert!(matches!(n, Ok(0) | Err(_)), "revoked stream still delivers data: {n:?}");
    // A's link goes down and cannot come back.
    for _ in 0..100 {
        if !ca.is_up() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!ca.is_up(), "the revoked device's link stayed up");
    assert!(!ca.wait_up(Duration::from_secs(1)).await, "the revoked device linked again");
    assert!(ca.open("127.0.0.1", echo).await.is_err());
    // B is untouched: cut off alone.
    echo_once(&mut sb, b"b still works").await;
    wait_audit(&h, |r| r["event"] == "revoked" && r["name"] == "a").await;
    wait_audit(&h, |r| r["event"] == "stream" && r["outcome"] == "cut off").await;

    // The CLI path: revoke in the store file; the running hub notices.
    revoke_at(&HubStore::new(h.hub.audit_path().parent().unwrap()), "b").unwrap();
    let n = tokio::time::timeout(T, sb.read(&mut buf)).await.expect("stream was not cut");
    assert!(matches!(n, Ok(0) | Err(_)));
    ca.shutdown();
    cb.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn used_expired_and_wrong_codes_are_refused() {
    let h = start_hub().await;
    let code = h.hub.create_pairing_code(60, Some(h.addr.to_string()), "x").unwrap();
    let first = Identity::generate().unwrap();
    pair(&first, &code, "first", PairVia::Dial(h.addr.to_string()), T).await.unwrap();

    // Used: a second holder gets nothing (no code outstanding, so not even TLS).
    let second = Identity::generate().unwrap();
    assert!(pair(&second, &code, "second", PairVia::Dial(h.addr.to_string()), T).await.is_err());

    // A wrong secret while another code is outstanding: refused by proof.
    let _other = h.hub.create_pairing_code(60, None, "other").unwrap();
    let mut forged = code.clone();
    forged.secret = [0x55; 16];
    let err = pair(&second, &forged, "second", PairVia::Dial(h.addr.to_string()), T).await.unwrap_err();
    assert!(err.to_string().contains("refused"), "{err}");

    // Expired at the hub (the device's own clock check bypassed): every
    // outstanding code is moved into the past in the store.
    let short = h.hub.create_pairing_code(60, None, "short").unwrap();
    let store = HubStore::new(h.hub.audit_path().parent().unwrap());
    store
        .update(|f| {
            for p in &mut f.pending {
                p.expires_at = 1;
            }
            Ok(())
        })
        .unwrap();
    h.hub.reload().unwrap();
    let mut late = short.clone();
    late.expires_at += 3600;
    assert!(pair(&second, &late, "late", PairVia::Dial(h.addr.to_string()), T).await.is_err());
    // And the device refuses an expired code itself.
    let mut expired = short.clone();
    expired.expires_at = 1;
    assert!(matches!(pair(&second, &expired, "late", PairVia::Dial(h.addr.to_string()), T).await, Err(LinkError::Pairing(_))));
    assert_eq!(h.hub.devices().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_redeemers_racing_one_code_pair_once() {
    let h = start_hub().await;
    let code = h.hub.create_pairing_code(60, Some(h.addr.to_string()), "x").unwrap();
    // From two sources, so neither is told "busy" for sharing one.
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let (ta, tb) = tokio::join!(connect_from("127.0.0.1", h.addr), connect_from("127.0.0.2", h.addr));
    let (ra, rb) = tokio::join!(pair(&a, &code, "a", PairVia::Connected(ta), T), pair(&b, &code, "b", PairVia::Connected(tb), T));
    let wins = [ra.is_ok(), rb.is_ok()];
    assert_eq!(wins.iter().filter(|w| **w).count(), 1, "exactly one redeemer wins: {ra:?} {rb:?}");
    let devs = h.hub.devices();
    assert_eq!(devs.len(), 1);
    let winner = if ra.is_ok() { &a } else { &b };
    assert_eq!(devs[0].fingerprint, winner.fingerprint());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strangers_holding_pairing_slots_get_the_device_a_busy_answer() {
    let h = start_hub().await;
    let code = h.hub.create_pairing_code(60, Some(h.addr.to_string()), "x").unwrap();
    // Four strangers from four sources finish TLS (a code is outstanding)
    // and then say nothing, holding every pairing slot.
    let mut held = Vec::new();
    for i in 2..=5 {
        let s = Identity::generate().unwrap();
        let cfg = tls::client_config(&s, Arc::new(Pinned(h.hub.fingerprint()))).unwrap();
        let tcp = connect_from(&format!("127.0.0.{i}"), h.addr).await;
        held.push(tls::connect(tcp, cfg, T).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let id = Identity::generate().unwrap();
    let err = pair(&id, &code, "late", PairVia::Dial(h.addr.to_string()), T).await.unwrap_err();
    assert!(err.to_string().contains("busy"), "{err}");
    // The strangers have about 3 s; then the same code works.
    tokio::time::sleep(Duration::from_millis(3500)).await;
    let name = pair(&id, &code, "late", PairVia::Dial(h.addr.to_string()), T).await.unwrap();
    assert_eq!(name, "test-hub");
    drop(held);
    wait_audit(&h, |r| r["event"] == "pair_refused" && r["outcome"].as_str().unwrap().contains("no request in time")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_sockets_do_not_lock_out_a_device() {
    // Many silent sockets from one source: only a few are admitted.
    let h = start_hub().await;
    let id = pair_new(&h, "d").await;
    let mut silent = Vec::new();
    for _ in 0..80 {
        silent.push(connect_from("127.0.0.2", h.addr).await);
    }
    let started = std::time::Instant::now();
    let c = client(&h, &id).await;
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    c.shutdown();
    drop(silent);

    // Every slot held: a new connection waits for one instead of being dropped.
    let h = start_hub_cfg(true, |c| {
        c.gate.slots = 4;
        c.gate.wait = Duration::from_secs(5);
        c.accept_timeout = Duration::from_secs(1);
        c.audit.refusal_window = Duration::from_millis(1500);
    })
    .await;
    let id = pair_new(&h, "d").await;
    let mut silent = Vec::new();
    for _ in 0..4 {
        silent.push(connect_from("127.0.0.3", h.addr).await);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let c = LinkClient::start(&id, link_cfg(h.hub.fingerprint(), HubRoute::Dial(h.addr.to_string()))).await.unwrap();
    assert!(c.wait_up(Duration::from_secs(4)).await, "the device waited for a slot and got in");
    c.shutdown();
    // The four silent ones timed out (1 s): one row, then the other three
    // coalesced into one summary row once the window (1.5 s) is over.
    tokio::time::sleep(Duration::from_millis(3200)).await;
    h.hub.flush_audit();
    let rows: Vec<_> = audit_rows(&h).into_iter().filter(|r| r["event"] == "handshake_refused" && r["peer"] == "127.0.0.3").collect();
    assert_eq!(rows.len(), 2, "one written, one summary: {rows:#?}");
    assert!(rows[0]["count"].is_null());
    assert_eq!(rows[1]["count"], 3, "{rows:#?}");
    drop(silent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hubs_own_network_is_denied() {
    let h = start_hub().await;
    let id = pair_new(&h, "d").await;
    let c = client(&h, &id).await;
    // Global IPv6 neighbours, its gateway, a public /28 at home, a sibling
    // /64 in the /56, a routed VPN subnet: the hub's LAN, by name and by
    // literal. The hub's own address is the hub itself.
    let lan = "the hub's local network";
    for (host, port, want) in [
        ("nas.test", 445, lan),
        ("me.test", 80, "the hub itself"),
        ("192.168.1.10", 80, "the hub itself"),
        ("gw.test", 80, lan),
        ("neighbour.test", 80, lan),
        ("2a01:4f8:1:2::99", 22, lan),
        ("81.2.69.160", 80, lan),
        ("2a01:4f8:1:3::5", 443, lan),
        ("45.10.20.5", 443, lan),
        ("64:ff9b::5102:45aa", 80, lan),
    ] {
        match c.open(host, port).await {
            Err(LinkError::Refused { status: Status::Denied, message }) => {
                assert_eq!(message, want, "{host}");
            }
            other => panic!("{host}: expected a denial, got {:?}", other.map(|_| ())),
        }
    }
    // The device learns the class only; the audit log has the address.
    let row = wait_audit(&h, |r| r["event"] == "denied" && r["target"] == "nas.test:445").await;
    assert_eq!(row["addr"], "[2a01:4f8:1:2::20]:445");
    // Names resolved by LLMNR / NetBIOS / mDNS never reach a resolver.
    for host in ["printer", "nas.local", "localhost", "box.lan"] {
        assert_eq!(refused_status(c.open(host, 80).await), Status::Denied, "{host}");
    }
    // Port 25 is denied by default (refused before anything is resolved or
    // dialled).
    assert_eq!(refused_status(c.open("93.184.0.1", 25).await), Status::Denied);
    // A manual block (the public IPv4 seen from outside) joins the detected
    // ones at once. (Checked on the block list: a test never dials out.)
    let store = HubStore::new(h.hub.audit_path().parent().unwrap());
    store
        .update(|f| {
            f.lan_cidrs.push("93.184.0.77/32".parse().unwrap());
            Ok(())
        })
        .unwrap();
    h.hub.reload().unwrap();
    let blocks = h.hub.lan_blocks();
    assert!(blocks.contains(&"93.184.0.77/32".parse().unwrap()));
    assert!(blocks.contains(&"2a01:4f8:1:2::/64".parse().unwrap()));
    assert!(blocks.contains(&"192.168.1.1/32".parse().unwrap()));
    c.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_interface_list_stops_the_hub_unless_overridden() {
    struct Broken;
    impl InterfaceSource for Broken {
        fn snapshot(&self) -> std::io::Result<HostNet> {
            Err(std::io::Error::other("no adapters for you"))
        }
    }
    let dir = tempfile::tempdir().unwrap();
    Hub::init(dir.path(), "h").unwrap();
    let mut cfg = test_cfg(dir.path(), Duration::from_secs(5));
    cfg.interfaces = Arc::new(Broken);
    let err = Hub::open(cfg).err().expect("the hub refuses to start");
    assert!(err.to_string().contains("--allow-undetected-lan"), "{err}");
    let mut cfg = test_cfg(dir.path(), Duration::from_secs(5));
    cfg.interfaces = Arc::new(Broken);
    cfg.allow_undetected_lan = true;
    let hub = Hub::open(cfg).expect("the owner's override");
    hub.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failing_interface_refresh_stops_new_streams() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Flaky(Arc<AtomicBool>);
    impl InterfaceSource for Flaky {
        fn snapshot(&self) -> std::io::Result<HostNet> {
            if self.0.load(Ordering::SeqCst) { Err(std::io::Error::other("gone")) } else { Ok(fake_net()) }
        }
    }
    let broken = Arc::new(AtomicBool::new(false));
    let b2 = broken.clone();
    let h = start_hub_cfg(true, move |c| {
        c.interfaces = Arc::new(Flaky(b2));
        c.lan_refresh_every = Duration::from_millis(100);
    })
    .await;
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    allow_loopback(&h, &id);
    let c = client(&h, &id).await;
    let _ok = c.open("127.0.0.1", echo).await.unwrap();
    broken.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(refused_status(c.open("127.0.0.1", echo).await), Status::Unavailable);
    broken.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(c.open("127.0.0.1", echo).await.is_ok());
    c.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_pinned_key_is_refused() {
    let h = start_hub().await;
    let mut code = h.hub.create_pairing_code(60, Some(h.addr.to_string()), "x").unwrap();
    let impostor = Identity::generate().unwrap();
    code.hub = impostor.fingerprint(); // the device expects some other hub
    let id = Identity::generate().unwrap();
    let err = pair(&id, &code, "d", PairVia::Dial(h.addr.to_string()), T).await.unwrap_err();
    assert!(matches!(err, LinkError::Tls(_)), "{err}");

    // A paired device whose pinned hub key is wrong never links.
    let real = pair_new(&h, "real").await;
    let c = LinkClient::start(&real, link_cfg(impostor.fingerprint(), HubRoute::Dial(h.addr.to_string()))).await.unwrap();
    assert!(!c.wait_up(Duration::from_secs(1)).await);
    c.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deny_rules_refuse_and_are_logged() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    let c = client(&h, &id).await;
    // Loopback and private addresses are denied by default.
    assert_eq!(refused_status(c.open("127.0.0.1", echo).await), Status::Denied);
    assert_eq!(refused_status(c.open("private.test", 443).await), Status::Denied);
    assert_eq!(refused_status(c.open("192.168.1.1", 80).await), Status::Denied);
    assert_eq!(refused_status(c.open("::1", 80).await), Status::Denied);
    // A denied domain is refused before it is resolved.
    let rules = Rules { deny_suffixes: vec!["blocked.test".into()], allow_self: vec!["127.0.0.1/32".parse().unwrap()], ..Default::default() };
    h.hub.set_rules(&id.fingerprint().short(), rules).unwrap();
    assert_eq!(refused_status(c.open("blocked.test", echo).await), Status::Denied);
    let mut ok = c.open("echo.test", echo).await.unwrap();
    echo_once(&mut ok, b"allowed").await;
    // Unknown names fail at the hub's resolver.
    assert_eq!(refused_status(c.open("nowhere.test", 80).await), Status::Unreachable);

    wait_audit(&h, |r| r["event"] == "denied" && r["outcome"].as_str().unwrap().starts_with("loopback")).await;
    wait_audit(&h, |r| r["event"] == "denied" && r["target"] == "private.test:443" && r["outcome"].as_str().unwrap().starts_with("private")).await;
    wait_audit(&h, |r| r["event"] == "denied" && r["outcome"].as_str().unwrap().starts_with("domain denied")).await;
    c.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_and_concurrency_limits() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    allow_loopback(&h, &id);
    let key = id.fingerprint().short();
    h.hub.set_limits(&key, Limits { max_concurrent: 1, opens_per_minute: 100, bytes_per_sec: 0 }).unwrap();
    let c = client(&h, &id).await;
    let mut first = c.open("127.0.0.1", echo).await.unwrap();
    echo_once(&mut first, b"one").await;
    assert_eq!(refused_status(c.open("127.0.0.1", echo).await), Status::Busy);
    drop(first);
    // The slot frees once the hub sees the stream end.
    let mut freed = false;
    for _ in 0..50 {
        if c.open("127.0.0.1", echo).await.is_ok() {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(freed);

    // A raise beyond the link's spare streams (1 -> 10 on a link made for
    // 1) relinks the device; an open right then waits for the new link
    // instead of failing, and promptly (a stream on the old link must not
    // hang: it once waited out the 15 s request timeout).
    h.hub.set_limits(&key, Limits { max_concurrent: 10, opens_per_minute: 100, bytes_per_sec: 0 }).unwrap();
    let started = std::time::Instant::now();
    let _a = c.open("127.0.0.1", echo).await.expect("the open waited for the new link");
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    wait_audit(&h, |r| r["event"] == "link_down" && r["outcome"].as_str().unwrap().contains("raised limit")).await;
    assert!(c.wait_up(T).await);
    assert_eq!(c.stream_limit(), Some(10), "the new link announced the new limit");
    // The rate: a new capacity of 2 leaves 2 tokens.
    h.hub.set_limits(&key, Limits { max_concurrent: 10, opens_per_minute: 2, bytes_per_sec: 0 }).unwrap();
    let _b = c.open("127.0.0.1", echo).await.unwrap();
    let _c = c.open("127.0.0.1", echo).await.unwrap();
    assert_eq!(refused_status(c.open("127.0.0.1", echo).await), Status::RateLimited);
    wait_audit(&h, |r| r["event"] == "denied" && r["outcome"].as_str().unwrap().contains("per minute")).await;
    c.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lower_limit_counts_streams_already_open() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    allow_loopback(&h, &id);
    let key = id.fingerprint().short();
    h.hub.set_limits(&key, Limits { max_concurrent: 4, opens_per_minute: 100, bytes_per_sec: 0 }).unwrap();
    let c = client(&h, &id).await;
    let mut open = Vec::new();
    for _ in 0..3 {
        open.push(c.open("127.0.0.1", echo).await.unwrap());
    }
    h.hub.set_limits(&key, Limits { max_concurrent: 2, opens_per_minute: 100, bytes_per_sec: 0 }).unwrap();
    assert_eq!(refused_status(c.open("127.0.0.1", echo).await), Status::Busy, "three still open against a limit of two");
    open.truncate(1);
    let mut ok = false;
    for _ in 0..50 {
        if c.open("127.0.0.1", echo).await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ok, "one open of two: room again");
    c.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn byte_rate_limit_slows_the_relay() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    allow_loopback(&h, &id);
    // 100 KB/s for both directions together; burst 100 KB.
    h.hub.set_limits(&id.fingerprint().short(), Limits { max_concurrent: 4, opens_per_minute: 100, bytes_per_sec: 100_000 }).unwrap();
    let c = client(&h, &id).await;
    let mut s = c.open("127.0.0.1", echo).await.unwrap();
    let start = std::time::Instant::now();
    // 300 KB up + 300 KB back = 600 KB: 5 s beyond the burst in theory. The
    // bound is a generous lower one (a slow machine only makes it slower);
    // the exact pacing is checked on paused time in the hub's unit tests.
    echo_once(&mut s, &vec![1u8; 300_000]).await;
    assert!(start.elapsed() >= Duration::from_secs(3), "{:?}", start.elapsed());
    c.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streams_count_from_arrival_and_one_control_stream_per_link() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    allow_loopback(&h, &id);
    h.hub.set_limits(&id.fingerprint().short(), Limits { max_concurrent: 2, opens_per_minute: 100, bytes_per_sec: 0 }).unwrap();
    let (mh, stop) = raw_session(&h, &id).await;
    // A control stream does not use a slot; the hub announces the limit on it.
    let mut ctl = mh.open().await.unwrap();
    write_msg(&mut ctl, &Message::Control).await.unwrap();
    write_msg(&mut ctl, &Message::Ping(1)).await.unwrap();
    assert_eq!(read_msg(&mut ctl).await.unwrap(), Message::Limit(2));
    assert_eq!(read_msg(&mut ctl).await.unwrap(), Message::Pong(1));
    // A second control stream on the same link is refused.
    let mut ctl2 = mh.open().await.unwrap();
    write_msg(&mut ctl2, &Message::Control).await.unwrap();
    assert!(matches!(read_msg(&mut ctl2).await.unwrap(), Message::Response { status: Status::BadRequest, .. }));
    drop(ctl2);
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Two streams that never send a request hold both slots...
    // (One byte of a length prefix each: yamux opens a stream on its first byte.)
    let mut s1 = mh.open().await.unwrap();
    let mut s2 = mh.open().await.unwrap();
    s1.write_all(&[0]).await.unwrap();
    s2.write_all(&[0]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    // ...so a third is told Busy (after the hub's short wait for a slot).
    let mut s3 = mh.open().await.unwrap();
    write_msg(&mut s3, &Message::Connect { host: "127.0.0.1".into(), port: echo }).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(2), read_msg(&mut s3)).await.unwrap().unwrap() {
        Message::Response { status, .. } => assert_eq!(status, Status::Busy),
        other => panic!("unexpected {other:?}"),
    }
    drop((s1, s2, s3));
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_holds_at_most_two_links_and_the_newest_wins() {
    let h = start_hub().await;
    let id = pair_new(&h, "d").await;
    let (m1, s1) = raw_session(&h, &id).await;
    let (m2, s2) = raw_session(&h, &id).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!m1.is_closed() && !m2.is_closed());
    let (m3, s3) = raw_session(&h, &id).await;
    for _ in 0..50 {
        if m1.is_closed() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(m1.is_closed(), "the oldest link was closed");
    assert!(!m2.is_closed() && !m3.is_closed());
    wait_audit(&h, |r| r["event"] == "link_down" && r["outcome"].as_str().unwrap().contains("newer link")).await;
    s1.cancel();
    s2.cancel();
    s3.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_open_is_on_record_before_the_stream_ends() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    allow_loopback(&h, &id);
    let c = client(&h, &id).await;
    let mut s = c.open("echo.test", echo).await.unwrap();
    echo_once(&mut s, b"in flight").await;
    // Still open: its row is already there (a crash now would keep it).
    let open = wait_audit(&h, |r| r["event"] == "stream_open" && r["target"] == format!("echo.test:{echo}")).await;
    assert_eq!(open["addr"], format!("127.0.0.1:{echo}"));
    assert!(!audit_rows(&h).iter().any(|r| r["event"] == "stream" && r["sid"] == open["sid"]));
    s.shutdown().await.unwrap();
    drop(s);
    let done = wait_audit(&h, |r| r["event"] == "stream" && r["sid"] == open["sid"]).await;
    assert_eq!(done["up"], 9);
    c.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_relaying_without_an_audit_record() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    allow_loopback(&h, &id);
    let c = client(&h, &id).await;
    h.hub.fail_audit_writes(true);
    match c.open("127.0.0.1", echo).await {
        Err(LinkError::Refused { status: Status::Unavailable, message }) => assert!(message.contains("audit"), "{message}"),
        other => panic!("expected Unavailable, got {:?}", other.map(|_| ())),
    }
    h.hub.fail_audit_writes(false);
    let mut s = c.open("127.0.0.1", echo).await.unwrap();
    echo_once(&mut s, b"recorded").await;
    wait_audit(&h, |r| r["event"] == "audit_resumed").await;
    c.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_store_stops_new_streams_until_it_reads_again() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    allow_loopback(&h, &id);
    let c = client(&h, &id).await;
    let path = h.hub.audit_path().parent().unwrap().join("hub.json");
    let good = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"{ this is not json").unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(refused_status(c.open("127.0.0.1", echo).await), Status::Unavailable);
    std::fs::write(&path, &good).unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(c.open("127.0.0.1", echo).await.is_ok());
    wait_audit(&h, |r| r["event"] == "store_unreadable").await;
    wait_audit(&h, |r| r["event"] == "store_resumed").await;
    c.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_names_are_cleaned_unique_and_never_shadow_a_fingerprint() {
    let h = start_hub().await;
    let a = pair_new_named(&h, "evil\u{202E}name\u{7}").await;
    let b = pair_new_named(&h, "evilname").await;
    let c = pair_new_named(&h, "0123456789abcdef").await;
    let names: Vec<String> = h.hub.devices().iter().map(|d| d.name.clone()).collect();
    assert_eq!(names, ["evilname", "evilname-2", "device-0123456789abcdef"]);
    // Revoking by fingerprint always reaches the right device.
    h.hub.revoke(&b.fingerprint().short()).unwrap();
    let devs = h.hub.devices();
    assert!(devs.iter().find(|d| d.fingerprint == b.fingerprint()).unwrap().revoked_at.is_some());
    assert!(devs.iter().find(|d| d.fingerprint == a.fingerprint()).unwrap().revoked_at.is_none());
    assert!(devs.iter().find(|d| d.fingerprint == c.fingerprint()).unwrap().revoked_at.is_none());
}

async fn pair_new_named(h: &TestHub, name: &str) -> Identity {
    let code: PairingCode = h.hub.create_pairing_code(60, Some(h.addr.to_string()), "x").unwrap();
    let id = Identity::generate().unwrap();
    pair(&id, &code, name, PairVia::Dial(h.addr.to_string()), T).await.unwrap();
    id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hub_down_stop_refuses_and_direct_goes_direct() {
    let hub_fp = Identity::generate().unwrap().fingerprint();
    let dead = format!("127.0.0.1:{}", dead_port().await);
    let echo = echo_server().await;
    let id = Identity::generate().unwrap();

    let mut cfg = link_cfg(hub_fp, HubRoute::Dial(dead.clone()));
    cfg.hub_wait = Duration::from_millis(300);
    assert_eq!(cfg.on_hub_down, OnHubDown::Stop, "STOP is the default");
    let stop = LinkClient::start(&id, cfg.clone()).await.unwrap();
    assert!(matches!(stop.open("127.0.0.1", echo).await, Err(LinkError::HubDown)));
    stop.shutdown();

    cfg.on_hub_down = OnHubDown::Direct;
    let direct = LinkClient::start(&id, cfg).await.unwrap();
    let mut s = direct.open("127.0.0.1", echo).await.unwrap();
    assert!(s.is_direct());
    echo_once(&mut s, b"direct").await;
    direct.shutdown();
}

/// A raw session as a paired device, below `LinkClient`.
async fn raw_session(h: &TestHub, id: &Identity) -> (mux::MuxHandle, CancellationToken) {
    let cfg = tls::client_config(id, Arc::new(Pinned(h.hub.fingerprint()))).unwrap();
    let est = tls::dial(&h.addr.to_string(), cfg, T).await.unwrap();
    let stop = CancellationToken::new();
    let (mh, _task) = mux::spawn(est.io.compat(), Mode::Client, |_| {}, stop.clone());
    (mh, stop)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_and_oversized_frames_do_not_hurt_the_hub() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    allow_loopback(&h, &id);
    let (mh, stop) = raw_session(&h, &id).await;

    // Oversized length prefix, followed by a megabyte nobody should buffer.
    let mut s = mh.open().await.unwrap();
    s.write_all(&[0xff, 0xff]).await.unwrap();
    match tokio::time::timeout(T, read_msg(&mut s)).await.unwrap().unwrap() {
        Message::Response { status, .. } => assert_eq!(status, Status::BadRequest),
        other => panic!("unexpected {other:?}"),
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), s.write_all(&vec![0xAB; 1 << 20])).await;
    drop(s);

    // Valid length, garbage body; unknown tag; a response sent as a request.
    for body in [vec![0x00, 0x03, 0x99, 1, 2], vec![0x00, 0x01, 0x7f], vec![0x00, 0x03, 0x80, 0x00, 0x00]] {
        let mut s = mh.open().await.unwrap();
        s.write_all(&body).await.unwrap();
        match tokio::time::timeout(T, read_msg(&mut s)).await.unwrap().unwrap() {
            Message::Response { status, .. } => assert_eq!(status, Status::BadRequest),
            other => panic!("unexpected {other:?}"),
        }
    }
    // Truncated request then close: the hub just drops the stream.
    let mut s = mh.open().await.unwrap();
    s.write_all(&[0x00, 0x10, 0x02]).await.unwrap();
    s.shutdown().await.unwrap();
    drop(s);

    // The same link still works.
    let mut s = mh.open().await.unwrap();
    write_msg(&mut s, &Message::Connect { host: "127.0.0.1".into(), port: echo }).await.unwrap();
    assert!(matches!(read_msg(&mut s).await.unwrap(), Message::Response { status: Status::Ok, .. }));
    echo_once(&mut s, b"still alive").await;
    wait_audit(&h, |r| r["event"] == "bad_request").await;
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_link_is_dropped_by_the_hub() {
    let h = start_hub_with(Duration::from_millis(800), true).await;
    let id = pair_new(&h, "quiet").await;
    // No control stream, no pings.
    let (mh, stop) = raw_session(&h, &id).await;
    let row = wait_audit(&h, |r| r["event"] == "link_down").await;
    assert_eq!(row["name"], "quiet");
    for _ in 0..50 {
        if mh.is_closed() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(mh.is_closed());
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_proxy_speaks_socks5_and_http_connect() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    let rules = Rules { allow_self: vec!["127.0.0.1/32".parse().unwrap()], deny_suffixes: vec!["blocked.test".into()], ..Default::default() };
    h.hub.set_rules(&id.fingerprint().short(), rules).unwrap();
    let c = client(&h, &id).await;
    let listener = sieve_link::proxy::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let paddr = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    tokio::spawn(sieve_link::proxy::serve(listener, c.clone(), stop.clone()));

    // SOCKS5 with a domain name (resolved at the hub).
    let mut s = TcpStream::connect(paddr).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 0]);
    let mut req = vec![5, 1, 0, 3, 9];
    req.extend_from_slice(b"echo.test");
    req.extend_from_slice(&echo.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0, "socks5 success");
    echo_once(&mut s, b"via socks").await;

    // SOCKS5 to a denied domain: "not allowed by ruleset".
    let mut s = TcpStream::connect(paddr).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    s.read_exact(&mut r).await.unwrap();
    let mut req = vec![5, 1, 0, 3, 12];
    req.extend_from_slice(b"blocked.test");
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req).await.unwrap();
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 2);

    // HTTP CONNECT, with bytes sent right after the head.
    let mut s = TcpStream::connect(paddr).await.unwrap();
    s.write_all(format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\nHost: 127.0.0.1:{echo}\r\n\r\nearly").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut b = [0u8; 1];
        s.read_exact(&mut b).await.unwrap();
        head.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
    let mut early = [0u8; 5];
    s.read_exact(&mut early).await.unwrap();
    assert_eq!(&early, b"early");
    echo_once(&mut s, b"via connect").await;

    // Plain HTTP proxying is not offered.
    let mut s = TcpStream::connect(paddr).await.unwrap();
    s.write_all(b"GET http://echo.test/ HTTP/1.1\r\nHost: echo.test\r\n\r\n").await.unwrap();
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp).await;
    assert!(resp.starts_with("HTTP/1.1 405"));
    stop.cancel();
    c.shutdown();
}

fn link_downs(h: &TestHub) -> Vec<serde_json::Value> {
    audit_rows(h).into_iter().filter(|r| r["event"] == "link_down").collect()
}

fn no_link_down(h: &TestHub) {
    let downs = link_downs(h);
    assert!(downs.is_empty(), "the link went down: {downs:#?}");
}

/// P2-E: limit 2, two streams open, a burst of more opens. Through the
/// device: each extra one is answered Busy by the device itself. Below the
/// device (a raw session that ignores the announced limit): each extra one
/// is answered Busy by the hub on its spare streams. Either way both open
/// streams keep working and the link stays up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_over_the_limit_gets_busy_and_healthy_streams_survive() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    allow_loopback(&h, &id);
    h.hub.set_limits(&id.fingerprint().short(), Limits { max_concurrent: 2, opens_per_minute: 1000, bytes_per_sec: 0 }).unwrap();

    let c = client(&h, &id).await;
    assert_eq!(c.stream_limit(), Some(2), "the hub announced the limit");
    let mut s1 = c.open("127.0.0.1", echo).await.unwrap();
    let mut s2 = c.open("127.0.0.1", echo).await.unwrap();
    let burst = (0..6).map(|_| c.open("127.0.0.1", echo));
    for r in futures::future::join_all(burst).await {
        assert_eq!(refused_status(r), Status::Busy);
    }
    echo_once(&mut s1, b"one still works").await;
    echo_once(&mut s2, b"two still works").await;
    assert!(c.is_up());
    no_link_down(&h);
    c.shutdown();
    drop((s1, s2));
    // That link's own end (the shutdown above), before the raw part.
    wait_audit(&h, |r| r["event"] == "link_down").await;
    let downs_before = link_downs(&h).len();

    // Below the device: a raw session opens two, then spare(2) = 8 more at once.
    let (mh, stop) = raw_session(&h, &id).await;
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut s = mh.open().await.unwrap();
        write_msg(&mut s, &Message::Connect { host: "127.0.0.1".into(), port: echo }).await.unwrap();
        assert!(matches!(read_msg(&mut s).await.unwrap(), Message::Response { status: Status::Ok, .. }));
        held.push(s);
    }
    let extra = (0..mux::spare(2)).map(|_| {
        let mh = mh.clone();
        async move {
            let mut s = mh.open().await.unwrap();
            write_msg(&mut s, &Message::Connect { host: "127.0.0.1".into(), port: echo }).await.unwrap();
            tokio::time::timeout(T, read_msg(&mut s)).await.expect("answered").expect("an answer, not a reset")
        }
    });
    for m in futures::future::join_all(extra).await {
        assert!(matches!(m, Message::Response { status: Status::Busy, .. }), "{m:?}");
    }
    for s in &mut held {
        echo_once(s, b"raw still works").await;
    }
    assert!(!mh.is_closed());
    assert_eq!(link_downs(&h).len(), downs_before, "the raw link went down: {:#?}", link_downs(&h));
    stop.cancel();
}

/// P2-A: a plain allow-cidr never reopens the hub, its LAN or loopback,
/// even 0.0.0.0/0; allow-lan opens a LAN block but not the hub.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allow_cidr_does_not_reopen_the_lan() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    let rules = Rules { allow_cidrs: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()], ..Default::default() };
    h.hub.set_rules(&id.fingerprint().short(), rules).unwrap();
    let c = client(&h, &id).await;
    for (host, port) in [("127.0.0.1", echo), ("192.168.1.10", 80), ("192.168.1.20", 445), ("81.2.69.170", 80), ("10.0.0.1", 80), ("nas.test", 445), ("::1", 80)] {
        assert_eq!(refused_status(c.open(host, port).await), Status::Denied, "{host}");
    }
    // allow-lan opens the NAS's block; the hub's own address stays closed.
    let rules = Rules { allow_lan: vec!["192.168.1.0/24".parse().unwrap()], ..Default::default() };
    h.hub.set_rules(&id.fingerprint().short(), rules).unwrap();
    match c.open("192.168.1.10", 80).await {
        Err(LinkError::Refused { status: Status::Denied, message }) => assert_eq!(message, "the hub itself"),
        other => panic!("expected the hub itself, got {:?}", other.map(|_| ())),
    }
    c.shutdown();
}

/// P2-C, hub dials out: the device sees the hub's (public) address as its
/// TCP peer and reports it; the hub denies it to that link as itself,
/// mapped and NAT64 forms included, and shows it in status.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dialling_hub_learns_its_public_address_from_the_device() {
    let h = start_hub_with(Duration::from_secs(5), false).await;
    let device_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let device_addr = device_listener.local_addr().unwrap();
    let code = h.hub.create_pairing_code(60, None, "vm").unwrap();
    let id = Identity::generate().unwrap();
    h.hub.dial(device_addr.to_string());
    pair(&id, &code, "vm", PairVia::Listener(&device_listener), T).await.unwrap();
    let mut cfg = link_cfg(h.hub.fingerprint(), HubRoute::Listen(device_addr));
    cfg.report_hub_addr = Some("93.184.0.77".parse().unwrap());
    let c = LinkClient::start_with_listener(&id, cfg, device_listener).unwrap();
    assert!(c.wait_up(T).await);
    wait_audit(&h, |r| r["event"] == "hub_address_learned" && r["addr"] == "93.184.0.77").await;
    // Denied before any connection is tried (nothing leaves this machine).
    for host in ["93.184.0.77", "::ffff:93.184.0.77", "64:ff9b::5db8:4d"] {
        match c.open(host, 443).await {
            Err(LinkError::Refused { status: Status::Denied, message }) => assert_eq!(message, "the hub itself", "{host}"),
            other => panic!("{host}: expected a denial, got {:?}", other.map(|_| ())),
        }
    }
    let learned = h.hub.learned_addresses();
    assert_eq!(learned.len(), 1);
    assert_eq!(learned[0].device, id.fingerprint().short());
    assert!(learned[0].addrs.contains(&"93.184.0.77/32".parse().unwrap()));
    // Only that link: the hub-wide blocks do not have it.
    assert!(!h.hub.lan_blocks().contains(&"93.184.0.77/32".parse().unwrap()));
    h.hub.write_status();
    let st = read_status(h.hub.audit_path().parent().unwrap()).unwrap();
    assert!(st.learned.iter().any(|l| l.addrs.contains(&"93.184.0.77/32".parse().unwrap())));
    c.shutdown();
}

/// P2-C, hub listens: the local address the device reached is the hub's
/// own when it is public (injected: loopback stands in for it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_listening_hub_learns_the_address_it_was_reached_on() {
    let h = start_hub_cfg(true, |c| c.test_local_addr = Some("93.184.0.88".parse().unwrap())).await;
    let id = pair_new(&h, "d").await;
    let c = client(&h, &id).await;
    wait_audit(&h, |r| r["event"] == "hub_address_learned" && r["addr"] == "93.184.0.88").await;
    match c.open("93.184.0.88", 443).await {
        Err(LinkError::Refused { status: Status::Denied, message }) => assert_eq!(message, "the hub itself"),
        other => panic!("expected a denial, got {:?}", other.map(|_| ())),
    }
    c.shutdown();
}

/// P2-F: when making room would delete rows younger than the floor, the
/// hub opens no new streams and says why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_audit_log_within_the_floor_stops_new_streams() {
    let dir = tempfile::tempdir().unwrap();
    Hub::init(dir.path(), "test-hub").unwrap();
    // Three rotated files of fresh rows, one more than `keep` allows.
    let fresh = format!("{{\"ts_ms\":{},\"event\":\"stream\",\"outcome\":\"x\"}}\n", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
    for i in 1..=3 {
        std::fs::write(dir.path().join(format!("audit.log.{i}")), &fresh).unwrap();
    }
    let mut cfg = test_cfg(dir.path(), Duration::from_secs(5));
    cfg.audit = AuditConfig { max_bytes: 4096, keep: 2, ..AuditConfig::default() };
    let hub = Hub::open(cfg).unwrap();
    let addr = hub.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let h = TestHub { _dir: dir, hub, addr };
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    allow_loopback(&h, &id);
    let c = client(&h, &id).await;
    match c.open("127.0.0.1", echo).await {
        Err(LinkError::Refused { status: Status::Unavailable, message }) => assert!(message.contains("retention floor"), "{message}"),
        other => panic!("expected Unavailable, got {:?}", other.map(|_| ())),
    }
    // Nothing was deleted.
    for i in 1..=3 {
        assert!(h.hub.audit_path().with_extension(format!("log.{i}")).exists());
    }
    h.hub.write_status();
    let st = read_status(h.hub.audit_path().parent().unwrap()).unwrap();
    assert!(st.unavailable.unwrap().contains("retention floor"));
    // The owner moves the oldest away: streams again.
    std::fs::remove_file(h.hub.audit_path().with_extension("log.1")).unwrap();
    h.hub.flush_audit();
    let mut s = c.open("127.0.0.1", echo).await.unwrap();
    echo_once(&mut s, b"room again").await;
    c.shutdown();
}

/// P3: a store unreadable past the grace cuts every link; readable again,
/// the device comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_store_unreadable_past_the_grace_cuts_the_links() {
    let h = start_hub_cfg(true, |c| c.store_grace = Duration::from_millis(500)).await;
    let id = pair_new(&h, "d").await;
    let c = client(&h, &id).await;
    let path = h.hub.audit_path().parent().unwrap().join("hub.json");
    let good = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"{ damaged").unwrap();
    wait_audit(&h, |r| r["event"] == "store_unreadable_links_cut").await;
    wait_audit(&h, |r| r["event"] == "link_down" && r["outcome"] == "cut off").await;
    std::fs::write(&path, &good).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(c.wait_up(T).await, "the device linked again once the store read");
    c.shutdown();
}

/// P3: a rule change that denies an open stream's destination cuts it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rule_change_cuts_streams_it_now_denies() {
    let h = start_hub().await;
    let echo = echo_server().await;
    let id = pair_new(&h, "d").await;
    allow_loopback(&h, &id);
    let c = client(&h, &id).await;
    let mut s = c.open("echo.test", echo).await.unwrap();
    echo_once(&mut s, b"before").await;
    // A deny-suffix for the name: the open stream ends.
    let rules = Rules { allow_self: vec!["127.0.0.1/32".parse().unwrap()], deny_suffixes: vec!["echo.test".into()], ..Default::default() };
    h.hub.set_rules(&id.fingerprint().short(), rules).unwrap();
    let mut buf = [0u8; 8];
    let _ = s.write_all(b"after").await;
    let n = tokio::time::timeout(T, s.read(&mut buf)).await.expect("the stream was not cut");
    assert!(matches!(n, Ok(0) | Err(_)), "{n:?}");
    let row = wait_audit(&h, |r| r["event"] == "stream" && r["outcome"].as_str().unwrap().starts_with("cut off: now denied")).await;
    assert!(row["outcome"].as_str().unwrap().contains("domain denied"), "{row}");
    // Other streams of the device are left alone; the link stays up.
    let mut other = c.open("127.0.0.1", echo).await.unwrap();
    echo_once(&mut other, b"other").await;
    no_link_down(&h);
    c.shutdown();
}

#[derive(Debug)]
struct AnyKey;

impl PeerPolicy for AnyKey {
    fn accepts(&self, _: &Fingerprint) -> bool {
        true
    }
}

/// P3: a pairing answer with a status this device does not know says the
/// hub is newer, not that the code was used.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_newer_hubs_pairing_answer_says_so() {
    let hub_id = Identity::generate().unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let scfg = tls::server_config(&hub_id, Arc::new(AnyKey)).unwrap();
    let fake = tokio::spawn(async move {
        let (tcp, _) = l.accept().await.unwrap();
        let est = tls::accept(tcp, scfg, T).await.unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut tx = Some(tx);
        let stop = CancellationToken::new();
        let (_h, task) = mux::spawn_with(
            est.io.compat(),
            Mode::Server,
            mux::config(),
            move |s| {
                if let Some(t) = tx.take() {
                    let _ = t.send(s);
                }
            },
            stop.clone(),
        );
        let mut io = rx.await.unwrap().compat();
        assert!(matches!(read_msg(&mut io).await.unwrap(), Message::Pair { .. }));
        // A response with status 9: well-formed, unknown to this version.
        io.write_all(&[0, 3, 0x80, 9, 0]).await.unwrap();
        io.flush().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        stop.cancel();
        let _ = task.await;
    });
    let code = PairingCode::new(hub_id.fingerprint(), 60, Some(addr.to_string())).unwrap();
    let id = Identity::generate().unwrap();
    let err = pair(&id, &code, "d", PairVia::Dial(addr.to_string()), T).await.unwrap_err();
    assert!(err.to_string().contains("newer version"), "{err}");
    assert!(!err.to_string().contains("used"), "{err}");
    fake.await.unwrap();
}
