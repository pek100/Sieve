//! Loopback integration tests. Every socket is on 127.0.0.1 with an
//! ephemeral port; names resolve through a fixed map, never DNS.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sieve_link::device::{PairVia, pair};
use sieve_link::hub::revoke_at;
use sieve_link::mux::{self, Mode};
use sieve_link::resolve::StaticResolver;
use sieve_link::store::HubStore;
use sieve_link::tls::{self, Pinned};
use sieve_link::wire::{Message, Status, read_msg, write_msg};
use sieve_link::{Fingerprint, Hub, HubConfig, HubRoute, Identity, LinkClient, LinkConfig, LinkError, Limits, OnHubDown, Rules};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;

const T: Duration = Duration::from_secs(10);

fn resolver() -> StaticResolver {
    let mut m: HashMap<String, Vec<IpAddr>> = HashMap::new();
    m.insert("echo.test".into(), vec!["127.0.0.1".parse().unwrap()]);
    m.insert("blocked.test".into(), vec!["127.0.0.1".parse().unwrap()]);
    m.insert("private.test".into(), vec!["10.0.0.1".parse().unwrap()]);
    StaticResolver(m)
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

async fn start_hub_with(dead_after: Duration, listen: bool) -> TestHub {
    let dir = tempfile::tempdir().unwrap();
    Hub::init(dir.path(), "test-hub").unwrap();
    let mut cfg = HubConfig::new(dir.path());
    cfg.resolver = Arc::new(resolver());
    cfg.dead_after = dead_after;
    cfg.reload_every = Duration::from_millis(100);
    cfg.connect_timeout = Duration::from_secs(3);
    let hub = Hub::open(cfg).unwrap();
    let addr = if listen { hub.listen("127.0.0.1:0".parse().unwrap()).await.unwrap() } else { "127.0.0.1:9".parse().unwrap() };
    TestHub { _dir: dir, hub, addr }
}

async fn start_hub() -> TestHub {
    start_hub_with(Duration::from_secs(5), true).await
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

fn allow_loopback(h: &TestHub, id: &Identity) {
    let rules = Rules { allow_cidrs: vec!["127.0.0.1/32".parse().unwrap()], ..Default::default() };
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

    // Expired at the hub (the device's own clock check bypassed).
    let short = h.hub.create_pairing_code(1, None, "short").unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut late = short.clone();
    late.expires_at += 3600;
    assert!(pair(&second, &late, "late", PairVia::Dial(h.addr.to_string()), T).await.is_err());
    // And the device refuses an expired code itself.
    assert!(matches!(pair(&second, &short, "late", PairVia::Dial(h.addr.to_string()), T).await, Err(LinkError::Pairing(_))));
    assert_eq!(h.hub.devices().len(), 1);
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
    let rules = Rules { deny_suffixes: vec!["blocked.test".into()], allow_cidrs: vec!["127.0.0.1/32".parse().unwrap()], ..Default::default() };
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

    h.hub.set_limits(&key, Limits { max_concurrent: 10, opens_per_minute: 2, bytes_per_sec: 0 }).unwrap();
    let _a = c.open("127.0.0.1", echo).await.unwrap();
    let _b = c.open("127.0.0.1", echo).await.unwrap();
    assert_eq!(refused_status(c.open("127.0.0.1", echo).await), Status::RateLimited);
    wait_audit(&h, |r| r["event"] == "denied" && r["outcome"].as_str().unwrap().contains("per minute")).await;
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
    // 100 KB up + 100 KB back = 200 KB: at least ~1 s beyond the burst.
    echo_once(&mut s, &vec![1u8; 100_000]).await;
    assert!(start.elapsed() >= Duration::from_millis(700), "{:?}", start.elapsed());
    c.shutdown();
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
    let rules = Rules { allow_cidrs: vec!["127.0.0.1/32".parse().unwrap()], deny_suffixes: vec!["blocked.test".into()], ..Default::default() };
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
