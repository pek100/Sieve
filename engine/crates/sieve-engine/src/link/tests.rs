//! The engine as a link device, on loopback: an in-process hub from
//! `sieve_link`, names from a fixed map, the hub's own network from a fixed
//! list, every socket on 127.0.0.1 with an ephemeral port. Each test runs under
//! a hard limit.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sieve_ipc::{ExitVia, LinkHubDown, LinkRoute, LinkSettings, LinkState, LinkUdp, Signal};
use sieve_link::netif::{FixedInterfaces, HostNet, IfAddr};
use sieve_link::resolve::StaticResolver;
use sieve_link::{Hub, HubConfig, Rules};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::exit::{self, DnsExit, Exit, ExitReport, Opened, UdpOnLink, Upstream};
use super::*;
use crate::dns::Connector;
use crate::tls::intercept::Dial;

const T: Duration = Duration::from_secs(10);
/// A public address that stands in for a site (the hub resolves names itself).
pub(crate) const SITE: &str = "81.2.69.170";

/// Every test's hard limit.
fn run(body: impl std::future::Future<Output = ()>) {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    let out = rt.block_on(async { tokio::time::timeout(Duration::from_secs(60), body).await });
    rt.shutdown_timeout(Duration::from_secs(10));
    out.expect("the test timed out");
}

/// Loopback as the link's network: counts every connect it makes.
#[derive(Default)]
pub(crate) struct LoopNet {
    pub(crate) connects: AtomicUsize,
    /// Every target asked for, in order.
    pub(crate) targets: Mutex<Vec<SocketAddr>>,
    local: Mutex<Vec<IpAddr>>,
}

impl LoopNet {
    /// Whether anything was asked of `ip` (a direct connect to a site).
    pub(crate) fn asked(&self, ip: IpAddr) -> bool {
        self.targets.lock().unwrap().iter().any(|t| t.ip() == ip)
    }
}

impl LinkNet for LoopNet {
    fn connect(&self, target: SocketAddr) -> BoxFuture<'_, Result<TcpStream, String>> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        self.targets.lock().unwrap().push(target);
        // This machine's network is off limits: loopback only.
        if !target.ip().is_loopback() {
            return Box::pin(async move { Err(format!("{target}: not on loopback, never dialled in a test")) });
        }
        Box::pin(async move { TcpStream::connect(target).await.map_err(|e| e.to_string()) })
    }
    fn listen_ip(&self) -> Option<IpAddr> {
        Some(IpAddr::from([127, 0, 0, 1]))
    }
    fn is_local(&self, ip: IpAddr) -> bool {
        self.local.lock().unwrap().contains(&ip)
    }
}

impl Connector for LoopNet {
    fn tcp(&self, target: SocketAddr) -> BoxFuture<'_, Result<TcpStream, String>> {
        LinkNet::connect(self, target)
    }
    fn udp(&self, _target: SocketAddr) -> Result<socket2::Socket, String> {
        Err("no UDP here".into())
    }
}

pub(crate) struct TestHub {
    _dir: tempfile::TempDir,
    pub(crate) hub: Hub,
    pub(crate) addr: SocketAddr,
}

impl Drop for TestHub {
    fn drop(&mut self) {
        self.hub.shutdown();
    }
}

pub(crate) async fn hub(listen: bool) -> TestHub {
    let dir = tempfile::tempdir().unwrap();
    Hub::init(dir.path(), "home").unwrap();
    let mut cfg = HubConfig::new(dir.path());
    let mut names: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for n in ["echo.test", "site.test", "doh.test"] {
        names.insert(n.into(), vec!["127.0.0.1".parse().unwrap()]);
    }
    names.insert("private.test".into(), vec!["10.0.0.1".parse().unwrap()]);
    cfg.resolver = Arc::new(StaticResolver(names));
    let a = |s: &str, prefix: u8| IfAddr { addr: s.parse().unwrap(), prefix };
    cfg.interfaces = Arc::new(FixedInterfaces(HostNet { addrs: vec![a("192.168.1.10", 24)], gateways: vec!["192.168.1.1".parse().unwrap()], routes: vec!["0.0.0.0/0".parse().unwrap()] }));
    cfg.dead_after = Duration::from_secs(3);
    cfg.reload_every = Duration::from_millis(100);
    cfg.connect_timeout = Duration::from_secs(3);
    let hub = Hub::open(cfg).unwrap();
    let addr = if listen { hub.listen("127.0.0.1:0".parse().unwrap()).await.unwrap() } else { "127.0.0.1:9".parse().unwrap() };
    TestHub { _dir: dir, hub, addr }
}

/// The servers of these tests are on this machine's loopback: the hub allows
/// reaching itself for the paired device.
pub(crate) fn allow_loopback(h: &TestHub, device: &str) {
    let rules = Rules { allow_self: vec!["127.0.0.1/32".parse().unwrap()], ..Default::default() };
    h.hub.set_rules(device, rules).unwrap();
}

pub(crate) async fn echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

async fn echo_once<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: &mut S, msg: &[u8]) {
    s.write_all(msg).await.unwrap();
    let mut back = vec![0u8; msg.len()];
    tokio::time::timeout(T, s.read_exact(&mut back)).await.expect("echo timed out").unwrap();
    assert_eq!(back, msg);
}

pub(crate) fn manager(dir: &Path, net: Arc<LoopNet>) -> Arc<LinkManager> {
    Arc::new(LinkManager::new(Some(dir), Box::new(move || Ok(net.clone() as Arc<dyn LinkNet>)), crate::policy::wall_ms))
}

/// Whether nothing listens on 127.0.0.1:`port` any more: it can be bound again
/// (soon after a close). A connect would not say: a filtering proxy on the test
/// machine (AdGuard) may accept a loopback connect whatever listens.
pub(crate) async fn port_free(port: u16) -> bool {
    for _ in 0..40 {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

pub(crate) async fn until(what: &str, cond: impl Fn() -> bool) {
    for _ in 0..300 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("never happened: {what}");
}

/// Pairs `m` with `h` by dialling it, and allows loopback for the new device.
pub(crate) async fn paired(m: &Arc<LinkManager>, h: &TestHub) {
    let code = h.hub.create_pairing_code(60, Some(h.addr.to_string()), "engine").unwrap();
    m.pair(&code.encode(), None).unwrap();
    assert_eq!(m.status().state, LinkState::Pairing);
    until("paired", || m.status().state == LinkState::Off).await;
    let fp = m.status().device_fingerprint.unwrap();
    allow_loopback(h, &fp[..16]);
}

pub(crate) fn exiting(route: LinkRoute, on_hub_down: LinkHubDown) -> LinkSettings {
    LinkSettings { exit: true, on_hub_down, udp: LinkUdp::Drop, route }
}

pub(crate) fn noop_reset() -> Arc<dyn Fn() + Send + Sync> {
    Arc::new(|| {})
}

#[test]
fn pairing_keeps_the_hub_and_the_key_never_the_code_and_a_restart_keeps_it_and_unpair_forgets_it() {
    run(async {
        let h = hub(true).await;
        let dir = tempfile::tempdir().unwrap();
        let net = Arc::new(LoopNet::default());
        let m = manager(dir.path(), net.clone());
        assert_eq!(m.status().state, LinkState::Unpaired);
        let code = h.hub.create_pairing_code(60, Some(h.addr.to_string()), "engine").unwrap().encode();
        m.pair(&code, None).unwrap();
        until("paired", || m.status().state == LinkState::Off).await;
        assert!(net.connects.load(Ordering::SeqCst) >= 1, "the pairing socket came from the link's network");
        let s = m.status();
        assert_eq!(s.hub_name.as_deref(), Some("home"));
        assert_eq!(s.hub_fingerprint, Some(h.hub.fingerprint().to_string()));
        assert_eq!(s.settings.as_ref().map(|s| (s.exit, s.on_hub_down, s.udp)), Some((false, LinkHubDown::Stop, LinkUdp::Drop)), "off, stop and drop by default");
        assert!(h.hub.devices().iter().any(|d| Some(d.fingerprint.to_string()) == s.device_fingerprint), "the hub lists this engine");
        // Nothing on disk or in the status holds the code.
        let link = dir.path().join(LINK_DIR);
        for entry in std::fs::read_dir(&link).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains(&code[4..40]), "a file holds the code");
        }
        assert!(!serde_json::to_string(&s).unwrap().contains(&code[4..40]));
        // The code is used: a second redeem is refused by the hub.
        m.unpair().unwrap();
        m.pair(&code, None).unwrap();
        until("refused", || m.status().state == LinkState::Unpaired).await;
        assert!(m.status().last_error.is_some_and(|e| e.starts_with("Pairing failed") && !e.contains(&code[4..40])), "{:?}", m.status().last_error);

        // A restart keeps a pairing.
        let code = h.hub.create_pairing_code(60, Some(h.addr.to_string()), "engine").unwrap().encode();
        m.pair(&code, None).unwrap();
        until("paired again", || m.status().state == LinkState::Off).await;
        let before = m.status();
        let again = manager(dir.path(), net.clone());
        let after = again.status();
        assert_eq!((after.state, after.hub_fingerprint.clone(), after.device_fingerprint.clone()), (LinkState::Off, before.hub_fingerprint, before.device_fingerprint));
        // Unpair forgets the hub and the key.
        again.unpair().unwrap();
        assert!(!link.join(LINK_FILE).exists() && !link.join(KEY_FILE).exists());
        assert_eq!(manager(dir.path(), net).status().state, LinkState::Unpaired);
    });
}

#[test]
fn a_bad_an_expired_or_an_addressless_code_is_refused_without_echoing_it() {
    run(async {
        let h = hub(true).await;
        let dir = tempfile::tempdir().unwrap();
        let m = manager(dir.path(), Arc::new(LoopNet::default()));
        let secret = "SL1-NOTACODEBUTSECRETLOOKING";
        let err = m.pair(secret, None).unwrap_err();
        assert_eq!(err, NOT_A_CODE);
        assert!(m.pair(&"x".repeat(LINK_CODE_MAX + 1), None).is_err());
        let addressless = h.hub.create_pairing_code(60, None, "engine").unwrap().encode();
        assert_eq!(m.pair(&addressless, None).unwrap_err(), NO_ADDRESS);
        let name = LinkRoute::Dial { address: "home.example.net:7443".into() };
        assert!(m.pair(&addressless, Some(name)).unwrap_err().contains("IP address with a port"));
        assert_eq!(m.status().state, LinkState::Unpaired);
        assert_eq!(m.set(exiting(LinkRoute::Listen { port: 7443 }, LinkHubDown::Stop)).unwrap_err(), NOT_PAIRED);
    });
}

#[test]
fn exiting_relays_by_name_and_by_address_through_the_hub_and_its_own_socket_is_the_links() {
    run(async {
        let h = hub(true).await;
        let port = echo().await;
        let dir = tempfile::tempdir().unwrap();
        let net = Arc::new(LoopNet::default());
        let m = manager(dir.path(), net.clone());
        paired(&m, &h).await;
        let site: IpAddr = SITE.parse().unwrap();
        assert!(m.plan(site).is_none(), "exit is off");
        m.set(exiting(LinkRoute::Dial { address: h.addr.to_string() }, LinkHubDown::Stop)).unwrap();
        assert!(m.plan(site).is_none(), "Sieve does not route yet: nothing runs");
        assert_eq!(m.status().state, LinkState::Connecting);
        let before = net.connects.load(Ordering::SeqCst);
        m.routes_up(net.clone(), noop_reset());
        until("up", || m.status().state == LinkState::Up).await;
        assert!(net.connects.load(Ordering::SeqCst) > before, "the link's own socket came from the link's network, never a plain connect");

        let plan = m.plan(site).expect("a public address exits");
        let remote = SocketAddr::new(site, port);
        // By name: the hub resolves it.
        let (opened, report) = exit::open(&plan, &*net, &exit::choose_host(Some("echo.test"), site), port, remote).await;
        assert_eq!(report, ExitReport { via: ExitVia::Hub, target: Some(format!("echo.test:{port}")), reason: None, signal: None });
        let mut s = opened.unwrap();
        assert!(matches!(s, Opened::Hub(_)));
        echo_once(&mut s, b"through the hub by name").await;
        // By address, when no name is known.
        let (opened, report) = exit::open(&plan, &*net, &exit::choose_host(None, "127.0.0.1".parse().unwrap()), port, remote).await;
        assert_eq!(report.target, Some(format!("127.0.0.1:{port}")));
        echo_once(&mut opened.unwrap(), b"through the hub by address").await;
        let row = h.hub.audit_path();
        let audit = std::fs::read_to_string(row).unwrap_or_default();
        assert!(!audit.contains("through the hub"), "the hub never logs payload");

        // A hub refusal surfaces with its reason, and is never a reason to go direct.
        let mut direct_plan = plan.clone();
        direct_plan.on_hub_down = LinkHubDown::Direct;
        let (opened, report) = exit::open(&direct_plan, &*net, "private.test", port, remote).await;
        assert!(opened.is_err());
        assert_eq!((report.via, report.signal), (ExitVia::Refused, Some(Signal::HubRefused)));
        assert!(report.reason.as_deref().is_some_and(|r| r.starts_with("denied")), "{report:?}");
        m.routes_down();
        assert!(m.plan(site).is_none(), "routes down: nothing exits");
    });
}

#[test]
fn the_hub_down_stops_by_default_and_goes_direct_when_set() {
    run(async {
        let h = hub(true).await;
        let port = echo().await;
        let dir = tempfile::tempdir().unwrap();
        let net = Arc::new(LoopNet::default());
        let m = manager(dir.path(), net.clone());
        paired(&m, &h).await;
        m.set(exiting(LinkRoute::Dial { address: h.addr.to_string() }, LinkHubDown::Stop)).unwrap();
        let resets = Arc::new(AtomicUsize::new(0));
        let counted = resets.clone();
        m.routes_up(net.clone(), Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        }));
        until("up", || m.status().state == LinkState::Up).await;
        drop(h);
        until("down", || m.status().state == LinkState::Down).await;
        assert!(resets.load(Ordering::SeqCst) >= 2, "the resolver sessions were dropped on up and on down");

        let site: IpAddr = SITE.parse().unwrap();
        let plan = m.plan(site).unwrap();
        // The direct path's target stands in for the site: loopback here.
        let remote: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let (opened, report) = exit::open(&plan, &*net, "echo.test", port, remote).await;
        assert!(opened.is_err(), "stopped: nothing leaves from this computer");
        assert_eq!((report.via, report.signal), (ExitVia::Stopped, Some(Signal::HubDown)));
        let connects = net.connects.load(Ordering::SeqCst);
        m.set(exiting(LinkRoute::Dial { address: "127.0.0.1:9".into() }, LinkHubDown::Direct)).unwrap();
        let plan = m.plan(site).unwrap();
        let (opened, report) = exit::open(&plan, &*net, "echo.test", port, remote).await;
        assert_eq!((report.via, report.signal), (ExitVia::Direct, None));
        assert!(net.connects.load(Ordering::SeqCst) > connects);
        echo_once(&mut opened.unwrap(), b"direct, as set").await;
        // Off again: nothing exits, the link stops.
        let mut off = m.status().settings.unwrap();
        off.exit = false;
        m.set(off).unwrap();
        assert!(m.plan(site).is_none());
        assert_eq!(m.status().state, LinkState::Off);
    });
}

#[test]
fn listening_pairs_and_links_when_the_hub_dials_in_and_says_where_it_listens() {
    run(async {
        let h = hub(false).await;
        let port = echo().await;
        let dir = tempfile::tempdir().unwrap();
        let net = Arc::new(LoopNet::default());
        let m = manager(dir.path(), net.clone());
        let free = { TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port() };
        let code = h.hub.create_pairing_code(60, None, "engine").unwrap().encode();
        m.pair(&code, Some(LinkRoute::Listen { port: free })).unwrap();
        assert_eq!(m.status().listening, Some(format!("127.0.0.1:{free}")), "the status says what is open while pairing");
        h.hub.dial(format!("127.0.0.1:{free}"));
        until("paired", || m.status().state == LinkState::Off).await;
        assert_eq!(m.status().listening, None, "nothing open once paired and off");
        let fp = m.status().device_fingerprint.unwrap();
        allow_loopback(&h, &fp[..16]);
        m.set(exiting(LinkRoute::Listen { port: free }, LinkHubDown::Stop)).unwrap();
        assert_eq!(m.status().listening, None, "routes down: no port open");
        m.routes_up(net.clone(), noop_reset());
        assert_eq!(m.status().listening, Some(format!("127.0.0.1:{free}")));
        until("up", || m.status().state == LinkState::Up).await;
        let plan = m.plan(SITE.parse().unwrap()).unwrap();
        let (opened, _) = exit::open(&plan, &*net, "echo.test", port, SocketAddr::new(SITE.parse().unwrap(), port)).await;
        echo_once(&mut opened.unwrap(), b"the hub dialled in").await;
        m.routes_down();
        assert!(port_free(free).await, "the port closed with the routes");
    });
}

#[test]
fn lan_loopback_private_and_the_hubs_own_address_never_exit() {
    run(async {
        let h = hub(true).await;
        let dir = tempfile::tempdir().unwrap();
        let net = Arc::new(LoopNet::default());
        net.local.lock().unwrap().push("81.2.69.171".parse().unwrap());
        let m = manager(dir.path(), net.clone());
        paired(&m, &h).await;
        m.set(exiting(LinkRoute::Dial { address: "81.2.69.200:7443".into() }, LinkHubDown::Stop)).unwrap();
        m.routes_up(net.clone(), noop_reset());
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.1.5", "169.254.1.1", "100.64.0.1", "::1", "fe80::1", "fd00::1", "224.0.0.251", "239.255.255.250", "255.255.255.255", "::ffff:192.168.1.5", "81.2.69.171", "81.2.69.200"] {
            assert!(m.plan(ip.parse().unwrap()).is_none(), "{ip} must not exit");
        }
        for ip in [SITE, "2a00:1450:4001::200e"] {
            assert!(m.plan(ip.parse().unwrap()).is_some(), "{ip} exits");
        }
        m.routes_down();
    });
}

/// P1-2 (2026-11-20 review): only the flow's own bytes name what the hub is
/// asked for; a nameless flow goes by its address, never by a name Sieve's DNS
/// recorded for that address (which any page can plant).
#[test]
fn the_hub_is_asked_for_the_carried_name_else_the_address() {
    let ip: IpAddr = "81.2.69.170".parse().unwrap();
    assert_eq!(exit::choose_host(Some("Video.Example."), ip), "video.example");
    assert_eq!(exit::choose_host(None, ip), "81.2.69.170", "no name of its own: by address");
    assert_eq!(exit::choose_host(Some("81.2.69.170"), ip), "81.2.69.170");
    assert_eq!(exit::choose_host(Some("bad name"), ip), "81.2.69.170");
    assert_eq!(exit::choose_host(Some("localhost"), ip), "81.2.69.170", "a single label is no name to ask for");
    let v6: IpAddr = "2a00:1450:4001::200e".parse().unwrap();
    assert_eq!(exit::choose_host(None, v6), "2a00:1450:4001::200e");
    assert_eq!(exit::shown("2a00:1450:4001::200e", 443), "[2a00:1450:4001::200e]:443");
}

#[test]
fn quic_is_always_refused_and_other_udp_follows_the_setting() {
    assert_eq!(exit::udp_on_link(true, LinkUdp::Drop), UdpOnLink::RefuseQuic);
    assert_eq!(exit::udp_on_link(true, LinkUdp::Direct), UdpOnLink::RefuseQuic, "QUIC direct would show this computer's address to the sites");
    assert_eq!(exit::udp_on_link(false, LinkUdp::Drop), UdpOnLink::Drop);
    assert_eq!(exit::udp_on_link(false, LinkUdp::Direct), UdpOnLink::Direct);
}

#[test]
fn a_lazy_upstream_wakes_both_halves_and_a_failed_open_is_an_error_not_a_hang() {
    run(async {
        let port = echo().await;
        let (lazy, starter) = exit::lazy();
        let mut up = Upstream::Lazy(lazy);
        let (mut r, mut w) = tokio::io::split(&mut up);
        let reader = async move {
            let mut buf = [0u8; 5];
            r.read_exact(&mut buf).await.unwrap();
            buf
        };
        let writer = async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            starter.start(async move { TcpStream::connect(("127.0.0.1", port)).await.map(Opened::Tcp) });
            w.write_all(b"hello").await.unwrap();
        };
        let (got, ()) = tokio::time::timeout(T, async { tokio::join!(reader, writer) }).await.expect("both halves were woken");
        assert_eq!(&got, b"hello");

        let (lazy, starter) = exit::lazy();
        let mut up = Upstream::Lazy(lazy);
        starter.start(async { Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "the hub refused")) });
        let mut buf = [0u8; 1];
        assert!(tokio::time::timeout(T, up.read(&mut buf)).await.unwrap().is_err());
        let net: Arc<dyn LinkNet> = Arc::new(LoopNet::default());
        let dir = tempfile::tempdir().unwrap();
        let ex = Exit { net, link: manager(dir.path(), Arc::new(LoopNet::default())), book: Arc::default() };
        let (lazy, starter) = exit::lazy();
        let mut up = Upstream::Lazy(lazy);
        starter.start(async { Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "stopped")) });
        assert!(ex.ready(&mut up).await.is_err(), "interception hears the failure before any handshake");
        // A lazy stream never started (a blocked flow) closes without opening.
        let (lazy, _starter) = exit::lazy();
        let mut up = Upstream::Lazy(lazy);
        tokio::time::timeout(T, up.shutdown()).await.unwrap().unwrap();
    });
}

/// A CA and a server for one name, on loopback.
fn tls_server(name: &str) -> (Arc<rustls::RootCertStore>, Arc<rustls::ServerConfig>) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca = params.self_signed(&ca_key).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![name.to_string()]).unwrap().signed_by(&key, &Issuer::from_params(&params, &ca_key)).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], rustls_pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap())
        .unwrap();
    (Arc::new(roots), Arc::new(config))
}

async fn tls_echo(config: Arc<rustls::ServerConfig>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(s).await {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = tls.read(&mut buf).await {
                        let _ = tls.write_all(&buf[..n]).await;
                        let _ = tls.flush().await;
                    }
                }
            });
        }
    });
    port
}

async fn shake(stream: Upstream, roots: Arc<rustls::RootCertStore>, name: &str) -> Result<(), String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
    let server = rustls_pki_types::ServerName::try_from(name.to_string()).unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(server, stream).await.map_err(|e| e.to_string())?;
    echo_once(&mut tls, b"end to end").await;
    Ok(())
}

/// What interception and Sieve's DNS do through the link: a fresh connection
/// by name (`Exit::dial_named`) and a resolver session (`DnsExit`), each with a
/// TLS handshake that validates the real server's certificate end to end. The
/// hub only carries bytes: a name the certificate does not cover fails.
#[test]
fn interception_and_encrypted_dns_through_the_link_validate_the_real_certificate_end_to_end() {
    run(async {
        let h = hub(true).await;
        let (roots, server) = tls_server("site.test");
        let port = tls_echo(server).await;
        let dir = tempfile::tempdir().unwrap();
        let net = Arc::new(LoopNet::default());
        let m = manager(dir.path(), net.clone());
        paired(&m, &h).await;
        m.set(exiting(LinkRoute::Dial { address: h.addr.to_string() }, LinkHubDown::Stop)).unwrap();
        m.routes_up(net.clone(), noop_reset());
        until("up", || m.status().state == LinkState::Up).await;
        let remote = SocketAddr::new(SITE.parse().unwrap(), port);

        let ex = Exit { net: net.clone(), link: m.clone(), book: Arc::default() };
        let fresh = ex.dial_named(remote, "site.test", 1).await.unwrap();
        assert!(matches!(fresh, Upstream::Opened(Opened::Hub(_))), "by name through the hub");
        shake(fresh, roots.clone(), "site.test").await.unwrap();
        let wrong = ex.dial_named(remote, "site.test", 1).await.unwrap();
        assert!(shake(wrong, roots.clone(), "other.test").await.is_err(), "the certificate is checked against the name, end to end");

        let dns = DnsExit { inner: net.clone(), net: net.clone(), link: m.clone() };
        let session = dns.resolver_stream(remote, "doh.test").await.unwrap();
        // doh.test resolves at the hub to the same server, whose certificate names site.test.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots.clone()).with_no_client_auth();
        let server_name = rustls_pki_types::ServerName::try_from("site.test".to_string()).unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(server_name, session).await.unwrap();
        echo_once(&mut tls, b"resolver session").await;
        let audit = std::fs::read_to_string(h.hub.audit_path()).unwrap_or_default();
        assert!(audit.contains(&format!("doh.test:{port}")), "the hub was asked for the resolver by name");
        // A LAN resolver is never asked through the link.
        let lan: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let connects = net.connects.load(Ordering::SeqCst);
        let _ = dns.resolver_stream(lan, "doh.test").await.unwrap();
        assert_eq!(net.connects.load(Ordering::SeqCst), connects + 1, "directly, through the egress");
        m.routes_down();
    });
}

#[test]
fn an_exit_row_says_how_the_flow_went_and_a_hub_problem_counts_once_with_no_other_row() {
    use crate::stack::book::FlowBook;
    let mut book = FlowBook::default();
    let id = book.open(crate::stack::book::tests_event(Some(1))).unwrap();
    book.own(id, Some("browser".into()));
    book.exit(id, ExitReport { via: ExitVia::Refused, target: Some("shop.example:443".into()), reason: Some("denied: not on the allow-list".into()), signal: Some(Signal::HubRefused) });
    book.close(id, sieve_ipc::FlowAction::Failed, 0, 0);
    let rows = book.take_log();
    assert_eq!(rows.len(), 1, "one row, the exit's: {rows:?}");
    assert!(matches!(&rows[0].outcome, sieve_ipc::LogOutcome::Exit { via: ExitVia::Refused, reason: Some(r), .. } if r.contains("allow-list")));
    let issues = book.issues(1);
    let problems: Vec<_> = issues.iter().flat_map(|a| &a.problems).collect();
    assert_eq!(problems.len(), 1);
    assert_eq!((problems[0].signal, problems[0].cause), (Signal::HubRefused, sieve_ipc::Cause::Hub), "the hub's, never Sieve's or the app's");
}

/// P2-2: with the global switch off nothing exits: the link stops, its port
/// closes, the status says off, and DNS goes as without it. On again, it runs.
#[test]
fn with_sieving_off_nothing_exits_the_link_stops_and_its_port_closes() {
    run(async {
        let h = hub(false).await;
        let dir = tempfile::tempdir().unwrap();
        let net = Arc::new(LoopNet::default());
        let m = manager(dir.path(), net.clone());
        let free = { TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port() };
        let code = h.hub.create_pairing_code(60, None, "engine").unwrap().encode();
        m.pair(&code, Some(LinkRoute::Listen { port: free })).unwrap();
        h.hub.dial(format!("127.0.0.1:{free}"));
        until("paired", || m.status().state == LinkState::Off).await;
        m.set(exiting(LinkRoute::Listen { port: free }, LinkHubDown::Stop)).unwrap();
        m.routes_up(net.clone(), noop_reset());
        until("up", || m.status().state == LinkState::Up).await;
        let site: IpAddr = SITE.parse().unwrap();
        assert!(m.plan(site).is_some());

        m.set_sieving(false);
        assert!(m.plan(site).is_none(), "paused: nothing exits");
        assert!(m.may_leave_directly(site));
        let s = m.status();
        assert_eq!((s.state, s.listening), (LinkState::Off, None), "stopped, and no port is said to be open");
        assert!(port_free(free).await, "the port closed");
        // DNS: the resolver session is not asked of the link (LoopNet refuses the
        // non-loopback target itself, so the error is the direct path's).
        let dns = DnsExit { inner: net.clone(), net: net.clone(), link: m.clone() };
        let err = dns.resolver_stream(SocketAddr::new(site, 443), "doh.test").await.err().unwrap();
        assert!(!err.contains("through the other device"), "{err}");
        assert!(net.asked(site), "directly, as without the link");

        m.set_sieving(true);
        assert!(m.plan(site).is_some(), "on again: exiting applies");
        assert_eq!(m.status().listening, Some(format!("127.0.0.1:{free}")));
        m.routes_down();
    });
}

/// P2-3: every change of the way out is told once, with the destinations it
/// concerns and the new way; a change of another choice is not.
#[test]
fn a_change_of_the_way_out_is_told_with_what_it_concerns() {
    run(async {
        let h = hub(true).await;
        let dir = tempfile::tempdir().unwrap();
        let net = Arc::new(LoopNet::default());
        let m = manager(dir.path(), net.clone());
        paired(&m, &h).await;
        let told: Arc<Mutex<Vec<(ExitVia, bool, bool)>>> = Arc::default();
        let into = told.clone();
        m.on_exit_change(Arc::new(move |concerns: &dyn Fn(IpAddr) -> bool, via: ExitVia| {
            into.lock().unwrap().push((via, concerns(SITE.parse().unwrap()), concerns("10.0.0.1".parse().unwrap())));
        }));
        m.routes_up(net.clone(), noop_reset());
        assert!(told.lock().unwrap().is_empty(), "exit is off: nothing changed");
        let on = exiting(LinkRoute::Dial { address: h.addr.to_string() }, LinkHubDown::Stop);
        m.set(on.clone()).unwrap();
        assert_eq!(*told.lock().unwrap(), [(ExitVia::Hub, true, false)], "on: public destinations, through the hub");
        m.set(LinkSettings { udp: LinkUdp::Direct, ..on.clone() }).unwrap();
        assert_eq!(told.lock().unwrap().len(), 1, "the UDP choice is no change of the way out for TCP");
        m.network_changed();
        assert_eq!(told.lock().unwrap().len(), 2, "a restart on a new network");
        m.set_sieving(false);
        assert_eq!(told.lock().unwrap().last(), Some(&(ExitVia::Direct, true, false)), "paused: directly from now on");
        m.set_sieving(true);
        m.set(LinkSettings { exit: false, ..on }).unwrap();
        assert_eq!(told.lock().unwrap().last(), Some(&(ExitVia::Direct, true, false)));
        assert_eq!(told.lock().unwrap().len(), 5);
        m.routes_down();
    });
}

/// An open flow's connection the book can end, as `ipstack`'s handle.
struct Ends(Arc<std::sync::atomic::AtomicBool>);

impl crate::stack::book::Idle for Ends {
    fn idle(&self) -> Duration {
        Duration::ZERO
    }
    fn evict(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// P2-3: the open TCP connections of sieved apps to destinations the change
/// concerns are ended, once, with one row; an app that is Off, a local
/// destination and UDP are left alone.
#[test]
fn a_change_of_the_way_out_ends_the_open_connections_it_concerns() {
    use crate::domain::{DomainFilter, FilterSlot};
    use crate::stack::book::{FlowBook, tests_event};
    let book = Mutex::new(FlowBook::default());
    let policy = sieve_ipc::Policy { sieving: true, off_apps: vec!["turned-off".into()], ..sieve_ipc::Policy::default() };
    let filter = FilterSlot::new(DomainFilter::new(&policy, sieve_filter::rules::RuleSet::empty()));
    let mut flows = Vec::new();
    for (key, remote, proto) in [
        (Some("browser"), "81.2.69.170:443", sieve_ipc::FlowProto::Tcp),
        (None, "81.2.69.170:443", sieve_ipc::FlowProto::Tcp),
        (Some("Turned-Off"), "81.2.69.170:443", sieve_ipc::FlowProto::Tcp),
        (Some("browser"), "10.0.0.1:443", sieve_ipc::FlowProto::Tcp),
        (Some("browser"), "81.2.69.170:443", sieve_ipc::FlowProto::Udp),
    ] {
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut b = book.lock().unwrap();
        let mut e = tests_event(Some(1));
        e.remote = remote.into();
        e.proto = proto;
        let idle: Option<Box<dyn crate::stack::book::Idle>> = (proto == sieve_ipc::FlowProto::Tcp).then(|| Box::new(Ends(ended.clone())) as _);
        let id = b.open_with(e, idle).unwrap();
        b.own(id, key.map(str::to_string));
        flows.push(ended);
    }
    let concerns = |ip: IpAddr| sieve_link::rules::denied_class(ip).is_none();
    let n = crate::stack::relay::reconnect_the_new_way(&book, &filter, &concerns, ExitVia::Hub);
    let ended: Vec<bool> = flows.iter().map(|f| f.load(Ordering::SeqCst)).collect();
    assert_eq!(ended, [true, true, false, false, false], "a sieved app's and an unknown app's public TCP only");
    assert_eq!(n, 2);
    let rows = book.lock().unwrap().take_log();
    assert_eq!(rows.len(), 1, "one summary row: {rows:?}");
    assert!(matches!(&rows[0].outcome, sieve_ipc::LogOutcome::Exit { via: ExitVia::Hub, target: None, reason: Some(r) } if r.contains("2 open connections")), "{rows:?}");
    assert_eq!(rows[0].session, Some(0), "every client sees it");
}

/// P2-6: a flow decided after the link restarted (a network move, here) opens on
/// the new link: the plan reads the running link when its open starts.
#[test]
fn a_plan_taken_before_a_restart_opens_on_the_new_link() {
    run(async {
        let h = hub(true).await;
        let port = echo().await;
        let dir = tempfile::tempdir().unwrap();
        let net = Arc::new(LoopNet::default());
        let m = manager(dir.path(), net.clone());
        paired(&m, &h).await;
        m.set(exiting(LinkRoute::Dial { address: h.addr.to_string() }, LinkHubDown::Stop)).unwrap();
        m.routes_up(net.clone(), noop_reset());
        until("up", || m.status().state == LinkState::Up).await;
        let site: IpAddr = SITE.parse().unwrap();
        let plan = m.plan(site).unwrap();
        m.network_changed();
        assert_eq!(m.status().state, LinkState::Connecting, "a dialling link restarts on a network move too");
        until("up again", || m.status().state == LinkState::Up).await;
        // The SYN-time plan's own client was shut down by the restart: an open on
        // it would be stopped. The plan reads the running one.
        let (opened, report) = exit::open(&plan, &*net, "echo.test", port, SocketAddr::new(site, port)).await;
        assert_eq!(report.via, ExitVia::Hub, "{report:?}");
        echo_once(&mut opened.unwrap(), b"on the new link").await;
        m.routes_down();
    });
}

/// P2-4: only a link that is not there is "down" (the hub-down setting then
/// decides); a linked hub that is slow or answers oddly is as a refusal, never
/// a reason to go direct. The hub answers before the device gives up.
#[test]
fn a_slow_hub_that_is_linked_is_a_refusal_and_answers_before_the_device_gives_up() {
    use exit::{Failed, failed};
    use sieve_link::LinkError;
    assert!(matches!(failed(LinkError::Timeout("hub answer"), true), Failed::Refused(w) if w.contains("did not answer in time")));
    assert!(matches!(failed(LinkError::Protocol("odd".into()), true), Failed::Refused(_)));
    assert!(matches!(failed(LinkError::Timeout("hub answer"), false), Failed::Down(_)), "the link went away meanwhile");
    assert!(matches!(failed(LinkError::HubDown, true), Failed::Down(_)));
    assert!(matches!(failed(LinkError::Io(std::io::Error::other("reset")), true), Failed::Down(_)));
    let refused = failed(LinkError::Refused { status: sieve_link::wire::Status::Denied, message: "no".into() }, false);
    assert_eq!(refused, Failed::Refused("denied: no".into()));
    run(async {
        let h = hub(true).await;
        let device = sieve_link::LinkConfig::new(h.hub.fingerprint(), sieve_link::HubRoute::Dial(h.addr.to_string()));
        let dir = tempfile::tempdir().unwrap();
        let hub = sieve_link::HubConfig::new(dir.path());
        assert!(hub.slot_wait + hub.connect_timeout < device.request_timeout, "the hub's worst answer comes before the device gives up");
    });
}

/// P3: a pairing that was finishing when the owner unpaired does not undo the
/// unpair: nothing is kept, nothing is written.
#[test]
fn an_unpair_is_never_undone_by_a_pairing_that_was_finishing() {
    run(async {
        let h = hub(true).await;
        let dir = tempfile::tempdir().unwrap();
        let m = manager(dir.path(), Arc::new(LoopNet::default()));
        let code = h.hub.create_pairing_code(60, None, "engine").unwrap().encode();
        // A pairing that waits (the hub never dials in), then an unpair.
        let free = { TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port() };
        m.pair(&code, Some(LinkRoute::Listen { port: free })).unwrap();
        let generation = lock(&m.state).pair_generation;
        m.unpair().unwrap();
        // The pairing's end arrives after the unpair, as when it raced it.
        let outcome = Ok((sieve_link::Identity::generate().unwrap(), h.hub.fingerprint(), "home".to_string()));
        m.paired(generation, &dir.path().join(LINK_DIR), LinkRoute::Listen { port: free }, outcome);
        assert_eq!(m.status().state, LinkState::Unpaired);
        assert!(!dir.path().join(LINK_DIR).join(LINK_FILE).exists(), "nothing written");
    });
}

/// P3: the hub's refusal and any error reach the log and the app as one plain
/// line: control and bidirectional characters are spaces.
#[test]
fn text_from_outside_is_one_plain_line() {
    assert_eq!(said("denied:\u{202E}moc.evil\u{2066}\r\nnext"), "denied: moc.evil   next");
    assert_eq!(said("x".repeat(LINK_TEXT_MAX + 50)).len(), LINK_TEXT_MAX);
}

/// P3: interception's fresh dials never leave directly for a destination exiting
/// concerns (by address too: `Exit::dial`), and a stop is written on the flow's
/// row as the hub's problem, so the flow's failure is not counted as the app's.
#[test]
fn interceptions_fresh_dials_go_only_through_the_link_and_say_so_on_the_row() {
    run(async {
        let h = hub(true).await;
        let dir = tempfile::tempdir().unwrap();
        let net = Arc::new(LoopNet::default());
        let m = manager(dir.path(), net.clone());
        paired(&m, &h).await;
        m.set(exiting(LinkRoute::Dial { address: h.addr.to_string() }, LinkHubDown::Stop)).unwrap();
        m.routes_up(net.clone(), noop_reset());
        until("up", || m.status().state == LinkState::Up).await;
        drop(h);
        until("down", || m.status().state == LinkState::Down).await;
        let site: SocketAddr = format!("{SITE}:443").parse().unwrap();
        let book: Arc<Mutex<crate::stack::book::FlowBook>> = Arc::default();
        let id = {
            let mut b = book.lock().unwrap();
            let id = b.open(crate::stack::book::tests_event(Some(1))).unwrap();
            b.own(id, Some("browser".into()));
            id
        };
        let ex = Exit { net: net.clone(), link: m.clone(), book: book.clone() };
        assert!(ex.dial(site).await.is_err(), "by address: stopped, as set");
        assert!(ex.dial_named(site, "site.test", id).await.is_err(), "by name: stopped, as set");
        assert!(!net.asked(site.ip()), "nothing went to the site from this computer");
        let mut b = book.lock().unwrap();
        b.close(id, sieve_ipc::FlowAction::Failed, 0, 0);
        let rows = b.take_log();
        assert_eq!(rows.iter().filter(|r| matches!(r.outcome, sieve_ipc::LogOutcome::Exit { via: ExitVia::Stopped, .. })).count(), 1, "{rows:?}");
        let problems: Vec<_> = b.issues(1).into_iter().flat_map(|a| a.problems).collect();
        assert_eq!(problems.iter().map(|p| p.signal).collect::<Vec<_>>(), [Signal::HubDown], "the hub's problem, no lost connection");
        drop(b);
        m.routes_down();
    });
}
