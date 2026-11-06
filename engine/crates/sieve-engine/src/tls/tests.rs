//! Interception against local servers, over two transports (task, "Offline
//! acceptance"): `tokio::io::duplex`, and `127.0.0.1:0` sequentially under one
//! lock (conventions: this machine's loopback loses replies in parallel). The
//! CA runs on fakes; the trust verifier is a fake (task D3): a real
//! `rustls-platform-verifier` call could ask Windows Update for roots.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs::kx_group::{SECP256R1, X25519, X25519MLKEM768};
use rustls::crypto::{CryptoProvider, aws_lc_rs, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, NamedGroup, RootCertStore, ServerConfig, SignatureScheme};
use sieve_filter::exclusions::{AutoReason, Pattern, Source as EntrySource, UpstreamVerdict};
use sieve_filter::rules::{ListText, RuleEngine, RuleSet};
use sieve_ipc::{FlowAction, FlowKind, FlowProto, LogOutcome, Policy};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::active::Active;
use super::intercept::{ClientWatch, Dial, DialFuture, FlowMeta, HttpsSlot, Interception, NoWatch, Outcome, Pair, run};
use super::upstream::{Chain, PlatformTrust, TRUST_TIMEOUT, TrustAnswer, TrustVerifier, Verifier, filter_alpn, handshake, is_post_handshake_auth, rustls_error};
use super::verdict::VerdictCache;
use super::{provider, public_roots};
use crate::ca::key::MemoryKeyStore;
use crate::ca::trust::{FakeFirefox, FakeRootStore};
use crate::ca::{Ca, Minter, Seams};
use crate::dns::NameMap;
use crate::domain::{DomainFilter, FilterSlot};
use crate::exclusions::browsers::{BrowserRegistry, BrowserSet};
use crate::exclusions::{AutoEntry, ExclusionSlot};
use crate::flow::classify::Decoded;
use crate::flow::flows::Action;
use crate::http::hook::{NoRewrite, ResponseHook};
use crate::policy::wall_ms;
use crate::stack::Meters;
use crate::stack::book::FlowBook;

pub(crate) const HOST: &str = "site.example";
pub(crate) const CHROME: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
const DAY_S: i64 = 86_400;
const LIMIT: Duration = Duration::from_secs(60);
const SHORT: Duration = Duration::from_millis(50);
/// certificatePolicies holding the CA/B EV policy, as DER.
const EV_POLICIES: [u8; 11] = [0x30, 0x09, 0x30, 0x07, 0x06, 0x05, 0x67, 0x81, 0x0c, 0x01, 0x01];
const CERT_POLICIES_OID: [u64; 4] = [2, 5, 29, 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arm {
    Duplex,
    Loopback,
}

pub(crate) const ARMS: [Arm; 2] = [Arm::Duplex, Arm::Loopback];

/// One loopback scenario at a time, machine-wide in this test binary.
static LOOPBACK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

impl Arm {
    pub(crate) async fn guard(self) -> Option<tokio::sync::MutexGuard<'static, ()>> {
        match self {
            Arm::Duplex => None,
            Arm::Loopback => Some(LOOPBACK.lock().await),
        }
    }
}

macro_rules! arms {
    ($name:ident, $body:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            for arm in crate::tls::tests::ARMS {
                let _guard = arm.guard().await;
                tokio::time::timeout(crate::tls::tests::LIMIT_FOR_ARMS, ($body)(arm)).await.unwrap_or_else(|_| panic!("{arm:?} timed out"));
            }
        }
    };
}
pub(crate) use arms;
pub(crate) const LIMIT_FOR_ARMS: Duration = LIMIT;

// ---- Chains: one rcgen helper, no AIA or CRL URLs.

pub(crate) struct Pki {
    params: CertificateParams,
    key: KeyPair,
    pub(crate) der: CertificateDer<'static>,
}

#[derive(Clone, Copy)]
pub(crate) struct LeafOpts {
    pub(crate) from_days: i64,
    pub(crate) to_days: i64,
    pub(crate) ev: bool,
}

pub(crate) const GOOD: LeafOpts = LeafOpts { from_days: -1, to_days: 30, ev: false };

impl Pki {
    pub(crate) fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        let key = KeyPair::generate().unwrap();
        let der = params.self_signed(&key).unwrap().der().clone();
        Self { params, key, der }
    }

    pub(crate) fn roots(&self) -> Arc<RootCertStore> {
        let mut store = RootCertStore::empty();
        store.add(self.der.clone()).unwrap();
        Arc::new(store)
    }

    pub(crate) fn leaf(&self, name: &str, opts: LeafOpts) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now + time::Duration::seconds(opts.from_days * DAY_S);
        params.not_after = now + time::Duration::seconds(opts.to_days * DAY_S);
        if opts.ev {
            params.custom_extensions.push(CustomExtension::from_oid_content(&CERT_POLICIES_OID, EV_POLICIES.to_vec()));
        }
        let cert = params.signed_by(&key, &Issuer::from_params(&self.params, &self.key)).unwrap();
        (vec![cert.der().clone()], PrivatePkcs8KeyDer::from(key.serialize_der()).into())
    }
}

/// A server config from a chain, with these ALPN values and groups.
pub(crate) fn server_tls(chain: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), alpn: &[&str], groups: Option<Vec<&'static dyn rustls::crypto::SupportedKxGroup>>) -> Arc<ServerConfig> {
    let provider = CryptoProvider { kx_groups: groups.unwrap_or_else(super::kx_groups), ..aws_lc_rs::default_provider() };
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider)).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(chain.0, chain.1).unwrap();
    config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Arc::new(config)
}

/// The same, with no tickets. The engine hangs up on a server it rejected right
/// after its handshake; one with tickets to send fails that write, so its side
/// of the handshake would not count as finished.
pub(crate) fn server_tls_no_tickets(chain: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)) -> Arc<ServerConfig> {
    let mut config = (*server_tls(chain, &[], None)).clone();
    config.send_tls13_tickets = 0;
    Arc::new(config)
}

// ---- Streams that remember what crossed them.

pub(crate) trait IoStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> IoStream for T {}

/// What a stream's far end sent.
#[derive(Clone, Default)]
pub(crate) struct Seen(Arc<Mutex<Vec<u8>>>);

impl Seen {
    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

pub(crate) struct Recording<S> {
    pub(crate) inner: S,
    pub(crate) read: Seen,
    pub(crate) written: Seen,
}

impl<S> Recording<S> {
    fn new(inner: S) -> Self {
        Self { inner, read: Seen::default(), written: Seen::default() }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Recording<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.read.0.lock().unwrap().extend_from_slice(&buf.filled()[before..]);
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Recording<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = polled {
            self.written.0.lock().unwrap().extend_from_slice(&data[..n]);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---- The upstream: scripted, on either transport.

pub(crate) type BoxStream = Box<dyn IoStream>;
pub(crate) type Handler = Arc<dyn Fn(usize, BoxStream) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// The recording connector: every socket a path opens comes from here.
pub(crate) struct TestDial {
    arm: Arm,
    handler: Handler,
    /// What each connection received, in dial order.
    pub(crate) conns: Mutex<Vec<Seen>>,
    /// Where the sockets really went (the loopback arm).
    pub(crate) peers: Mutex<Vec<SocketAddr>>,
    /// Dials past this many fail.
    pub(crate) allow: AtomicUsize,
}

impl TestDial {
    pub(crate) fn new(arm: Arm, handler: Handler) -> Self {
        Self { arm, handler, conns: Mutex::default(), peers: Mutex::default(), allow: AtomicUsize::new(usize::MAX) }
    }

    pub(crate) fn seen(&self, conn: usize) -> Vec<u8> {
        self.conns.lock().unwrap()[conn].bytes()
    }

    pub(crate) fn count(&self) -> usize {
        self.conns.lock().unwrap().len()
    }

    async fn open(&self) -> Result<BoxStream, String> {
        let index = {
            let mut conns = self.conns.lock().unwrap();
            if conns.len() >= self.allow.load(Ordering::Relaxed) {
                return Err("refused by the test".to_string());
            }
            conns.push(Seen::default());
            conns.len() - 1
        };
        let seen = self.conns.lock().unwrap()[index].clone();
        let (far, near): (BoxStream, BoxStream) = match self.arm {
            Arm::Duplex => {
                let (a, b): (DuplexStream, DuplexStream) = tokio::io::duplex(1 << 20);
                (Box::new(a), Box::new(b))
            }
            Arm::Loopback => {
                let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
                let local = listener.local_addr().map_err(|e| e.to_string())?;
                let (near, far) = tokio::join!(TcpStream::connect(local), listener.accept());
                let near = near.map_err(|e| e.to_string())?;
                self.peers.lock().unwrap().push(near.peer_addr().map_err(|e| e.to_string())?);
                (Box::new(far.map_err(|e| e.to_string())?.0), Box::new(near))
            }
        };
        let far = Recording { inner: far, read: seen, written: Seen::default() };
        tokio::spawn((self.handler)(index, Box::new(far)));
        Ok(near)
    }
}

impl Dial for TestDial {
    type Stream = BoxStream;

    fn dial(&self, _target: SocketAddr) -> DialFuture<'_, BoxStream> {
        Box::pin(self.open())
    }
}

/// A server that answers TLS with `configs[min(conn, last)]`, runs `after` on
/// the session and echoes nothing itself.
pub(crate) fn tls_server<F, Fut>(configs: Vec<Arc<ServerConfig>>, shaken: Arc<AtomicUsize>, after: F) -> Handler
where
    F: Fn(usize, tokio_rustls::server::TlsStream<BoxStream>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let after = Arc::new(after);
    raw(move |conn, stream| {
        let config = configs[conn.min(configs.len() - 1)].clone();
        let (after, shaken) = (after.clone(), shaken.clone());
        async move {
            if let Ok(tls) = tokio_rustls::TlsAcceptor::from(config).accept(stream).await {
                shaken.fetch_add(1, Ordering::Relaxed);
                after(conn, tls).await;
            }
        }
    })
}

/// A handler from a plain async closure.
pub(crate) fn raw<F, Fut>(f: F) -> Handler
where
    F: Fn(usize, BoxStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    Arc::new(move |conn, stream| Box::pin(f(conn, stream)))
}

/// Echoes until the client ends.
pub(crate) async fn echo<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) {
    let mut buf = [0u8; 4096];
    while let Ok(n) = stream.read(&mut buf).await {
        if n == 0 || stream.write_all(&buf[..n]).await.is_err() || stream.flush().await.is_err() {
            break;
        }
    }
    let _ = stream.shutdown().await;
}

// ---- The trust fake.

pub(crate) struct FakeTrust {
    pub(crate) answer: Mutex<TrustAnswer>,
    pub(crate) calls: AtomicUsize,
    pub(crate) blocks: Duration,
}

impl FakeTrust {
    pub(crate) fn says(answer: TrustAnswer) -> Arc<Self> {
        Arc::new(Self { answer: Mutex::new(answer), calls: AtomicUsize::new(0), blocks: Duration::ZERO })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl TrustVerifier for FakeTrust {
    fn verify(&self, _chain: &Chain, _host: &ServerName<'static>) -> TrustAnswer {
        self.calls.fetch_add(1, Ordering::Relaxed);
        std::thread::sleep(self.blocks);
        *self.answer.lock().unwrap()
    }
}

struct FakeBrowsers;

impl BrowserRegistry for FakeBrowsers {
    fn commands(&self) -> Vec<String> {
        vec![format!("\"{CHROME}\"")]
    }
}

// ---- The rig.

/// A CA on fakes, its root made at `made_ms`.
pub(crate) fn test_ca(made_ms: u64) -> (Arc<Ca>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let seams = Seams { keys: Arc::new(MemoryKeyStore::default()), store: Arc::new(FakeRootStore::default()), firefox: Arc::new(FakeFirefox::default()) };
    let ca = Arc::new(Ca::new(dir.path().to_path_buf(), "BOX".into(), seams).unwrap());
    ca.reconcile(true, made_ms).unwrap();
    (ca, dir)
}

pub(crate) struct Rig {
    pub(crate) deps: Arc<Interception<TestDial>>,
    pub(crate) minter: Arc<Minter>,
    pub(crate) trust: Arc<FakeTrust>,
    _ca: Arc<Ca>,
    _dirs: Vec<tempfile::TempDir>,
}

pub(crate) struct RigOpts {
    pub(crate) roots: Arc<RootCertStore>,
    pub(crate) trust: Arc<FakeTrust>,
    pub(crate) trust_timeout: Duration,
    pub(crate) rules: RuleSet,
    pub(crate) hook: Arc<dyn ResponseHook>,
    pub(crate) minter: bool,
    pub(crate) skip_ev: bool,
    pub(crate) ca_made_ms: u64,
    pub(crate) watch: Arc<dyn ClientWatch>,
    pub(crate) clock: fn() -> u64,
}

impl RigOpts {
    pub(crate) fn new(roots: Arc<RootCertStore>) -> Self {
        Self { roots, trust: FakeTrust::says(TrustAnswer::Trusted), trust_timeout: TRUST_TIMEOUT, rules: RuleSet::empty(), hook: Arc::new(NoRewrite), minter: true, skip_ev: true, ca_made_ms: wall_ms(), watch: Arc::new(NoWatch), clock: wall_ms }
    }
}

pub(crate) fn list_rules(text: &str) -> RuleSet {
    RuleSet { user: Arc::new(RuleEngine::empty()), lists: Arc::new(RuleEngine::compile(&[ListText { id: "fixture", text, trusted: false }])) }
}

impl Rig {
    pub(crate) fn new(dial: TestDial, opts: RigOpts) -> Self {
        let (ca, ca_dir) = test_ca(opts.ca_made_ms);
        let minter = ca.minter().expect("a root");
        let store_dir = tempfile::tempdir().unwrap();
        let mut slot = ExclusionSlot::with_sources(Some(store_dir.path()), &[], Vec::new(), wall_ms());
        if !opts.skip_ev {
            slot = slot.without_ev_skip();
        }
        slot.set_browsers(BrowserSet::read(&FakeBrowsers));
        let policy = Policy { sieving: true, https: true, ..Policy::default() };
        let minted = (ca.clone(), opts.minter);
        let deps = Interception {
            connector: Arc::new(dial),
            exclusions: Arc::new(slot),
            verifier: Arc::new(Verifier::new(opts.roots, opts.trust.clone(), opts.trust_timeout).unwrap()),
            verdicts: VerdictCache::default(),
            active: Active::default(),
            minter: Box::new(move || if minted.1 { minted.0.minter() } else { None }),
            filter: Arc::new(FilterSlot::new(DomainFilter::new(&policy, opts.rules))),
            names: Arc::new(Mutex::new(NameMap::default())),
            book: Arc::new(Mutex::new(FlowBook::default())),
            meters: Arc::new(Meters::default()),
            watch: opts.watch,
            hook: opts.hook,
            clock: opts.clock,
        };
        Rig { deps: Arc::new(deps), minter, trust: opts.trust, _ca: ca, _dirs: vec![ca_dir, store_dir] }
    }

    /// An open flow in the book, as `admit` makes it.
    fn open_flow(&self) -> u64 {
        let event = sieve_ipc::FlowEvent {
            id: 0,
            pid: Some(42),
            exe: Some(CHROME.into()),
            session: Some(1),
            proto: FlowProto::Tcp,
            local: "198.18.0.1:5000".into(),
            remote: "192.0.2.1:443".into(),
            kind: FlowKind::Tls,
            host: Some(HOST.into()),
            action: FlowAction::Relayed,
            bytes_up: 0,
            bytes_down: 0,
            open: true,
            reason: None,
            rule: None,
            list: None,
            forwarded: None,
        };
        self.deps.book.lock().unwrap().open(event).unwrap()
    }

    /// One flow: the app's end, and its task. The SYN-time socket comes first,
    /// as `handle_tcp` opens it.
    pub(crate) async fn flow(&self, opts: FlowOpts) -> (DuplexStream, JoinHandle<Outcome>) {
        let (app_end, stack_end) = tokio::io::duplex(1 << 20);
        let id = self.open_flow();
        let upstream = self.deps.connector.open().await.expect("the SYN-time socket");
        let deps = self.deps.clone();
        let task = tokio::spawn(async move {
            let decide = move |_: &Decoded| opts.action;
            let meta = FlowMeta { id, remote: opts.remote, exe: opts.exe, session: opts.session, may_decrypt: opts.may_decrypt, app_off: opts.app_off, names_now_ms: 0, decide: &decide };
            let out = run(&deps, stack_end, upstream, meta).await;
            deps.book.lock().unwrap().close(id, out.action, out.bytes_up, out.bytes_down);
            out
        });
        (app_end, task)
    }

    pub(crate) fn reasons(&self) -> Vec<String> {
        self.deps
            .book
            .lock()
            .unwrap()
            .take_log()
            .into_iter()
            .filter_map(|r| match r.outcome {
                LogOutcome::NotDecrypted { reason } => Some(reason),
                _ => None,
            })
            .collect()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct FlowOpts {
    pub(crate) remote: SocketAddr,
    pub(crate) exe: Option<&'static str>,
    pub(crate) session: Option<u32>,
    pub(crate) may_decrypt: bool,
    pub(crate) app_off: bool,
    pub(crate) action: Action,
}

pub(crate) fn flow_opts() -> FlowOpts {
    FlowOpts { remote: "192.0.2.1:443".parse().unwrap(), exe: Some(CHROME), session: Some(1), may_decrypt: true, app_off: false, action: Action::Pass }
}

// ---- The client: accepts anything, and remembers what it was shown.

#[derive(Debug, Default)]
pub(crate) struct Shown(Mutex<Option<Vec<u8>>>);

impl Shown {
    pub(crate) fn leaf(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone().expect("a certificate was shown")
    }
}

#[derive(Debug)]
struct ClientAccepts {
    shown: Arc<Shown>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for ClientAccepts {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, TlsError> {
        *self.shown.0.lock().unwrap() = Some(end_entity.to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A browser's stand-in: judges nothing itself, remembers the leaf.
pub(crate) fn client_tls(alpn: &[&str], groups: Option<Vec<&'static dyn rustls::crypto::SupportedKxGroup>>) -> (Arc<ClientConfig>, Arc<Shown>) {
    let provider = Arc::new(CryptoProvider { kx_groups: groups.unwrap_or_else(super::kx_groups), ..aws_lc_rs::default_provider() });
    let shown = Arc::<Shown>::default();
    let verifier = Arc::new(ClientAccepts { shown: shown.clone(), provider: provider.clone() });
    let mut config = ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    (Arc::new(config), shown)
}

pub(crate) type ClientTls = tokio_rustls::client::TlsStream<Recording<DuplexStream>>;

/// A handshake over the app's end; the bytes it wrote stay readable.
pub(crate) async fn connect(app: DuplexStream, config: Arc<ClientConfig>, sni: &str) -> Result<ClientTls, (std::io::Error, Seen)> {
    let recording = Recording::new(app);
    let written = recording.written.clone();
    tokio_rustls::TlsConnector::from(config).connect(ServerName::try_from(sni.to_string()).unwrap(), recording).await.map_err(|e| (e, written))
}

pub(crate) fn issuer_of(der: &[u8]) -> String {
    X509Certificate::from_der(der).unwrap().1.issuer().to_string()
}

fn subject_of(der: &[u8]) -> String {
    X509Certificate::from_der(der).unwrap().1.subject().to_string()
}

/// Whoever minted what the client saw is Sieve.
pub(crate) fn shown_is_sieves(shown: &Shown, rig: &Rig) -> bool {
    issuer_of(&shown.leaf()) == subject_of(rig.minter.root_der())
}

fn expect_real(shown: &Shown, rig: &Rig) {
    assert!(!shown_is_sieves(shown, rig), "the client judged the real certificate");
}

/// One upstream on `configs`, echoing.
fn echo_dial(arm: Arm, configs: Vec<Arc<ServerConfig>>) -> (TestDial, Arc<AtomicUsize>) {
    let shaken = Arc::new(AtomicUsize::new(0));
    (TestDial::new(arm, tls_server(configs, shaken.clone(), |_, tls| echo(tls))), shaken)
}

/// Not TLS and not the start of a request, so the classifier answers at once.
const PING: [u8; 4] = [0, 1, 2, 3];

/// A round trip of plain bytes through whatever the path is.
async fn round_trip<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
    stream.write_all(&PING).await.unwrap();
    stream.flush().await.unwrap();
    let mut pong = [0u8; PING.len()];
    stream.read_exact(&mut pong).await.unwrap();
    assert_eq!(pong, PING);
}

// ---- Upstream first and the verifier stack.

async fn passes_through(arm: Arm, pki: &Pki, leaf_pki: &Pki, opts: LeafOpts, sni_on_cert: &str, trust: Arc<FakeTrust>, reason: &str) -> Rig {
    let config = server_tls_no_tickets(leaf_pki.leaf(sni_on_cert, opts));
    let (dial, shaken) = echo_dial(arm, vec![config]);
    let rig = Rig::new(dial, RigOpts { trust, ..RigOpts::new(pki.roots()) });
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    expect_real(&shown, &rig);
    round_trip(&mut tls).await;
    assert_eq!(shaken.load(Ordering::Relaxed), 2, "our handshake on the first socket, the client's own on the fresh one");
    assert_eq!(rig.deps.connector.count(), 2);
    // The client's bytes reached the real server unchanged, in order.
    let sent = tls.get_ref().0.written.bytes();
    let arrived = rig.deps.connector.seen(1);
    assert_eq!(arrived[..sent.len().min(arrived.len())], sent[..sent.len().min(arrived.len())]);
    tls.shutdown().await.unwrap();
    drop(tls);
    assert_eq!(task.await.unwrap().action, FlowAction::Relayed);
    assert_eq!(rig.reasons(), [reason]);
    rig
}

arms!(expired_chain_passes_through_with_client_hello_intact, |arm| async move {
    let pki = Pki::new("Test Public Root");
    passes_through(arm, &pki, &pki, LeafOpts { from_days: -30, to_days: -1, ev: false }, HOST, FakeTrust::says(TrustAnswer::Trusted), "floor:upstream-invalid").await;
});

arms!(wrong_name_passes_through, |arm| async move {
    let pki = Pki::new("Test Public Root");
    passes_through(arm, &pki, &pki, GOOD, "other.example", FakeTrust::says(TrustAnswer::Trusted), "floor:upstream-invalid").await;
});

arms!(unknown_root_passes_through_and_never_asks_the_trust_verifier, |arm| async move {
    let (public, private) = (Pki::new("Test Public Root"), Pki::new("A Corporate Proxy"));
    let trust = FakeTrust::says(TrustAnswer::Trusted);
    passes_through(arm, &public, &private, GOOD, HOST, trust.clone(), "floor:non-public-root").await;
    assert_eq!(trust.calls(), 0, "a private root never touches CryptoAPI");
});

arms!(sieves_own_root_upstream_passes_through, |arm| async move {
    // The upstream shows a leaf of the engine's own root: no stacking.
    let pki = Pki::new("Test Public Root");
    let (ca, _dir) = test_ca(wall_ms());
    let minter = ca.minter().unwrap();
    let leaf = minter.leaf(crate::ca::LeafRequest { host: HOST, upstream_not_after_ms: u64::MAX }, wall_ms()).unwrap();
    let chain = (vec![CertificateDer::from(leaf.der.clone()), CertificateDer::from(minter.root_der().to_vec())], PrivatePkcs8KeyDer::from(minter.leaf_key_pkcs8().to_vec()).into());
    let (dial, _) = echo_dial(arm, vec![server_tls(chain, &[], None)]);
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, _) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.reasons(), ["floor:non-public-root"]);
});

arms!(trust_failure_passes_through, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let trust = FakeTrust::says(TrustAnswer::Rejected);
    passes_through(arm, &pki, &pki, GOOD, HOST, trust.clone(), "floor:upstream-invalid").await;
    assert_eq!(trust.calls(), 1);
});

arms!(revoked_passes_through_and_closes_open_flows_to_that_host, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let configs = vec![server_tls(pki.leaf(HOST, GOOD), &[], None), server_tls(pki.leaf(HOST, GOOD), &[], None)];
    let (dial, _) = echo_dial(arm, configs);
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    // The first connection is intercepted and stays open.
    let (app, first_task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut first = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig));
    round_trip(&mut first).await;
    // A new leaf, a new trust call, and this time it is revoked.
    *rig.trust.answer.lock().unwrap() = TrustAnswer::Revoked;
    let (app, second_task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut second = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    expect_real(&shown, &rig);
    round_trip(&mut second).await;
    // The open flow ended.
    tokio::time::timeout(Duration::from_secs(10), first_task).await.expect("the open flow closed").unwrap();
    let mut rest = Vec::new();
    let _ = first.read_to_end(&mut rest).await;
    assert!(rest.is_empty());
    drop(second);
    second_task.await.unwrap();
    assert_eq!(rig.reasons(), ["floor:upstream-revoked"]);
});

arms!(trust_timeout_passes_through_and_is_not_cached, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let trust = Arc::new(FakeTrust { answer: Mutex::new(TrustAnswer::Trusted), calls: AtomicUsize::new(0), blocks: Duration::from_millis(400) });
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts { trust, trust_timeout: SHORT, ..RigOpts::new(pki.roots()) });
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    expect_real(&shown, &rig);
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.reasons(), ["floor:upstream-unavailable"]);
    assert!(rig.deps.verdicts.get(HOST, 443, wall_ms()).is_none(), "not cached");
});

#[tokio::test]
async fn the_trust_call_does_not_block_the_runtime() {
    // One worker: if the call ran on it, nothing else could.
    let pki = Pki::new("Test Public Root");
    let trust = Arc::new(FakeTrust { answer: Mutex::new(TrustAnswer::Trusted), calls: AtomicUsize::new(0), blocks: Duration::from_millis(300) });
    let verifier = Verifier::new(pki.roots(), trust, Duration::from_secs(10)).unwrap();
    let (chain, _) = pki.leaf(HOST, GOOD);
    let chain = Chain { end_entity: chain[0].clone(), intermediates: Vec::new(), ocsp: Vec::new() };
    let ticks = Arc::new(AtomicU64::new(0));
    let ticker = {
        let ticks = ticks.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                ticks.fetch_add(1, Ordering::Relaxed);
            }
        })
    };
    assert_eq!(verifier.verify(&chain, HOST, false).await, UpstreamVerdict::Eligible);
    ticker.abort();
    assert!(ticks.load(Ordering::Relaxed) >= 5, "only {} ticks", ticks.load(Ordering::Relaxed));
}

arms!(no_client_byte_reaches_upstream_before_the_verdict, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let trust = Arc::new(FakeTrust { answer: Mutex::new(TrustAnswer::Trusted), calls: AtomicUsize::new(0), blocks: Duration::from_millis(300) });
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts { trust: trust.clone(), ..RigOpts::new(pki.roots()) });
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let connecting = tokio::spawn(connect(app, client, HOST));
    // While the trust call runs, the client has no answer.
    while trust.calls() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!connecting.is_finished(), "nothing was answered before the verdict");
    let during = rig.deps.connector.seen(0);
    let mut tls = connecting.await.unwrap().unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig));
    // The client's random: record header 5, handshake header 4, version 2.
    let hello = tls.get_ref().0.written.bytes();
    let random = &hello[11..43];
    assert!(!during.is_empty() && !during.windows(random.len()).any(|w| w == random), "the upstream saw the engine's hello, not the client's");
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
});

#[tokio::test]
async fn resumption_is_disabled_upstream_so_the_verifier_always_runs() {
    let pki = Pki::new("Test Public Root");
    // A server that issues tickets, handshaking twice: both show their chain.
    let config = server_tls(pki.leaf(HOST, GOOD), &[], None);
    for _ in 0..2 {
        let (near, far) = tokio::io::duplex(1 << 16);
        let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
        let server = tokio::spawn(async move {
            if let Ok(tls) = acceptor.accept(far).await {
                echo(tls).await;
            }
        });
        match handshake(near, HOST, Vec::new()).await {
            super::upstream::HandshakeEnd::Done(shaken) => assert!(!shaken.chain.end_entity.is_empty(), "the verifier ran"),
            _ => panic!("no handshake"),
        }
        server.abort();
    }
    let capture = Arc::default();
    let shown = format!("{:?}", super::upstream::client_config(&capture, Vec::new()).unwrap().resumption);
    assert!(shown.contains("NoClientSessionStorage"), "{shown}");
}

arms!(replay_on_a_fresh_socket_is_byte_exact, |arm| async move {
    let pki = Pki::new("Test Public Root");
    // The fresh socket (connection 1) is raw: it records and answers plainly.
    let shaken = Arc::new(AtomicUsize::new(0));
    let tls_side = tls_server(vec![server_tls(pki.leaf("other.example", GOOD), &[], None)], shaken, |_, tls| echo(tls));
    let handler = raw(move |conn, stream| {
        let tls_side = tls_side.clone();
        async move {
            if conn == 0 {
                tls_side(conn, stream).await;
            } else {
                echo(stream).await;
            }
        }
    });
    let rig = Rig::new(TestDial::new(arm, handler), RigOpts::new(pki.roots()));
    let (mut app, task) = rig.flow(flow_opts()).await;
    // A real ClientHello, split across writes, with bytes after it.
    let (client, _) = client_tls(&[], None);
    let mut conn = rustls::ClientConnection::new(client, ServerName::try_from(HOST).unwrap()).unwrap();
    let mut hello = Vec::new();
    conn.write_tls(&mut hello).unwrap();
    let (head, tail) = hello.split_at(30);
    app.write_all(head).await.unwrap();
    app.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    app.write_all(tail).await.unwrap();
    app.write_all(b"TRAILING").await.unwrap();
    let mut sent = hello.clone();
    sent.extend_from_slice(b"TRAILING");
    let mut echoed = vec![0u8; sent.len()];
    app.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, sent, "both directions after");
    assert_eq!(rig.deps.connector.seen(1), sent, "exact");
    app.write_all(b"more").await.unwrap();
    let mut more = [0u8; 4];
    app.read_exact(&mut more).await.unwrap();
    assert_eq!(&more, b"more");
    drop(app);
    let out = task.await.unwrap();
    assert_eq!((out.action, out.bytes_up), (FlowAction::Relayed, sent.len() as u64 + 4));
});

arms!(fresh_connect_failure_closes_the_app_side_and_the_book_says_failed, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf("other.example", GOOD), &[], None)]);
    dial.allow.store(1, Ordering::Relaxed);
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, _) = client_tls(&[], None);
    assert!(connect(app, client, HOST).await.is_err(), "the app side closed");
    assert_eq!(task.await.unwrap().action, FlowAction::Failed);
    let batch = rig.deps.book.lock().unwrap().take_batch();
    assert_eq!(batch.last().map(|e| (e.action, e.open)), Some((FlowAction::Failed, false)));
});

arms!(verdict_cache_rejection_skips_the_handshake, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let (dial, shaken) = echo_dial(arm, vec![server_tls_no_tickets(pki.leaf("other.example", GOOD))]);
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    for _ in 0..2 {
        let (app, task) = rig.flow(flow_opts()).await;
        let (client, _) = client_tls(&[], None);
        let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
        round_trip(&mut tls).await;
        drop(tls);
        task.await.unwrap();
    }
    assert_eq!(rig.deps.connector.count(), 3, "first: ours and a fresh one; second: the SYN-time socket alone");
    assert_eq!(shaken.load(Ordering::Relaxed), 3, "ours once, the client's twice");
    assert_eq!(rig.reasons(), ["floor:upstream-invalid", "floor:upstream-invalid"]);
});

arms!(same_leaf_skips_only_the_trust_call, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let (dial, shaken) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    for _ in 0..2 {
        let (app, task) = rig.flow(flow_opts()).await;
        let (client, shown) = client_tls(&[], None);
        let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
        assert!(shown_is_sieves(&shown, &rig));
        round_trip(&mut tls).await;
        drop(tls);
        task.await.unwrap();
    }
    assert_eq!(rig.trust.calls(), 1, "the trust call once");
    assert_eq!(shaken.load(Ordering::Relaxed), 2, "the handshake each time");
});

arms!(a_cached_trust_ends_at_24h_however_often_the_host_is_visited, |arm| async move {
    static NOW: AtomicU64 = AtomicU64::new(0);
    fn clock() -> u64 {
        NOW.load(Ordering::Relaxed)
    }
    const HOUR_MS: u64 = 3_600_000;
    let start = wall_ms();
    NOW.store(start, Ordering::Relaxed);
    let pki = Pki::new("Test Public Root");
    // One leaf throughout: only the trust answer changes.
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts { clock, ..RigOpts::new(pki.roots()) });
    let (app, open_task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut open = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig));
    round_trip(&mut open).await;
    *rig.trust.answer.lock().unwrap() = TrustAnswer::Revoked;
    // A visit inside the 24 h skips the call, and must not extend the 24 h.
    NOW.store(start + 23 * HOUR_MS, Ordering::Relaxed);
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig), "still inside the cached verdict");
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.trust.calls(), 1, "the same leaf skips the call");
    // 24 h after the call that was really made.
    NOW.store(start + 24 * HOUR_MS, Ordering::Relaxed);
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert_eq!(rig.trust.calls(), 2, "the OS is asked again");
    expect_real(&shown, &rig);
    round_trip(&mut tls).await;
    tokio::time::timeout(Duration::from_secs(10), open_task).await.expect("the open flow closed").unwrap();
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.reasons(), ["floor:upstream-revoked"]);
});

/// A flow held inside its trust call; `during` runs while it is there.
async fn close_during_the_trust_call(arm: Arm, during: impl FnOnce(&Rig), reason: &str) {
    let pki = Pki::new("Test Public Root");
    let trust = Arc::new(FakeTrust { answer: Mutex::new(TrustAnswer::Trusted), calls: AtomicUsize::new(0), blocks: Duration::from_millis(300) });
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts { trust: trust.clone(), ..RigOpts::new(pki.roots()) });
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let connecting = tokio::spawn(connect(app, client, HOST));
    while trust.calls() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    during(&rig);
    let mut tls = connecting.await.unwrap().unwrap_or_else(|(e, _)| panic!("{e}"));
    expect_real(&shown, &rig);
    round_trip(&mut tls).await;
    assert_eq!(rig.deps.meters.https.intercepted.load(Ordering::Relaxed), 0);
    assert!(rig.deps.active.is_empty(), "a pass-through is not an intercepted flow");
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.reasons(), [reason]);
}

arms!(off_during_the_trust_call_never_decrypts, |arm| async move {
    close_during_the_trust_call(
        arm,
        |rig| {
            let slot = HttpsSlot::default();
            slot.set(Some(rig.deps.clone()));
            slot.set(None);
        },
        "off",
    )
    .await;
});

arms!(a_revocation_found_during_the_trust_call_reaches_the_flow, |arm| async move {
    close_during_the_trust_call(arm, |rig| rig.deps.active.close_host(HOST), "floor:upstream-revoked").await;
});

arms!(off_during_the_client_handshake_closes_it_without_blaming_the_client, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let watched = Arc::new(Watched::default());
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts { watch: watched.clone(), ..RigOpts::new(pki.roots()) });
    let (mut app, task) = rig.flow(flow_opts()).await;
    // A hello, then silence: the engine's answer proves the local handshake began.
    let (client, _) = client_tls(&[], None);
    let mut conn = rustls::ClientConnection::new(client, ServerName::try_from(HOST).unwrap()).unwrap();
    let mut hello = Vec::new();
    conn.write_tls(&mut hello).unwrap();
    app.write_all(&hello).await.unwrap();
    let mut answer = [0u8; 1];
    app.read_exact(&mut answer).await.unwrap();
    rig.deps.active.close_all();
    tokio::time::timeout(LIMIT, task).await.expect("closed").unwrap();
    let mut rest = Vec::new();
    let _ = app.read_to_end(&mut rest).await;
    assert!(watched.refused.lock().unwrap().is_empty(), "the engine closed it: not evidence about the client");
});

arms!(a_flow_that_starts_after_the_close_never_decrypts, |arm| async move {
    // It took the slot's `Interception` before the switch went off.
    let pki = Pki::new("Test Public Root");
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    rig.deps.active.close_all();
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    expect_real(&shown, &rig);
    round_trip(&mut tls).await;
    assert_eq!(rig.deps.connector.count(), 1, "the SYN-time socket, unused until now");
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.reasons(), ["off"]);
});

/// A pass-through decided after our handshake: while the fresh socket is spliced
/// the first one has ended, so the server never holds two connections.
async fn first_socket_ends_during_the_splice(arm: Arm, opts: LeafOpts, ca_made_ms: u64, reason: &str) {
    let pki = Pki::new("Test Public Root");
    let ended: Arc<Mutex<Vec<usize>>> = Arc::default();
    let record = ended.clone();
    let config = server_tls(pki.leaf(HOST, opts), &[], None);
    // Ends with the socket, whichever step of the server's it finds that in.
    let handler = raw(move |conn, stream| {
        let (record, config) = (record.clone(), config.clone());
        async move {
            if let Ok(tls) = tokio_rustls::TlsAcceptor::from(config).accept(stream).await {
                echo(tls).await;
            }
            record.lock().unwrap().push(conn);
        }
    });
    let rig = Rig::new(TestDial::new(arm, handler), RigOpts { ca_made_ms, ..RigOpts::new(pki.roots()) });
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, _) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    round_trip(&mut tls).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !ended.lock().unwrap().contains(&0) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("connection 0 saw its end");
    round_trip(&mut tls).await;
    assert!(!task.is_finished(), "the splice is still open");
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.reasons(), [reason]);
}

arms!(a_rejected_upstream_ends_its_first_socket_before_the_splice, |arm| async move {
    first_socket_ends_during_the_splice(arm, LeafOpts { from_days: -30, to_days: -1, ev: false }, wall_ms(), "floor:upstream-invalid").await;
});

arms!(a_failed_mint_ends_the_first_socket_before_the_splice, |arm| async move {
    first_socket_ends_during_the_splice(arm, GOOD, wall_ms() - 400 * 86_400_000, "floor:no-root").await;
});

arms!(server_first_bytes_are_forwarded_and_the_flow_only_splices, |arm| async move {
    let handler = raw(|_, mut stream| async move {
        let _ = stream.write_all(b"220 ready\r\n").await;
        let _ = stream.flush().await;
        echo(stream).await;
    });
    let pki = Pki::new("Test Public Root");
    let rig = Rig::new(TestDial::new(arm, handler), RigOpts::new(pki.roots()));
    let (mut app, task) = rig.flow(flow_opts()).await;
    let mut banner = [0u8; 11];
    app.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"220 ready\r\n");
    round_trip(&mut app).await;
    drop(app);
    assert_eq!(task.await.unwrap().action, FlowAction::Relayed);
    assert_eq!(rig.deps.connector.count(), 1, "no second socket");
});

// ---- Client certificate, EV.

fn cert_server(pki: &Pki, client_pki: &Pki, required: bool) -> Arc<ServerConfig> {
    let builder = WebPkiClientVerifier::builder_with_provider(client_pki.roots(), provider());
    let verifier = if required { builder.build() } else { builder.allow_unauthenticated().build() }.unwrap();
    let (chain, key) = pki.leaf(HOST, GOOD);
    Arc::new(ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap().with_client_cert_verifier(verifier).with_single_cert(chain, key).unwrap())
}

arms!(client_cert_request_passes_through_and_adds_auto_entry, |arm| async move {
    let (pki, clients) = (Pki::new("Test Public Root"), Pki::new("Clients"));
    let (dial, _) = echo_dial(arm, vec![cert_server(&pki, &clients, false)]);
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    for round in 0..2 {
        let (app, task) = rig.flow(flow_opts()).await;
        let (client, shown) = client_tls(&[], None);
        let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
        expect_real(&shown, &rig);
        round_trip(&mut tls).await;
        drop(tls);
        task.await.unwrap();
        assert_eq!(rig.deps.connector.count(), if round == 0 { 2 } else { 3 }, "the second connect skips the handshake");
    }
    assert_eq!(rig.reasons(), ["auto:client-cert", "auto:client-cert"]);
    assert!(rig.deps.exclusions.get_at(wall_ms()).find(Some(HOST), "192.0.2.1".parse().unwrap(), Some(CHROME), true) == Some(&EntrySource::Auto(AutoReason::ClientCert)));
});

arms!(an_asker_under_an_unknown_root_writes_nothing_to_the_store, |arm| async move {
    let (public, private, clients) = (Pki::new("Test Public Root"), Pki::new("A Corporate Proxy"), Pki::new("Clients"));
    let (dial, _) = echo_dial(arm, vec![cert_server(&private, &clients, false)]);
    let rig = Rig::new(dial, RigOpts::new(public.roots()));
    for round in 0..2 {
        let (app, task) = rig.flow(flow_opts()).await;
        let (client, shown) = client_tls(&[], None);
        let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
        expect_real(&shown, &rig);
        round_trip(&mut tls).await;
        drop(tls);
        task.await.unwrap();
        assert_eq!(rig.deps.connector.count(), if round == 0 { 2 } else { 3 }, "the rejection is remembered, in the bounded cache");
    }
    assert_eq!(rig.reasons(), ["floor:non-public-root", "floor:non-public-root"]);
    assert_eq!(rig.deps.exclusions.get_at(wall_ms()).find(Some(HOST), "192.0.2.1".parse().unwrap(), Some(CHROME), true), None);
    assert_eq!(rig.trust.calls(), 0);
    rig.deps.exclusions.flush();
    assert!(!crate::exclusions::auto::path(rig._dirs[1].path()).exists(), "nothing reached the disk");
});

arms!(client_presents_its_own_certificate_to_the_real_server_through_the_splice, |arm| async move {
    let (pki, clients) = (Pki::new("Test Public Root"), Pki::new("Clients"));
    let presented = Arc::new(AtomicUsize::new(0));
    let saw = presented.clone();
    let handler = tls_server(vec![cert_server(&pki, &clients, true)], Arc::default(), move |_, tls| {
        if tls.get_ref().1.peer_certificates().is_some_and(|c| !c.is_empty()) {
            saw.fetch_add(1, Ordering::Relaxed);
        }
        echo(tls)
    });
    let rig = Rig::new(TestDial::new(arm, handler), RigOpts::new(pki.roots()));
    let (app, task) = rig.flow(flow_opts()).await;
    let (chain, key) = clients.leaf("me.example", GOOD);
    let shown = Arc::<Shown>::default();
    let verifier = Arc::new(ClientAccepts { shown: shown.clone(), provider: provider() });
    let config = ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap().dangerous().with_custom_certificate_verifier(verifier).with_client_auth_cert(chain, key).unwrap();
    let mut tls = connect(app, Arc::new(config), HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    round_trip(&mut tls).await;
    expect_real(&shown, &rig);
    assert_eq!(presented.load(Ordering::Relaxed), 1, "the real server saw the client's certificate");
    drop(tls);
    task.await.unwrap();
});

#[test]
fn post_handshake_error_closes_and_adds_the_entry() {
    // Mapping level: the rustls server cannot send post-handshake auth; real
    // behaviour is U9 in the runbook.
    let auth = TlsError::InappropriateHandshakeMessage { expect_types: vec![], got_type: rustls::HandshakeType::CertificateRequest };
    assert!(is_post_handshake_auth(&auth));
    assert!(!is_post_handshake_auth(&TlsError::InappropriateHandshakeMessage { expect_types: vec![], got_type: rustls::HandshakeType::Certificate }));
    assert!(!is_post_handshake_auth(&TlsError::DecryptError));
    let wrapped = std::io::Error::new(std::io::ErrorKind::InvalidData, auth);
    assert!(rustls_error(&wrapped).is_some_and(is_post_handshake_auth), "found through the I/O error hyper would carry");
}

arms!(ev_oid_passes_through_and_expires_with_the_certificate, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let ev = LeafOpts { ev: true, ..GOOD };
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, ev), &[], None)]);
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    expect_real(&shown, &rig);
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.reasons(), ["auto:ev"]);
    let store = |now| rig.deps.exclusions.get_at(now).find(Some(HOST), "192.0.2.1".parse().unwrap(), Some(CHROME), true).cloned();
    assert_eq!(store(wall_ms()), Some(EntrySource::Auto(AutoReason::Ev)));
    assert_eq!(store(wall_ms() + 31 * 86_400_000), None, "gone with its certificate (30 days)");
});

arms!(ev_with_skip_off_intercepts, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let ev = LeafOpts { ev: true, ..GOOD };
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, ev), &[], None)]);
    let rig = Rig::new(dial, RigOpts { skip_ev: false, ..RigOpts::new(pki.roots()) });
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig));
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
});

// ---- ALPN, leaves.

/// What one case ended as: did it intercept, and what each side negotiated.
#[derive(Debug, PartialEq, Eq)]
struct AlpnCase {
    intercepted: bool,
    client: Option<Vec<u8>>,
    server: Option<Vec<u8>>,
}

async fn alpn_case(arm: Arm, offered: &[&str], server_alpn: &[&str], port: u16) -> AlpnCase {
    let pki = Pki::new("Test Public Root");
    let negotiated = Arc::new(Mutex::new(None));
    let got = negotiated.clone();
    let handler = tls_server(vec![server_tls(pki.leaf(HOST, GOOD), server_alpn, None)], Arc::default(), move |_, tls| {
        *got.lock().unwrap() = Some(tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec));
        echo(tls)
    });
    let rig = Rig::new(TestDial::new(arm, handler), RigOpts::new(pki.roots()));
    let opts = FlowOpts { remote: SocketAddr::new("192.0.2.1".parse().unwrap(), port), ..flow_opts() };
    let (app, task) = rig.flow(opts).await;
    let (client, shown) = client_tls(offered, None);
    let connected = connect(app, client, HOST).await;
    let case = match connected {
        Ok(tls) => {
            let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
            let server = negotiated.lock().unwrap().clone().flatten();
            let case = AlpnCase { intercepted: shown_is_sieves(&shown, &rig), client: alpn, server };
            drop(tls);
            case
        }
        Err(_) => AlpnCase { intercepted: false, client: None, server: None },
    };
    let _ = task.await;
    case
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alpn_matrix() {
    const H2: &str = "h2";
    const H1: &str = "http/1.1";
    struct Row {
        offered: &'static [&'static str],
        server: &'static [&'static str],
        port: u16,
        intercepted: bool,
        expect: fn() -> Option<Vec<u8>>,
    }
    let none = || None;
    let rows = [
        // Server selecting h2.
        Row { offered: &[H2, H1], server: &[H2], port: 443, intercepted: true, expect: || Some(b"h2".to_vec()) },
        Row { offered: &[H1, H2], server: &[H2], port: 443, intercepted: true, expect: || Some(b"h2".to_vec()) },
        Row { offered: &["h3", H2], server: &[H2], port: 443, intercepted: true, expect: || Some(b"h2".to_vec()) },
        Row { offered: &[H2], server: &[H2], port: 443, intercepted: true, expect: || Some(b"h2".to_vec()) },
        // Server selecting http/1.1.
        Row { offered: &[H2, H1], server: &[H1], port: 443, intercepted: true, expect: || Some(b"http/1.1".to_vec()) },
        Row { offered: &[H1], server: &[H1], port: 443, intercepted: true, expect: || Some(b"http/1.1".to_vec()) },
        // The server's own preference between two (rustls takes the server's order).
        Row { offered: &[H2, H1], server: &[H1, H2], port: 443, intercepted: true, expect: || Some(b"http/1.1".to_vec()) },
        // Server selecting nothing, with an ALPN client: both agree on none.
        Row { offered: &[H2, H1], server: &[], port: 443, intercepted: true, expect: none },
        Row { offered: &[H1], server: &[], port: 443, intercepted: true, expect: none },
        // No common protocol: the refusal is the client's own to see.
        Row { offered: &[H1], server: &[H2], port: 443, intercepted: false, expect: none },
        Row { offered: &[H2], server: &[H1], port: 443, intercepted: false, expect: none },
        // A protocol interception does not speak: the floor.
        Row { offered: &["acme-tls/1"], server: &[], port: 443, intercepted: false, expect: none },
        Row { offered: &["h3"], server: &[], port: 443, intercepted: false, expect: none },
        // No ALPN: by port.
        Row { offered: &[], server: &[], port: 443, intercepted: true, expect: none },
        Row { offered: &[], server: &[], port: 8443, intercepted: true, expect: none },
        Row { offered: &[], server: &[], port: 8444, intercepted: false, expect: none },
    ];
    let offer = |names: &[&str]| filter_alpn(&names.iter().map(|n| n.to_string()).collect::<Vec<_>>());
    assert_eq!(offer(&[H1, H2]), [H1.as_bytes().to_vec(), H2.as_bytes().to_vec()], "the client's order");
    assert_eq!(offer(&["h3", H2]), [H2.as_bytes().to_vec()], "h3 never applies to TCP");
    assert!(offer(&["acme-tls/1"]).is_empty());
    for arm in ARMS {
        let _guard = arm.guard().await;
        for row in &rows {
            let case = tokio::time::timeout(LIMIT, alpn_case(arm, row.offered, row.server, row.port)).await.unwrap_or_else(|_| panic!("{:?} {:?} timed out", row.offered, row.server));
            assert_eq!(case.intercepted, row.intercepted, "{arm:?} offered {:?} server {:?} port {}", row.offered, row.server, row.port);
            assert_eq!(case.client, (row.expect)(), "{arm:?} offered {:?} server {:?}: the client's ALPN", row.offered, row.server);
            if case.client.is_some() {
                assert_eq!(case.client, case.server, "both sides agree");
            }
        }
    }
}

arms!(no_alpn_non_http_is_copied_between_the_two_sessions, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig), "decrypted");
    round_trip(&mut tls).await;
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
});

arms!(leaf_names_only_the_sni_and_chains_to_the_minter_root, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    let (app, task) = rig.flow(flow_opts()).await;
    // A client that really verifies, trusting the minter's root and nothing else.
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(rig.minter.root_der().to_vec())).unwrap();
    let verified = super::client_config(Arc::new(roots), &[]).unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(verified)).connect(ServerName::try_from(HOST).unwrap(), app).await.unwrap();
    let certs = tls.get_ref().1.peer_certificates().unwrap();
    let (_, leaf) = X509Certificate::from_der(&certs[0]).unwrap();
    let san = leaf.subject_alternative_name().unwrap().unwrap();
    assert_eq!(san.value.general_names, [x509_parser::extensions::GeneralName::DNSName(HOST)], "only the SNI");
    drop(tls);
    task.await.unwrap();
});

arms!(no_minter_or_bad_host_passes_through, |arm| async move {
    let pki = Pki::new("Test Public Root");
    // No root at all: the floor, on the SYN-time socket.
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts { minter: false, ..RigOpts::new(pki.roots()) });
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    expect_real(&shown, &rig);
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.reasons(), ["floor:no-root"]);
    assert_eq!(rig.deps.connector.count(), 1);
    // A root past its end: no validity left for a leaf, a fresh socket.
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let long_ago = wall_ms() - 400 * 86_400_000;
    let rig = Rig::new(dial, RigOpts { ca_made_ms: long_ago, ..RigOpts::new(pki.roots()) });
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    expect_real(&shown, &rig);
    round_trip(&mut tls).await;
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.reasons(), ["floor:no-root"]);
    assert_eq!(rig.deps.connector.count(), 2);
});

arms!(early_data_is_refused_and_replayed_after_the_handshake, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    let (base, shown) = client_tls(&[], None);
    let mut early = (*base).clone();
    early.enable_early_data = true;
    let early = Arc::new(early);
    for _ in 0..2 {
        let (app, task) = rig.flow(flow_opts()).await;
        let mut tls = connect(app, early.clone(), HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
        assert!(!tls.get_ref().1.is_early_data_accepted(), "no ticket was issued and none would be honoured");
        assert!(shown_is_sieves(&shown, &rig));
        // The same bytes, one round trip later.
        round_trip(&mut tls).await;
        drop(tls);
        task.await.unwrap();
    }
    let config = super::server::server_config(rig.minter.leaf(crate::ca::LeafRequest { host: HOST, upstream_not_after_ms: u64::MAX }, wall_ms()).unwrap().der.clone(), rig.minter.root_der().to_vec(), rig.minter.leaf_key_pkcs8().to_vec(), Vec::new()).unwrap();
    assert_eq!((config.max_early_data_size, config.send_tls13_tickets), (0, 0));
});

/// What slice 7's evidence will read.
#[derive(Default)]
struct Watched {
    refused: Mutex<Vec<(String, Option<rustls::AlertDescription>)>>,
    requests: AtomicUsize,
    silent: AtomicUsize,
}

impl ClientWatch for Watched {
    fn handshake_failed(&self, pair: &Pair, alert: Option<rustls::AlertDescription>) {
        self.refused.lock().unwrap().push((pair.host.clone(), alert));
    }

    fn request_seen(&self, _: &Pair) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    fn closed_without_request(&self, _: &Pair, _: Duration) {
        self.silent.fetch_add(1, Ordering::Relaxed);
    }
}

arms!(client_watch_hears_a_refusal_and_a_silent_close, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let watched = Arc::new(Watched::default());
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts { watch: watched.clone(), ..RigOpts::new(pki.roots()) });
    // A client that trusts only its own bundle: the pinning case of plan 4.3.
    let (app, task) = rig.flow(flow_opts()).await;
    let pinned = super::client_config(Pki::new("Its Own Bundle").roots(), &[]).unwrap();
    assert!(tokio_rustls::TlsConnector::from(Arc::new(pinned)).connect(ServerName::try_from(HOST).unwrap(), app).await.is_err());
    assert_eq!(task.await.unwrap().action, FlowAction::Failed);
    assert_eq!(*watched.refused.lock().unwrap(), [(HOST.to_string(), Some(rustls::AlertDescription::UnknownCA))]);
    // A client that handshakes and leaves.
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, _) = client_tls(&[], None);
    let tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    drop(tls);
    task.await.unwrap();
    assert_eq!(watched.silent.load(Ordering::Relaxed), 1);
    assert_eq!(watched.requests.load(Ordering::Relaxed), 0);
});

// ---- Key exchange.

async fn client_group(arm: Arm, groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>) -> NamedGroup {
    let pki = Pki::new("Test Public Root");
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, shown) = client_tls(&[], Some(groups));
    let tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig), "the intercepting side answered");
    let group = tls.get_ref().1.negotiated_key_exchange_group().unwrap().name();
    drop(tls);
    task.await.unwrap();
    group
}

arms!(client_offering_mlkem_first_negotiates_it, |arm| async move {
    assert_eq!(client_group(arm, vec![X25519MLKEM768, X25519, SECP256R1]).await, NamedGroup::X25519MLKEM768);
});

arms!(x25519_only_client_connects_with_x25519, |arm| async move {
    assert_eq!(client_group(arm, vec![X25519]).await, NamedGroup::X25519);
});

// Task finding F5: rustls takes the first group in the client's own order.
arms!(client_listing_x25519_first_keeps_its_preference, |arm| async move {
    assert_eq!(client_group(arm, vec![X25519, X25519MLKEM768]).await, NamedGroup::X25519);
});

arms!(upstream_prefers_mlkem_and_an_x25519_only_server_still_connects, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let cases: [(Option<Vec<&'static dyn rustls::crypto::SupportedKxGroup>>, usize); 2] = [(None, 0), (Some(vec![X25519]), 1)];
    for (groups, slot) in cases {
        let config = server_tls(pki.leaf(HOST, GOOD), &[], groups);
        let (dial, _) = echo_dial(arm, vec![config]);
        let rig = Rig::new(dial, RigOpts::new(pki.roots()));
        let (app, task) = rig.flow(flow_opts()).await;
        let (client, shown) = client_tls(&[], None);
        let tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
        assert!(shown_is_sieves(&shown, &rig));
        drop(tls);
        task.await.unwrap();
        assert_eq!(rig.deps.meters.https.upstream_groups[slot].load(Ordering::Relaxed), 1, "{slot}");
        assert_eq!(rig.deps.meters.https.client_groups[0].load(Ordering::Relaxed), 1, "and the client side kept the hybrid");
    }
});

// ---- Forwarded, ECH, the switch.

arms!(forwarded_flow_hello_reaches_upstream_unchanged_with_no_handshake_of_ours, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let (dial, shaken) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    let (app, task) = rig.flow(FlowOpts { may_decrypt: false, exe: None, session: None, ..flow_opts() }).await;
    let (client, shown) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    expect_real(&shown, &rig);
    round_trip(&mut tls).await;
    assert_eq!(rig.deps.connector.count(), 1, "no second socket");
    assert_eq!(shaken.load(Ordering::Relaxed), 1, "the client's handshake alone");
    let sent = tls.get_ref().0.written.bytes();
    assert!(rig.deps.connector.seen(0).starts_with(&sent));
    drop(tls);
    task.await.unwrap();
    assert_eq!(rig.reasons(), ["floor:forwarded"]);
});

/// A browser's GREASE ECH extension on a hello rustls's client would otherwise
/// send: the real hello bytes with one more extension are not a valid thing to
/// build by hand, so the fact is asked of the parsed `Decoded`.
#[tokio::test]
async fn grease_ech_with_a_resolved_sni_intercepts_and_unresolved_passes() {
    use crate::flow::sni::build;
    let pki = Pki::new("Test Public Root");
    let ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
    let hello = || {
        let groups = (0x000a_u16, vec![0, 2, 0, 0x1d]);
        let versions = (0x002b_u16, vec![2, 3, 4]);
        build::records(&build::handshake(&[build::sni_ext(HOST), build::ech_ext(), groups, versions]), 1 << 14)
    };
    for resolved in [false, true] {
        let rig = Rig::new(TestDial::new(Arm::Duplex, raw(|_, stream| echo(stream))), RigOpts::new(pki.roots()));
        if resolved {
            rig.deps.names.lock().unwrap().record(HOST, ip, 300, 0);
        }
        let (mut app, task) = rig.flow(flow_opts()).await;
        app.write_all(&hello()).await.unwrap();
        // Our handshake to an echo peer fails, so a resolved name gets as far
        // as the upstream; an unresolved one never leaves the floor.
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(app);
        let _ = tokio::time::timeout(Duration::from_secs(20), task).await;
        let reasons = rig.reasons();
        if resolved {
            assert_ne!(reasons.first().map(String::as_str), Some("floor:ech"), "GREASE: the SNI is real, {reasons:?}");
            assert_eq!(rig.deps.connector.count(), 2, "it went on to ask the upstream");
        } else {
            assert_eq!(reasons, ["floor:ech"]);
            assert_eq!(rig.deps.connector.count(), 1);
        }
    }
}

#[tokio::test]
async fn switch_off_uses_relay_tcp_and_never_touches_tls() {
    let slot = HttpsSlot::<TestDial>::default();
    assert!(slot.get().is_none(), "no slot: `handle_tcp` takes `relay_tcp`");
    let source = include_str!("../stack/relay.rs");
    let branch = source.find("if let Some(https) = ctx.https.get()").expect("the one branch");
    let relay = source.find("relay_tcp(&mut app, upstream, FIRST_BYTES_WAIT, decide).await").expect("the old path");
    assert!(branch < relay, "the branch comes before the plain relay and returns");
    assert!(source[branch..relay].contains("return;"), "and an intercepted flow never falls through");
    assert!(!source.contains("tokio_rustls"), "the relay itself touches no TLS");
}

arms!(switch_off_closes_intercepted_flows, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let (dial, _) = echo_dial(arm, vec![server_tls(pki.leaf(HOST, GOOD), &[], None)]);
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    let slot = HttpsSlot::default();
    slot.set(Some(rig.deps.clone()));
    let (app, task) = rig.flow(flow_opts()).await;
    let (client, _) = client_tls(&[], None);
    let mut tls = connect(app, client, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    round_trip(&mut tls).await;
    slot.set(None);
    assert!(slot.get().is_none());
    tokio::time::timeout(Duration::from_secs(10), task).await.expect("closed").unwrap();
    let mut rest = Vec::new();
    let _ = tls.read_to_end(&mut rest).await;
    assert!(rest.is_empty(), "the app side ended");
});

#[test]
fn policy_without_https_builds_no_slot() {
    use super::intercept::wanted;
    let on = Policy { https: true, sieving: true, ..Policy::default() };
    assert!(wanted(&on));
    assert!(!wanted(&Policy { https: false, ..on.clone() }));
    assert!(!wanted(&Policy { sieving: false, ..on }), "not sieving: no decryption");
    assert!(!wanted(&Policy::default()), "the default is off");
}

#[test]
fn production_verifier_constructs() {
    // No verify call: that may ask Windows Update for roots (task D3).
    let trust = Arc::new(PlatformTrust::new().unwrap());
    Verifier::new(public_roots(), trust, TRUST_TIMEOUT).unwrap();
}

#[tokio::test]
async fn the_tests_dial_only_loopback() {
    let dial = TestDial::new(Arm::Loopback, raw(|_, stream| echo(stream)));
    let _guard = Arm::Loopback.guard().await;
    let _first = dial.dial("192.0.2.1:443".parse().unwrap()).await.unwrap();
    let _second = dial.dial("198.51.100.7:8443".parse().unwrap()).await.unwrap();
    let peers = dial.peers.lock().unwrap().clone();
    assert_eq!(peers.len(), 2);
    assert!(peers.iter().all(|p| p.ip().is_loopback()), "the target asked for never leaves the machine: {peers:?}");
}

#[test]
fn an_auto_entry_is_removed_by_its_pattern() {
    let slot = ExclusionSlot::with_sources(None, &[], Vec::new(), wall_ms());
    slot.add_auto(AutoEntry::host(HOST, AutoReason::Pinning, wall_ms(), None), wall_ms());
    assert!(slot.remove_auto(&Pattern::Exact(HOST.into()), None));
}

/// Slice 6's live check (`docs/live/engine-slice-6.md`), run by the user: U1 to
/// U14. Offline it cannot pass and claims nothing.
#[test]
#[ignore = "live: docs/live/engine-slice-6.md, run by the user with the switch driven by scripts/live/engine-ca.ps1"]
fn live_https_intercepts_public_and_passes_floor() {
    panic!("this check is the runbook: docs/live/engine-slice-6.md");
}
