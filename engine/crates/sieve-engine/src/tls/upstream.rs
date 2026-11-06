//! The upstream handshake and its validation (plan 2.6, task D2). The rustls
//! client gets [`CapturingVerifier`]: it records the chain and the staple and
//! asserts, while the handshake's signatures are still checked by the provider.
//! Nothing from the client is sent until [`Verifier::verify`] returns. Then:
//! 1. eligibility: the public root set, inline, no OS, no network. Sieve's root
//!    and any other interceptor's are not in that set, so "must not anchor in
//!    Sieve's own root" needs no check of its own (S52);
//! 2. the local checks: CRLite, then Certificate Transparency ([`ValidationSlot`],
//!    slice 11), inline, even for a known leaf, since a filter that arrived an
//!    hour ago must reach a host visited all day. A private root never gets here,
//!    which is plan 2.6's "public roots only" by order, with no second test;
//! 3. trust: [`TrustVerifier`], the Windows chain engine in production, on a
//!    blocking thread behind a semaphore and a timeout, because CryptoAPI can
//!    wait seconds on a fetch and rustls's verifier runs inside the handshake
//!    poll, on a worker that also carries the relay.
//!
//! Resumption is off upstream: a resumed handshake skips the verifier, so it
//! would capture nothing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::digest::{SHA256, digest};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{EchConfig, EchMode, ResolvesClientCert, Resumption, WebPkiServerVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, NamedGroup, RootCertStore, SignatureScheme};
use sieve_filter::exclusions::{HTTP_ALPN, UpstreamVerdict};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use x509_parser::prelude::{FromDer, ParsedExtension, X509Certificate};

use super::ct::{SpkiHash, anchor_spki_hash, spki_hash};
use super::ech::ECH_HANDSHAKE_TIMEOUT;
use super::provider;
use super::validation::ValidationSlot;
use super::verdict::LeafHash;

/// How long the upstream handshake may take before the flow passes through.
pub const UPSTREAM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the trust call may take. A timeout passes through and is not cached.
pub const TRUST_TIMEOUT: Duration = Duration::from_secs(5);
/// Trust calls at once: each can hold a blocking thread for its whole timeout.
pub const TRUST_CONCURRENCY: usize = 16;
/// The CA/B Forum's EV policy (plan 2.6).
const EV_POLICY: &str = "2.23.140.1.1";

/// The client's ALPN list kept to what interception speaks over TCP, in the
/// client's order (plan 2.8). The client's `h3` never applies to TCP.
pub fn filter_alpn(offered: &[String]) -> Vec<Vec<u8>> {
    offered.iter().filter(|a| HTTP_ALPN.contains(&a.as_str())).map(|a| a.as_bytes().to_vec()).collect()
}

/// What the upstream showed.
#[derive(Debug, Clone)]
pub struct Chain {
    pub end_entity: CertificateDer<'static>,
    pub intermediates: Vec<CertificateDer<'static>>,
    pub ocsp: Vec<u8>,
}

/// What the handshake learned, shared with the rustls callbacks.
#[derive(Debug, Default)]
pub(super) struct Capture {
    chain: Mutex<Option<Chain>>,
    asked_for_certificate: AtomicBool,
}

#[derive(Debug)]
struct CapturingVerifier {
    capture: Arc<Capture>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], _name: &ServerName<'_>, ocsp: &[u8], _now: UnixTime) -> Result<ServerCertVerified, TlsError> {
        let chain = Chain { end_entity: end_entity.clone().into_owned(), intermediates: intermediates.iter().map(|c| c.clone().into_owned()).collect(), ocsp: ocsp.to_vec() };
        *self.capture.chain.lock().unwrap_or_else(|p| p.into_inner()) = Some(chain);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Records "the server asked" and sends no certificate (plan 2.11).
#[derive(Debug)]
struct RecordsTheAsk(Arc<Capture>);

impl ResolvesClientCert for RecordsTheAsk {
    fn resolve(&self, _hints: &[&[u8]], _schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        self.0.asked_for_certificate.store(true, Ordering::Relaxed);
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// A finished upstream handshake, not yet judged.
pub struct Handshaken<S> {
    pub tls: TlsStream<S>,
    pub chain: Chain,
    pub alpn: Option<Vec<u8>>,
    pub group: Option<NamedGroup>,
}

pub enum HandshakeEnd<S> {
    Done(Box<Handshaken<S>>),
    /// The server asked for a client certificate, and showed this chain. Not
    /// judged yet, and a chain it cannot sign for is possible: judged good, it
    /// can only make the name it covers pass through.
    ClientCertificate(Chain),
    /// `Protocol` (it needs less than rustls offers) or `Unavailable` (a timeout
    /// or a dropped connection).
    Failed(UpstreamVerdict),
    /// A handshake that offered ECH ended any other way than `Done`: a rejection,
    /// a reset, a timeout or a certificate request. The chain, if any, was for
    /// the public name, so it is dropped unjudged and no verdict follows (task D10).
    EchFailed,
}

pub(super) fn client_config(capture: &Arc<Capture>, alpn: Vec<Vec<u8>>, ech: Option<&EchConfig>) -> Result<ClientConfig, String> {
    let provider = provider();
    let verifier = Arc::new(CapturingVerifier { capture: capture.clone(), provider: provider.clone() });
    let builder = ClientConfig::builder_with_provider(provider);
    // TLS 1.3 only with ECH, which any server publishing a config speaks.
    let builder = match ech {
        Some(config) => builder.with_ech(EchMode::Enable(config.clone())),
        None => builder.with_safe_default_protocol_versions(),
    };
    let mut config = builder
        .map_err(|e| format!("TLS versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(RecordsTheAsk(capture.clone())));
    config.alpn_protocols = alpn;
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}

/// The handshake on `stream`, with the client's SNI and filtered ALPN, and ECH
/// when a usable config is given.
pub async fn handshake<S>(stream: S, sni: &str, alpn: Vec<Vec<u8>>, ech: Option<EchConfig>) -> HandshakeEnd<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let capture = Arc::new(Capture::default());
    let offered = ech.is_some();
    let Ok(config) = client_config(&capture, alpn, ech.as_ref()) else { return if offered { HandshakeEnd::EchFailed } else { HandshakeEnd::Failed(UpstreamVerdict::Protocol) } };
    let Ok(name) = ServerName::try_from(sni.to_string()) else { return HandshakeEnd::Failed(UpstreamVerdict::Protocol) };
    let connect = TlsConnector::from(Arc::new(config)).connect(name, stream);
    let limit = if offered { ECH_HANDSHAKE_TIMEOUT } else { UPSTREAM_HANDSHAKE_TIMEOUT };
    let answer = tokio::time::timeout(limit, connect).await;
    if offered && (!matches!(answer, Ok(Ok(_))) || capture.asked_for_certificate.load(Ordering::Relaxed)) {
        return HandshakeEnd::EchFailed;
    }
    let chain = capture.chain.lock().unwrap_or_else(|p| p.into_inner()).take();
    // An ask with no chain proves nothing about the server: it ends like any
    // other handshake that did not finish.
    let chain = match chain {
        Some(chain) if capture.asked_for_certificate.load(Ordering::Relaxed) => return HandshakeEnd::ClientCertificate(chain),
        chain => chain,
    };
    let tls = match answer {
        Ok(Ok(tls)) => tls,
        // TLS itself said no: it needs less than rustls offers.
        Ok(Err(e)) if rustls_error(&e).is_some() => return HandshakeEnd::Failed(UpstreamVerdict::Protocol),
        // A reset or a timeout says nothing about the server, so it is not cached.
        Ok(Err(_)) | Err(_) => return HandshakeEnd::Failed(UpstreamVerdict::Unavailable),
    };
    let Some(chain) = chain else { return HandshakeEnd::Failed(UpstreamVerdict::Protocol) };
    let (_, connection) = tls.get_ref();
    let alpn = connection.alpn_protocol().map(<[u8]>::to_vec);
    let group = connection.negotiated_key_exchange_group().map(|g| g.name());
    HandshakeEnd::Done(Box::new(Handshaken { tls, chain, alpn, group }))
}

/// A leaf as far as interception cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafFacts {
    pub hash: LeafHash,
    pub not_after_ms: u64,
    /// Carries the EV policy.
    pub ev: bool,
}

/// The facts of a leaf; None when it does not parse, which eligibility will
/// have refused already.
pub fn leaf_facts(der: &[u8]) -> Option<LeafFacts> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let hash = digest(&SHA256, der).as_ref().try_into().ok()?;
    let not_after_ms = u64::try_from(cert.validity().not_after.timestamp()).ok()?.saturating_mul(1_000);
    let ev = cert.extensions().iter().any(|e| match e.parsed_extension() {
        ParsedExtension::CertificatePolicies(policies) => policies.iter().any(|p| p.policy_id.to_id_string() == EV_POLICY),
        _ => false,
    });
    Some(LeafFacts { hash, not_after_ms, ev })
}

/// The trust half (plan 2.6): revocation and whatever else the OS holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAnswer {
    Trusted,
    Revoked,
    Rejected,
}

/// Blocks: [`Verifier`] runs it off the runtime.
pub trait TrustVerifier: Send + Sync + 'static {
    fn verify(&self, chain: &Chain, host: &ServerName<'static>) -> TrustAnswer;
}

/// Production: Windows' chain engine, with its AIA, OCSP and CRL fetches. Tests
/// never call it (task D3): it may ask Windows Update for roots.
pub struct PlatformTrust(rustls_platform_verifier::Verifier);

impl PlatformTrust {
    pub fn new() -> Result<Self, String> {
        rustls_platform_verifier::Verifier::new(provider()).map(Self).map_err(|e| format!("the platform verifier: {e}"))
    }
}

fn answer_of(result: Result<ServerCertVerified, TlsError>) -> TrustAnswer {
    match result {
        Ok(_) => TrustAnswer::Trusted,
        Err(TlsError::InvalidCertificate(CertificateError::Revoked)) => TrustAnswer::Revoked,
        Err(_) => TrustAnswer::Rejected,
    }
}

impl TrustVerifier for PlatformTrust {
    fn verify(&self, chain: &Chain, host: &ServerName<'static>) -> TrustAnswer {
        answer_of(self.0.verify_server_cert(&chain.end_entity, &chain.intermediates, host, &chain.ocsp, UnixTime::now()))
    }
}

/// The three checks, with the dials of the last.
pub struct Verifier {
    eligibility: Arc<WebPkiServerVerifier>,
    roots: Arc<RootCertStore>,
    validation: Arc<ValidationSlot>,
    trust: Arc<dyn TrustVerifier>,
    permits: Arc<Semaphore>,
    timeout: Duration,
}

impl Verifier {
    /// `roots` is `tls::public_roots()` in production, a test's own in tests.
    pub fn new(roots: Arc<RootCertStore>, trust: Arc<dyn TrustVerifier>, timeout: Duration, validation: Arc<ValidationSlot>) -> Result<Self, String> {
        let eligibility = WebPkiServerVerifier::builder_with_provider(roots.clone(), provider()).build().map_err(|e| format!("the public roots: {e}"))?;
        Ok(Self { eligibility, roots, validation, trust, permits: Arc::new(Semaphore::new(TRUST_CONCURRENCY)), timeout })
    }

    /// Eligibility: inline, no OS. An unknown issuer is a private root; anything
    /// else wrong with the chain is invalid.
    pub fn eligibility(&self, chain: &Chain, host: &ServerName<'static>) -> UpstreamVerdict {
        match self.eligibility.verify_server_cert(&chain.end_entity, &chain.intermediates, host, &chain.ocsp, UnixTime::now()) {
            Ok(_) => UpstreamVerdict::Eligible,
            Err(TlsError::InvalidCertificate(CertificateError::UnknownIssuer)) => UpstreamVerdict::NonPublicRoot,
            Err(_) => UpstreamVerdict::Invalid,
        }
    }

    /// The issuer's key hash, from the path eligibility accepts (task D5).
    ///
    /// TENSION (S51): the path is built twice per new connection, because
    /// `WebPkiServerVerifier` does not hand it over. Rebuilding eligibility on
    /// `webpki` directly would remove the second build and rewrite slice 6's tested
    /// error mapping; not worth it without a measured cost, which
    /// `bench_validation_local_checks` reports.
    pub(crate) fn issuer_hash(&self, chain: &Chain, now_ms: u64) -> Option<SpkiHash> {
        let leaf = webpki::EndEntityCert::try_from(&chain.end_entity).ok()?;
        let now = UnixTime::since_unix_epoch(Duration::from_millis(now_ms));
        let algorithms = provider().signature_verification_algorithms.all;
        let path = leaf.verify_for_usage(algorithms, &self.roots.roots, &chain.intermediates, now, webpki::KeyUsage::server_auth(), None, None).ok()?;
        // The first intermediate is the one that signed the leaf (test
        // `issuer_hash_of_an_intermediate_matches_the_recorded_issuer`).
        Some(match path.intermediate_certificates().next() {
            Some(issuer) => spki_hash(issuer.subject_public_key_info().as_ref()),
            None => anchor_spki_hash(path.anchor().subject_public_key_info.as_ref()),
        })
    }

    /// Trust, off the runtime. The permit goes with the blocking call, so a
    /// call that timed out still counts until it ends.
    pub async fn trust(&self, chain: Chain, host: ServerName<'static>) -> UpstreamVerdict {
        let trust = self.trust.clone();
        let permits = self.permits.clone();
        let work = async move {
            let permit = permits.acquire_owned().await.ok()?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                trust.verify(&chain, &host)
            })
            .await
            .ok()
        };
        match tokio::time::timeout(self.timeout, work).await {
            Ok(Some(TrustAnswer::Trusted)) => UpstreamVerdict::Eligible,
            Ok(Some(TrustAnswer::Revoked)) => UpstreamVerdict::Revoked,
            Ok(Some(TrustAnswer::Rejected)) => UpstreamVerdict::Invalid,
            _ => UpstreamVerdict::Unavailable,
        }
    }

    /// All three, in order. `trust_known` means this same leaf was already trusted,
    /// so the trust call does not run; the local checks always do.
    pub async fn verify(&self, chain: &Chain, sni: &str, trust_known: bool, now_ms: u64) -> UpstreamVerdict {
        let Ok(host) = ServerName::try_from(sni.to_string()) else { return UpstreamVerdict::Invalid };
        let eligible = self.eligibility(chain, &host);
        if eligible != UpstreamVerdict::Eligible {
            return eligible;
        }
        if let Some(verdict) = self.validation.check(chain, now_ms, || self.issuer_hash(chain, now_ms)).verdict {
            return verdict;
        }
        if trust_known {
            return eligible;
        }
        self.trust(chain.clone(), host).await
    }
}

/// True for the rustls error a TLS 1.3 post-handshake client-auth request raises
/// on an open connection (task D16): it names the handshake message it refused.
pub fn is_post_handshake_auth(error: &TlsError) -> bool {
    matches!(error, TlsError::InappropriateHandshakeMessage { got_type: rustls::HandshakeType::CertificateRequest, .. })
}

/// The fatal alert behind a hyper or I/O error, when the peer sent one.
pub fn alert_in(error: &(dyn std::error::Error + 'static)) -> Option<rustls::AlertDescription> {
    match rustls_error(error) {
        Some(TlsError::AlertReceived(alert)) => Some(*alert),
        _ => None,
    }
}

/// Finds the rustls error behind a hyper or I/O error.
pub fn rustls_error<'a>(error: &'a (dyn std::error::Error + 'static)) -> Option<&'a TlsError> {
    let mut current = Some(error);
    while let Some(e) = current {
        if let Some(tls) = e.downcast_ref::<TlsError>() {
            return Some(tls);
        }
        // `io::Error::source` skips the error it wraps; `get_ref` does not.
        let wrapped = e.downcast_ref::<std::io::Error>().and_then(std::io::Error::get_ref);
        current = match wrapped {
            Some(inner) => Some(inner as &(dyn std::error::Error + 'static)),
            None => e.source(),
        };
    }
    None
}
