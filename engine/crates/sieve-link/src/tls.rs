//! TLS 1.3 with raw public keys (RFC 7250) on both sides, each pinned by its
//! fingerprint. No certificate authority, no names: a peer is accepted when
//! its key's fingerprint is one the local policy knows (the paired hub, the
//! paired devices, or any key while a pairing code is outstanding) AND it
//! proves possession of that key in the handshake's CertificateVerify.
//!
//! Who dials does not decide the role: either side may be the TLS client.
//! ALPN carries the protocol version ("sieve-link/1"); a peer that does not
//! offer it is refused. Session resumption and 0-RTT are off, so every
//! connection runs the full handshake and the full key check.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{AlwaysResolvesClientRawPublicKeys, Resumption};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{AlwaysResolvesServerRawPublicKeys, NoServerSessionStorage};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use crate::error::{LinkError, Result};
use crate::identity::{Fingerprint, Identity};
use crate::wire::ALPN;

/// The name every client sends; the verifiers ignore it (keys are pinned).
const SERVER_NAME: &str = "sieve-link.invalid";
/// Label of the keying material that binds a pairing proof to its session.
const EXPORTER_LABEL: &[u8] = b"EXPORTER-sieve-link-pair-v1";

/// aws-lc-rs, the engine's provider. With the `prefer-post-quantum` feature
/// its first key-exchange group is X25519MLKEM768; X25519 remains as the
/// fallback the provider offers.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Which peer keys this side accepts.
pub trait PeerPolicy: Send + Sync + std::fmt::Debug {
    fn accepts(&self, peer: &Fingerprint) -> bool;
}

/// Exactly one key (a device's view of its hub).
#[derive(Debug)]
pub struct Pinned(pub Fingerprint);

impl PeerPolicy for Pinned {
    fn accepts(&self, peer: &Fingerprint) -> bool {
        *peer == self.0
    }
}

#[derive(Debug)]
struct PinVerifier {
    policy: Arc<dyn PeerPolicy>,
    algs: WebPkiSupportedAlgorithms,
}

impl PinVerifier {
    fn check(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>]) -> std::result::Result<(), rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(CertificateError::BadEncoding));
        }
        let fp = Fingerprint::of_spki(end_entity.as_ref());
        if self.policy.accepts(&fp) {
            Ok(())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify13(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(cert.as_ref()), dss, &self.algs)
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity, intermediates).map(|_| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not used".into()))
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.verify13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for PinVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], _now: UnixTime) -> std::result::Result<ClientCertVerified, rustls::Error> {
        self.check(end_entity, intermediates).map(|_| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not used".into()))
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.verify13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn verifier(policy: Arc<dyn PeerPolicy>, provider: &CryptoProvider) -> Arc<PinVerifier> {
    Arc::new(PinVerifier { policy, algs: provider.signature_verification_algorithms })
}

/// The accepting side's config: presents `id`, requires a client key `policy` accepts.
pub fn server_config(id: &Identity, policy: Arc<dyn PeerPolicy>) -> Result<Arc<ServerConfig>> {
    let provider = provider();
    let v = verifier(policy, &provider);
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(v)
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(id.certified_key())));
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg.session_storage = Arc::new(NoServerSessionStorage {});
    cfg.send_tls13_tickets = 0;
    cfg.max_early_data_size = 0;
    Ok(Arc::new(cfg))
}

/// The dialling side's config: presents `id`, requires a server key `policy` accepts.
pub fn client_config(id: &Identity, policy: Arc<dyn PeerPolicy>) -> Result<Arc<ClientConfig>> {
    let provider = provider();
    let v = verifier(policy, &provider);
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(v)
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(id.certified_key())));
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg.resumption = Resumption::disabled();
    cfg.enable_early_data = false;
    Ok(Arc::new(cfg))
}

/// A finished handshake.
pub struct Established {
    pub io: TlsStream<TcpStream>,
    /// The peer's verified key.
    pub peer: Fingerprint,
    /// Keying material unique to this session (RFC 8446 7.5), for pairing.
    pub exporter: [u8; 32],
    pub remote: SocketAddr,
    /// This side's address on the connection (the one the peer reached).
    pub local: SocketAddr,
    /// The negotiated key-exchange group (for tests and logs).
    pub kx_group: Option<rustls::NamedGroup>,
}

pub(crate) fn tune(tcp: &TcpStream) {
    let _ = tcp.set_nodelay(true);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    let _ = socket2::SockRef::from(tcp).set_tcp_keepalive(&ka);
}

fn finish(io: TlsStream<TcpStream>, remote: SocketAddr, local: SocketAddr) -> Result<Established> {
    let (peer, exporter, alpn_ok, kx_group) = {
        let common: &rustls::CommonState = match &io {
            TlsStream::Client(c) => c.get_ref().1,
            TlsStream::Server(s) => s.get_ref().1,
        };
        let peer = common
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| Fingerprint::of_spki(c.as_ref()))
            .ok_or_else(|| LinkError::Tls("the peer presented no key".into()))?;
        let alpn_ok = common.alpn_protocol() == Some(ALPN);
        let kx_group = common.negotiated_key_exchange_group().map(|g| g.name());
        let exporter = match &io {
            TlsStream::Client(c) => c.get_ref().1.export_keying_material([0u8; 32], EXPORTER_LABEL, None)?,
            TlsStream::Server(s) => s.get_ref().1.export_keying_material([0u8; 32], EXPORTER_LABEL, None)?,
        };
        (peer, exporter, alpn_ok, kx_group)
    };
    if !alpn_ok {
        return Err(LinkError::Tls("the peer does not speak sieve-link/1".into()));
    }
    Ok(Established { io, peer, exporter, remote, local, kx_group })
}

/// Dials `addr` and runs the handshake as the TLS client.
pub async fn dial(addr: &str, cfg: Arc<ClientConfig>, limit: Duration) -> Result<Established> {
    let fut = async {
        let tcp = TcpStream::connect(addr).await?;
        client_handshake(tcp, cfg).await
    };
    tokio::time::timeout(limit, fut).await.map_err(|_| LinkError::Timeout("handshake"))?
}

/// Runs the handshake as the TLS client on a socket the caller connected.
pub async fn connect(tcp: TcpStream, cfg: Arc<ClientConfig>, limit: Duration) -> Result<Established> {
    tokio::time::timeout(limit, client_handshake(tcp, cfg)).await.map_err(|_| LinkError::Timeout("handshake"))?
}

async fn client_handshake(tcp: TcpStream, cfg: Arc<ClientConfig>) -> Result<Established> {
    tune(&tcp);
    let remote = tcp.peer_addr()?;
    let local = tcp.local_addr()?;
    let name = ServerName::try_from(SERVER_NAME).expect("static name");
    let tls = TlsConnector::from(cfg).connect(name, tcp).await.map_err(|e| LinkError::Tls(e.to_string()))?;
    finish(TlsStream::Client(tls), remote, local)
}

/// Runs the handshake on an accepted socket as the TLS server.
pub async fn accept(tcp: TcpStream, cfg: Arc<ServerConfig>, limit: Duration) -> Result<Established> {
    tune(&tcp);
    let remote = tcp.peer_addr()?;
    let local = tcp.local_addr()?;
    let fut = async {
        let tls = TlsAcceptor::from(cfg).accept(tcp).await.map_err(|e| LinkError::Tls(e.to_string()))?;
        finish(TlsStream::Server(tls), remote, local)
    };
    tokio::time::timeout(limit, fut).await.map_err(|_| LinkError::Timeout("handshake"))?
}
