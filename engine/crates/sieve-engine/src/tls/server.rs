//! The client-facing side: who rustls can answer, and with what (plan 2.7, 2.8,
//! 2.10). A client that shares nothing with rustls would be broken after the
//! decision, when pass-through is no longer free, so it is asked before any
//! answer (task D10).

use std::sync::Arc;

use rustls::SupportedCipherSuite;
use rustls::crypto::CryptoProvider;
use rustls::{ServerConfig, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use super::provider;
use crate::flow::sni::TlsOffer;

/// The leaves are ECDSA P-256 (plan 2.2), so a TLS 1.2 suite must sign with it.
const LEAF_SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;

fn suite_fits(suite: &SupportedCipherSuite, offer: &TlsOffer) -> bool {
    let signs = match suite {
        SupportedCipherSuite::Tls13(_) => true,
        SupportedCipherSuite::Tls12(s) => s.sign.contains(&LEAF_SCHEME),
    };
    signs && offer.suites.contains(&u16::from(suite.suite())) && offer.versions.contains(&u16::from(suite.version().version))
}

fn shares(provider: &CryptoProvider, offer: &TlsOffer) -> bool {
    provider.kx_groups.iter().any(|g| offer.groups.contains(&u16::from(g.name()))) && provider.cipher_suites.iter().any(|s| suite_fits(s, offer))
}

/// True when the client shares a version of 1.2 or later, a suite and a group
/// with the engine's provider.
pub fn speaks_to(offer: &TlsOffer) -> bool {
    shares(&provider(), offer)
}

/// The per-connection answer: the minted leaf, the ALPN the server chose, no
/// early data (rustls's default, plan 2.10), no tickets (a resumption would
/// skip nothing here, and each connection has its own upstream to pair with).
pub fn server_config(leaf_der: Vec<u8>, root_der: Vec<u8>, leaf_key_pkcs8: Vec<u8>, alpn: Vec<Vec<u8>>) -> Result<Arc<ServerConfig>, String> {
    let chain = vec![CertificateDer::from(leaf_der), CertificateDer::from(root_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_pkcs8));
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("the leaf: {e}"))?;
    config.alpn_protocols = alpn;
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TLS12: u16 = 0x0303;
    const TLS13: u16 = 0x0304;
    const TLS11: u16 = 0x0302;
    const AES128_GCM_SHA256: u16 = 0x1301;
    const ECDHE_ECDSA_AES128_GCM: u16 = 0xc02b;
    const ECDHE_RSA_AES128_GCM: u16 = 0xc02f;
    const X25519: u16 = 0x001d;
    const RC4_MD5: u16 = 0x0004;

    fn offer(versions: &[u16], suites: &[u16], groups: &[u16]) -> TlsOffer {
        TlsOffer { versions: versions.to_vec(), suites: suites.to_vec(), groups: groups.to_vec() }
    }

    #[test]
    fn a_client_is_asked_for_a_version_a_suite_and_a_group() {
        assert!(speaks_to(&offer(&[TLS13], &[AES128_GCM_SHA256], &[X25519])));
        assert!(speaks_to(&offer(&[TLS12], &[ECDHE_ECDSA_AES128_GCM], &[X25519])));
        assert!(!speaks_to(&offer(&[TLS12], &[AES128_GCM_SHA256], &[X25519])), "a 1.3 suite under 1.2");
        assert!(!speaks_to(&offer(&[TLS12], &[ECDHE_RSA_AES128_GCM], &[X25519])), "an RSA suite: the leaf is ECDSA");
        assert!(!speaks_to(&offer(&[TLS11], &[ECDHE_ECDSA_AES128_GCM], &[X25519])), "TLS 1.1");
        assert!(!speaks_to(&offer(&[TLS13], &[RC4_MD5], &[X25519])), "no shared suite");
        assert!(!speaks_to(&offer(&[TLS13], &[AES128_GCM_SHA256], &[0x0100])), "FFDHE only");
        assert!(!speaks_to(&TlsOffer::default()));
    }
}
