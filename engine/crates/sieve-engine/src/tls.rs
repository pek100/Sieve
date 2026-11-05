//! The one owner of how the engine speaks TLS (plan 2.6, 2.7): TLS 1.2 and
//! 1.3 on aws-lc-rs, with key exchange groups in the plan's order on every
//! session the engine makes or answers. Early data stays off (plan 2.10,
//! rustls's default). Later slices build on [`provider`], so one change here
//! reaches every session.

use std::sync::Arc;

use rustls::crypto::{CryptoProvider, SupportedKxGroup, aws_lc_rs};
use rustls::{ClientConfig, RootCertStore};

/// X25519MLKEM768, then X25519, then secp256r1 (plan 2.7), most preferred first.
pub fn kx_groups() -> Vec<&'static dyn SupportedKxGroup> {
    use aws_lc_rs::kx_group::{SECP256R1, X25519, X25519MLKEM768};
    vec![X25519MLKEM768, X25519, SECP256R1]
}

/// The crypto provider of every session.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider { kx_groups: kx_groups(), ..aws_lc_rs::default_provider() })
}

/// The public root set (plan 2.6). It needs no network and no OS call, so a
/// certificate check cannot wait on the DNS it is carrying (task D4).
pub fn public_roots() -> Arc<RootCertStore> {
    Arc::new(RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() })
}

/// A client configuration with no client certificate, offering `alpn`.
pub fn client_config(roots: Arc<RootCertStore>, alpn: &[&[u8]]) -> Result<ClientConfig, String> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::NamedGroup;

    #[test]
    fn key_exchange_preference_order_is_the_plans() {
        let names: Vec<NamedGroup> = kx_groups().iter().map(|g| g.name()).collect();
        assert_eq!(names, [NamedGroup::X25519MLKEM768, NamedGroup::X25519, NamedGroup::secp256r1]);
        assert_eq!(provider().kx_groups.len(), names.len());
    }

    #[test]
    fn the_public_roots_are_not_empty_and_a_client_config_builds() {
        let roots = public_roots();
        assert!(!roots.is_empty());
        let config = client_config(roots, &[b"h2"]).unwrap();
        assert_eq!(config.alpn_protocols, [b"h2".to_vec()]);
        assert!(!config.enable_early_data, "plan 2.10");
    }
}
