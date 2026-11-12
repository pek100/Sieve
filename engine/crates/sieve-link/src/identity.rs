//! A side's long-term identity: an Ed25519 key pair, known to peers only by
//! the SHA-256 of its SubjectPublicKeyInfo (the fingerprint pinned at pairing).

use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::Ed25519KeyPair;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

use crate::error::{LinkError, Result};

/// SHA-256 of a public key's SubjectPublicKeyInfo DER.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    pub fn of_spki(spki_der: &[u8]) -> Self {
        let d = digest::digest(&digest::SHA256, spki_der);
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        Fingerprint(out)
    }

    /// The first 16 hex digits: what lists and audit rows show.
    pub fn short(&self) -> String {
        self.to_string()[..16].to_string()
    }

    /// Whether `prefix` (hex, any case, at least 8 digits) starts this
    /// fingerprint. Used by the CLI to name a device.
    pub fn matches_prefix(&self, prefix: &str) -> bool {
        let p = prefix.trim().to_ascii_lowercase();
        p.len() >= 8 && self.to_string().starts_with(&p)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.short())
    }
}

impl FromStr for Fingerprint {
    type Err = LinkError;
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() != 64 {
            return Err(LinkError::Store("a fingerprint is 64 hex digits".into()));
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|_| LinkError::Store("a fingerprint is 64 hex digits".into()))?;
        }
        Ok(Fingerprint(out))
    }
}

impl serde::Serialize for Fingerprint {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for Fingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// An Ed25519 key pair. The private half never leaves this struct except to
/// its own file (`save`); `Debug` shows the fingerprint only.
pub struct Identity {
    /// Wiped when dropped. (The copy handed to rustls / aws-lc-rs for
    /// signing is theirs; aws-lc frees its key with its own cleansing.)
    pkcs8: zeroize::Zeroizing<Vec<u8>>,
    spki: Vec<u8>,
    key: Arc<CertifiedKey>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({})", self.fingerprint().short())
    }
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| LinkError::Tls("key generation failed".into()))?;
        Self::from_pkcs8(doc.as_ref())
    }

    pub fn from_pkcs8(der: &[u8]) -> Result<Self> {
        let provider = crate::tls::provider();
        // The provider parses this copy into its own key object; the DER
        // wrapper is dropped inside rustls (not wiped: out of our hands).
        let signer = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec())))
            .map_err(|e| LinkError::Tls(format!("unusable private key: {e}")))?;
        let spki = signer
            .public_key()
            .ok_or_else(|| LinkError::Tls("the key has no public half".into()))?
            .as_ref()
            .to_vec();
        // A raw public key (RFC 7250) travels where a certificate would.
        let key = Arc::new(CertifiedKey::new(vec![CertificateDer::from(spki.clone())], signer));
        Ok(Identity { pkcs8: zeroize::Zeroizing::new(der.to_vec()), spki, key })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_spki(&self.spki)
    }

    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    pub(crate) fn certified_key(&self) -> Arc<CertifiedKey> {
        self.key.clone()
    }

    /// Loads the key from `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let der = zeroize::Zeroizing::new(
            std::fs::read(path).map_err(|e| LinkError::Store(format!("cannot read {}: {e}", path.display())))?,
        );
        Self::from_pkcs8(&der)
    }

    /// Writes the key to a new file at `path`; refuses to overwrite one.
    pub fn save_new(&self, path: &Path) -> Result<()> {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(path)
            .map_err(|e| LinkError::Store(format!("cannot create {}: {e}", path.display())))?;
        f.write_all(&self.pkcs8)?;
        f.sync_all()?;
        Ok(())
    }

    /// Loads the key at `path`, or creates and saves one if there is none.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            let id = Self::generate()?;
            id.save_new(path)?;
            Ok(id)
        }
    }
}

