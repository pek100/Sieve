//! Test helpers: a key pair generated in memory by the real `minisign` tool,
//! never written anywhere (law 13), and a tree listing for the "nothing
//! changed" checks.

use std::collections::BTreeMap;
use std::path::Path;

use minisign::{KeyPair, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use super::Kind;
use super::trust::TrustAnchor;

pub struct TestKey {
    public: PublicKey,
    secret: SecretKey,
}

/// The trusted comment a real release carries.
pub fn comment(kind: &Kind, version: u64) -> String {
    format!("sieve-update kind={kind} version={version}")
}

impl TestKey {
    pub fn new() -> Self {
        let KeyPair { pk, sk } = KeyPair::generate_unencrypted_keypair().unwrap();
        Self { public: pk, secret: sk }
    }

    pub fn public_line(&self) -> String {
        self.public.to_base64()
    }

    pub fn anchor(&self) -> TrustAnchor {
        TrustAnchor::parse(&self.public_line()).unwrap()
    }

    /// A `.minisig` over `bytes` with this trusted comment.
    pub fn sign(&self, bytes: &[u8], trusted: &str) -> String {
        minisign::sign(None, &self.secret, std::io::Cursor::new(bytes), Some(trusted), Some("test")).unwrap().into_string()
    }

    /// A `.minisig` with minisign's own default comment.
    pub fn sign_default(&self, bytes: &[u8]) -> String {
        minisign::sign(None, &self.secret, std::io::Cursor::new(bytes), None, None).unwrap().into_string()
    }
}

/// Every file under `dir`: relative path to (size, sha256).
pub fn listing(dir: &Path) -> BTreeMap<String, (u64, [u8; 32])> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, (u64, [u8; 32])>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.map(Result::unwrap) {
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let bytes = std::fs::read(&path).unwrap();
                let name = path.strip_prefix(root).unwrap().display().to_string();
                out.insert(name, (bytes.len() as u64, Sha256::digest(&bytes).into()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}
