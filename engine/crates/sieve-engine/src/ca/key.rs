//! The root's key behind a seam (plan 2.2). The engine holds a [`RootKey`]:
//! public bytes and a sign call, never private bytes. `win::cng` is the real
//! store; tests use [`MemoryKeyStore`], so no test can create a machine key.

use std::sync::Mutex;

use rcgen::{Error, PKCS_ECDSA_P256_SHA256, PublicKeyData, SignatureAlgorithm, SigningKey};

/// What a key store's key can do.
pub trait RootSigner: Send + Sync {
    /// The public key as a SEC1 uncompressed point.
    fn public_point(&self) -> &[u8];
    /// An ECDSA P-256 SHA-256 signature of `message`, DER encoded.
    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, String>;
}

/// Persisted root keys by name. `delete` of an absent key is success.
pub trait KeyStore: Send + Sync {
    fn create(&self, name: &str) -> Result<RootKey, String>;
    fn open(&self, name: &str) -> Result<RootKey, String>;
    fn delete(&self, name: &str) -> Result<(), String>;
}

/// A signer in the shape rcgen takes. rcgen's error has no room for a reason,
/// so the last failure waits here for [`RootKey::take_sign_error`].
pub struct RootKey {
    signer: Box<dyn RootSigner>,
    sign_error: Mutex<Option<String>>,
}

impl RootKey {
    pub fn new(signer: Box<dyn RootSigner>) -> Self {
        Self { signer, sign_error: Mutex::new(None) }
    }

    pub fn take_sign_error(&self) -> Option<String> {
        self.sign_error.lock().unwrap_or_else(|p| p.into_inner()).take()
    }
}

impl PublicKeyData for RootKey {
    fn der_bytes(&self) -> &[u8] {
        self.signer.public_point()
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for RootKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        self.signer.sign_der(msg).map_err(|why| {
            *self.sign_error.lock().unwrap_or_else(|p| p.into_inner()) = Some(why);
            Error::RemoteKeyError
        })
    }
}

#[cfg(test)]
pub use memory::{MemoryKeyStore, signer as memory_signer};

#[cfg(test)]
mod memory {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};

    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData, SigningKey};

    use super::{KeyStore, RootKey, RootSigner};
    use crate::ca::trust::Faults;

    struct MemorySigner {
        key: Arc<KeyPair>,
        point: Vec<u8>,
    }

    impl RootSigner for MemorySigner {
        fn public_point(&self) -> &[u8] {
            &self.point
        }

        fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, String> {
            self.key.sign(message).map_err(|e| e.to_string())
        }
    }

    pub fn signer(key: Arc<KeyPair>) -> RootKey {
        let point = key.der_bytes().to_vec();
        RootKey::new(Box::new(MemorySigner { key, point }))
    }

    /// In-memory keys. `broken` names keys that exist and will not open.
    #[derive(Default)]
    pub struct MemoryKeyStore {
        pub faults: Arc<Faults>,
        pub keys: Mutex<BTreeMap<String, Arc<KeyPair>>>,
        pub broken: Mutex<BTreeSet<String>>,
        /// Every name ever created: a key is never reused.
        pub created: Mutex<Vec<String>>,
    }

    impl MemoryKeyStore {
        pub fn names(&self) -> Vec<String> {
            self.keys.lock().unwrap().keys().cloned().collect()
        }
    }

    impl KeyStore for MemoryKeyStore {
        fn create(&self, name: &str) -> Result<RootKey, String> {
            self.faults.step("key create", || {
                let key = Arc::new(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?);
                self.keys.lock().unwrap().insert(name.to_string(), key.clone());
                self.created.lock().unwrap().push(name.to_string());
                Ok(signer(key))
            })
        }

        fn open(&self, name: &str) -> Result<RootKey, String> {
            self.faults.step("key open", || {
                if self.broken.lock().unwrap().contains(name) {
                    return Err(format!("{name}: access denied"));
                }
                let keys = self.keys.lock().unwrap();
                Ok(signer(keys.get(name).ok_or_else(|| format!("{name}: no such key"))?.clone()))
            })
        }

        fn delete(&self, name: &str) -> Result<(), String> {
            self.faults.step("key delete", || {
                self.keys.lock().unwrap().remove(name);
                Ok(())
            })
        }
    }
}
