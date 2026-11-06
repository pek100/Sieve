//! `LocalMachine\Root` (plan 2.3): add with the Server Authentication property
//! already on the context, read and remove by SHA-1 thumbprint only.

use std::ffi::c_void;

use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_ENHKEY_USAGE_PROP_ID, CERT_FIND_SHA1_HASH, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE,
    CERT_STORE_ADD_NEW, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_LOCAL_MACHINE,
    CRYPT_INTEGER_BLOB, CertAddCertificateContextToStore, CertCloseStore, CertCreateCertificateContext,
    CertDeleteCertificateFromStore, CertFindCertificateInStore, CertFreeCertificateContext, CertOpenStore,
    CertSetCertificateContextProperty, HCERTSTORE, X509_ASN_ENCODING,
};

use super::wide;
use crate::ca::trust::{RootStore, SERVER_AUTH_EKU_DER, StoreWrites, add_with_property};

const ROOT_STORE: &str = "Root";
/// A thumbprint is 20 bytes.
const SHA1_LEN: usize = 20;

struct Store(HCERTSTORE);

impl Store {
    fn open() -> Result<Self, String> {
        let name = wide(ROOT_STORE);
        let flags = CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG.0);
        // SAFETY: `name` is NUL-terminated and outlives the call.
        unsafe {
            CertOpenStore(CERT_STORE_PROV_SYSTEM_W, CERT_QUERY_ENCODING_TYPE(0), None, flags, Some(name.as_ptr().cast::<c_void>()))
        }
        .map(Self)
        .map_err(|e| format!("CertOpenStore: {e}"))
    }

    /// The certificate with this thumbprint; the caller owns the context.
    fn find(&self, thumbprint: &str) -> Result<Option<*mut CERT_CONTEXT>, String> {
        let mut hash = hash_bytes(thumbprint)?;
        let blob = CRYPT_INTEGER_BLOB { cbData: SHA1_LEN as u32, pbData: hash.as_mut_ptr() };
        // SAFETY: `blob` and `hash` outlive the call.
        let found = unsafe {
            CertFindCertificateInStore(self.0, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, Some((&raw const blob).cast::<c_void>()), None)
        };
        Ok((!found.is_null()).then_some(found))
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: opened by CertOpenStore and closed once.
        let _ = unsafe { CertCloseStore(Some(self.0), 0) };
    }
}

fn hash_bytes(thumbprint: &str) -> Result<[u8; SHA1_LEN], String> {
    let refuse = || format!("not a thumbprint: {thumbprint:?}");
    if thumbprint.len() != 2 * SHA1_LEN || !thumbprint.is_ascii() {
        return Err(refuse());
    }
    let mut out = [0u8; SHA1_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&thumbprint[2 * i..2 * i + 2], 16).map_err(|_| refuse())?;
    }
    Ok(out)
}

/// A context freed on drop.
struct Context(*mut CERT_CONTEXT);

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: created by CertCreateCertificateContext and freed once.
        let _ = unsafe { CertFreeCertificateContext(Some(self.0)) };
    }
}

impl StoreWrites for Store {
    type Context = Context;

    fn context(&self, der: &[u8]) -> Result<Context, String> {
        // SAFETY: Windows copies `der` into the context.
        let context = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der) };
        if context.is_null() {
            return Err(format!("CertCreateCertificateContext: {}", windows::core::Error::from_thread()));
        }
        Ok(Context(context))
    }

    fn set_server_auth(&self, context: &Context) -> Result<(), String> {
        let blob = CRYPT_INTEGER_BLOB { cbData: SERVER_AUTH_EKU_DER.len() as u32, pbData: SERVER_AUTH_EKU_DER.as_ptr().cast_mut() };
        // SAFETY: the context is valid and Windows copies the encoded usage.
        unsafe {
            CertSetCertificateContextProperty(context.0, CERT_ENHKEY_USAGE_PROP_ID, 0, Some((&raw const blob).cast::<c_void>()))
        }
        .map_err(|e| format!("CertSetCertificateContextProperty: {e}"))
    }

    fn add_new(&self, context: &Context) -> Result<(), String> {
        // SAFETY: both handles are valid; the add copies the context with
        // its properties, and no context comes back to free.
        unsafe { CertAddCertificateContextToStore(Some(self.0), context.0, CERT_STORE_ADD_NEW, None) }
            .map_err(|e| format!("CertAddCertificateContextToStore: {e}"))
    }
}

/// The machine's root store. Built only by the service and its verbs (law 13).
pub struct WindowsRootStore;

impl RootStore for WindowsRootStore {
    fn add(&self, der: &[u8]) -> Result<(), String> {
        add_with_property(&Store::open()?, der)
    }

    fn read(&self, thumbprint: &str) -> Result<Option<Vec<u8>>, String> {
        let store = Store::open()?;
        let Some(found) = store.find(thumbprint)? else { return Ok(None) };
        let found = Context(found);
        // SAFETY: the context is valid and its encoded bytes live with it.
        let der = unsafe { std::slice::from_raw_parts((*found.0).pbCertEncoded, (*found.0).cbCertEncoded as usize) };
        Ok(Some(der.to_vec()))
    }

    fn remove(&self, thumbprint: &str) -> Result<(), String> {
        let store = Store::open()?;
        let Some(found) = store.find(thumbprint)? else { return Ok(()) };
        // SAFETY: the delete frees the context in every case, so no Context
        // guard wraps it.
        unsafe { CertDeleteCertificateFromStore(found) }.map_err(|e| format!("CertDeleteCertificateFromStore: {e}"))
    }
}
