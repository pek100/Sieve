//! The root's key in CNG (plan 2.2): machine scope, Microsoft Software KSP,
//! not exportable, with a DACL of SYSTEM only, set before the key is
//! finalized. The engine signs through `NCryptSignHash`, so the key never
//! enters this process as bytes.

use sha2::{Digest, Sha256};
use windows::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, CERT_KEY_SPEC, MS_KEY_STORAGE_PROVIDER, NCRYPT_EXPORT_POLICY_PROPERTY,
    NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_PERSIST_FLAG, NCRYPT_PROV_HANDLE,
    NCRYPT_SECURITY_DESCR_PROPERTY, NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey,
    NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, GetSecurityDescriptorLength};
use windows::core::PCWSTR;

use super::wide;
use crate::ca::cng_blob::{ecc_public_blob_to_point, p1363_to_der};
use crate::ca::key::{KeyStore, RootKey, RootSigner};
use crate::service::acl::SecurityDescriptor;

/// SYSTEM only, protected: nothing inherited.
pub const KEY_SDDL: &str = "D:P(A;;GA;;;SY)";
/// No export flag set: the key is not exportable.
const EXPORT_NONE: u32 = 0;
/// `NTE_BAD_KEYSET`: the key does not exist.
const KEY_NOT_FOUND: windows::core::HRESULT = windows::core::HRESULT(0x8009_0016_u32 as i32);
/// The largest `r||s` of P-256.
const P256_SIGNATURE: usize = 64;

/// An open NCrypt object, freed on drop.
struct Object(NCRYPT_HANDLE);

impl Drop for Object {
    fn drop(&mut self) {
        // SAFETY: the handle came from NCrypt and is freed once.
        let _ = unsafe { NCryptFreeObject(self.0) };
    }
}

fn provider() -> Result<(Object, NCRYPT_PROV_HANDLE), String> {
    let mut handle = NCRYPT_PROV_HANDLE::default();
    // SAFETY: an out pointer and a constant provider name.
    unsafe { NCryptOpenStorageProvider(&raw mut handle, MS_KEY_STORAGE_PROVIDER, 0) }
        .map_err(|e| format!("NCryptOpenStorageProvider: {e}"))?;
    Ok((Object(NCRYPT_HANDLE(handle.0)), handle))
}

/// A key this process may sign with; the public point is read once.
struct CngSigner {
    _object: Object,
    key: NCRYPT_KEY_HANDLE,
    point: Vec<u8>,
}

// SAFETY: NCrypt key handles may be used from any thread; the handle is only
// freed in Drop, when no other reference exists.
unsafe impl Send for CngSigner {}
unsafe impl Sync for CngSigner {}

impl RootSigner for CngSigner {
    fn public_point(&self) -> &[u8] {
        &self.point
    }

    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let digest = Sha256::digest(message);
        let mut signature = [0u8; P256_SIGNATURE];
        let mut written = 0u32;
        // SAFETY: the key is open; the buffers outlive the call and `written`
        // receives the length Windows wrote.
        unsafe { NCryptSignHash(self.key, None, &digest, Some(&mut signature), &raw mut written, NCRYPT_SILENT_FLAG) }
            .map_err(|e| format!("NCryptSignHash: {e}"))?;
        p1363_to_der(&signature[..written as usize])
    }
}

fn public_point(key: NCRYPT_KEY_HANDLE) -> Result<Vec<u8>, String> {
    let mut length = 0u32;
    // SAFETY: a size probe with no output buffer.
    unsafe { NCryptExportKey(key, None, BCRYPT_ECCPUBLIC_BLOB, None, None, &raw mut length, NCRYPT_SILENT_FLAG) }
        .map_err(|e| format!("NCryptExportKey size: {e}"))?;
    let mut blob = vec![0u8; length as usize];
    // SAFETY: `blob` holds the size Windows just asked for. This exports the
    // PUBLIC blob only; the private blob is refused by the export policy.
    unsafe { NCryptExportKey(key, None, BCRYPT_ECCPUBLIC_BLOB, None, Some(&mut blob), &raw mut length, NCRYPT_SILENT_FLAG) }
        .map_err(|e| format!("NCryptExportKey: {e}"))?;
    ecc_public_blob_to_point(&blob[..length as usize])
}

fn root_key(key: NCRYPT_KEY_HANDLE) -> Result<RootKey, String> {
    let object = Object(NCRYPT_HANDLE(key.0));
    let point = public_point(key)?;
    Ok(RootKey::new(Box::new(CngSigner { _object: object, key, point })))
}

/// The machine's CNG store. Built only by the service and its verbs (law 13).
pub struct CngKeyStore;

fn open_handle(provider: NCRYPT_PROV_HANDLE, name: &[u16]) -> windows::core::Result<NCRYPT_KEY_HANDLE> {
    let mut key = NCRYPT_KEY_HANDLE::default();
    let flags = NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG;
    // SAFETY: `name` is NUL-terminated and outlives the call.
    unsafe { NCryptOpenKey(provider, &raw mut key, PCWSTR(name.as_ptr()), CERT_KEY_SPEC(0), flags) }?;
    Ok(key)
}

fn set_property(key: NCRYPT_KEY_HANDLE, property: PCWSTR, value: &[u8], flags: NCRYPT_FLAGS, what: &str) -> Result<(), String> {
    // SAFETY: `value` outlives the call; NCrypt copies it.
    unsafe { NCryptSetProperty(NCRYPT_HANDLE(key.0), property, value, flags) }.map_err(|e| format!("{what}: {e}"))
}

impl KeyStore for CngKeyStore {
    fn create(&self, name: &str) -> Result<RootKey, String> {
        let (_provider, handle) = provider()?;
        let text = wide(name);
        let mut key = NCRYPT_KEY_HANDLE::default();
        let flags = NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG;
        // SAFETY: `text` is NUL-terminated and outlives the call.
        unsafe {
            NCryptCreatePersistedKey(handle, &raw mut key, BCRYPT_ECDSA_P256_ALGORITHM, PCWSTR(text.as_ptr()), CERT_KEY_SPEC(0), flags)
        }
        .map_err(|e| format!("NCryptCreatePersistedKey: {e}"))?;
        let guard = Object(NCRYPT_HANDLE(key.0));

        let persist = NCRYPT_PERSIST_FLAG | NCRYPT_SILENT_FLAG;
        set_property(key, NCRYPT_EXPORT_POLICY_PROPERTY, &EXPORT_NONE.to_le_bytes(), persist, "export policy")?;
        let descriptor = SecurityDescriptor::from_sddl(KEY_SDDL)?;
        // SAFETY: the descriptor is valid while `descriptor` lives, and its
        // length is what GetSecurityDescriptorLength reports.
        let bytes = unsafe {
            std::slice::from_raw_parts(descriptor.raw().0.cast::<u8>(), GetSecurityDescriptorLength(descriptor.raw()) as usize)
        };
        // For this property the flags name the part of the descriptor set.
        let dacl = NCRYPT_FLAGS(DACL_SECURITY_INFORMATION.0) | NCRYPT_SILENT_FLAG;
        set_property(key, NCRYPT_SECURITY_DESCR_PROPERTY, bytes, dacl, "key DACL")?;
        // SAFETY: the key is open and not yet finalized.
        unsafe { NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG) }.map_err(|e| format!("NCryptFinalizeKey: {e}"))?;
        std::mem::forget(guard);
        root_key(key)
    }

    fn open(&self, name: &str) -> Result<RootKey, String> {
        let (_provider, handle) = provider()?;
        let key = open_handle(handle, &wide(name)).map_err(|e| format!("NCryptOpenKey: {e}"))?;
        root_key(key)
    }

    fn delete(&self, name: &str) -> Result<(), String> {
        let (_provider, handle) = provider()?;
        let key = match open_handle(handle, &wide(name)) {
            Ok(key) => key,
            Err(e) if e.code() == KEY_NOT_FOUND => return Ok(()),
            Err(e) => return Err(format!("NCryptOpenKey: {e}")),
        };
        let guard = Object(NCRYPT_HANDLE(key.0));
        // SAFETY: the key is open. On success NCryptDeleteKey has freed the handle,
        // so the guard must not; on failure the handle is still this code's to free.
        unsafe { NCryptDeleteKey(key, NCRYPT_SILENT_FLAG.0) }.map_err(|e| format!("NCryptDeleteKey: {e}"))?;
        std::mem::forget(guard);
        Ok(())
    }
}
