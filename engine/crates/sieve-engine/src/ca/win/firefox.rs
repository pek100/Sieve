//! The machine's Firefox policy value (plan 2.3): Mozilla's documented
//! enterprise policy, which covers every profile with no NSS tooling. Whether
//! to write or remove it is decided in `Ca`; this only does the registry work.

use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_VALUE_TYPE,
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteValueW, RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW,
    RegSetValueExW,
};
use windows::core::{PCWSTR, w};

use super::wide;
use crate::ca::trust::{FIREFOX_POLICY_ON, FirefoxPolicy};

/// Where the policy lives, and the keys to remove upward once empty (never
/// `SOFTWARE\Policies` itself).
const POLICY_KEY: &str = r"SOFTWARE\Policies\Mozilla\Firefox\Certificates";
const POLICY_PARENTS: [&str; 3] =
    [r"SOFTWARE\Policies\Mozilla\Firefox\Certificates", r"SOFTWARE\Policies\Mozilla\Firefox", r"SOFTWARE\Policies\Mozilla"];
const POLICY_VALUE: PCWSTR = w!("ImportEnterpriseRoots");
/// Either says Firefox is installed for the machine. A per-user install may
/// not be seen by SYSTEM (UNVERIFIED, docs/live/engine-slice-5.md).
const INSTALLED_KEYS: [&str; 2] = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe", r"SOFTWARE\Mozilla\Mozilla Firefox"];

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: opened by RegOpenKeyExW or RegCreateKeyExW and closed once.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

fn check(code: WIN32_ERROR, what: &str) -> Result<(), String> {
    if code == ERROR_SUCCESS { Ok(()) } else { Err(format!("{what}: {}", windows::core::Error::from(code))) }
}

/// The key under HKLM, or None when it does not exist.
fn open(path: &str, access: windows::Win32::System::Registry::REG_SAM_FLAGS) -> Result<Option<Key>, String> {
    let text = wide(path);
    let mut key = HKEY::default();
    // SAFETY: `text` is NUL-terminated and outlives the call.
    let code = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(text.as_ptr()), None, access, &raw mut key) };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    check(code, path)?;
    Ok(Some(Key(key)))
}

/// Removes the key when it holds no value and no subkey.
fn delete_if_empty(path: &str) -> Result<bool, String> {
    let Some(key) = open(path, KEY_QUERY_VALUE)? else { return Ok(true) };
    let (mut subkeys, mut values) = (0u32, 0u32);
    // SAFETY: the out pointers live through the call.
    let code = unsafe {
        RegQueryInfoKeyW(key.0, None, None, None, Some(&raw mut subkeys), None, None, Some(&raw mut values), None, None, None, None)
    };
    check(code, path)?;
    if subkeys != 0 || values != 0 {
        return Ok(false);
    }
    let text = wide(path);
    // SAFETY: `text` is NUL-terminated and outlives the call.
    check(unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, PCWSTR(text.as_ptr())) }, path)?;
    Ok(true)
}

/// The machine's Firefox policy. Built only by the service and its verbs (law 13).
pub struct RegistryFirefoxPolicy;

impl FirefoxPolicy for RegistryFirefoxPolicy {
    fn installed(&self) -> Result<bool, String> {
        for path in INSTALLED_KEYS {
            if open(path, KEY_QUERY_VALUE)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn read(&self) -> Result<Option<u32>, String> {
        let Some(key) = open(POLICY_KEY, KEY_QUERY_VALUE)? else { return Ok(None) };
        let mut value = 0u32;
        let mut kind = REG_VALUE_TYPE::default();
        let mut size = size_of::<u32>() as u32;
        // SAFETY: `value` holds the `size` bytes given.
        let code = unsafe {
            RegQueryValueExW(key.0, POLICY_VALUE, None, Some(&raw mut kind), Some((&raw mut value).cast::<u8>()), Some(&raw mut size))
        };
        if code == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        check(code, "ImportEnterpriseRoots")?;
        if kind != REG_DWORD {
            return Err(format!("ImportEnterpriseRoots has registry type {}", kind.0));
        }
        Ok(Some(value))
    }

    fn set(&self) -> Result<(), String> {
        let text = wide(POLICY_KEY);
        let mut key = HKEY::default();
        // SAFETY: `text` is NUL-terminated and outlives the call.
        let code = unsafe {
            RegCreateKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(text.as_ptr()), None, PCWSTR::null(), REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &raw mut key, None)
        };
        check(code, POLICY_KEY)?;
        let key = Key(key);
        // SAFETY: the key is open; the bytes outlive the call.
        let code = unsafe { RegSetValueExW(key.0, POLICY_VALUE, None, REG_DWORD, Some(&FIREFOX_POLICY_ON.to_le_bytes())) };
        check(code, "ImportEnterpriseRoots")
    }

    fn delete(&self) -> Result<(), String> {
        if let Some(key) = open(POLICY_KEY, KEY_SET_VALUE)? {
            // SAFETY: the key is open.
            let code = unsafe { RegDeleteValueW(key.0, POLICY_VALUE) };
            if code != ERROR_FILE_NOT_FOUND {
                check(code, "ImportEnterpriseRoots")?;
            }
        }
        for path in POLICY_PARENTS {
            if !delete_if_empty(path)? {
                break;
            }
        }
        Ok(())
    }
}
