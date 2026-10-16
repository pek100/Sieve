//! pid to process facts (read only, no admin).
//!
//! Exe path: `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` then
//! `QueryFullProcessImageNameW`. Product name: `GetFileVersionInfoSizeW`,
//! `GetFileVersionInfoW`, `VerQueryValueW` on `\StringFileInfo\<lang><cp>\ProductName`,
//! cached per exe path (version info does not change while a file is in use).
//!
//! When Windows refuses (elevated or protected processes from a normal
//! user), the answer is `exe: null` and `name: "pid <n>"`. Only pids 0 and 4
//! have fixed labels ("System idle", "System"). Never a guessed name.

use crate::protocol::ProcessInfo;

/// Facts about one pid. `exe_of` and `product_of` are the OS lookups,
/// injected so the naming rules are testable without Windows.
pub fn describe(
    pid: u32,
    exe_of: impl FnOnce(u32) -> Option<String>,
    product_of: impl FnOnce(&str) -> Option<String>,
) -> ProcessInfo {
    let exe = if is_kernel_pid(pid) { None } else { exe_of(pid) };
    let product = exe.as_deref().and_then(product_of);
    let name = label(pid, exe.as_deref());
    ProcessInfo { pid, exe, name, product }
}

/// pids 0 (System Idle Process) and 4 (System) have no image file.
pub fn is_kernel_pid(pid: u32) -> bool {
    pid == 0 || pid == 4
}

/// Display name: the exe file name when known, else a fixed label for the
/// kernel pids, else "pid <n>".
pub fn label(pid: u32, exe: Option<&str>) -> String {
    match exe {
        Some(path) => file_name(path).to_string(),
        None => match pid {
            0 => "System idle".to_string(),
            4 => "System".to_string(),
            n => format!("pid {n}"),
        },
    }
}

/// Last component of a Windows (or forward-slash) path.
fn file_name(path: &str) -> &str {
    match path.rfind(['\\', '/']) {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

#[cfg(windows)]
pub use os::{exe_path, product_name};

#[cfg(windows)]
mod os {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::sync::{Mutex, OnceLock};

    use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER};
    use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };
    use windows::core::{PCWSTR, PWSTR};

    /// Longest path QueryFullProcessImageNameW can return (UNICODE_STRING limit).
    const MAX_PATH_CHARS: u32 = 32_768;

    /// Full image path of a running process, or None when Windows refuses
    /// (access denied, process gone).
    pub fn exe_path(pid: u32) -> Option<String> {
        // SAFETY: plain call; the handle is closed below on every path.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let mut cap: u32 = 512;
        let result = loop {
            let mut buf = vec![0u16; cap as usize];
            let mut len = cap;
            // SAFETY: `buf` holds `len` u16s; Windows writes at most that many
            // and sets `len` to the characters written (no terminator).
            let r = unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len) };
            match r {
                Ok(()) => break buf.get(..len as usize).map(String::from_utf16_lossy),
                Err(e) if e.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() && cap < MAX_PATH_CHARS => {
                    cap = MAX_PATH_CHARS;
                }
                Err(_) => break None,
            }
        };
        // SAFETY: `handle` came from OpenProcess and is closed once.
        let _ = unsafe { CloseHandle(handle) };
        result.filter(|p| !p.is_empty())
    }

    fn cache() -> &'static Mutex<HashMap<String, Option<String>>> {
        static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
        CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// ProductName from the exe's version resource, cached per path
    /// (a missing one is cached too).
    pub fn product_name(exe: &str) -> Option<String> {
        if let Some(hit) = lock_cache().get(exe) {
            return hit.clone();
        }
        let found = read_product_name(exe);
        lock_cache().insert(exe.to_string(), found.clone());
        found
    }

    /// The cache only holds plain data, so a poisoned lock is still usable.
    fn lock_cache() -> std::sync::MutexGuard<'static, HashMap<String, Option<String>>> {
        match cache().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn read_product_name(exe: &str) -> Option<String> {
        let path = wide(exe);
        // SAFETY: `path` is a NUL-terminated UTF-16 string that outlives the calls.
        let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(path.as_ptr()), None) };
        if size == 0 {
            return None;
        }
        // u32 storage keeps the block aligned for the u16 strings inside it.
        let mut block = vec![0u32; (size as usize).div_ceil(4)];
        // SAFETY: `block` has at least `size` bytes.
        unsafe { GetFileVersionInfoW(PCWSTR(path.as_ptr()), None, size, block.as_mut_ptr().cast::<c_void>()) }.ok()?;

        let mut keys: Vec<(u16, u16)> = Vec::new();
        if let Some(words) = query(&block, "\\VarFileInfo\\Translation") {
            keys.extend(words.chunks_exact(2).map(|p| (p[0], p[1])));
        }
        // Common fallbacks when the translation table is missing or wrong:
        // US English with Unicode, US English with Windows-1252, neutral Unicode.
        keys.extend([(0x0409, 0x04B0), (0x0409, 0x04E4), (0x0000, 0x04B0)]);

        keys.into_iter().find_map(|(lang, cp)| {
            let words = query(&block, &format!("\\StringFileInfo\\{lang:04x}{cp:04x}\\ProductName"))?;
            let text = String::from_utf16_lossy(words);
            let text = text.trim_end_matches('\0').trim();
            (!text.is_empty()).then(|| text.to_string())
        })
    }

    /// VerQueryValueW for `sub`, returned as the u16 words it points at
    /// (for the translation table `len` is bytes, for strings it is chars;
    /// both read as u16 here, so bytes are halved).
    fn query<'a>(block: &'a [u32], sub: &str) -> Option<&'a [u16]> {
        let key = wide(sub);
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let mut len: u32 = 0;
        // SAFETY: `block` is the buffer GetFileVersionInfoW filled; `ptr` is
        // set to a location inside it and `len` to its length.
        let ok = unsafe { VerQueryValueW(block.as_ptr().cast::<c_void>(), PCWSTR(key.as_ptr()), &mut ptr, &mut len) };
        if !ok.as_bool() || ptr.is_null() || len == 0 || !ptr.cast::<u16>().is_aligned() {
            return None;
        }
        let words = if sub.starts_with("\\VarFileInfo") { len as usize / 2 } else { len as usize };
        let start = block.as_ptr() as usize;
        let end = start + block.len() * 4;
        let at = ptr as usize;
        if at < start || at + words * 2 > end {
            return None;
        }
        // SAFETY: checked above that [ptr, ptr + words * 2) lies inside `block`
        // and is 2-byte aligned; the slice borrows `block`.
        Some(unsafe { std::slice::from_raw_parts(ptr.cast::<u16>(), words) })
    }
}

/// Off Windows there is no process table to ask.
#[cfg(not(windows))]
pub fn exe_path(_pid: u32) -> Option<String> {
    None
}

#[cfg(not(windows))]
pub fn product_name(_exe: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn never_exe(_: u32) -> Option<String> {
        panic!("must not query the OS for this pid")
    }

    #[test]
    fn kernel_pids_get_fixed_labels_and_no_os_query() {
        let idle = describe(0, never_exe, |_| None);
        assert_eq!(idle, ProcessInfo { pid: 0, exe: None, name: "System idle".into(), product: None });
        let system = describe(4, never_exe, |_| None);
        assert_eq!(system, ProcessInfo { pid: 4, exe: None, name: "System".into(), product: None });
    }

    #[test]
    fn access_denied_gives_exe_null_and_pid_label() {
        let p = describe(15500, |_| None, |_| panic!("no exe, no product lookup"));
        assert_eq!(p, ProcessInfo { pid: 15500, exe: None, name: "pid 15500".into(), product: None });
    }

    #[test]
    fn known_exe_gives_file_name_and_product() {
        let p = describe(
            9120,
            |_| Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe".into()),
            |exe| {
                assert!(exe.ends_with("chrome.exe"));
                Some("Google Chrome".into())
            },
        );
        assert_eq!(p.exe.as_deref(), Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"));
        assert_eq!(p.name, "chrome.exe");
        assert_eq!(p.product.as_deref(), Some("Google Chrome"));
    }

    #[test]
    fn exe_without_version_info_has_product_null() {
        let p = describe(77, |_| Some(r"C:\tools\thing.exe".into()), |_| None);
        assert_eq!(p.name, "thing.exe");
        assert_eq!(p.product, None);
    }

    #[test]
    fn label_handles_both_separators() {
        assert_eq!(label(1, Some(r"C:\a\b\c.exe")), "c.exe");
        assert_eq!(label(1, Some("C:/a/b/c.exe")), "c.exe");
        assert_eq!(label(1, Some("c.exe")), "c.exe");
        assert_eq!(label(8, None), "pid 8");
    }
}
