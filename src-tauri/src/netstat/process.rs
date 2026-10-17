//! pid to process facts (read only, no admin).
//!
//! Exe path: `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` then
//! `QueryFullProcessImageNameW`. Product name: `GetFileVersionInfoSizeW`,
//! `GetFileVersionInfoW`, `VerQueryValueW` on `\StringFileInfo\<lang><cp>\ProductName`,
//! cached per exe path (version info does not change while a file is in use).
//!
//! When Windows refuses (elevated or protected processes from a normal
//! user), the answer is `exe: null`, and the name is the display name of the
//! Windows services the process hosts (`service_names`: EnumServicesStatusExW
//! with SC_MANAGER_ENUMERATE_SERVICE, read only, no admin), else
//! `"pid <n>"`. Pid 4 has the fixed label "System". Never a guessed name.
//! Pid 0 (the System Idle Process) owns no socket of its own: its rows are
//! closed connections in TIME_WAIT, and `super::assemble` drops them.

use std::collections::HashMap;

use crate::protocol::ProcessInfo;

/// Facts about one pid. `exe_of`, `product_of` and `service_of` are the OS
/// lookups, injected so the naming rules are testable without Windows.
/// `service_of` is asked only when the exe is hidden.
pub fn describe(
    pid: u32,
    exe_of: impl FnOnce(u32) -> Option<String>,
    product_of: impl FnOnce(&str) -> Option<String>,
    service_of: impl FnOnce(u32) -> Option<String>,
) -> ProcessInfo {
    let exe = if is_kernel_pid(pid) { None } else { exe_of(pid) };
    let product = exe.as_deref().and_then(product_of);
    let service = if exe.is_none() && !is_kernel_pid(pid) { service_of(pid) } else { None };
    let name = label(pid, exe.as_deref(), service.as_deref());
    ProcessInfo { pid, exe, name, product }
}

/// The name for a process hosting these services: the display name when it
/// is one, else the first by name and how many more ("Windows Update and 3
/// more"). Sorted, so the name (and the app it groups into) is stable from
/// one sample to the next. None for no services.
pub fn service_label(mut names: Vec<String>) -> Option<String> {
    names.retain(|n| !n.trim().is_empty());
    names.sort();
    names.dedup();
    match names.len() {
        0 => None,
        1 => names.pop(),
        n => Some(format!("{} and {} more", names[0], n - 1)),
    }
}

/// The service-name lookup for one snapshot: pid -> its label.
pub fn service_lookup(services: &HashMap<u32, Vec<String>>) -> impl Fn(u32) -> Option<String> + '_ {
    move |pid| services.get(&pid).and_then(|names| service_label(names.clone()))
}

/// pids 0 (System Idle Process) and 4 (System) have no image file.
pub fn is_kernel_pid(pid: u32) -> bool {
    pid == 0 || pid == 4
}

/// Display name: the exe file name when known, else a fixed label for the
/// kernel pids, else the hosted services' name, else "pid <n>".
pub fn label(pid: u32, exe: Option<&str>, service: Option<&str>) -> String {
    match (exe, service) {
        (Some(path), _) => file_name(path).to_string(),
        (None, _) if pid == 0 => "System idle".to_string(),
        (None, _) if pid == 4 => "System".to_string(),
        (None, Some(service)) => service.to_string(),
        (None, None) => format!("pid {pid}"),
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
pub use os::{exe_path, product_name, service_names};

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

    use windows::Win32::Foundation::ERROR_MORE_DATA;
    use windows::Win32::System::Services::{
        CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW, SC_ENUM_PROCESS_INFO,
        SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
    };

    /// First buffer for the service list (64 KiB, about 400 services); it
    /// grows to what Windows asks for.
    const SERVICE_BUF_WORDS: usize = 8 * 1024;
    /// Calls before giving up on a list that keeps changing under us.
    const SERVICE_ROUNDS: usize = 16;

    /// Running Windows services by the pid that hosts them, display names.
    /// Read only: the service manager opened for enumeration only (no admin).
    /// An empty map when Windows refuses; names are then left to "pid <n>".
    pub fn service_names() -> HashMap<u32, Vec<String>> {
        let mut out: HashMap<u32, Vec<String>> = HashMap::new();
        // SAFETY: plain call; the handle is closed below on every path.
        let Ok(scm) = (unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) }) else {
            return out;
        };
        // u64 storage keeps the buffer aligned for the structs Windows writes into it.
        let mut buf: Vec<u64> = vec![0; SERVICE_BUF_WORDS];
        let mut resume: u32 = 0;
        for _ in 0..SERVICE_ROUNDS {
            let (mut needed, mut count) = (0u32, 0u32);
            let result = {
                // SAFETY: a byte view of `buf`, which outlives this call.
                let bytes = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), buf.len() * 8) };
                // SAFETY: `bytes` is writable for its whole length; the out pointers are valid locals.
                unsafe {
                    EnumServicesStatusExW(
                        scm,
                        SC_ENUM_PROCESS_INFO,
                        SERVICE_WIN32,
                        SERVICE_ACTIVE,
                        Some(bytes),
                        &mut needed,
                        &mut count,
                        Some(&mut resume),
                        PCWSTR::null(),
                    )
                }
            };
            // SAFETY: Windows wrote `count` entries at the start of `buf`; their
            // strings point into `buf`, which is not touched until they are read.
            let entries = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(), count as usize) };
            for e in entries {
                let pid = e.ServiceStatusProcess.dwProcessId;
                // SAFETY: a NUL-terminated string inside `buf` (or null, which reads as an error).
                let name = if e.lpDisplayName.is_null() { None } else { unsafe { e.lpDisplayName.to_string() }.ok() };
                if let (true, Some(name)) = (pid != 0, name) {
                    out.entry(pid).or_default().push(name);
                }
            }
            match result {
                Ok(()) => break,
                Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() => {
                    // Nothing fitted: grow to what Windows asked for, then ask again from `resume`.
                    if count == 0 {
                        buf = vec![0; (needed as usize).div_ceil(8).max(buf.len() * 2)];
                    }
                }
                Err(_) => break,
            }
        }
        // SAFETY: `scm` came from OpenSCManagerW and is closed once.
        let _ = unsafe { CloseServiceHandle(scm) };
        out
    }

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
pub fn service_names() -> HashMap<u32, Vec<String>> {
    HashMap::new()
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

    fn never_service(_: u32) -> Option<String> {
        panic!("must not ask for services for this pid")
    }

    fn no_service(_: u32) -> Option<String> {
        None
    }

    #[test]
    fn kernel_pids_get_fixed_labels_and_no_os_query() {
        let idle = describe(0, never_exe, |_| None, never_service);
        assert_eq!(idle, ProcessInfo { pid: 0, exe: None, name: "System idle".into(), product: None });
        let system = describe(4, never_exe, |_| None, never_service);
        assert_eq!(system, ProcessInfo { pid: 4, exe: None, name: "System".into(), product: None });
    }

    #[test]
    fn access_denied_gives_exe_null_and_pid_label() {
        let p = describe(15500, |_| None, |_| panic!("no exe, no product lookup"), no_service);
        assert_eq!(p, ProcessInfo { pid: 15500, exe: None, name: "pid 15500".into(), product: None });
    }

    #[test]
    fn a_hidden_exe_takes_its_windows_service_name() {
        // The 'pid 5720' with 1244 connections on the first live look: a service host.
        let services: HashMap<u32, Vec<String>> = HashMap::from([
            (5720, vec!["Delivery Optimization".to_owned()]),
            (1200, vec!["Windows Update".to_owned(), "Background Intelligent Transfer Service".to_owned(), "Cryptographic Services".to_owned()]),
        ]);
        let lookup = service_lookup(&services);
        let p = describe(5720, |_| None, |_| panic!("no exe, no product lookup"), &lookup);
        assert_eq!(p, ProcessInfo { pid: 5720, exe: None, name: "Delivery Optimization".into(), product: None });
        // Several services: the first by name and how many more, stable across samples.
        assert_eq!(describe(1200, |_| None, |_| None, &lookup).name, "Background Intelligent Transfer Service and 2 more");
        // No service for the pid: back to "pid <n>".
        assert_eq!(describe(77, |_| None, |_| None, &lookup).name, "pid 77");
        // A readable exe wins, and services are not asked.
        assert_eq!(describe(5720, |_| Some(r"C:\Windows\System32\svchost.exe".into()), |_| None, never_service).name, "svchost.exe");
    }

    #[test]
    fn service_label_is_stable_and_skips_blank_names() {
        assert_eq!(service_label(vec![]), None);
        assert_eq!(service_label(vec![" ".into()]), None);
        assert_eq!(service_label(vec!["B".into(), "A".into(), "A".into()]), Some("A and 1 more".into()));
        assert_eq!(service_label(vec!["A".into(), "B".into()]), service_label(vec!["B".into(), "A".into()]));
    }

    /// Live check (read only, no admin): the service list of this machine
    /// names at least one running service host.
    /// `cargo test --manifest-path src-tauri/Cargo.toml --lib -- --ignored live_service_names`
    #[test]
    #[ignore = "live: reads this machine's service list"]
    fn live_service_names_name_running_service_hosts() {
        let services = service_names();
        let total: usize = services.values().map(Vec::len).sum();
        eprintln!("live services: {total} running services in {} processes", services.len());
        assert!(!services.is_empty());
        assert!(!services.contains_key(&0));
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
            never_service,
        );
        assert_eq!(p.exe.as_deref(), Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"));
        assert_eq!(p.name, "chrome.exe");
        assert_eq!(p.product.as_deref(), Some("Google Chrome"));
    }

    #[test]
    fn exe_without_version_info_has_product_null() {
        let p = describe(77, |_| Some(r"C:\tools\thing.exe".into()), |_| None, never_service);
        assert_eq!(p.name, "thing.exe");
        assert_eq!(p.product, None);
    }

    #[test]
    fn label_handles_both_separators() {
        assert_eq!(label(1, Some(r"C:\a\b\c.exe"), None), "c.exe");
        assert_eq!(label(1, Some("C:/a/b/c.exe"), None), "c.exe");
        assert_eq!(label(1, Some("c.exe"), Some("ignored")), "c.exe");
        assert_eq!(label(8, None, None), "pid 8");
        assert_eq!(label(8, None, Some("Print Spooler")), "Print Spooler");
    }
}
