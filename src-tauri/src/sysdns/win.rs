//! The Windows calls of `sysdns`. Read only, except `run_elevated`:
//!
//! - `read_interfaces`: GetAdaptersAddresses (servers in force, per active
//!   adapter) plus the Tcpip / Tcpip6 `NameServer` registry values (the
//!   hand-set lists) under HKLM, read only.
//! - `process_names`: the process list (Toolhelp snapshot), read only.
//! - `run_elevated`: ShellExecuteExW with verb "runas" on powershell.exe and
//!   one script file. Windows shows its UAC prompt; declining it is
//!   `SysDnsError::Declined` and nothing ran.
//!
//! Off Windows every call is an error (Sieve is a Windows app; the stubs
//! keep `cargo test` building elsewhere).

use std::path::Path;

#[cfg(not(windows))]
use super::InterfaceDns;
use super::SysDnsError;

/// Process image names (lower case) that mean AdGuard for Windows is running.
pub const ADGUARD_EXES: [&str; 2] = ["adguard.exe", "adguardsvc.exe"];

/// True when one of `names` is an AdGuard process (case does not matter).
pub fn adguard_in<S: AsRef<str>>(names: &[S]) -> bool {
    names.iter().any(|n| ADGUARD_EXES.contains(&n.as_ref().to_ascii_lowercase().as_str()))
}

/// How long the elevated script may take once the prompt is answered.
pub const ELEVATED_TIMEOUT_MS: u32 = 120_000;

#[cfg(windows)]
mod imp {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::Path;

    use windows::Win32::Foundation::{CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_CANCELLED, ERROR_FILE_NOT_FOUND, HANDLE, NO_ERROR, WAIT_OBJECT_0};
    use windows::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, IF_TYPE_SOFTWARE_LOOPBACK,
        IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS};
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows::Win32::UI::Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::core::{HRESULT, PCWSTR};

    use super::super::{InterfaceDns, SysDnsError, family_dns, parse_name_server};
    use super::ELEVATED_TIMEOUT_MS;

    const V4_KEY: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\";
    const V6_KEY: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\";
    /// ShowWindow's SW_HIDE: the elevated PowerShell shows no console.
    const SW_HIDE: i32 = 0;
    /// Attempts at the GetAdaptersAddresses size probe (the list can grow between calls).
    const ATTEMPTS: usize = 4;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn from_wide(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    /// A REG_SZ under HKLM, or "" when the value does not exist.
    fn reg_string(key: &str, value: &str) -> Result<String, SysDnsError> {
        let (k, v) = (wide(key), wide(value));
        let mut size: u32 = 0;
        // SAFETY: valid NUL-terminated strings; a null data pointer asks for the size.
        let rc = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, PCWSTR(k.as_ptr()), PCWSTR(v.as_ptr()), RRF_RT_REG_SZ, None, None, Some(&mut size)) };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(String::new());
        }
        if rc != NO_ERROR {
            return Err(SysDnsError::Read(format!("registry {key}{value}: error {}", rc.0)));
        }
        let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
        let mut bytes = u32::try_from(buf.len() * 2).unwrap_or(u32::MAX);
        // SAFETY: `buf` holds `bytes` bytes.
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(k.as_ptr()),
                PCWSTR(v.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                Some(buf.as_mut_ptr().cast()),
                Some(&mut bytes),
            )
        };
        match rc {
            NO_ERROR => Ok(from_wide(&buf)),
            ERROR_FILE_NOT_FOUND => Ok(String::new()),
            e => Err(SysDnsError::Read(format!("registry {key}{value}: error {}", e.0))),
        }
    }

    /// The address in a SOCKET_ADDRESS, when it is IPv4 or IPv6.
    ///
    /// SAFETY: `a.lpSockaddr` points at a sockaddr of `a.iSockaddrLength` bytes (from GetAdaptersAddresses).
    unsafe fn socket_ip(a: &SOCKET_ADDRESS) -> Option<IpAddr> {
        if a.lpSockaddr.is_null() {
            return None;
        }
        let len = usize::try_from(a.iSockaddrLength).ok()?;
        // SAFETY: non-null, from the adapter list (see the function's contract).
        let family = unsafe { (*a.lpSockaddr).sa_family };
        if family == AF_INET && len >= std::mem::size_of::<SOCKADDR_IN>() {
            // SAFETY: an AF_INET sockaddr of at least SOCKADDR_IN size.
            let sin = unsafe { &*(a.lpSockaddr as *const SOCKADDR_IN) };
            // SAFETY: every view of the IN_ADDR union is plain bytes.
            let b = unsafe { sin.sin_addr.S_un.S_un_b };
            Some(IpAddr::V4(Ipv4Addr::new(b.s_b1, b.s_b2, b.s_b3, b.s_b4)))
        } else if family == AF_INET6 && len >= std::mem::size_of::<SOCKADDR_IN6>() {
            // SAFETY: an AF_INET6 sockaddr of at least SOCKADDR_IN6 size.
            let sin6 = unsafe { &*(a.lpSockaddr as *const SOCKADDR_IN6) };
            // SAFETY: every view of the IN6_ADDR union is plain bytes.
            Some(IpAddr::V6(Ipv6Addr::from(unsafe { sin6.sin6_addr.u.Byte })))
        } else {
            None
        }
    }

    pub fn read_interfaces() -> Result<Vec<InterfaceDns>, SysDnsError> {
        let flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        let mut size: u32 = 16 * 1024;
        let mut buf: Vec<u64> = Vec::new();
        let mut done = false;
        for _ in 0..ATTEMPTS {
            buf = vec![0u64; (size as usize).div_ceil(8)];
            // SAFETY: `buf` is `size` bytes, 8-aligned; the call fills a linked list inside it.
            let rc = unsafe { GetAdaptersAddresses(u32::from(AF_UNSPEC.0), flags, None, Some(buf.as_mut_ptr().cast()), &mut size) };
            if rc == NO_ERROR.0 {
                done = true;
                break;
            }
            if rc != ERROR_BUFFER_OVERFLOW.0 {
                return Err(SysDnsError::Read(format!("GetAdaptersAddresses: error {rc}")));
            }
        }
        if !done {
            return Err(SysDnsError::Read("GetAdaptersAddresses: the adapter list kept growing".to_owned()));
        }
        let mut out = Vec::new();
        let mut node = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !node.is_null() {
            // SAFETY: a node of the list GetAdaptersAddresses wrote into `buf`, alive while `buf` is.
            let a = unsafe { &*node };
            node = a.Next;
            if a.OperStatus != IfOperStatusUp || a.IfType == IF_TYPE_SOFTWARE_LOOPBACK || a.IfType == IF_TYPE_TUNNEL {
                continue;
            }
            // SAFETY: strings owned by the list.
            let alias = unsafe { a.FriendlyName.to_string() }.unwrap_or_default();
            // SAFETY: as above; the adapter name is its interface GUID in braces.
            let guid = unsafe { a.AdapterName.to_string() }.unwrap_or_default();
            // SAFETY: the IfIndex view of the first union is always written.
            let v4_index = unsafe { a.Anonymous1.Anonymous.IfIndex };
            let index = if v4_index != 0 { v4_index } else { a.Ipv6IfIndex };
            let (mut in_v4, mut in_v6) = (Vec::new(), Vec::new());
            let mut dns = a.FirstDnsServerAddress;
            while !dns.is_null() {
                // SAFETY: a node of the same list.
                let d = unsafe { &*dns };
                dns = d.Next;
                // SAFETY: the address of a list node.
                match unsafe { socket_ip(&d.Address) } {
                    Some(ip @ IpAddr::V4(_)) => in_v4.push(ip),
                    Some(ip @ IpAddr::V6(_)) => in_v6.push(ip),
                    None => {}
                }
            }
            let hand_v4 = parse_name_server(&reg_string(&format!("{V4_KEY}{guid}"), "NameServer")?);
            let hand_v6 = parse_name_server(&reg_string(&format!("{V6_KEY}{guid}"), "NameServer")?);
            out.push(InterfaceDns { alias, index, v4: family_dns(&hand_v4, &in_v4), v6: family_dns(&hand_v6, &in_v6) });
        }
        Ok(out)
    }

    pub fn process_names() -> Result<Vec<String>, SysDnsError> {
        // SAFETY: a process snapshot; closed below.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|e| SysDnsError::Read(format!("process list: {e}")))?;
        let mut names = Vec::new();
        let mut entry = PROCESSENTRY32W { dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap_or(0), ..Default::default() };
        // SAFETY: `entry.dwSize` is set; the snapshot handle is valid.
        let mut more = unsafe { Process32FirstW(snap, &mut entry) }.is_ok();
        while more {
            names.push(from_wide(&entry.szExeFile));
            // SAFETY: as above.
            more = unsafe { Process32NextW(snap, &mut entry) }.is_ok();
        }
        // SAFETY: the handle came from CreateToolhelp32Snapshot. A failed close leaks one handle; nothing to do.
        let _ = unsafe { CloseHandle(snap) };
        Ok(names)
    }

    pub fn run_elevated(script: &Path) -> Result<u32, SysDnsError> {
        let verb = wide("runas");
        let file = wide("powershell.exe");
        let params = wide(&format!(
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{}\"",
            script.display()
        ));
        let mut info = SHELLEXECUTEINFOW {
            cbSize: u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>()).unwrap_or(0),
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            lpVerb: PCWSTR(verb.as_ptr()),
            lpFile: PCWSTR(file.as_ptr()),
            lpParameters: PCWSTR(params.as_ptr()),
            nShow: SW_HIDE,
            ..Default::default()
        };
        // SAFETY: every string outlives the call; `info` is fully initialised.
        if let Err(e) = unsafe { ShellExecuteExW(&mut info) } {
            if e.code() == HRESULT::from_win32(ERROR_CANCELLED.0) {
                return Err(SysDnsError::Declined);
            }
            return Err(SysDnsError::Elevation(format!("could not start the elevated script: {e}")));
        }
        let process: HANDLE = info.hProcess;
        if process.is_invalid() {
            return Err(SysDnsError::Elevation("the elevated script gave no process to wait for".to_owned()));
        }
        // SAFETY: a process handle we own (SEE_MASK_NOCLOSEPROCESS); closed below.
        let waited = unsafe { WaitForSingleObject(process, ELEVATED_TIMEOUT_MS) };
        let mut code: u32 = 0;
        // SAFETY: as above.
        let got = unsafe { GetExitCodeProcess(process, &mut code) };
        // SAFETY: as above. A failed close leaks one handle; nothing to do.
        let _ = unsafe { CloseHandle(process) };
        if waited != WAIT_OBJECT_0 {
            return Err(SysDnsError::Elevation(format!(
                "the elevated script did not finish within {} s",
                ELEVATED_TIMEOUT_MS / 1000
            )));
        }
        got.map_err(|e| SysDnsError::Elevation(format!("no exit code from the elevated script: {e}")))?;
        Ok(code)
    }
}

#[cfg(windows)]
pub use imp::{process_names, read_interfaces};

/// Runs `script` with PowerShell as administrator and waits for its exit
/// code. Windows asks the user first (UAC).
#[cfg(windows)]
pub fn run_elevated(script: &Path) -> Result<u32, SysDnsError> {
    imp::run_elevated(script)
}

#[cfg(not(windows))]
pub fn read_interfaces() -> Result<Vec<InterfaceDns>, SysDnsError> {
    Err(SysDnsError::Read("Windows DNS can only be read on Windows".to_owned()))
}

#[cfg(not(windows))]
pub fn process_names() -> Result<Vec<String>, SysDnsError> {
    Err(SysDnsError::Read("the process list is read on Windows only".to_owned()))
}

#[cfg(not(windows))]
pub fn run_elevated(_script: &Path) -> Result<u32, SysDnsError> {
    Err(SysDnsError::Elevation("only Windows can run the DNS script".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adguard_is_found_by_either_exe_in_any_case() {
        assert!(adguard_in(&["explorer.exe", "Adguard.exe"]));
        assert!(adguard_in(&["ADGUARDSVC.EXE"]));
        assert!(!adguard_in(&["explorer.exe", "adguardvpn.exe", "AdGuard Browser Assistant.exe"]));
        assert!(!adguard_in::<&str>(&[]));
    }

    /// Read only: lists the active adapters and their DNS. Never writes.
    #[cfg(windows)]
    #[test]
    fn reading_interfaces_and_processes_works_without_admin() {
        let ifaces = read_interfaces().expect("adapters are readable without admin");
        for i in &ifaces {
            assert!(!i.alias.is_empty());
            for s in i.v4.servers.iter().chain(&i.v6.servers) {
                s.parse::<std::net::IpAddr>().expect("servers are addresses");
            }
        }
        let names = process_names().expect("process list is readable");
        assert!(names.iter().any(|n| n.eq_ignore_ascii_case("cargo.exe") || n.to_ascii_lowercase().starts_with("sieve")), "{names:?}");
    }
}
