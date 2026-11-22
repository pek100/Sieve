//! Windows' own internet test, refused on Sieve's adapter, so the physical network
//! stays the internet connection: the one the taskbar draws and
//! `GetInternetConnectionProfile` returns.
//!
//! The Network List Service (`netprofm`, which runs the connectivity test, NCSI)
//! proves each network's internet access by a plain HTTP fetch bound to that
//! network's own address. Through Sieve's routes the fetch bound to Sieve's
//! adapter reaches the engine and succeeds (NCSI event 4042,
//! `ActiveHttpProbeSucceeded`, on the adapter's GUID), and Windows then prefers
//! Sieve's network as the internet connection whatever the interface metrics say:
//! on a Windows Server 2025 VM (2026-11-22) Sieve stayed it with its IPv4 metric at
//! 50 against Ethernet's 5, with its IPv6 metric back to automatic as well, and
//! with the metric set before its routes came up. A PC on Wi-Fi then showed a wired
//! icon. With that fetch refused, NCSI rates Sieve's network "local network" only
//! (`PassivePacketHops`) and the physical network is the internet connection
//! (same VM: `GetInternetConnectionProfile` named Ethernet for 5 minutes).
//!
//! The same service's fetch bound to the physical adapter's address leaves that
//! adapter by the strong host rule and never reaches Sieve, so the physical
//! network's own rating, and Windows' sign-in page detection on it, are
//! unchanged.
//!
//! The fetch is known by the process that makes it, not by the name it asks: after
//! its configured host failed, the service fell back to another host within two
//! minutes and rated Sieve "internet" again (same VM, a block rule on the
//! configured hosts). Only plain HTTP ([`PROBE_PORT`]) is refused, the one
//! protocol the test uses.
//!
//! TENSION: where Windows runs several services in one host process (machines with
//! little memory), the service shares its process, and the plain HTTP of the others
//! in it is refused through Sieve too. Their HTTPS, and every flow on a machine with
//! a process of its own for the service, are unaffected.

use std::sync::Mutex;

use crate::flow::packet::Proto;

/// The service that runs Windows' connectivity test.
pub const LIST_SERVICE: &str = "netprofm";
/// The connectivity test's protocol: plain HTTP.
pub const PROBE_PORT: u16 = 80;
/// How long the service's process id is trusted before it is read again: it changes
/// only when the service restarts.
pub const PID_FOR_MS: u64 = 10_000;

/// Whether a flow through Sieve is Windows' connectivity test: TCP to [`PROBE_PORT`]
/// from the process that hosts [`LIST_SERVICE`] (`service_pid`, None when it could
/// not be read, which refuses nothing).
pub fn is_probe(proto: Proto, port: u16, pid: Option<u32>, service_pid: Option<u32>) -> bool {
    proto == Proto::Tcp && port == PROBE_PORT && pid.is_some_and(|p| p != 0 && Some(p) == service_pid)
}

/// [`LIST_SERVICE`]'s process id, read through `read` at most once per
/// [`PID_FOR_MS`].
pub struct ServicePid<R> {
    read: R,
    held: Mutex<Option<(Option<u32>, u64)>>,
}

impl<R: Fn() -> Option<u32>> ServicePid<R> {
    pub fn new(read: R) -> Self {
        Self { read, held: Mutex::new(None) }
    }

    pub fn get(&self, now_ms: u64) -> Option<u32> {
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        match *held {
            Some((pid, at)) if now_ms.saturating_sub(at) < PID_FOR_MS => pid,
            _ => {
                let pid = (self.read)();
                *held = Some((pid, now_ms));
                pid
            }
        }
    }
}

/// [`is_probe`] for a flow through Sieve now, with the service's process id read
/// from the service manager (held for [`PID_FOR_MS`]), and only for TCP to
/// [`PROBE_PORT`] from an attributed process.
#[cfg(windows)]
pub fn refuses(proto: Proto, port: u16, pid: Option<u32>, now_ms: u64) -> bool {
    static SERVICE: std::sync::OnceLock<ServicePid<fn() -> Option<u32>>> = std::sync::OnceLock::new();
    if !is_probe(proto, port, pid, pid) {
        return false;
    }
    let service = SERVICE.get_or_init(|| ServicePid::new(list_service_pid as fn() -> Option<u32>));
    is_probe(proto, port, pid, service.get(now_ms))
}

/// The process id of the running [`LIST_SERVICE`], or None (not running, or the
/// service manager refused).
#[cfg(windows)]
pub fn list_service_pid() -> Option<u32> {
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
        SERVICE_STATUS_PROCESS,
    };
    use windows::core::{HSTRING, PCWSTR};
    // SAFETY: plain call; the handle is closed below on every path.
    let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }.ok()?;
    // SAFETY: `scm` is open; the name is NUL-terminated.
    let service = unsafe { OpenServiceW(scm, &HSTRING::from(LIST_SERVICE), SERVICE_QUERY_STATUS) };
    let pid = service.as_ref().ok().and_then(|s| {
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0u32;
        // SAFETY: a byte view of `status`, which outlives the call.
        let bytes = unsafe { std::slice::from_raw_parts_mut((&raw mut status).cast::<u8>(), size_of::<SERVICE_STATUS_PROCESS>()) };
        // SAFETY: `s` is open; `bytes` is writable for its whole length.
        unsafe { QueryServiceStatusEx(*s, SC_STATUS_PROCESS_INFO, Some(bytes), &mut needed) }.ok()?;
        (status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId != 0).then_some(status.dwProcessId)
    });
    if let Ok(s) = service {
        // SAFETY: opened above, closed once.
        let _ = unsafe { CloseServiceHandle(s) };
    }
    // SAFETY: opened above, closed once.
    let _ = unsafe { CloseServiceHandle(scm) };
    pid
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    const SERVICE: u32 = 1624;

    #[test]
    fn only_the_services_plain_http_is_the_probe() {
        assert!(is_probe(Proto::Tcp, PROBE_PORT, Some(SERVICE), Some(SERVICE)));
        assert!(!is_probe(Proto::Tcp, 443, Some(SERVICE), Some(SERVICE)), "its HTTPS goes on");
        assert!(!is_probe(Proto::Udp, PROBE_PORT, Some(SERVICE), Some(SERVICE)), "UDP is not the test");
        assert!(!is_probe(Proto::Tcp, PROBE_PORT, Some(4321), Some(SERVICE)), "another process's plain HTTP goes on");
        assert!(!is_probe(Proto::Tcp, PROBE_PORT, None, Some(SERVICE)), "an unattributed flow is not the service's");
        assert!(!is_probe(Proto::Tcp, PROBE_PORT, Some(SERVICE), None), "a service that could not be read refuses nothing");
        assert!(!is_probe(Proto::Tcp, PROBE_PORT, Some(0), Some(0)), "pid 0 is no process");
    }

    #[test]
    fn the_services_pid_is_read_again_only_after_its_time() {
        let reads = AtomicU32::new(0);
        let pid = ServicePid::new(|| Some(SERVICE + reads.fetch_add(1, Ordering::Relaxed)));
        assert_eq!(pid.get(0), Some(SERVICE));
        assert_eq!(pid.get(PID_FOR_MS - 1), Some(SERVICE), "held");
        assert_eq!(pid.get(PID_FOR_MS), Some(SERVICE + 1), "a restarted service is found again");
        assert_eq!(reads.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_failed_read_is_held_too_and_tried_again_later() {
        let reads = AtomicU32::new(0);
        let pid = ServicePid::new(|| (reads.fetch_add(1, Ordering::Relaxed) > 0).then_some(SERVICE));
        assert_eq!(pid.get(5), None);
        assert_eq!(pid.get(6), None, "not asked again at once");
        assert_eq!(pid.get(5 + PID_FOR_MS), Some(SERVICE));
    }
}
