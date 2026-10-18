//! Which DNS servers Windows uses, per active adapter. READ ONLY: one
//! GetAdaptersAddresses call, no registry, no admin, no writes. Sieve never
//! changes Windows DNS (docs/conventions.md, "Sieve off means a normal
//! network"); this read feeds the window's safety net, which warns when an
//! adapter still asks 127.0.0.1 or ::1 (set by an old Sieve build, or by
//! hand) while no Sieve DNS listener answers there. The decision itself is
//! pure TypeScript (`strandedAdapters` in src/core/dns.ts).
//!
//! Command: `windows_dns()` -> `WindowsDns`.
//!
//! Wire shape `windows_dns`, version 1 (TS mirror `parseWindowsDns`,
//! fixture src/data/fixtures/windows-dns-v1.json):
//! `{v, adapters: [{alias, index, servers}]}`, servers in force in Windows'
//! order, both families, as IP address text.

use std::net::IpAddr;

use serde::Serialize;

pub const WINDOWS_DNS_VERSION: u32 = 1;

/// One active adapter's DNS servers in force.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdapterDns {
    /// The adapter's FriendlyName, as Windows' network settings show it.
    pub alias: String,
    pub index: u32,
    /// IPv4 and IPv6 servers, in Windows' order.
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsDns {
    pub v: u32,
    /// Active adapters only: up, not loopback, not a tunnel.
    pub adapters: Vec<AdapterDns>,
}

/// Errors of this module; strings only at the command boundary.
#[derive(Debug, thiserror::Error)]
pub enum WinDnsError {
    #[error("{0}")]
    Read(String),
}

/// The wire answer from what was read.
pub fn windows_dns_of(adapters: Vec<AdapterDns>) -> WindowsDns {
    WindowsDns { v: WINDOWS_DNS_VERSION, adapters }
}

/// An adapter's servers as wire text.
pub fn server_texts(servers: &[IpAddr]) -> Vec<String> {
    servers.iter().map(IpAddr::to_string).collect()
}

#[cfg(windows)]
mod imp {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, IF_TYPE_SOFTWARE_LOOPBACK,
        IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS};

    use super::{AdapterDns, WinDnsError, server_texts};

    /// Attempts at the GetAdaptersAddresses size probe (the list can grow between calls).
    const ATTEMPTS: usize = 4;

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

    pub fn read_adapters() -> Result<Vec<AdapterDns>, WinDnsError> {
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
                return Err(WinDnsError::Read(format!("GetAdaptersAddresses: error {rc}")));
            }
        }
        if !done {
            return Err(WinDnsError::Read("GetAdaptersAddresses: the adapter list kept growing".to_owned()));
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
            // SAFETY: a string owned by the list.
            let alias = unsafe { a.FriendlyName.to_string() }.unwrap_or_default();
            // SAFETY: the IfIndex view of the first union is always written.
            let v4_index = unsafe { a.Anonymous1.Anonymous.IfIndex };
            let index = if v4_index != 0 { v4_index } else { a.Ipv6IfIndex };
            let mut servers = Vec::new();
            let mut dns = a.FirstDnsServerAddress;
            while !dns.is_null() {
                // SAFETY: a node of the same list.
                let d = unsafe { &*dns };
                dns = d.Next;
                // SAFETY: the address of a list node.
                if let Some(ip) = unsafe { socket_ip(&d.Address) } {
                    servers.push(ip);
                }
            }
            out.push(AdapterDns { alias, index, servers: server_texts(&servers) });
        }
        Ok(out)
    }
}

/// Active adapters and their DNS servers in force. Read only.
#[cfg(windows)]
pub use imp::read_adapters;

#[cfg(not(windows))]
pub fn read_adapters() -> Result<Vec<AdapterDns>, WinDnsError> {
    Err(WinDnsError::Read("Windows DNS can only be read on Windows".to_owned()))
}

#[tauri::command]
pub async fn windows_dns() -> Result<WindowsDns, String> {
    tauri::async_runtime::spawn_blocking(|| read_adapters().map(windows_dns_of))
        .await
        .map_err(|e| format!("Windows DNS task failed: {e}"))?
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn serialises_to_the_shared_v1_fixture() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../src/data/fixtures/windows-dns-v1.json")).expect("fixture is JSON");
        let w = windows_dns_of(vec![
            AdapterDns { alias: "Wi-Fi".into(), index: 12, servers: server_texts(&[ip("192.0.2.53"), ip("2001:db8::53")]) },
            AdapterDns { alias: "Ethernet 2".into(), index: 7, servers: server_texts(&[ip("127.0.0.1"), ip("::1")]) },
        ]);
        assert_eq!(serde_json::to_value(&w).expect("serialises"), fixture);
    }

    #[test]
    fn loopback_is_written_the_way_the_window_compares_it() {
        // The TS decision compares text: Rust's canonical forms are what it expects.
        assert_eq!(server_texts(&[ip("127.0.0.1"), ip("0:0:0:0:0:0:0:1")]), vec!["127.0.0.1", "::1"]);
    }

    /// Read only: lists the active adapters and their DNS. Never writes.
    #[cfg(windows)]
    #[test]
    fn reading_adapters_works_without_admin() {
        let adapters = read_adapters().expect("adapters are readable without admin");
        for a in &adapters {
            assert!(!a.alias.is_empty());
            for s in &a.servers {
                s.parse::<IpAddr>().expect("servers are addresses");
            }
        }
    }
}
