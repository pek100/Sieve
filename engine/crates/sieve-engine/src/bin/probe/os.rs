//! The probe's Windows calls: elevation check, TUN address, test routes,
//! best (physical) interface, and binding forwarder sockets to it.
//!
//! Everything this module adds to the system is recorded in [`CLEANUP`]
//! and removed by [`cleanup`], which runs on normal exit, Ctrl+C and from
//! the panic hook. If the process is killed outright, Windows removes the
//! Wintun adapter when its handle closes, and the routes and address bound
//! to that interface go with it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

use windows::Win32::Foundation::{CloseHandle, HANDLE, NO_ERROR, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry,
    GetBestInterfaceEx, InitializeIpForwardEntry, InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2,
    MIB_UNICASTIPADDRESS_ROW,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF,
    IP_UNICAST_IF, MIB_IPPROTO_NETMGMT, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET, SOCKET, setsockopt,
};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// True when this process runs with an elevated (admin) token.
pub fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: plain calls on our own process token; the handle is closed.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

fn sockaddr_inet(ip: IpAddr) -> SOCKADDR_INET {
    let mut s = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(v4) => {
            s.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(v4.octets()) } },
                sin_zero: [0; 8],
            };
        }
        IpAddr::V6(v6) => {
            s.Ipv6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR { u: IN6_ADDR_0 { Byte: v6.octets() } },
                ..Default::default()
            };
        }
    }
    s
}

fn prefix_len(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
}

fn check(code: WIN32_ERROR, what: &str) -> Result<(), String> {
    if code == NO_ERROR { Ok(()) } else { Err(format!("{what} failed: Win32 error {}", code.0)) }
}

/// What the probe added, for removal.
enum Added {
    Route(MIB_IPFORWARD_ROW2),
    Address(MIB_UNICASTIPADDRESS_ROW),
}

// SAFETY: the rows are plain data (no pointers into other memory).
unsafe impl Send for Added {}

static CLEANUP: Mutex<Vec<Added>> = Mutex::new(Vec::new());

fn remember(a: Added) {
    CLEANUP.lock().unwrap_or_else(|p| p.into_inner()).push(a);
}

/// Adds the TUN's own address (a host address, on-link prefix /32 or /128).
pub fn add_address(luid: u64, ip: IpAddr) -> Result<(), String> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: initializes a row we own.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = NET_LUID_LH { Value: luid };
    row.Address = sockaddr_inet(ip);
    row.OnLinkPrefixLength = prefix_len(ip);
    // SAFETY: `row` is a valid, initialized row.
    check(unsafe { CreateUnicastIpAddressEntry(&row) }, "CreateUnicastIpAddressEntry")?;
    remember(Added::Address(row));
    Ok(())
}

/// Routes exactly one host (/32 or /128) into the TUN, on-link.
pub fn add_host_route(luid: u64, ip: IpAddr) -> Result<(), String> {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: initializes a row we own.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = NET_LUID_LH { Value: luid };
    row.DestinationPrefix.Prefix = sockaddr_inet(ip);
    row.DestinationPrefix.PrefixLength = prefix_len(ip);
    // Next hop: the unspecified address of the same family (on-link).
    row.NextHop = sockaddr_inet(if ip.is_ipv4() { IpAddr::from([0u8; 4]) } else { IpAddr::from([0u8; 16]) });
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    // SAFETY: `row` is a valid, initialized row.
    check(unsafe { CreateIpForwardEntry2(&row) }, "CreateIpForwardEntry2")?;
    remember(Added::Route(row));
    Ok(())
}

/// Removes every route and address this process added. Idempotent.
/// Returns (removed, failed).
pub fn cleanup() -> (usize, usize) {
    let mut list = CLEANUP.lock().unwrap_or_else(|p| p.into_inner());
    let (mut ok, mut failed) = (0, 0);
    // Routes first, then addresses (reverse order of creation).
    while let Some(a) = list.pop() {
        // SAFETY: each row is exactly what was passed to the matching Create call.
        let code = unsafe {
            match &a {
                Added::Route(r) => DeleteIpForwardEntry2(r),
                Added::Address(r) => DeleteUnicastIpAddressEntry(r),
            }
        };
        if code == NO_ERROR { ok += 1 } else { failed += 1 }
    }
    (ok, failed)
}

/// The interface Windows would use for `ip` right now (call before adding
/// the TUN route, so the answer is the physical interface).
pub fn best_interface(ip: IpAddr) -> Result<u32, String> {
    let s = sockaddr_inet(ip);
    let mut index = 0u32;
    // SAFETY: `s` is a SOCKADDR_IN or SOCKADDR_IN6 as the family field says;
    // GetBestInterfaceEx reads the family and the matching struct.
    let code = unsafe { GetBestInterfaceEx((&s as *const SOCKADDR_INET).cast::<SOCKADDR>(), &mut index) };
    if code == 0 { Ok(index) } else { Err(format!("GetBestInterfaceEx({ip}) failed: {code}")) }
}

/// The source address Windows picks for `ip` right now, read with a UDP
/// connect (no packet is sent). Call before adding the TUN route: the
/// answer is an address of the physical interface. Forwarder sockets bind
/// to it; without that, an IPv6 connect pinned to the physical interface
/// picked the TUN's ULA as source and failed with 10049 (live run 1).
pub fn egress_source(ip: IpAddr) -> Result<IpAddr, String> {
    let any: SocketAddr = if ip.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let s = std::net::UdpSocket::bind(any).map_err(|e| format!("udp bind: {e}"))?;
    s.connect(SocketAddr::new(ip, 443)).map_err(|e| format!("no route to {ip}: {e}"))?;
    let src = s.local_addr().map_err(|e| format!("local_addr: {e}"))?.ip();
    let link_local = match src {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    };
    if src.is_unspecified() || link_local {
        return Err(format!("no usable source address for {ip} (got {src})"));
    }
    Ok(src)
}

/// Forces a socket's unicast traffic out of interface `index`, so forwarded
/// flows never re-enter the TUN. Byte order per family comes from the
/// tested helper (IPv4 network order, IPv6 host order).
pub fn bind_to_interface(sock: &socket2::Socket, target: SocketAddr, index: u32) -> Result<(), String> {
    use std::os::windows::io::AsRawSocket;
    let s = SOCKET(sock.as_raw_socket() as usize);
    let (level, name) = match target {
        SocketAddr::V4(_) => (IPPROTO_IP.0, IP_UNICAST_IF),
        SocketAddr::V6(_) => (IPPROTO_IPV6.0, IPV6_UNICAST_IF),
    };
    let value = crate::support::unicast_if_value(index, target.is_ipv4());
    // SAFETY: `s` is a live socket; the option value is a 4-byte DWORD.
    let r = unsafe { setsockopt(s, level, name, Some(&value)) };
    if r == 0 { Ok(()) } else { Err(format!("setsockopt UNICAST_IF failed: {}", std::io::Error::last_os_error())) }
}
