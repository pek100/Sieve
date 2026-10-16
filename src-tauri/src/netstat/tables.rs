//! Raw IP Helper table reads (read only, no admin): `GetExtendedTcpTable`
//! with `TCP_TABLE_OWNER_PID_ALL` and `GetExtendedUdpTable` with
//! `UDP_TABLE_OWNER_PID`, for AF_INET and AF_INET6.
//!
//! Size-probe then fill: ask for the size with no buffer, allocate, fill. If
//! the table grew between the two calls Windows answers
//! ERROR_INSUFFICIENT_BUFFER with the new size, and we try again a bounded
//! number of times. The bytes go to `decode.rs` untouched.

use super::NetstatError;
use super::decode::TableKind;

/// Tries before giving up on a table that keeps growing between calls.
pub const MAX_ATTEMPTS: u32 = 5;

/// Read one whole table as the bytes Windows filled.
#[cfg(windows)]
pub fn read_table(kind: TableKind) -> Result<Vec<u8>, NetstatError> {
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};

    let mut size: u32 = 0;
    // Probe: no buffer, Windows writes the size it needs.
    let first = call(kind, None, &mut size);
    if first != NO_ERROR.0 && first != ERROR_INSUFFICIENT_BUFFER.0 {
        return Err(NetstatError::Table { kind, code: first });
    }
    for _ in 0..MAX_ATTEMPTS {
        // u32 storage keeps the buffer 4-byte aligned like the row structs.
        let words = size.div_ceil(4).max(1);
        let mut buf = vec![0u32; words as usize];
        let mut len = words.saturating_mul(4);
        let code = call(kind, Some(buf.as_mut_slice()), &mut len);
        if code == NO_ERROR.0 {
            return Ok(buf.iter().flat_map(|w| w.to_ne_bytes()).collect());
        }
        if code != ERROR_INSUFFICIENT_BUFFER.0 {
            return Err(NetstatError::Table { kind, code });
        }
        // The table grew; Windows wrote the new size into `len`.
        size = len;
    }
    Err(NetstatError::TableKeptGrowing { kind, attempts: MAX_ATTEMPTS })
}

/// One GetExtended*Table call. `buf: None` is the size probe.
#[cfg(windows)]
fn call(kind: TableKind, buf: Option<&mut [u32]>, size: &mut u32) -> u32 {
    use std::ffi::c_void;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    let af = match kind {
        TableKind::Tcp4 | TableKind::Udp4 => u32::from(AF_INET.0),
        TableKind::Tcp6 | TableKind::Udp6 => u32::from(AF_INET6.0),
    };
    let ptr = buf.map(|b| b.as_mut_ptr().cast::<c_void>());
    // SAFETY: `ptr` is either None (size probe) or points at a live buffer of
    // at least `*size` bytes, which Windows fills and does not retain.
    unsafe {
        match kind {
            TableKind::Tcp4 | TableKind::Tcp6 => GetExtendedTcpTable(ptr, size, false, af, TCP_TABLE_OWNER_PID_ALL, 0),
            TableKind::Udp4 | TableKind::Udp6 => GetExtendedUdpTable(ptr, size, false, af, UDP_TABLE_OWNER_PID, 0),
        }
    }
}

/// Off Windows there are no IP Helper tables.
#[cfg(not(windows))]
pub fn read_table(_kind: TableKind) -> Result<Vec<u8>, NetstatError> {
    Err(NetstatError::Unsupported)
}
