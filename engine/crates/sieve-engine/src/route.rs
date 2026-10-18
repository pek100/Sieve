//! Sieve's routes, for removal only (plan 1.5 `restore`, 1.6). Every route
//! the engine will ever add sits on its Wintun interface, named
//! [`ADAPTER_NAME`]; removing them is how any off path gives the machine its
//! normal routing back. Slice 2 adds no route: this is the cleanup that
//! `restore` and `uninstall` run so they are complete before slice 3.

/// The engine's adapter (plan 1.4).
pub const ADAPTER_NAME: &str = "Sieve";

/// True for the interface whose routes are Sieve's (case-insensitive, the
/// whole name: "Sieve Spike" from the probe is not Sieve's product adapter).
pub fn is_sieve_interface(alias: &str) -> bool {
    alias.eq_ignore_ascii_case(ADAPTER_NAME)
}

/// Deletes every route (IPv4 and IPv6) on an interface named "Sieve" and
/// returns how many went. A route that cannot be deleted is an error naming
/// how many could.
#[cfg(windows)]
pub fn delete_sieve_routes() -> Result<usize, String> {
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceLuidToAlias, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_TABLE2,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    const ALIAS_CHARS: usize = 257;
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: Windows allocates the table; it is freed with FreeMibTable below.
    let code = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if code != NO_ERROR || table.is_null() {
        return Err(format!("GetIpForwardTable2: {code:?}"));
    }
    let (mut deleted, mut failed) = (0usize, 0usize);
    // SAFETY: `table` is valid until FreeMibTable; NumEntries rows follow.
    unsafe {
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for row in rows {
            let mut alias = [0u16; ALIAS_CHARS];
            if ConvertInterfaceLuidToAlias(&row.InterfaceLuid, &mut alias) != NO_ERROR {
                continue;
            }
            let len = alias.iter().position(|c| *c == 0).unwrap_or(alias.len());
            if !is_sieve_interface(&String::from_utf16_lossy(&alias[..len])) {
                continue;
            }
            if DeleteIpForwardEntry2(row) == NO_ERROR { deleted += 1 } else { failed += 1 }
        }
        FreeMibTable(table.cast());
    }
    if failed == 0 { Ok(deleted) } else { Err(format!("{failed} routes could not be deleted ({deleted} were)")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_interface_named_sieve_is_sieves() {
        assert!(is_sieve_interface("Sieve") && is_sieve_interface("SIEVE") && is_sieve_interface("sieve"));
        for other in ["Sieve Spike", "Wi-Fi", "Ethernet", "", "Sieve2", "AdGuard VPN"] {
            assert!(!is_sieve_interface(other), "{other}");
        }
    }
}
