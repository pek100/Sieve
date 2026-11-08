//! Sieve's routes (plan 1.4, 1.6). Every route the engine adds sits on its
//! Wintun interface, named [`ADAPTER_NAME`], in the active store only
//! (`apply`, the one place that writes a route), so all of them go with the
//! adapter when the engine's handle closes and none survives a reboot.
//! Removing them is how every off path gives the machine its normal routing
//! back (`restore`, `uninstall`, the watchdog, the start-up cleanup).
//! - [`prefix`]: prefixes and the complement the plan cuts holes with;
//! - [`table`]: the adapter and forwarding tables as data (fixtures in tests);
//! - [`plan`]: which prefixes to route, derived from those tables;
//! - [`pin`]: the egress interface and source address of an upstream socket;
//! - [`journal`]: routes recorded on disk before they are added;
//! - `apply` and `watch` (Windows): the writes and `NotifyRouteChange2`;
//! - [`capture`]: what catches the DNS Client's queries while routes are up, and
//!   `wfp` (Windows), the dynamic filter session it blocks their leak with.

pub mod capture;
pub mod journal;
pub mod pin;
pub mod plan;
pub mod prefix;
pub mod table;

#[cfg(windows)]
pub mod apply;
#[cfg(windows)]
pub mod watch;
#[cfg(windows)]
pub mod wfp;

/// The engine's adapter (plan 1.4).
pub const ADAPTER_NAME: &str = "Sieve";

/// True for the interface whose routes are Sieve's (case-insensitive, the
/// whole name: "Sieve Spike" from the probe is not Sieve's product adapter).
pub fn is_sieve_interface(alias: &str) -> bool {
    alias.eq_ignore_ascii_case(ADAPTER_NAME)
}

/// Deletes every route (IPv4 and IPv6) on an interface named "Sieve" and
/// reports deletions and races with an earlier cleanup separately. Failures
/// retain their Win32 codes in the report.
#[cfg(windows)]
pub fn delete_sieve_routes() -> Result<journal::Replay, String> {
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
    let mut report = journal::Replay::default();
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
            report.observe(classify_delete(DeleteIpForwardEntry2(row).0));
        }
        FreeMibTable(table.cast());
    }
    if report.failed == 0 { Ok(report) } else { Err(report.summary()) }
}

/// One classification shared by table cleanup and journal replay.
/// ERROR_NOT_FOUND (no such route) and ERROR_FILE_NOT_FOUND (the route's
/// adapter no longer exists, so the route went with it) are already-deleted
/// routes; every other error survives with its code.
#[cfg(windows)]
pub fn classify_delete(code: u32) -> journal::Deleted {
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, NO_ERROR};
    if code == NO_ERROR.0 {
        journal::Deleted::Yes
    } else if code == ERROR_NOT_FOUND.0 || code == ERROR_FILE_NOT_FOUND.0 {
        journal::Deleted::NotThere
    } else {
        journal::Deleted::Failed(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn fake_delete_codes_agree_for_named_cleanup_and_journal_replay() {
        use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, NO_ERROR};
        use journal::{Entry, Journal, Replay};
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(dir.path());
        let codes = [NO_ERROR.0, ERROR_NOT_FOUND.0, ERROR_ACCESS_DENIED.0, ERROR_ACCESS_DENIED.0];
        let mut named = Replay::default();
        for code in codes {
            journal.append(&Entry { prefix: "192.0.2.1/32".parse().unwrap(), luid: u64::from(code) }).unwrap();
            named.observe(classify_delete(code));
        }
        let replay = journal.replay(|entry| classify_delete(entry.luid as u32)).unwrap();
        assert_eq!(named, replay);
        assert_eq!((replay.deleted, replay.already_gone, replay.failed), (1, 1, 2));
        assert_eq!(replay.failed_codes, std::collections::BTreeMap::from([(ERROR_ACCESS_DENIED.0, 2)]));
        assert!(replay.summary().contains(&format!("codes {{{}: 2}}", ERROR_ACCESS_DENIED.0)));
        assert_eq!(journal.read().unwrap().0.len(), codes.len(), "failed entries remain retryable");
        assert_eq!(classify_delete(ERROR_FILE_NOT_FOUND.0), journal::Deleted::NotThere, "the adapter took its routes with it");
        let cleaned = journal.replay(|_| classify_delete(ERROR_NOT_FOUND.0)).unwrap();
        assert_eq!((cleaned.deleted, cleaned.already_gone, cleaned.failed), (0, codes.len(), 0));
        assert!(cleaned.failed_codes.is_empty());
        assert!(journal.read().unwrap().0.is_empty());
    }

    #[test]
    fn only_the_interface_named_sieve_is_sieves() {
        assert!(is_sieve_interface("Sieve") && is_sieve_interface("SIEVE") && is_sieve_interface("sieve"));
        for other in ["Sieve Spike", "Wi-Fi", "Ethernet", "", "Sieve2", "AdGuard VPN"] {
            assert!(!is_sieve_interface(other), "{other}");
        }
    }
}
