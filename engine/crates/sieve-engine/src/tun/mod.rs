//! The engine's Wintun adapter (plan 1.4, 7.1).
//!
//! `wintun.dll` 0.14.1 sits beside `sieve-engine.exe` in the locked install
//! folder (the folder check covers it like every file there). Before it is
//! loaded: the file's SHA-256 must equal [`WINTUN_SHA256`] (the official
//! amd64 build, the hash the spike verified), and `wintun-bindings` checks
//! its Authenticode signer is "WireGuard LLC". It is loaded by absolute path
//! only, after `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`.
//!
//! The adapter is named "Sieve" with a fixed GUID, so a leftover is
//! recognisable and every off path finds its routes by name. Wintun removes
//! the adapter when the engine's handle closes (a stop, a kill, a crash),
//! and every route and address on it goes with it.

#[cfg(windows)]
pub mod device;
#[cfg(feature = "relay-experiments")]
pub mod batch;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub const WINTUN_DLL: &str = "wintun.dll";
/// SHA-256 of Wintun 0.14.1's `bin/amd64/wintun.dll` (wintun.net, 2026-10-17,
/// 427,552 bytes, signed by WireGuard LLC). The installer bundles this file;
/// `scripts/wintun.mjs` refuses to bundle any other.
pub const WINTUN_SHA256: &str = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
/// Wintun's prebuilt-binaries licence, shipped beside the DLL.
pub const WINTUN_LICENSE: &str = "wintun-LICENSE.txt";

/// The adapter's identity (plan 1.4).
pub const TUNNEL_TYPE: &str = "Sieve";
pub const ADAPTER_GUID: u128 = 0x5e7e_5e7e_51e7_4e00_8a11_5e7e_0000_0003;
/// The adapter's own addresses: the benchmark range (RFC 2544) and a ULA.
pub const TUN_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
pub const TUN_V6: Ipv6Addr = Ipv6Addr::new(0xfd53, 0x6965, 0x7665, 1, 0, 0, 0, 1);
pub const MTU: u16 = 1500;
/// Wintun's ring (4 MiB, as the spike).
pub const RING_BYTES: u32 = 0x40_0000;

pub fn own_addresses() -> [IpAddr; 2] {
    [IpAddr::V4(TUN_V4), IpAddr::V6(TUN_V6)]
}

/// `wintun.dll` beside this exe.
pub fn dll_beside(exe: &Path) -> PathBuf {
    exe.with_file_name(WINTUN_DLL)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The file's SHA-256 must be the pinned one.
pub fn verify_dll(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let got = hex(&Sha256::digest(&bytes));
    if got != WINTUN_SHA256 {
        return Err(format!("{}: SHA-256 {got} is not the pinned Wintun 0.14.1 build", path.display()));
    }
    Ok(())
}

/// Which packets from the adapter go to the stack: unicast only. Windows
/// sends multicast and broadcast chatter (SSDP, LLMNR, mDNS, neighbour
/// discovery) out of every interface, the TUN included; relaying it looped
/// in the spike's live run 1. Packets to the adapter's own addresses are
/// dropped too: nothing listens there.
pub fn admit(dst: IpAddr) -> bool {
    let not_unicast = match dst {
        IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified() || v6.is_loopback() || (v6.segments()[0] & 0xffc0) == 0xfe80,
    };
    !not_unicast && !own_addresses().contains(&dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_dll_passes_and_one_changed_byte_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(WINTUN_DLL);
        // The real DLL is never in the repo; when the machine has it, it must pass.
        let real = Path::new(r"E:\ml-tools\wintun\wintun\bin\amd64\wintun.dll");
        if let Ok(bytes) = std::fs::read(real) {
            std::fs::write(&path, &bytes).unwrap();
            assert_eq!(verify_dll(&path), Ok(()));
            let mut changed = bytes;
            changed[1000] ^= 1;
            std::fs::write(&path, &changed).unwrap();
            assert!(verify_dll(&path).unwrap_err().contains("is not the pinned"));
        }
        std::fs::write(&path, b"MZ not wintun").unwrap();
        assert!(verify_dll(&path).unwrap_err().contains("is not the pinned"));
        assert!(verify_dll(&dir.path().join("missing.dll")).is_err());
        assert_eq!(dll_beside(Path::new(r"E:\Sieve\sieve-engine.exe")), Path::new(r"E:\Sieve\wintun.dll"));
    }

    #[test]
    fn only_unicast_to_somewhere_else_reaches_the_stack() {
        for ok in ["93.184.215.14", "192.168.7.1", "2606:4700::1"] {
            assert!(admit(ok.parse().unwrap()), "{ok}");
        }
        // The destinations live run 1 looped on, and the adapter's own addresses.
        for no in [
            "239.255.255.250", "224.0.0.252", "224.0.0.251", "255.255.255.255", "ff02::1:3", "ff02::c", "ff02::1", "ff02::fb",
            "ff12::8384", "169.254.1.1", "fe80::1", "0.0.0.0", "::", "198.18.0.1", "fd53:6965:7665:1::1", "127.0.0.1",
        ] {
            assert!(!admit(no.parse().unwrap()), "{no}");
        }
    }

    #[test]
    fn the_hash_pin_is_the_spikes_verified_build() {
        assert_eq!(WINTUN_SHA256.len(), 64);
        let doc = include_str!("../../../../../docs/research/2026-10-17-wintun-spike.md");
        assert!(doc.contains(WINTUN_SHA256), "the spike report records the same hash");
    }
}
