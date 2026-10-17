//! Windows DNS settings: read them, point them at Sieve's DNS filter, and
//! restore them. The ONE place Sieve changes the system, behind the
//! `filtering.systemDns` data switch, and only when the user asks.
//!
//! - `mod.rs` (this file, pure): the wire shapes, the registry value parser,
//!   which servers count as "set by hand" vs DHCP, and the derived state.
//! - `script`: the pure generators of the elevated PowerShell (point,
//!   restore). Every alias is quoted; restore puts each family back exactly.
//! - `backup`: the backup JSON and the standalone `restore-dns.ps1` beside
//!   it, in the app's data dir. Written BEFORE anything changes.
//! - `win` (Windows only): the read-only calls (GetAdaptersAddresses, the
//!   Tcpip registry keys, the process list) and the one elevated run
//!   (ShellExecuteExW, verb "runas": Windows shows its UAC prompt).
//! - `commands`: `system_dns_state` (read only), `system_dns_point`,
//!   `system_dns_restore`, `adguard_running` (read only).
//!
//! Wire shape `system_dns_state`, version 1 (TS mirror `parseSystemDns`,
//! fixture src/data/fixtures/system-dns-v1.json):
//! `{v, interfaces: [{alias, index, v4: {servers, dhcp}, v6: {servers, dhcp}, uses_sieve}],
//!   pointed, backup, backup_dir}`.

pub mod backup;
pub mod commands;
pub mod script;
pub mod win;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

pub const SYSTEM_DNS_VERSION: u32 = 1;

/// The addresses Windows is pointed at: the proxy listens on both (dns::proxy::DEFAULT_BINDS).
pub const SIEVE_V4: Ipv4Addr = Ipv4Addr::LOCALHOST;
pub const SIEVE_V6: Ipv6Addr = Ipv6Addr::LOCALHOST;

/// DNS servers of one address family on one adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyDns {
    /// In force, in order. For a hand-set family these are exactly what was set.
    pub servers: Vec<String>,
    /// True when the servers come from DHCP (or the adapter's defaults): nothing set by hand.
    pub dhcp: bool,
}

/// One active adapter's DNS, both families. Raw facts, as read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceDns {
    /// The adapter's alias (FriendlyName), what Set-DnsClientServerAddress -InterfaceAlias takes.
    pub alias: String,
    pub index: u32,
    pub v4: FamilyDns,
    pub v6: FamilyDns,
}

/// What the window sees per adapter: the facts plus one derived flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InterfaceView {
    #[serde(flatten)]
    pub dns: InterfaceDns,
    /// IPv4 DNS is exactly 127.0.0.1 and IPv6 DNS exactly ::1.
    pub uses_sieve: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SystemDnsState {
    pub v: u32,
    pub interfaces: Vec<InterfaceView>,
    /// Some active adapter sends lookups to a loopback address.
    pub pointed: bool,
    /// Sieve's backup (made before it pointed Windows here) exists.
    pub backup: bool,
    /// Folder of the backup and `restore-dns.ps1`.
    pub backup_dir: Option<String>,
}

/// Errors of this module; strings only at the command boundary.
#[derive(Debug, thiserror::Error)]
pub enum SysDnsError {
    #[error("{0}")]
    Read(String),
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("backup {path} is not readable: {why}")]
    BadBackup { path: String, why: String },
    #[error("you declined the Windows prompt, so nothing was changed")]
    Declined,
    #[error("{0}")]
    Refused(String),
    #[error("the elevated script failed (exit code {code}); the backup is kept, restore with {restore}")]
    ScriptFailed { code: u32, restore: String },
    #[error("{0}")]
    Elevation(String),
}

/// Parse a Tcpip `NameServer` / `DhcpNameServer` registry value: addresses
/// separated by commas, spaces or semicolons (Windows writes commas for a
/// hand-set list and spaces for a DHCP one). Anything that is not an IP
/// address is dropped; order is kept; an empty or blank value is no servers.
pub fn parse_name_server(raw: &str) -> Vec<IpAddr> {
    raw.split([',', ' ', ';', '\0', '\t'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect()
}

/// One family's DNS from the registry's hand-set list and the servers in
/// force (GetAdaptersAddresses). A non-empty hand-set list means static, and
/// those exact servers are what a restore must set; otherwise DHCP.
pub fn family_dns(hand_set: &[IpAddr], in_force: &[IpAddr]) -> FamilyDns {
    if hand_set.is_empty() {
        FamilyDns { servers: in_force.iter().map(IpAddr::to_string).collect(), dhcp: true }
    } else {
        FamilyDns { servers: hand_set.iter().map(IpAddr::to_string).collect(), dhcp: false }
    }
}

fn is_loopback(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The adapter asks Sieve: IPv4 exactly 127.0.0.1, IPv6 exactly ::1.
pub fn uses_sieve(i: &InterfaceDns) -> bool {
    i.v4.servers == [SIEVE_V4.to_string()] && i.v6.servers == [SIEVE_V6.to_string()]
}

/// Some lookup goes to a loopback address on this adapter.
pub fn sends_to_loopback(i: &InterfaceDns) -> bool {
    i.v4.servers.iter().chain(&i.v6.servers).any(|s| is_loopback(s))
}

/// The state the window gets, derived from the facts.
pub fn state(interfaces: Vec<InterfaceDns>, backup: bool, backup_dir: Option<String>) -> SystemDnsState {
    let pointed = interfaces.iter().any(sends_to_loopback);
    SystemDnsState {
        v: SYSTEM_DNS_VERSION,
        interfaces: interfaces
            .into_iter()
            .map(|dns| InterfaceView { uses_sieve: uses_sieve(&dns), dns })
            .collect(),
        pointed,
        backup,
        backup_dir,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn fam(servers: &[&str], dhcp: bool) -> FamilyDns {
        FamilyDns { servers: servers.iter().map(|s| (*s).to_owned()).collect(), dhcp }
    }

    /// The sample pair used across the module: one adapter on DHCP, one set by hand.
    pub(crate) fn sample() -> Vec<InterfaceDns> {
        vec![
            InterfaceDns {
                alias: "Wi-Fi".into(),
                index: 12,
                v4: fam(&["192.0.2.53"], true),
                v6: fam(&["2001:db8::53"], true),
            },
            InterfaceDns {
                alias: "Ethernet 2".into(),
                index: 7,
                v4: fam(&["198.51.100.53", "203.0.113.53"], false),
                v6: fam(&[], true),
            },
        ]
    }

    #[test]
    fn registry_name_server_values_parse_in_order() {
        let ip = |s: &str| s.parse::<IpAddr>().expect("ip");
        assert_eq!(parse_name_server("198.51.100.53,203.0.113.53"), vec![ip("198.51.100.53"), ip("203.0.113.53")]);
        assert_eq!(parse_name_server("192.0.2.1 192.0.2.2"), vec![ip("192.0.2.1"), ip("192.0.2.2")]);
        assert_eq!(parse_name_server("2001:db8::1, ::1"), vec![ip("2001:db8::1"), ip("::1")]);
        assert_eq!(parse_name_server(""), Vec::<IpAddr>::new());
        assert_eq!(parse_name_server("  "), Vec::<IpAddr>::new());
        // Junk between addresses is dropped, not guessed at.
        assert_eq!(parse_name_server("192.0.2.1,dns.example,;192.0.2.9"), vec![ip("192.0.2.1"), ip("192.0.2.9")]);
    }

    #[test]
    fn hand_set_servers_win_and_mean_static() {
        let ip = |s: &str| s.parse::<IpAddr>().expect("ip");
        assert_eq!(family_dns(&[], &[ip("192.0.2.53")]), fam(&["192.0.2.53"], true));
        assert_eq!(family_dns(&[ip("198.51.100.53")], &[ip("198.51.100.53")]), fam(&["198.51.100.53"], false));
        // A family with nothing in force and nothing set by hand is DHCP with no servers.
        assert_eq!(family_dns(&[], &[]), fam(&[], true));
    }

    #[test]
    fn state_derives_pointed_and_uses_sieve() {
        let s = state(sample(), false, None);
        assert!(!s.pointed);
        assert!(s.interfaces.iter().all(|i| !i.uses_sieve));

        let mut pointed = sample();
        for i in &mut pointed {
            i.v4 = fam(&["127.0.0.1"], false);
            i.v6 = fam(&["::1"], false);
        }
        let s = state(pointed, true, Some("C:\\x".into()));
        assert!(s.pointed && s.backup);
        assert!(s.interfaces.iter().all(|i| i.uses_sieve));

        // One family on loopback is enough to need the proxy, but is not "uses Sieve".
        let mut half = sample();
        half[0].v4 = fam(&["127.0.0.1"], false);
        let s = state(half, false, None);
        assert!(s.pointed);
        assert!(!s.interfaces[0].uses_sieve);
    }

    #[test]
    fn state_serialises_to_the_shared_v1_fixture() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../src/data/fixtures/system-dns-v1.json")).expect("fixture is JSON");
        let s = state(sample(), false, None);
        assert_eq!(serde_json::to_value(&s).expect("serialises"), fixture);
    }
}
