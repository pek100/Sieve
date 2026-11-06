//! Sieve's filtering engine (docs/plans/2026-10-17-https-filtering.md).
//! - [`flow`]: the flow decoders moved from the Wintun spike (slice 1);
//! - [`service`]: the Windows service and its install, uninstall and
//!   restore verbs (slice 2);
//! - [`ipc`]: the pipe server and the per-connection protocol (slice 2, 3);
//! - [`route`]: the route plan, pinning, the journal, and the only writes
//!   of routing state (on the engine's own adapter, slice 3);
//! - [`tun`]: the pinned wintun.dll and the adapter (slice 3);
//! - [`stack`]: the relay of every flow, with attribution (slice 3);
//! - [`dns`]: lookups on the TUN answered over encrypted upstreams, and their
//!   answers read into the IP-to-names map (slices 3, 4);
//! - [`tls`]: the one owner of how the engine speaks TLS (plan 2.7), and
//!   interception behind `filtering.https` (slice 6);
//! - [`http`]: decrypted requests through hyper, with full-URL rules (slice 6);
//! - [`exclusions`]: the store behind `sieve_filter::exclusions::decrypt`;
//! - [`heal`]: self-healing exclusions and their notices (slice 7);
//! - [`lru`]: the bounded caches' shape;
//! - [`coexist`]: AdGuard and VPN detection, read only (slice 3);
//! - [`update`]: signed updates, the service as the only updater (slice 13);
//! - [`watchdog`], [`policy`]: hang and crash-loop safety (slice 3);
//! - [`control`]: the running engine's facts and its routing loop;
//! - [`domain`]: the one per-flow decision (slice 4);
//! - [`lists`]: the default lists' download, cache and compile (slice 4);
//! - [`ca`]: the root CA, its removal paths and the leaf API (slice 5);
//! - [`inject`]: the content injection library (slice 9), not yet wired to
//!   traffic: `http::hook` is where it will plug in.
//!
//! Traffic goes through the engine only while the user's `filtering.engine`
//! switch is on; off, killed or crashed is a normal network.
pub mod ca;
pub mod coexist;
pub mod control;
pub mod dns;
pub mod domain;
pub mod exclusions;
#[cfg(feature = "relay-experiments")]
pub mod experiments;
pub mod flow;
pub mod hand_file;
pub mod heal;
pub mod http;
pub mod inject;
pub mod ipc;
pub mod lists;
pub mod lru;
pub mod policy;
pub mod route;
pub mod service;
pub mod stack;
pub mod tls;
pub mod tun;
pub mod update;
pub mod watchdog;

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// ipstack's upstream build.rs copied wintun.dll into target/ on every
    /// Windows build (spike report, section 2). The vendored copy must have no
    /// build script, and the workspace must use it.
    #[test]
    fn vendored_ipstack_has_no_build_script() {
        let engine = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let vendor = engine.join("vendor/ipstack");
        assert!(!vendor.join("build.rs").exists(), "vendor/ipstack/build.rs must not exist");
        let manifest = std::fs::read_to_string(vendor.join("Cargo.toml")).unwrap();
        assert!(!manifest.lines().any(|l| l.trim_start().starts_with("build")), "no build key");
        assert!(vendor.join("LICENSE").is_file(), "Apache-2.0 requires the licence text");
        let workspace = std::fs::read_to_string(engine.join("Cargo.toml")).unwrap();
        assert!(workspace.contains(r#"ipstack = { path = "vendor/ipstack" }"#), "the patch is in place");
    }
}
