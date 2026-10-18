//! Sieve's filtering engine (docs/plans/2026-10-17-https-filtering.md).
//! - [`flow`]: the flow decoders moved from the Wintun spike (slice 1);
//! - [`service`]: the Windows service and its install, uninstall and
//!   restore verbs (slice 2);
//! - [`ipc`]: the pipe server and the per-connection protocol (slice 2);
//! - [`route`]: removal of Sieve's routes for the off paths.
//!
//! Nothing here changes traffic yet: no adapter and no route is ever added.
pub mod flow;
pub mod ipc;
pub mod route;
pub mod service;

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
