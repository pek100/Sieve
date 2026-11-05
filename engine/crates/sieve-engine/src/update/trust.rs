//! The trust anchor and the update host, compiled in (plan 7.5): a constant,
//! not a setting or a file, so a local user cannot swap them. Release numbers
//! come from the Cargo version, the one source of truth.

use minisign_verify::PublicKey;

use super::Refusal;

/// The update public key, a minisign key line (`RW...`), from the user's
/// offline key pair (docs/live/updates.md, step 1). Until they generate it this
/// is a marked placeholder: such a build verifies nothing and fetches nothing.
/// Never a random stand-in, whose secret half someone could hold.
pub const PUBLIC_KEY: &str = "PLACEHOLDER: the user's minisign public key goes here (docs/live/updates.md)";

/// Where the index and every artefact are fetched from. `.invalid` cannot
/// resolve (RFC 2606), so no accident reaches the network.
pub const UPDATE_BASE_URL: &str = "https://updates.sieve.invalid/";

const PLACEHOLDER_PREFIX: &str = "PLACEHOLDER";
const PLACEHOLDER_HOST_SUFFIX: &str = ".invalid/";

/// The minisign key every signature is checked against. Every verify takes one,
/// so tests pass their own; only the service's start names [`PUBLIC_KEY`].
pub struct TrustAnchor(pub(super) PublicKey);

impl TrustAnchor {
    /// A key line, or [`Refusal::NoKey`] for the placeholder and anything
    /// that is not a public key.
    pub fn parse(line: &str) -> Result<Self, Refusal> {
        if line.starts_with(PLACEHOLDER_PREFIX) {
            return Err(Refusal::NoKey);
        }
        PublicKey::from_base64(line).map(Self).map_err(|_| Refusal::NoKey)
    }
}

/// The compiled-in anchor, or None while key or host is a placeholder: then
/// updates are `not_configured` and the fetcher is never called.
pub fn configured(key: &str, base_url: &str) -> Option<TrustAnchor> {
    if base_url.ends_with(PLACEHOLDER_HOST_SUFFIX) {
        return None;
    }
    TrustAnchor::parse(key).ok()
}

const MAJOR_SCALE: u64 = 1_000_000;
const MINOR_SCALE: u64 = 1_000;

/// A release's rising number: `major*1_000_000 + minor*1_000 + patch`.
pub const fn release_number(major: u64, minor: u64, patch: u64) -> u64 {
    major * MAJOR_SCALE + minor * MINOR_SCALE + patch
}

const fn digits(text: &str) -> u64 {
    let bytes = text.as_bytes();
    let mut value = 0;
    let mut i = 0;
    while i < bytes.len() {
        value = value * 10 + (bytes[i] - b'0') as u64;
        i += 1;
    }
    value
}

/// This build's release number, from its Cargo version at compile time.
pub const OWN_RELEASE: u64 = release_number(
    digits(env!("CARGO_PKG_VERSION_MAJOR")),
    digits(env!("CARGO_PKG_VERSION_MINOR")),
    digits(env!("CARGO_PKG_VERSION_PATCH")),
);

/// A release number as the app shows it (`1.2.3`).
pub fn display_version(number: u64) -> String {
    format!("{}.{}.{}", number / MAJOR_SCALE, number / MINOR_SCALE % MINOR_SCALE, number % MINOR_SCALE)
}

#[cfg(test)]
mod tests {
    use super::super::testing::TestKey;
    use super::*;

    #[test]
    fn release_numbers_rise_with_the_version_and_display_back() {
        assert_eq!(release_number(1, 2, 3), 1_002_003);
        assert!(release_number(0, 2, 0) > release_number(0, 1, 999));
        assert!(release_number(1, 0, 0) > release_number(0, 999, 999));
        assert_eq!(display_version(release_number(12, 34, 56)), "12.34.56");
    }

    #[test]
    fn the_own_release_is_the_cargo_version() {
        assert_eq!(display_version(OWN_RELEASE), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn a_placeholder_key_or_host_is_not_configured() {
        let real = TestKey::new().public_line();
        assert!(configured(&real, "https://updates.example/").is_some());
        assert!(configured(&real, UPDATE_BASE_URL).is_none(), "the placeholder host never fetches");
        assert!(configured(PUBLIC_KEY, "https://updates.example/").is_none());
        assert!(configured("not a key", "https://updates.example/").is_none());
    }
}
