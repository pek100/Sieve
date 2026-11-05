//! The scriptlet and redirect resource archive is pinned by SHA-256 in code
//! (plan 5.5, 7.1): a download whose hash differs is refused and the last
//! verified copy is kept. This module only checks; the engine downloads. From
//! slice 13 the engine also receives the bundle as a signed update
//! (`updates\resources`, `sieve_engine::update`); the pin retires once a loader
//! here reads that file.

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinError {
    #[error("the pinned hash is not 64 hex digits")]
    BadPin,
    #[error("archive hash {actual} does not match the pin {pinned}")]
    Mismatch { pinned: String, actual: String },
}

/// Lower-case hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Ok when `archive` hashes to `pinned` (hex, either case).
pub fn verify(archive: &[u8], pinned: &str) -> Result<(), PinError> {
    let pinned = pinned.to_ascii_lowercase();
    if pinned.len() != 64 || !pinned.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PinError::BadPin);
    }
    let actual = sha256_hex(archive);
    if actual == pinned { Ok(()) } else { Err(PinError::Mismatch { pinned, actual }) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256("abc"), FIPS 180-2 appendix B.1.
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn the_pinned_archive_is_accepted_in_either_case() {
        assert_eq!(verify(b"abc", ABC), Ok(()));
        assert_eq!(verify(b"abc", &ABC.to_uppercase()), Ok(()));
    }

    #[test]
    fn one_changed_byte_is_refused() {
        let err = verify(b"abd", ABC).unwrap_err();
        assert!(matches!(err, PinError::Mismatch { ref pinned, .. } if pinned == ABC), "{err}");
    }

    #[test]
    fn a_malformed_pin_is_refused_not_compared() {
        assert_eq!(verify(b"abc", "abc"), Err(PinError::BadPin));
        assert_eq!(verify(b"abc", &"z".repeat(64)), Err(PinError::BadPin));
    }
}
