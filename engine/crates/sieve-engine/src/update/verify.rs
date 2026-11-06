//! Verification of one signed artefact: the signature over the exact bytes,
//! then the signed kind and version from the trusted comment. Pure; nothing
//! here touches a file.

use minisign_verify::Signature;

use super::trust::TrustAnchor;
use super::{Kind, Refusal};

const COMMENT_PREFIX: &str = "sieve-update";
const KIND_FIELD: &str = "kind=";
const VERSION_FIELD: &str = "version=";
/// A `.minisig` is four short lines; anything larger is not one.
pub const MAX_SIGNATURE_BYTES: u64 = 4 * 1024;
/// Prehashed signatures only (`minisign -S` default since 0.11).
const ALLOW_LEGACY: bool = false;

/// What a trusted comment states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub kind: Kind,
    pub version: u64,
}

/// The one accepted grammar: exactly `sieve-update kind=<k> version=<n>`,
/// with `<n>` in plain digits. Anything else is refused, including a real
/// minisign default comment (a file signed without `-t` is not an update).
pub fn parse_comment(comment: &str) -> Result<Signed, Refusal> {
    let bad = || Refusal::BadComment(comment.chars().take(MAX_SHOWN_COMMENT).collect());
    let mut parts = comment.split(' ');
    let (Some(COMMENT_PREFIX), Some(kind), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(bad());
    };
    let kind = kind.strip_prefix(KIND_FIELD).and_then(Kind::parse).ok_or_else(bad)?;
    let version = version.strip_prefix(VERSION_FIELD).ok_or_else(bad)?;
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    Ok(Signed { kind, version: version.parse().map_err(|_| bad())? })
}

const MAX_SHOWN_COMMENT: usize = 80;

/// The signature over `bytes` and the kind asked for; the signed version on
/// success. The caller compares that version with what it holds.
pub fn verify_artefact(anchor: &TrustAnchor, bytes: &[u8], signature: &[u8], want: &Kind) -> Result<u64, Refusal> {
    if signature.is_empty() {
        return Err(Refusal::NoSignature);
    }
    let text = std::str::from_utf8(signature).map_err(|_| Refusal::BadSignature)?;
    let signature = Signature::decode(text).map_err(|_| Refusal::BadSignature)?;
    anchor.0.verify(bytes, &signature, ALLOW_LEGACY).map_err(|_| Refusal::BadSignature)?;
    let signed = parse_comment(signature.trusted_comment())?;
    if signed.kind != *want {
        return Err(Refusal::WrongKind { want: want.to_string(), got: signed.kind.to_string() });
    }
    Ok(signed.version)
}

/// A signed version must be above the installed one, even when correctly signed.
pub fn require_newer(version: u64, installed: u64) -> Result<(), Refusal> {
    if version > installed { Ok(()) } else { Err(Refusal::NotNewer { version, installed }) }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{TestKey, comment};
    use super::super::trust::PUBLIC_KEY;
    use super::*;

    const BODY: &[u8] = b"the artefact's bytes";

    fn engine() -> Kind {
        Kind::Engine
    }

    #[test]
    fn a_valid_artefact_verifies() {
        let key = TestKey::new();
        let sig = key.sign(BODY, &comment(&engine(), 7));
        assert_eq!(verify_artefact(&key.anchor(), BODY, sig.as_bytes(), &engine()), Ok(7));
    }

    #[test]
    fn one_changed_byte_anywhere_is_refused() {
        let key = TestKey::new();
        let sig = key.sign(BODY, &comment(&engine(), 7));
        for at in [0, BODY.len() / 2, BODY.len() - 1] {
            let mut bent = BODY.to_vec();
            bent[at] ^= 1;
            assert_eq!(verify_artefact(&key.anchor(), &bent, sig.as_bytes(), &engine()), Err(Refusal::BadSignature), "{at}");
        }
    }

    #[test]
    fn a_changed_trusted_comment_is_refused() {
        let key = TestKey::new();
        let sig = key.sign(BODY, &comment(&engine(), 7));
        let raised = sig.replace("version=7", "version=8");
        assert_ne!(raised, sig);
        assert_eq!(verify_artefact(&key.anchor(), BODY, raised.as_bytes(), &engine()), Err(Refusal::BadSignature));
    }

    #[test]
    fn another_keys_signature_is_refused() {
        let sig = TestKey::new().sign(BODY, &comment(&engine(), 7));
        assert_eq!(verify_artefact(&TestKey::new().anchor(), BODY, sig.as_bytes(), &engine()), Err(Refusal::BadSignature));
    }

    #[test]
    fn no_signature_is_refused() {
        assert_eq!(verify_artefact(&TestKey::new().anchor(), BODY, b"", &engine()), Err(Refusal::NoSignature));
    }

    #[test]
    fn a_garbled_signature_is_refused() {
        let key = TestKey::new();
        for garbled in [&b"not a signature"[..], &[0xff, 0xfe, 0x00][..], b"untrusted comment: x\nAAAA\ntrusted comment: y\nAAAA\n"] {
            assert_eq!(verify_artefact(&key.anchor(), BODY, garbled, &engine()), Err(Refusal::BadSignature));
        }
    }

    #[test]
    fn another_kinds_comment_is_refused() {
        let key = TestKey::new();
        let list = Kind::List("sensitive".into());
        let sig = key.sign(BODY, &comment(&list, 7));
        for want in [Kind::Engine, Kind::Index] {
            assert_eq!(
                verify_artefact(&key.anchor(), BODY, sig.as_bytes(), &want),
                Err(Refusal::WrongKind { want: want.to_string(), got: "list:sensitive".into() })
            );
        }
    }

    #[test]
    fn equal_and_lower_versions_are_refused_even_when_correctly_signed() {
        let key = TestKey::new();
        for version in [6, 7] {
            let sig = key.sign(BODY, &comment(&engine(), version));
            let signed = verify_artefact(&key.anchor(), BODY, sig.as_bytes(), &engine()).unwrap();
            assert_eq!(require_newer(signed, 7), Err(Refusal::NotNewer { version, installed: 7 }));
        }
        assert_eq!(require_newer(8, 7), Ok(()));
    }

    #[test]
    fn a_comment_with_anything_extra_is_refused() {
        for bad in [
            "",
            "sieve-update",
            "sieve-update kind=engine",
            "sieve-update version=1 kind=engine",
            "sieve-update kind=engine version=1 extra",
            "sieve-update kind=engine version=1 ",
            " sieve-update kind=engine version=1",
            "sieve-update  kind=engine version=1",
            "sieve-update kind=engine version=",
            "sieve-update kind=engine version=-1",
            "sieve-update kind=engine version=+1",
            "sieve-update kind=engine version=0x1",
            "sieve-update kind=engine version=99999999999999999999999",
            "sieve-update kind=nothing version=1",
            "sieve-update kind=list: version=1",
            "SIEVE-UPDATE kind=engine version=1",
            "timestamp:1700000000\tfile:x\thashed",
        ] {
            assert!(matches!(parse_comment(bad), Err(Refusal::BadComment(_))), "{bad:?}");
        }
        assert_eq!(parse_comment("sieve-update kind=list:a-1 version=3"), Ok(Signed { kind: Kind::List("a-1".into()), version: 3 }));
    }

    /// A file signed with minisign's own default comment is no update.
    #[test]
    fn a_real_default_minisign_comment_is_refused() {
        let key = TestKey::new();
        let sig = key.sign_default(BODY);
        assert!(matches!(verify_artefact(&key.anchor(), BODY, sig.as_bytes(), &engine()), Err(Refusal::BadComment(_))));
    }

    /// Parses the placeholder form itself, so this still tests something after
    /// the real key is in.
    #[test]
    fn the_placeholder_key_refuses_everything() {
        let placeholder = format!("{}: not yet generated", "PLACEHOLDER");
        assert!(matches!(TrustAnchor::parse(&placeholder), Err(Refusal::NoKey)));
        assert!(matches!(TrustAnchor::parse(""), Err(Refusal::NoKey)));
    }

    /// Either the marked placeholder or a decodable public key; never a
    /// secret-key box line (`RWQAAEIy`, `RWRTY0Iy`, plan section 2).
    #[test]
    fn the_compiled_key_is_a_placeholder_or_a_public_key() {
        assert!(!PUBLIC_KEY.starts_with("RWQAAEIy") && !PUBLIC_KEY.starts_with("RWRTY0Iy"));
        match TrustAnchor::parse(PUBLIC_KEY) {
            Ok(_) => assert!(PUBLIC_KEY.starts_with("RW")),
            Err(Refusal::NoKey) => assert!(PUBLIC_KEY.starts_with("PLACEHOLDER")),
            Err(other) => panic!("{other}"),
        }
    }
}
