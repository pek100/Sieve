//! The signed index: what the host currently offers (plan 7.5, D5 to D7). It
//! expires, so a host cannot freeze a machine on old releases, and its own
//! version must not fall, so it cannot serve an older unexpired index.
//!
//! The index carries no hash: each artefact has its own signature, and a hash
//! would be a second owner of the same fact. It signs each artefact's `size`,
//! which caps the download before any verification.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::swap::SUPERVISOR_EXE;
use super::trust::TrustAnchor;
use super::verify::verify_artefact;
use super::{Kind, Refusal};

pub const INDEX_FILE: &str = "index.json";
pub const SIGNATURE_SUFFIX: &str = ".minisig";
/// The index is read to at most this many bytes.
pub const MAX_INDEX_BYTES: u64 = 1 << 20;
const SCHEMA: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub version: u64,
    /// A bare name on the catalogue host, validated by [`parse_index`].
    pub file: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    schema: u32,
    version: u64,
    expires_unix: u64,
    artefacts: BTreeMap<String, Entry>,
}

/// An accepted index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    pub version: u64,
    pub artefacts: BTreeMap<Kind, Entry>,
}

impl Index {
    /// Entries of every kind the service applies by itself, in kind order.
    pub fn data(&self) -> impl Iterator<Item = (&Kind, &Entry)> {
        self.artefacts.iter().filter(|(k, _)| k.data_file().is_some())
    }
}

/// A bare file name: no separator, no drive, no dots of its own, no device
/// trailer. It only ever joins the catalogue URL and a staging folder, so it
/// cannot be the name the supervisor's own copy takes in that folder.
fn valid_file_name(name: &str) -> bool {
    const FORBIDDEN: &[char] = &['/', '\\', ':', '*', '?', '"', '<', '>', '|', '%', '&', '#'];
    !name.is_empty()
        && !name.eq_ignore_ascii_case(SUPERVISOR_EXE)
        && !name.contains(FORBIDDEN)
        && !name.chars().any(char::is_control)
        && !name.starts_with('.')
        && !name.ends_with(['.', ' '])
}

/// Checks the signature first, then every signed fact.
///
/// A kind this build does not know is left out, not refused: the index is
/// signed, nothing unknown is ever fetched, and refusing it would freeze every
/// older install on the release that first offers a new kind.
pub fn parse_index(anchor: &TrustAnchor, body: &[u8], signature: &[u8], now_unix: u64, accepted: u64) -> Result<Index, Refusal> {
    let signed_version = verify_artefact(anchor, body, signature, &Kind::Index)?;
    let parsed: Body = serde_json::from_slice(body).map_err(|e| Refusal::BadIndex(e.to_string()))?;
    if parsed.schema != SCHEMA {
        return Err(Refusal::BadIndex(format!("schema {} is not {SCHEMA}", parsed.schema)));
    }
    if parsed.version != signed_version {
        return Err(Refusal::VersionMismatch { kind: Kind::Index.to_string(), signed: signed_version, listed: parsed.version });
    }
    if parsed.version < accepted {
        return Err(Refusal::IndexOlder { version: parsed.version, accepted });
    }
    if now_unix >= parsed.expires_unix {
        return Err(Refusal::IndexExpired);
    }
    let mut artefacts = BTreeMap::new();
    for (key, entry) in parsed.artefacts {
        if !valid_file_name(&entry.file) {
            return Err(Refusal::BadFileName(entry.file));
        }
        if let Some(kind) = Kind::parse(&key).filter(|k| *k != Kind::Index) {
            artefacts.insert(kind, entry);
        }
    }
    Ok(Index { version: parsed.version, artefacts })
}

/// An artefact's signed version must be the one the index lists: two validly
/// signed files cannot be mixed and matched.
pub fn require_listed(kind: &Kind, signed: u64, entry: &Entry) -> Result<(), Refusal> {
    if signed == entry.version {
        Ok(())
    } else {
        Err(Refusal::VersionMismatch { kind: kind.to_string(), signed, listed: entry.version })
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{TestKey, comment};
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn body(version: u64, expires: u64, file: &str) -> String {
        serde_json::json!({
            "schema": 1,
            "version": version,
            "expires_unix": expires,
            "artefacts": { "engine": { "version": 9, "file": file, "size": 10 } }
        })
        .to_string()
    }

    fn parse(key: &TestKey, text: &str, accepted: u64, now: u64) -> Result<Index, Refusal> {
        let version = serde_json::from_str::<serde_json::Value>(text).ok().and_then(|v| v["version"].as_u64()).unwrap_or(1);
        let sig = key.sign(text.as_bytes(), &comment(&Kind::Index, version));
        parse_index(&key.anchor(), text.as_bytes(), sig.as_bytes(), now, accepted)
    }

    #[test]
    fn a_valid_index_parses_with_its_entries() {
        let index = parse(&TestKey::new(), &body(4, NOW + 1, "sieve-engine.exe"), 3, NOW).unwrap();
        assert_eq!(index.version, 4);
        assert_eq!(index.artefacts[&Kind::Engine], Entry { version: 9, file: "sieve-engine.exe".into(), size: 10 });
    }

    #[test]
    fn an_expired_index_is_refused_and_reported_stale() {
        let key = TestKey::new();
        for now in [NOW, NOW + 1] {
            assert_eq!(parse(&key, &body(4, NOW, "a"), 0, now), Err(Refusal::IndexExpired), "{now}");
        }
        assert!(parse(&key, &body(4, NOW, "a"), 0, NOW - 1).is_ok());
    }

    #[test]
    fn an_older_unexpired_index_is_refused() {
        let key = TestKey::new();
        assert_eq!(parse(&key, &body(4, NOW + 1, "a"), 5, NOW), Err(Refusal::IndexOlder { version: 4, accepted: 5 }));
        assert!(parse(&key, &body(5, NOW + 1, "a"), 5, NOW).is_ok(), "the same index may be read again");
    }

    #[test]
    fn an_index_signed_as_another_kind_is_refused() {
        let key = TestKey::new();
        let text = body(4, NOW + 1, "a");
        let sig = key.sign(text.as_bytes(), &comment(&Kind::Resources, 4));
        assert_eq!(
            parse_index(&key.anchor(), text.as_bytes(), sig.as_bytes(), NOW, 0),
            Err(Refusal::WrongKind { want: "index".into(), got: "resources".into() })
        );
    }

    #[test]
    fn the_signed_version_must_equal_the_bodys() {
        let key = TestKey::new();
        let text = body(4, NOW + 1, "a");
        let sig = key.sign(text.as_bytes(), &comment(&Kind::Index, 5));
        assert!(matches!(parse_index(&key.anchor(), text.as_bytes(), sig.as_bytes(), NOW, 0), Err(Refusal::VersionMismatch { .. })));
    }

    #[test]
    fn a_file_name_with_a_separator_is_refused() {
        let key = TestKey::new();
        for bad in [r"..\x", "a/b", "C:x", "..", ".", "", "a.", "a ", r"\\host\share", "a%2fb", "a\nb"] {
            assert_eq!(parse(&key, &body(4, NOW + 1, bad), 0, NOW), Err(Refusal::BadFileName(bad.into())), "{bad:?}");
        }
    }

    /// The staging folder holds the supervisor under this name, in the path's
    /// own case-insensitive reading: a release so named would be overwritten.
    #[test]
    fn the_supervisors_own_name_is_refused() {
        let key = TestKey::new();
        for bad in [SUPERVISOR_EXE.to_string(), SUPERVISOR_EXE.to_uppercase()] {
            assert_eq!(parse(&key, &body(4, NOW + 1, &bad), 0, NOW), Err(Refusal::BadFileName(bad.clone())), "{bad}");
        }
    }

    #[test]
    fn unknown_fields_are_refused() {
        let key = TestKey::new();
        let with_top = r#"{"schema":1,"version":1,"expires_unix":9999999999,"artefacts":{},"url":"x"}"#;
        assert!(matches!(parse(&key, with_top, 0, NOW), Err(Refusal::BadIndex(_))));
        let in_entry = r#"{"schema":1,"version":1,"expires_unix":9999999999,"artefacts":{"engine":{"version":1,"file":"a","size":1,"sha256":"x"}}}"#;
        assert!(matches!(parse(&key, in_entry, 0, NOW), Err(Refusal::BadIndex(_))));
        let schema = r#"{"schema":2,"version":1,"expires_unix":9999999999,"artefacts":{}}"#;
        assert!(matches!(parse(&key, schema, 0, NOW), Err(Refusal::BadIndex(_))));
    }

    #[test]
    fn a_kind_this_build_does_not_know_is_left_out_and_never_the_index_itself() {
        let text = r#"{"schema":1,"version":1,"expires_unix":9999999999,"artefacts":{"drivers":{"version":1,"file":"d","size":1},"index":{"version":1,"file":"i","size":1},"list:a":{"version":2,"file":"l","size":1}}}"#;
        let index = parse(&TestKey::new(), text, 0, NOW).unwrap();
        assert_eq!(index.artefacts.keys().cloned().collect::<Vec<_>>(), [Kind::List("a".into())]);
    }

    #[test]
    fn the_artefact_comment_must_match_its_index_entry() {
        let entry = Entry { version: 9, file: "a".into(), size: 1 };
        assert_eq!(require_listed(&Kind::Engine, 9, &entry), Ok(()));
        assert_eq!(
            require_listed(&Kind::Engine, 8, &entry),
            Err(Refusal::VersionMismatch { kind: "engine".into(), signed: 8, listed: 9 })
        );
    }

    #[test]
    fn a_broken_signature_is_refused_before_the_body_is_read() {
        let key = TestKey::new();
        assert_eq!(parse_index(&key.anchor(), b"{not json", b"", NOW, 0), Err(Refusal::NoSignature));
    }
}
