//! The scriptlet and redirect resource bundle is pinned by SHA-256 in code
//! (plan 5.5, 7.1): a download whose hash differs is refused and the last
//! verified copy is kept. This module only checks and deserializes; the engine
//! downloads, and nothing in a bundle runs in the service.
//!
//! The bundle is a JSON array of adblock-rust `Resource` values, written by
//! `scripts/resources/assemble-ubo.mjs` (docs/tasks/2026-11-02-content.md, D1):
//! adblock-rust's own assembler cannot read a current uBlock Origin, panics on
//! bad input and gives every scriptlet the default permission.
//!
//! From slice 13 the engine also receives the bundle as a signed update
//! (`updates\resources`, `sieve_engine::update`): the engine's loader
//! (`sieve_engine::lists::resources`) prefers that copy, through
//! [`load_signed_bundle`], and the pin stays as its fallback until a signed
//! update exists.

use std::collections::HashSet;

use adblock::resources::{AddResourceError, InMemoryResourceStorage, Resource};
use sha2::{Digest, Sha256};

/// uBlock Origin's naming rule for scriptlets only a trusted list may use.
const TRUSTED_PREFIX: &str = "trusted-";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinError {
    #[error("the pinned hash is not 64 hex digits")]
    BadPin,
    #[error("archive hash {actual} does not match the pin {pinned}")]
    Mismatch { pinned: String, actual: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    #[error(transparent)]
    Pin(#[from] PinError),
    #[error("the resource bundle is not valid JSON: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("resource {name} was refused: {source}")]
    Refused {
        name: String,
        #[source]
        source: AddResourceError,
    },
    #[error("resource {0} is named trusted but any list could inject it")]
    UntrustedPrivileged(String),
    #[error("resource {name} depends on {dependency}, which the bundle does not hold")]
    DanglingDependency { name: String, dependency: String },
}

/// A verified bundle, whole: one bad resource refuses all of it.
#[derive(Clone)]
pub struct ResourceBundle {
    pub(crate) storage: InMemoryResourceStorage,
    /// Every name and alias a `+js()` rule can ask for.
    identifiers: HashSet<String>,
}

impl std::fmt::Debug for ResourceBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceBundle").field("identifiers", &self.identifiers.len()).finish_non_exhaustive()
    }
}

impl ResourceBundle {
    /// Is a resource by this name or alias in the bundle?
    pub fn contains(&self, identifier: &str) -> bool {
        self.identifiers.contains(identifier)
    }
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

fn identifiers_of(resource: &Resource) -> impl Iterator<Item = &String> {
    std::iter::once(&resource.name).chain(&resource.aliases)
}

/// Verifies `bytes` against `pinned`, then loads every resource. The hash is
/// checked first, so an unverified file is never parsed.
pub fn load_bundle(bytes: &[u8], pinned: &str) -> Result<ResourceBundle, ResourceError> {
    verify(bytes, pinned)?;
    load_signed_bundle(bytes)
}

/// Loads a bundle the signed update path already verified: its signature, kind
/// and version were checked before the file was put where only an admin can
/// write. Every other check of a bundle still runs.
pub fn load_signed_bundle(bytes: &[u8]) -> Result<ResourceBundle, ResourceError> {
    let resources: Vec<Resource> = serde_json::from_slice(bytes)?;

    let mut identifiers = HashSet::new();
    for resource in &resources {
        identifiers.extend(identifiers_of(resource).cloned());
        let privileged = identifiers_of(resource).any(|id| id.starts_with(TRUSTED_PREFIX));
        if privileged && resource.permission.to_bits() == 0 {
            return Err(ResourceError::UntrustedPrivileged(resource.name.clone()));
        }
    }

    let mut storage = InMemoryResourceStorage::default();
    for resource in resources {
        if let Some(dependency) = resource.dependencies.iter().find(|d| !identifiers.contains(*d)) {
            return Err(ResourceError::DanglingDependency { name: resource.name.clone(), dependency: dependency.clone() });
        }
        let name = resource.name.clone();
        storage.add_resource(resource).map_err(|source| ResourceError::Refused { name, source })?;
    }
    Ok(ResourceBundle { storage, identifiers })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{ListText, RuleEngine};

    /// SHA-256("abc"), FIPS 180-2 appendix B.1.
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const FIXTURE: &[u8] = include_bytes!("../testdata/resources-fixture.json");

    fn load(json: &str) -> Result<ResourceBundle, ResourceError> {
        load_bundle(json.as_bytes(), &sha256_hex(json.as_bytes()))
    }

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

    #[test]
    fn the_fixture_bundle_loads_with_names_and_aliases() {
        let bundle = load_bundle(FIXTURE, &sha256_hex(FIXTURE)).unwrap();
        for id in ["sieve-set-flag.js", "ssf.js", "sieve-flag-name.fn", "trusted-sieve-flag.js", "sieve-noop.js", "sieve-1x1.gif"] {
            assert!(bundle.contains(id), "{id}");
        }
        assert!(!bundle.contains("sieve-parameterised.js"));
    }

    #[test]
    fn one_changed_byte_in_a_bundle_loads_nothing() {
        let mut changed = FIXTURE.to_vec();
        changed[10] ^= 1;
        let err = load_bundle(&changed, &sha256_hex(FIXTURE)).unwrap_err();
        assert!(matches!(err, ResourceError::Pin(PinError::Mismatch { .. })), "{err}");
    }

    #[test]
    fn a_bad_pin_loads_nothing() {
        assert!(matches!(load_bundle(FIXTURE, "abc"), Err(ResourceError::Pin(PinError::BadPin))));
    }

    #[test]
    fn malformed_json_is_refused_after_the_pin_passes() {
        assert!(matches!(load("[{"), Err(ResourceError::Malformed(_))));
        assert!(matches!(load(r#"{"name":"x.js"}"#), Err(ResourceError::Malformed(_))));
    }

    #[test]
    fn bad_base64_refuses_the_whole_bundle() {
        let json = r#"[{"name":"a.js","kind":{"mime":"application/javascript"},"content":"Zm9v"},
                       {"name":"b.js","kind":{"mime":"application/javascript"},"content":"not base64!"}]"#;
        let err = load(json).unwrap_err();
        assert!(matches!(err, ResourceError::Refused { ref name, source: AddResourceError::InvalidBase64Content } if name == "b.js"), "{err}");
    }

    #[test]
    fn a_duplicate_name_or_alias_refuses_the_whole_bundle() {
        let duplicate = r#"[{"name":"a.js","kind":{"mime":"application/javascript"},"content":"Zm9v"},
                            {"name":"a.js","kind":{"mime":"application/javascript"},"content":"Zm9v"}]"#;
        let alias = r#"[{"name":"a.js","kind":{"mime":"application/javascript"},"content":"Zm9v"},
                        {"name":"b.js","aliases":["a.js"],"kind":{"mime":"application/javascript"},"content":"Zm9v"}]"#;
        for json in [duplicate, alias] {
            assert!(matches!(load(json), Err(ResourceError::Refused { source: AddResourceError::NameAlreadyAdded, .. })));
        }
    }

    #[test]
    fn a_trusted_resource_with_the_default_mask_refuses_the_whole_bundle() {
        let by_name = r#"[{"name":"trusted-x.js","kind":{"mime":"application/javascript"},"content":"Zm9v"}]"#;
        let by_alias = r#"[{"name":"x.js","aliases":["trusted-x.js"],"kind":{"mime":"application/javascript"},"content":"Zm9v"}]"#;
        for json in [by_name, by_alias] {
            assert!(matches!(load(json), Err(ResourceError::UntrustedPrivileged(_))));
        }
        let masked = r#"[{"name":"trusted-x.js","kind":{"mime":"application/javascript"},"content":"Zm9v","permission":1}]"#;
        assert!(load(masked).is_ok());
    }

    #[test]
    fn a_dependency_the_bundle_does_not_hold_refuses_the_whole_bundle() {
        let json = r#"[{"name":"a.js","kind":{"mime":"application/javascript"},"content":"Zm9v","dependencies":["gone.fn"]}]"#;
        assert!(matches!(load(json), Err(ResourceError::DanglingDependency { .. })));
    }

    #[test]
    fn on_refusal_an_engine_keeps_its_prior_bundle() {
        let list = [ListText { id: "l", text: "sieve-test.invalid##+js(sieve-set-flag, a, b)\n", trusted: true }];
        let mut engine = RuleEngine::compile(&list);
        engine.use_resources(&load_bundle(FIXTURE, &sha256_hex(FIXTURE)).unwrap());
        let url = "https://sieve-test.invalid/";
        let before = engine.page_cosmetics(url).scriptlets;
        assert!(before.contains("sieveSetFlag"), "{before}");

        let mut changed = FIXTURE.to_vec();
        changed[10] ^= 1;
        if let Ok(bundle) = load_bundle(&changed, &sha256_hex(FIXTURE)) {
            engine.use_resources(&bundle);
        }
        assert!(engine.page_cosmetics(url).scriptlets.contains("sieveSetFlag"));
    }
}
