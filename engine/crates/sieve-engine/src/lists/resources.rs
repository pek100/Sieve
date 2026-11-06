//! Where the scriptlet bundle comes from at compile time (plan 5.5, 7.5). A copy
//! the signed update path placed (`updates\resources`) wins; without one, a copy
//! that hashes to the pin in code is the fallback, until a signed update exists.
//! Nothing here downloads: the update cycle places the signed copy, and the
//! pinned copy's download belongs with the question of where a bundle comes from
//! before slice 13 (docs/tasks/2026-11-02-content.md, Q1).

use std::path::Path;

use sieve_filter::resources::{ResourceBundle, load_bundle, load_signed_bundle, sha256_hex};

use crate::update::{Kind, data_path};

/// The pin of the unsigned fallback. None: Q1 of the content task is open, so no
/// real bundle has been reviewed and no hash can be named here.
pub const RESOURCE_PIN: Option<&str> = None;
/// The pinned fallback's copy, in the lists' folder.
pub const PINNED_COPY: &str = "resources.json";

/// A verified bundle and the fact the report quotes.
pub struct Loaded {
    pub bundle: ResourceBundle,
    /// `sha256:<hex>` of the bytes in use, whichever copy they came from.
    pub pin: String,
}

fn fact(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// The bundle to use, and why a present copy was refused. No bundle is a
/// normal state: scriptlets stay out until one exists, and nothing else depends
/// on it. A refused copy falls through, so a bad update cannot take the pinned
/// copy away.
pub fn load(engine_dir: &Path, pin: Option<&str>) -> (Option<Loaded>, Option<String>) {
    let mut refused = None;
    if let Some(bytes) = data_path(engine_dir, &Kind::Resources).and_then(|p| std::fs::read(p).ok()) {
        match load_signed_bundle(&bytes) {
            Ok(bundle) => return (Some(Loaded { bundle, pin: fact(&bytes) }), None),
            Err(why) => refused = Some(format!("the signed resource library was refused: {why}")),
        }
    }
    let Some(pin) = pin else { return (None, refused) };
    let Ok(bytes) = std::fs::read(engine_dir.join(super::cache::FOLDER).join(PINNED_COPY)) else { return (None, refused) };
    match load_bundle(&bytes, pin) {
        Ok(bundle) => (Some(Loaded { bundle, pin: fact(&bytes) }), refused),
        Err(why) => (None, Some(format!("the pinned resource library was refused: {why}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUNDLE: &[u8] = include_bytes!("../../../sieve-filter/testdata/resources-fixture.json");
    /// Another valid bundle, so the two copies can be told apart.
    const SIGNED: &[u8] = b"[]";

    fn put_signed(dir: &Path, bytes: &[u8]) {
        let path = data_path(dir, &Kind::Resources).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn put_pinned(dir: &Path, bytes: &[u8]) {
        let folder = dir.join(crate::lists::cache::FOLDER);
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join(PINNED_COPY), bytes).unwrap();
    }

    #[test]
    fn nothing_in_the_folder_is_no_bundle_and_no_problem() {
        let dir = tempfile::tempdir().unwrap();
        let (loaded, why) = load(dir.path(), Some(&sha256_hex(BUNDLE)));
        assert!(loaded.is_none() && why.is_none());
    }

    #[test]
    fn the_signed_copy_wins_over_the_pinned_one() {
        let dir = tempfile::tempdir().unwrap();
        put_pinned(dir.path(), BUNDLE);
        put_signed(dir.path(), SIGNED);
        let (loaded, why) = load(dir.path(), Some(&sha256_hex(BUNDLE)));
        assert_eq!(loaded.unwrap().pin, fact(SIGNED));
        assert_eq!(why, None);
    }

    #[test]
    fn the_pin_stays_the_fallback_until_a_signed_copy_exists() {
        let dir = tempfile::tempdir().unwrap();
        put_pinned(dir.path(), BUNDLE);
        let (loaded, why) = load(dir.path(), Some(&sha256_hex(BUNDLE)));
        assert_eq!(loaded.unwrap().pin, fact(BUNDLE));
        assert_eq!(why, None);
    }

    #[test]
    fn a_copy_that_differs_from_the_pin_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        put_pinned(dir.path(), BUNDLE);
        let (loaded, why) = load(dir.path(), Some(&sha256_hex(SIGNED)));
        assert!(loaded.is_none());
        assert!(why.unwrap().contains("pinned"));
    }

    #[test]
    fn a_broken_signed_copy_falls_back_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        put_signed(dir.path(), b"not json");
        put_pinned(dir.path(), BUNDLE);
        let (loaded, why) = load(dir.path(), Some(&sha256_hex(BUNDLE)));
        assert_eq!(loaded.unwrap().pin, fact(BUNDLE));
        assert!(why.unwrap().contains("signed"));
    }

    #[test]
    fn with_no_pin_in_code_only_a_signed_copy_loads() {
        assert_eq!(RESOURCE_PIN, None);
        let dir = tempfile::tempdir().unwrap();
        put_pinned(dir.path(), BUNDLE);
        assert!(load(dir.path(), RESOURCE_PIN).0.is_none());
        put_signed(dir.path(), SIGNED);
        assert!(load(dir.path(), RESOURCE_PIN).0.is_some());
    }
}
