//! Where the scriptlet bundle comes from at compile time (plan 5.5, 7.5). A copy
//! the signed update path placed (`updates\resources`) wins; without one, the
//! bundle compiled into the engine is used, checked against the pin in code.
//! Nothing here downloads.
//!
//! The owner's decision of 2026-11-20 (content Q1, docs/tasks/2026-11-06-open-decisions.md):
//! the recommended source was a bundle the owner assembles at a reviewed uBO
//! tag and publishes on Sieve's own release, hash pinned in code. The
//! repository is private, so an installed engine cannot fetch a release asset;
//! the practical form ships now: the assembled bundle is committed
//! (`data/ubo-resources.json`, uBO 1.76.6, see its NOTICE), embedded and
//! pinned. The download path is the signed copy above, which the update cycle
//! places once releases are public (slice 13), and which then wins.

use std::path::Path;

use sieve_filter::resources::{ResourceBundle, load_bundle, load_signed_bundle, sha256_hex};

use crate::update::{Kind, data_path};

/// SHA-256 of the shipped bundle, `data/ubo-resources.json` (uBlock Origin
/// 1.76.6, assembled by `scripts/resources/assemble-ubo.mjs`).
pub const RESOURCE_PIN: &str = "21dc25d59fe301f5625dd09aaaa48e987e175ded250fa566cc1fb1bf790d066e";
/// The shipped bundle's bytes. Byte-exact in git (`.gitattributes`: `-text`).
pub const SHIPPED: &[u8] = include_bytes!("../../data/ubo-resources.json");

/// A verified bundle and the fact the report quotes.
pub struct Loaded {
    pub bundle: ResourceBundle,
    /// `sha256:<hex>` of the bytes in use, whichever copy they came from.
    pub pin: String,
}

fn fact(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// The bundle to use, and why a present copy was refused. A refused signed
/// copy falls through to the shipped one, so a bad update cannot take
/// scriptlets away. A shipped copy that does not match `pin` (a build from a
/// tree whose file was changed) loads nothing and says so: scriptlets stay out,
/// filtering carries on.
pub fn load(engine_dir: Option<&Path>, shipped: &[u8], pin: &str) -> (Option<Loaded>, Option<String>) {
    let mut refused = None;
    match engine_dir.and_then(|d| data_path(d, &Kind::Resources)).map_or(Ok(None), |p| read_copy(&p, "signed")) {
        Ok(Some(bytes)) => match load_signed_bundle(&bytes) {
            Ok(bundle) => return (Some(Loaded { bundle, pin: fact(&bytes) }), None),
            Err(why) => refused = Some(format!("the signed resource library was refused: {why}")),
        },
        Ok(None) => {}
        Err(why) => refused = Some(why),
    }
    match load_bundle(shipped, pin) {
        Ok(bundle) => (Some(Loaded { bundle, pin: fact(shipped) }), refused),
        Err(why) => {
            let shipped_why = format!("the shipped resource library was refused: {why}");
            (None, Some(refused.map_or(shipped_why.clone(), |r| format!("{r}; {shipped_why}"))))
        }
    }
}

/// A copy's bytes. Only a missing file is absence: a copy that is there and
/// cannot be read is said, like one that is refused.
fn read_copy(path: &Path, which: &str) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("the {which} resource library could not be read: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sieve_filter::rules::{ListText, RuleEngine};

    const BUNDLE: &[u8] = include_bytes!("../../../sieve-filter/testdata/resources-fixture.json");
    /// Another valid bundle, so the two copies can be told apart.
    const SIGNED: &[u8] = b"[]";

    fn put_signed(dir: &Path, bytes: &[u8]) {
        let path = data_path(dir, &Kind::Resources).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn with_nothing_on_disk_the_shipped_copy_loads() {
        let dir = tempfile::tempdir().unwrap();
        let (loaded, why) = load(Some(dir.path()), BUNDLE, &sha256_hex(BUNDLE));
        assert_eq!(loaded.unwrap().pin, fact(BUNDLE));
        assert_eq!(why, None);
        let (loaded, why) = load(None, BUNDLE, &sha256_hex(BUNDLE));
        assert_eq!(loaded.unwrap().pin, fact(BUNDLE), "no engine folder: the shipped copy still loads");
        assert_eq!(why, None);
    }

    #[test]
    fn a_copy_that_cannot_be_read_is_said_and_not_taken_for_absence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(data_path(dir.path(), &Kind::Resources).unwrap()).unwrap();
        let (loaded, why) = load(Some(dir.path()), BUNDLE, &sha256_hex(BUNDLE));
        assert_eq!(loaded.unwrap().pin, fact(BUNDLE), "it falls through like a refused copy");
        assert!(why.unwrap().contains("signed resource library could not be read"));
    }

    #[test]
    fn the_signed_copy_wins_over_the_shipped_one() {
        let dir = tempfile::tempdir().unwrap();
        put_signed(dir.path(), SIGNED);
        let (loaded, why) = load(Some(dir.path()), BUNDLE, &sha256_hex(BUNDLE));
        assert_eq!(loaded.unwrap().pin, fact(SIGNED));
        assert_eq!(why, None);
    }

    #[test]
    fn a_shipped_copy_that_differs_from_the_pin_loads_nothing_and_says_so() {
        let (loaded, why) = load(None, BUNDLE, &sha256_hex(SIGNED));
        assert!(loaded.is_none());
        assert!(why.unwrap().contains("shipped resource library was refused"));
    }

    #[test]
    fn a_broken_signed_copy_falls_back_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        put_signed(dir.path(), b"not json");
        let (loaded, why) = load(Some(dir.path()), BUNDLE, &sha256_hex(BUNDLE));
        assert_eq!(loaded.unwrap().pin, fact(BUNDLE));
        assert!(why.unwrap().contains("signed"));
    }

    /// The real bundle: the file in the tree is the one the pin names, every
    /// resource in it loads (one bad resource would refuse all), and it is the
    /// uBO set the NOTICE describes.
    #[test]
    fn the_shipped_bundle_matches_its_pin_and_loads_whole() {
        assert_eq!(sha256_hex(SHIPPED), RESOURCE_PIN, "data/ubo-resources.json changed: review it, then update the pin and the NOTICE");
        let (loaded, why) = load(None, SHIPPED, RESOURCE_PIN);
        assert_eq!(why, None);
        let bundle = loaded.unwrap().bundle;
        let names: Vec<serde_json::Value> = serde_json::from_slice(SHIPPED).unwrap();
        assert_eq!(names.len(), 200, "uBO 1.76.6: 200 resources");
        for id in [
            "json-prune.js",
            "json-prune-fetch-response.js",
            "json-prune-xhr-response.js",
            "set-constant.js",
            "set.js",
            "trusted-replace-fetch-response.js",
            "trusted-replace-xhr-response.js",
            "xml-prune.js",
            "m3u-prune.js",
            "abort-on-property-read.js",
            "aopr.js",
            "noop.js",
            "1x1.gif",
            "google-ima.js",
            "noop-vmap1.xml",
        ] {
            assert!(bundle.contains(id), "{id}");
        }
    }

    /// The video site's ad rules as the default lists write them (AdGuard's
    /// lists in their uBO flavour use these scriptlets for the player's ad
    /// placements, its mid-roll markers and its ad requests). Each must find its
    /// scriptlet in the shipped bundle, or it injects nothing. The rule text here
    /// is representative, not copied from a list, and the site is a reserved
    /// name (no site names in engine source, plan 5.7): the live check proves the lists.
    #[test]
    fn the_video_sites_ad_scriptlets_resolve_in_the_shipped_bundle() {
        let list = "\
video.example##+js(set-constant, ytInitialPlayerResponse.adPlacements, undefined)
video.example##+js(set-constant, ytInitialPlayerResponse.playerAds, undefined)
video.example##+js(json-prune, playerResponse.adPlacements playerResponse.playerAds playerResponse.adSlots adPlacements playerAds adSlots)
video.example##+js(json-prune-fetch-response, playerAds adPlacements adSlots, , propsToMatch, /\\/(player|get_watch)\\?/)
video.example##+js(json-prune-xhr-response, playerAds adPlacements adSlots, , propsToMatch, /\\/player\\?/)
video.example##+js(trusted-replace-fetch-response, /\"adPlacements.*?\"\\}\\}\\}\\],/, , player?)
video.example##+js(xml-prune, xpath(//*[name()=\"Period\"][.//*[@value=\"Ad\"]]), , .mpd)
";
        const WATCH: &str = "https://www.video.example/watch?v=sieve";
        let mut engine = RuleEngine::compile(&[ListText { id: "adguard-base", text: list, trusted: true }]);
        engine.use_resources(&load_bundle(SHIPPED, RESOURCE_PIN).unwrap());
        let scriptlets = engine.page_cosmetics(WATCH).scriptlets;
        for name in ["setConstant", "jsonPrune", "jsonPruneFetchResponse", "jsonPruneXhrResponse", "trustedReplaceFetchResponse", "xmlPrune"] {
            assert!(scriptlets.contains(name), "{name} missing from the page's scriptlets");
        }
        let elsewhere = engine.page_cosmetics("https://other.example/").scriptlets;
        assert!(!elsewhere.contains("jsonPrune"), "only the video site gets them");

        let mut untrusted = RuleEngine::compile(&[ListText { id: "own", text: list, trusted: false }]);
        untrusted.use_resources(&load_bundle(SHIPPED, RESOURCE_PIN).unwrap());
        let s = untrusted.page_cosmetics(WATCH).scriptlets;
        assert!(s.contains("jsonPrune") && !s.contains("trustedReplaceFetchResponse"), "a list that is not trusted gets no trusted scriptlet");
    }
}
