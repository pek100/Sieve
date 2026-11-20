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
//! places once releases are public (slice 13), and which then wins when it is
//! not older than the shipped one.
//!
//! "Older" reads the one signed fact about a placed copy: its version, which
//! the minisig trusted comment signs (`sieve-update kind=resources version=<n>`)
//! and the update cycle records in `update-state.json` only after placing the
//! file. The bundle's JSON carries no version or date, and a file date can be
//! changed by a copy. A resources version is the uBO tag the bundle was
//! assembled from, as a release number (`1.76.6` is 1_076_006), so the
//! publisher and this build count the same way. A copy with no recorded
//! version (a crash between placing and recording, or an unreadable record)
//! counts as older: the shipped bundle is the safe side.

use std::path::Path;

use sieve_filter::resources::{ResourceBundle, load_bundle, load_signed_bundle, sha256_hex};

use crate::update::state::load_record;
use crate::update::trust::release_number;
use crate::update::{Kind, data_path};

/// SHA-256 of the shipped bundle, `data/ubo-resources.json` (uBlock Origin
/// 1.76.6, assembled by `scripts/resources/assemble-ubo.mjs`).
pub const RESOURCE_PIN: &str = "21dc25d59fe301f5625dd09aaaa48e987e175ded250fa566cc1fb1bf790d066e";
/// The shipped bundle's bytes. Byte-exact in git (`.gitattributes`: `-text`).
pub const SHIPPED: &[u8] = include_bytes!("../../data/ubo-resources.json");
/// The shipped bundle's resources version: its uBO tag, 1.76.6. Changes with the
/// pin and the NOTICE.
pub const SHIPPED_VERSION: u64 = release_number(1, 76, 6);

/// The shipped copy: its bytes, the pin they must hash to, and its version.
#[derive(Clone, Copy)]
pub struct Shipped<'a> {
    pub bytes: &'a [u8],
    pub pin: &'a str,
    pub version: u64,
}

/// The bundle compiled into this engine.
pub const THIS_BUILD: Shipped<'static> = Shipped { bytes: SHIPPED, pin: RESOURCE_PIN, version: SHIPPED_VERSION };

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
/// filtering carries on. A signed copy older than the shipped one is passed
/// over: an engine update must not be undone by an earlier bundle.
pub fn load(engine_dir: Option<&Path>, shipped: Shipped<'_>) -> (Option<Loaded>, Option<String>) {
    let mut refused = None;
    let copy = engine_dir.and_then(|d| data_path(d, &Kind::Resources).map(|p| (d, p)));
    match copy.map_or(Ok(None), |(d, p)| read_copy(&p, "signed").map(|bytes| bytes.map(|b| (d, b)))) {
        Ok(Some((dir, bytes))) => match signed_version(dir) {
            Some(version) if version >= shipped.version => match load_signed_bundle(&bytes) {
                Ok(bundle) => return (Some(Loaded { bundle, pin: fact(&bytes) }), None),
                Err(why) => refused = Some(format!("the signed resource library was refused: {why}")),
            },
            // An engine update that ships a newer bundle leaves the last signed
            // copy behind: passing it over is the expected case, not a fault, so
            // nothing is said. The Status's resource pin names the copy in use.
            Some(_) => {}
            None => refused = Some("the signed resource library has no recorded version, so the shipped one is used".to_string()),
        },
        Ok(None) => {}
        Err(why) => refused = Some(why),
    }
    match load_bundle(shipped.bytes, shipped.pin) {
        Ok(bundle) => (Some(Loaded { bundle, pin: fact(shipped.bytes) }), refused),
        Err(why) => {
            let shipped_why = format!("the shipped resource library was refused: {why}");
            (None, Some(refused.map_or(shipped_why.clone(), |r| format!("{r}; {shipped_why}"))))
        }
    }
}

/// The signed version the update cycle recorded for the placed copy; None when
/// there is none or the record cannot be read.
fn signed_version(engine_dir: &Path) -> Option<u64> {
    load_record(engine_dir).ok()?.versions.get(&Kind::Resources.to_string()).copied()
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

    /// The fixture as the shipped copy, at uBO 1.76.6.
    fn shipped(pin: &str) -> Shipped<'_> {
        Shipped { bytes: BUNDLE, pin, version: release_number(1, 76, 6) }
    }

    /// Places a signed copy as the update cycle does: the file, then its signed
    /// version in the record (None: the record never got it).
    fn put_signed(dir: &Path, bytes: &[u8], version: Option<u64>) {
        let path = data_path(dir, &Kind::Resources).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
        if let Some(v) = version {
            let mut record = crate::update::state::Record::default();
            record.versions.insert(Kind::Resources.to_string(), v);
            crate::update::state::save_record(dir, &record).unwrap();
        }
    }

    #[test]
    fn with_nothing_on_disk_the_shipped_copy_loads() {
        let dir = tempfile::tempdir().unwrap();
        let pin = sha256_hex(BUNDLE);
        let (loaded, why) = load(Some(dir.path()), shipped(&pin));
        assert_eq!(loaded.unwrap().pin, fact(BUNDLE));
        assert_eq!(why, None);
        let (loaded, why) = load(None, shipped(&pin));
        assert_eq!(loaded.unwrap().pin, fact(BUNDLE), "no engine folder: the shipped copy still loads");
        assert_eq!(why, None);
    }

    #[test]
    fn a_copy_that_cannot_be_read_is_said_and_not_taken_for_absence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(data_path(dir.path(), &Kind::Resources).unwrap()).unwrap();
        let (loaded, why) = load(Some(dir.path()), shipped(&sha256_hex(BUNDLE)));
        assert_eq!(loaded.unwrap().pin, fact(BUNDLE), "it falls through like a refused copy");
        assert!(why.unwrap().contains("signed resource library could not be read"));
    }

    #[test]
    fn a_signed_copy_as_new_or_newer_wins_over_the_shipped_one() {
        for version in [release_number(1, 76, 6), release_number(1, 77, 0)] {
            let dir = tempfile::tempdir().unwrap();
            put_signed(dir.path(), SIGNED, Some(version));
            let (loaded, why) = load(Some(dir.path()), shipped(&sha256_hex(BUNDLE)));
            assert_eq!(loaded.unwrap().pin, fact(SIGNED), "{version}");
            assert_eq!(why, None);
        }
    }

    /// The review's case: the engine updated to a newer shipped bundle, and the
    /// signed copy an earlier update placed is still on disk. It must not win.
    #[test]
    fn a_signed_copy_older_than_the_shipped_one_is_passed_over() {
        let dir = tempfile::tempdir().unwrap();
        put_signed(dir.path(), SIGNED, Some(release_number(1, 76, 5)));
        let (loaded, why) = load(Some(dir.path()), shipped(&sha256_hex(BUNDLE)));
        assert_eq!(loaded.unwrap().pin, fact(BUNDLE));
        assert_eq!(why, None, "the expected case after an engine update, not a fault");
    }

    #[test]
    fn a_signed_copy_with_no_recorded_version_is_passed_over_and_said() {
        let dir = tempfile::tempdir().unwrap();
        put_signed(dir.path(), SIGNED, None);
        let (loaded, why) = load(Some(dir.path()), shipped(&sha256_hex(BUNDLE)));
        assert_eq!(loaded.unwrap().pin, fact(BUNDLE));
        assert!(why.unwrap().contains("no recorded version"));
        std::fs::write(dir.path().join(crate::update::state::STATE_FILE), b"not json").unwrap();
        let (loaded, _) = load(Some(dir.path()), shipped(&sha256_hex(BUNDLE)));
        assert_eq!(loaded.unwrap().pin, fact(BUNDLE), "an unreadable record is no version");
    }

    #[test]
    fn a_shipped_copy_that_differs_from_the_pin_loads_nothing_and_says_so() {
        let (loaded, why) = load(None, shipped(&sha256_hex(SIGNED)));
        assert!(loaded.is_none());
        assert!(why.unwrap().contains("shipped resource library was refused"));
    }

    #[test]
    fn a_broken_signed_copy_falls_back_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        put_signed(dir.path(), b"not json", Some(release_number(2, 0, 0)));
        let (loaded, why) = load(Some(dir.path()), shipped(&sha256_hex(BUNDLE)));
        assert_eq!(loaded.unwrap().pin, fact(BUNDLE));
        assert!(why.unwrap().contains("signed"));
    }

    #[test]
    fn this_build_ships_at_its_ubo_tag() {
        assert_eq!(crate::update::trust::display_version(THIS_BUILD.version), "1.76.6");
        assert_eq!((THIS_BUILD.bytes, THIS_BUILD.pin), (SHIPPED, RESOURCE_PIN));
    }

    /// The real bundle: the file in the tree is the one the pin names, every
    /// resource in it loads (one bad resource would refuse all), and it is the
    /// uBO set the NOTICE describes.
    #[test]
    fn the_shipped_bundle_matches_its_pin_and_loads_whole() {
        assert_eq!(sha256_hex(SHIPPED), RESOURCE_PIN, "data/ubo-resources.json changed: review it, then update the pin and the NOTICE");
        let (loaded, why) = load(None, THIS_BUILD);
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

    /// uBO marks `prevent-clipboard-write` as needing trust although its name has
    /// no `trusted-` prefix; the shipped bundle keeps that, so only a trusted
    /// (uBO- or AdGuard-authored) list can run it.
    #[test]
    fn prevent_clipboard_write_needs_a_trusted_list() {
        const URL: &str = "https://site.example/";
        let scriptlets = |trusted: bool| {
            let mut engine = RuleEngine::compile(&[ListText { id: "l", text: "site.example##+js(prevent-clipboard-write)\n", trusted }]);
            engine.use_resources(&load_bundle(SHIPPED, RESOURCE_PIN).unwrap());
            engine.page_cosmetics(URL).scriptlets
        };
        assert!(scriptlets(false).is_empty(), "an untrusted list gets nothing");
        assert!(!scriptlets(true).is_empty(), "the control: a trusted list gets it");
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
