//! The filter lists Sieve knows (plan 5.4). Every list is downloaded at run
//! time by the engine and never vendored or bundled; this table only names
//! them.
//!
//! Trusted scriptlets (the permissioned `trusted-*` resources and
//! `prevent-clipboard-write`) run only from a list its [`Author`] makes
//! trusted: the uBO team's own lists (uAssets) and the AdGuard team's own
//! filters. The owner's decision of 2026-11-20
//! (docs/tasks/2026-11-06-open-decisions.md): a row is marked by who writes
//! it, not by where it is served, so a third-party list mirrored on AdGuard's
//! servers (EasyList, EasyPrivacy, regional community lists) is untrusted.
//!
//! Each row says what it is for (`kind`) and the lowest protection level that
//! turns it on (`level`). The app's profiles are derived from the levels, and a
//! row's default is derived from its level too ([`Level::default_of`]), so the
//! recommended profile and the engine's defaults are one fact, not two.

/// Whether a list is on before the user changes anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Default {
    On,
    Off,
    /// Off until a named slice's live acceptance turns it on with numbers.
    Gated(&'static str),
}

/// What a list is for: how the app groups it and says what it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ads,
    Tracking,
    Annoyances,
    /// Sites known for scams and malware (parity row 33, browsing security).
    Security,
    /// Ads on sites in a language; `languages` says which.
    Language,
}

/// The protection levels, in order: a list is on at its own level and every
/// stricter one. `Optional` is no level: the user adds it by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Minimal,
    Balanced,
    Strict,
    Optional,
}

/// The recommended level: what a person gets who changes nothing.
pub const RECOMMENDED: Level = Level::Balanced;

impl Level {
    /// A row's default, derived: on exactly when the recommended level includes it.
    pub const fn default_of(self) -> Default {
        match self {
            Level::Minimal | Level::Balanced => Default::On,
            Level::Strict | Level::Optional => Default::Off,
        }
    }
}

/// Who writes a list's rules, whoever hosts the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Author {
    /// The AdGuard team's own filters.
    Adguard,
    /// The uBlock Origin team's own lists (uAssets).
    Ubo,
    /// Anyone else, including a third-party list AdGuard's servers mirror.
    ThirdParty,
}

impl Author {
    /// Only the two teams that write the trusted scriptlets may use them.
    pub const fn trusted(self) -> bool {
        matches!(self, Author::Adguard | Author::Ubo)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct List {
    /// Stable id, used in settings and in the rule provenance map.
    pub id: &'static str,
    pub title: &'static str,
    pub url: &'static str,
    /// SPDX expression of the list's own licence.
    pub licence: &'static str,
    pub default: Default,
    /// Who writes the list; its trust follows ([`List::trusted`]).
    pub author: Author,
    /// The list's public project page; a report's issue page derives from it (plan 8.4).
    pub homepage: &'static str,
    pub kind: Kind,
    pub level: Level,
    /// What turning it on does, in plain words.
    pub description: &'static str,
    /// Primary language subtags (BCP 47) of the sites it is for; empty for every site.
    pub languages: &'static [&'static str],
}

impl List {
    /// May this list's rules run trusted scriptlets? Derived from its author.
    pub const fn trusted(&self) -> bool {
        self.author.trusted()
    }
}

const ADGUARD_HOME: &str = "https://github.com/AdguardTeam/AdguardFilters";
const UASSETS_HOME: &str = "https://github.com/uBlockOrigin/uAssets";

macro_rules! adguard {
    ($id:literal, $title:literal, $n:literal, $kind:ident, $level:ident, $languages:expr, $description:literal) => {
        List {
            id: $id,
            title: $title,
            url: concat!("https://filters.adtidy.org/extension/ublock/filters/", $n, ".txt"),
            licence: "GPL-3.0-only",
            default: Level::$level.default_of(),
            author: Author::Adguard,
            homepage: ADGUARD_HOME,
            kind: Kind::$kind,
            level: Level::$level,
            description: $description,
            languages: $languages,
        }
    };
}

macro_rules! uassets {
    ($id:literal, $title:literal, $file:literal, $kind:ident, $level:ident, $default:expr, $description:literal) => {
        List {
            id: $id,
            title: $title,
            url: concat!("https://ublockorigin.github.io/uAssets/filters/", $file),
            licence: "GPL-3.0-only",
            default: $default,
            author: Author::Ubo,
            homepage: UASSETS_HOME,
            kind: Kind::$kind,
            level: Level::$level,
            description: $description,
            languages: &[],
        }
    };
}

/// Every known list, in display order.
pub const LISTS: &[List] = &[
    adguard!("adguard-base", "AdGuard Base filter", "2", Ads, Minimal, &[], "Removes ads on most websites."),
    adguard!("adguard-tracking", "AdGuard Tracking Protection", "3", Tracking, Balanced, &[], "Blocks trackers and analytics that follow you from site to site."),
    adguard!("adguard-url-tracking", "AdGuard URL Tracking", "17", Tracking, Balanced, &[], "Removes tracking codes from the links you open. Works only inside decrypted HTTPS traffic."),
    List {
        id: "adguard-dns",
        title: "AdGuard DNS filter",
        url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        licence: "GPL-3.0-only",
        default: Level::Minimal.default_of(),
        author: Author::Adguard,
        homepage: "https://github.com/AdguardTeam/AdGuardSDNSFilter",
        kind: Kind::Ads,
        level: Level::Minimal,
        description: "Blocks ad and tracker servers by name, for every app, not only the browser.",
        languages: &[],
    },
    adguard!("adguard-social", "AdGuard Social Media filter", "4", Tracking, Strict, &[], "Removes share buttons and social widgets that report the pages you read."),
    uassets!("ubo-badware", "uBlock filters: Badware risks", "badware.txt", Security, Balanced, Level::Balanced.default_of(), "Blocks sites known for scams, fake downloads and malware."),
    // On at every level since 2026-11-22 (docs/tasks/2026-11-06-open-decisions.md):
    // slice 10's two arms ran in run 9 and only the arm with these lists kept
    // the video site clean (10 of 10 in Chrome and Edge, also after autoplay). They are
    // ad lists, so Minimal has them too, and a stored Minimal still reads Minimal.
    uassets!("ubo-filters", "uBlock filters", "filters.txt", Ads, Minimal, Level::Minimal.default_of(), "uBlock Origin's own ad list."),
    uassets!("ubo-quick-fixes", "uBlock filters: Quick fixes", "quick-fixes.txt", Ads, Minimal, Level::Minimal.default_of(), "Quick repairs for sites the uBlock lists affect."),
    uassets!("ubo-unbreak", "uBlock filters: Unbreak", "unbreak.txt", Ads, Minimal, Level::Minimal.default_of(), "Exceptions that keep sites working with the uBlock lists."),
    adguard!("adguard-cookies", "AdGuard Annoyances: cookie notices", "18", Annoyances, Strict, &[], "Hides cookie consent banners."),
    adguard!("adguard-popups", "AdGuard Annoyances: popups", "19", Annoyances, Strict, &[], "Blocks pop-ups and newsletter prompts."),
    adguard!("adguard-mobile", "AdGuard Annoyances: mobile app banners", "20", Annoyances, Strict, &[], "Hides banners asking you to install a site's app."),
    adguard!("adguard-other", "AdGuard Annoyances: other", "21", Annoyances, Strict, &[], "Hides other distractions that fit none of the groups above."),
    adguard!("adguard-widgets", "AdGuard Annoyances: widgets", "22", Annoyances, Strict, &[], "Hides chat bubbles, support boxes and similar widgets."),
    adguard!("adguard-chinese", "AdGuard Chinese filter", "224", Language, Optional, &["zh"], "Removes ads on Chinese-language sites."),
    adguard!("adguard-dutch", "AdGuard Dutch filter", "8", Language, Optional, &["nl"], "Removes ads on Dutch-language sites."),
    adguard!("adguard-french", "AdGuard French filter", "16", Language, Optional, &["fr"], "Removes ads on French-language sites."),
    adguard!("adguard-german", "AdGuard German filter", "6", Language, Optional, &["de"], "Removes ads on German-language sites."),
    adguard!("adguard-japanese", "AdGuard Japanese filter", "7", Language, Optional, &["ja"], "Removes ads on Japanese-language sites."),
    adguard!("adguard-russian", "AdGuard Russian filter", "1", Language, Optional, &["ru"], "Removes ads on Russian-language sites."),
    adguard!("adguard-spanish", "AdGuard Spanish/Portuguese filter", "9", Language, Optional, &["es", "pt"], "Removes ads on Spanish and Portuguese-language sites."),
    adguard!("adguard-turkish", "AdGuard Turkish filter", "13", Language, Optional, &["tr"], "Removes ads on Turkish-language sites."),
    adguard!("adguard-ukrainian", "AdGuard Ukrainian filter", "23", Language, Optional, &["uk"], "Removes ads on Ukrainian-language sites."),
];

/// The list with this id.
pub fn find(id: &str) -> Option<&'static List> {
    LISTS.iter().find(|l| l.id == id)
}

/// The lists that are on with no user choice.
pub fn defaults_on() -> impl Iterator<Item = &'static List> {
    LISTS.iter().filter(|l| l.default == Default::On)
}

/// The lists the user's choice names, in catalogue order; None means the
/// defaults. An id no catalogue row has (an older or newer app, or one of the
/// user's own lists) is ignored here.
pub fn selected(ids: Option<&[String]>) -> Vec<&'static List> {
    match ids {
        None => defaults_on().collect(),
        Some(ids) => LISTS.iter().filter(|l| ids.iter().any(|id| id == l.id)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn none_selects_the_catalogue_defaults() {
        let ids: Vec<_> = selected(None).iter().map(|l| l.id).collect();
        assert_eq!(ids, defaults_on().map(|l| l.id).collect::<Vec<_>>());
    }

    #[test]
    fn only_selected_lists_are_named_in_catalogue_order() {
        let ids = ["adguard-cookies".to_string(), "nope".to_string(), "adguard-dns".to_string()];
        let got: Vec<_> = selected(Some(&ids)).iter().map(|l| l.id).collect();
        assert_eq!(got, ["adguard-dns", "adguard-cookies"]);
        assert!(selected(Some(&[])).is_empty(), "the user turned every list off");
    }

    const ADGUARD_UBO: &str = "https://filters.adtidy.org/extension/ublock/filters/";
    const UASSETS: &str = "https://ublockorigin.github.io/uAssets/filters/";

    #[test]
    fn ids_and_urls_are_unique_and_https_on_known_hosts() {
        let ids: HashSet<_> = LISTS.iter().map(|l| l.id).collect();
        let urls: HashSet<_> = LISTS.iter().map(|l| l.url).collect();
        assert_eq!((ids.len(), urls.len()), (LISTS.len(), LISTS.len()));
        for l in LISTS {
            assert!(l.url.starts_with("https://"), "{}", l.id);
            assert!(l.url.ends_with(".txt"), "{}", l.id);
            assert_eq!(l.licence, "GPL-3.0-only", "{}", l.id);
            // A custom list's id starts `custom-`; no catalogue row may take that shape.
            assert!(!l.id.starts_with("custom-"), "{}", l.id);
        }
        assert!(LISTS.iter().filter(|l| l.url.starts_with(ADGUARD_UBO)).count() >= 3);
        assert_eq!(LISTS.iter().filter(|l| l.url.starts_with(UASSETS)).count(), 4);
    }

    /// The app derives the issue page from this, and may open only these owners
    /// (src-tauri/capabilities/default.json).
    #[test]
    fn every_homepage_is_https_on_an_owner_the_app_may_open() {
        for l in LISTS {
            assert!(
                l.homepage.starts_with("https://github.com/AdguardTeam/") || l.homepage.starts_with("https://github.com/uBlockOrigin/"),
                "{}",
                l.id
            );
            assert!(!l.homepage.ends_with('/'), "{}", l.id);
        }
        assert_eq!(find("adguard-base").map(|l| l.homepage), Some(ADGUARD_HOME));
        assert_eq!(find("ubo-filters").map(|l| l.homepage), Some(UASSETS_HOME));
    }

    /// The owner's rule of 2026-11-20: trust follows the author. Every trusted
    /// row is written by the uBO or the AdGuard team, and its author agrees with
    /// its project page (the URL's host is not the test: AdGuard's servers also
    /// mirror third-party lists).
    #[test]
    fn every_trusted_row_is_written_by_the_ubo_or_adguard_team() {
        for l in LISTS {
            assert_eq!(l.trusted(), matches!(l.author, Author::Adguard | Author::Ubo), "{}", l.id);
            match l.author {
                Author::Adguard => assert!(l.homepage.starts_with("https://github.com/AdguardTeam/"), "{}", l.id),
                Author::Ubo => assert_eq!(l.homepage, UASSETS_HOME, "{}", l.id),
                Author::ThirdParty => assert!(!l.trusted(), "{}", l.id),
            }
        }
        assert!(!Author::ThirdParty.trusted());
    }

    /// A third-party list, even one served from AdGuard's own mirror, compiles
    /// as untrusted: its trusted scriptlet injects nothing, while the same rule
    /// from an AdGuard-authored row runs.
    #[test]
    fn a_third_party_list_cannot_run_a_trusted_scriptlet() {
        use crate::resources::{load_bundle, sha256_hex};
        use crate::rules::{ListText, RuleEngine};
        const FIXTURE: &[u8] = include_bytes!("../testdata/resources-fixture.json");
        const RULE: &str = "sieve-test.invalid##+js(trusted-sieve-flag, a)\n";
        const URL: &str = "https://sieve-test.invalid/";
        let mirrored = List {
            id: "third-party-mirror",
            title: "A community list",
            url: concat!("https://filters.adtidy.org/extension/ublock/filters/", "101", ".txt"),
            author: Author::ThirdParty,
            ..*find("adguard-base").unwrap()
        };
        let scriptlets = |row: &List| {
            let mut engine = RuleEngine::compile(&[ListText { id: row.id, text: RULE, trusted: row.trusted() }]);
            engine.use_resources(&load_bundle(FIXTURE, &sha256_hex(FIXTURE)).unwrap());
            engine.page_cosmetics(URL).scriptlets
        };
        assert!(scriptlets(&mirrored).is_empty(), "a third-party list gets no trusted scriptlet");
        assert!(scriptlets(find("adguard-base").unwrap()).contains("sieveTrustedFlag"), "the control: AdGuard's own list does");
        assert!(scriptlets(find("ubo-filters").unwrap()).contains("sieveTrustedFlag"), "and uBO's own list does");
    }

    /// The plan table, with the owner's decision of 2026-11-22: slice 10's uBO
    /// arm was the only one that passed, so the uBO lists are on by default.
    #[test]
    fn defaults_follow_the_plan_table() {
        let on: Vec<_> = defaults_on().map(|l| l.id).collect();
        assert_eq!(on, ["adguard-base", "adguard-tracking", "adguard-url-tracking", "adguard-dns", "ubo-badware", "ubo-filters", "ubo-quick-fixes", "ubo-unbreak"]);
        let minimal: Vec<_> = LISTS.iter().filter(|l| l.level == Level::Minimal).map(|l| l.id).collect();
        assert_eq!(minimal, ["adguard-base", "adguard-dns", "ubo-filters", "ubo-quick-fixes", "ubo-unbreak"], "the uBO ad lists are in every level");
        assert!(LISTS.iter().filter(|l| l.id.starts_with("ubo-")).all(|l| l.trusted() && l.author == Author::Ubo), "uBO's own lists, trusted by author");
        assert!(LISTS.iter().all(|l| !matches!(l.default, Default::Gated(_))), "nothing waits on a live check now");
        assert_eq!(find("adguard-cookies").map(|l| l.default), Some(Default::Off));
        assert_eq!(find("nope"), None);
    }

    /// On by default is not forced: the user's own choice may leave them out.
    #[test]
    fn the_ubo_lists_can_be_left_out() {
        let ids: Vec<String> = defaults_on().filter(|l| !l.id.starts_with("ubo-")).map(|l| l.id.to_string()).collect();
        let got: Vec<_> = selected(Some(&ids)).iter().map(|l| l.id).collect();
        assert_eq!(got, ["adguard-base", "adguard-tracking", "adguard-url-tracking", "adguard-dns"]);
    }

    /// One fact, two readers: the engine's defaults are the recommended level.
    #[test]
    fn the_defaults_are_exactly_the_recommended_level() {
        for l in LISTS {
            match l.default {
                Default::Gated(_) => assert_eq!(l.level, Level::Optional, "a gated row is in no level: {}", l.id),
                d => assert_eq!(d == Default::On, l.level <= RECOMMENDED, "{}", l.id),
            }
        }
    }

    /// Each level adds a list to the one below, so no two levels select the same
    /// lists and the app can always tell which one is in force.
    #[test]
    fn every_level_adds_at_least_one_list() {
        for level in [Level::Minimal, Level::Balanced, Level::Strict] {
            assert!(LISTS.iter().any(|l| l.level == level && !matches!(l.default, Default::Gated(_))), "{level:?}");
        }
    }

    #[test]
    fn languages_are_exactly_on_the_language_rows_and_every_row_says_what_it_does() {
        for l in LISTS {
            assert_eq!(!l.languages.is_empty(), l.kind == Kind::Language, "{}", l.id);
            assert!(l.kind != Kind::Language || l.level == Level::Optional, "a language row belongs to no level: {}", l.id);
            assert!(l.description.ends_with('.') && l.description.len() < 120, "{}", l.id);
            for lang in l.languages {
                assert!(lang.len() == 2 && lang.chars().all(|c| c.is_ascii_lowercase()), "{}: {lang}", l.id);
            }
        }
        assert!(LISTS.iter().any(|l| l.kind == Kind::Security && l.default == Default::On), "browsing security is on by default");
    }
}
