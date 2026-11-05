//! The filter lists Sieve knows (plan 5.4). Every list is downloaded at run
//! time by the engine and never vendored or bundled; this table only names
//! them. `trusted` lists may use `trusted-*` scriptlets (uBO's own rule:
//! only the lists of the projects that write those scriptlets).

/// Whether a list is on before the user changes anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Default {
    On,
    Off,
    /// Off until a named slice's live acceptance turns it on with numbers.
    Gated(&'static str),
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
    pub trusted: bool,
    /// The list's public project page; a report's issue page derives from it (plan 8.4).
    pub homepage: &'static str,
}

const UBO_SLICE: &str = "slice 10 (YouTube acceptance, two arms)";
const ADGUARD_HOME: &str = "https://github.com/AdguardTeam/AdguardFilters";
const UASSETS_HOME: &str = "https://github.com/uBlockOrigin/uAssets";

macro_rules! adguard {
    ($id:literal, $title:literal, $n:literal, $default:expr) => {
        List {
            id: $id,
            title: $title,
            url: concat!("https://filters.adtidy.org/extension/ublock/filters/", $n, ".txt"),
            licence: "GPL-3.0-only",
            default: $default,
            trusted: true,
            homepage: ADGUARD_HOME,
        }
    };
}

macro_rules! uassets {
    ($id:literal, $title:literal, $file:literal, $default:expr) => {
        List {
            id: $id,
            title: $title,
            url: concat!("https://ublockorigin.github.io/uAssets/filters/", $file),
            licence: "GPL-3.0-only",
            default: $default,
            trusted: true,
            homepage: UASSETS_HOME,
        }
    };
}

/// Every known list, in display order.
pub const LISTS: &[List] = &[
    adguard!("adguard-base", "AdGuard Base filter", "2", Default::On),
    adguard!("adguard-tracking", "AdGuard Tracking Protection", "3", Default::On),
    adguard!("adguard-url-tracking", "AdGuard URL Tracking", "17", Default::On),
    List {
        id: "adguard-dns",
        title: "AdGuard DNS filter",
        url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        licence: "GPL-3.0-only",
        default: Default::On,
        trusted: true,
        homepage: "https://github.com/AdguardTeam/AdGuardSDNSFilter",
    },
    uassets!("ubo-filters", "uBlock filters", "filters.txt", Default::Gated(UBO_SLICE)),
    uassets!("ubo-quick-fixes", "uBlock filters: Quick fixes", "quick-fixes.txt", Default::Gated(UBO_SLICE)),
    uassets!("ubo-unbreak", "uBlock filters: Unbreak", "unbreak.txt", Default::Gated(UBO_SLICE)),
    adguard!("adguard-cookies", "AdGuard Annoyances: cookie notices", "18", Default::Off),
    adguard!("adguard-popups", "AdGuard Annoyances: popups", "19", Default::Off),
    adguard!("adguard-mobile", "AdGuard Annoyances: mobile app banners", "20", Default::Off),
    adguard!("adguard-other", "AdGuard Annoyances: other", "21", Default::Off),
    adguard!("adguard-widgets", "AdGuard Annoyances: widgets", "22", Default::Off),
];

/// The list with this id.
pub fn find(id: &str) -> Option<&'static List> {
    LISTS.iter().find(|l| l.id == id)
}

/// The lists that are on with no user choice.
pub fn defaults_on() -> impl Iterator<Item = &'static List> {
    LISTS.iter().filter(|l| l.default == Default::On)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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
        }
        assert!(LISTS.iter().filter(|l| l.url.starts_with(ADGUARD_UBO)).count() >= 3);
        assert!(LISTS.iter().filter(|l| l.url.starts_with(UASSETS)).count() == 3);
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

    #[test]
    fn defaults_follow_the_plan_table() {
        let on: Vec<_> = defaults_on().map(|l| l.id).collect();
        assert_eq!(on, ["adguard-base", "adguard-tracking", "adguard-url-tracking", "adguard-dns"]);
        assert!(LISTS.iter().filter(|l| l.id.starts_with("ubo-")).all(|l| l.default == Default::Gated(UBO_SLICE)));
        assert_eq!(find("adguard-cookies").map(|l| l.default), Some(Default::Off));
        assert_eq!(find("nope"), None);
    }
}
