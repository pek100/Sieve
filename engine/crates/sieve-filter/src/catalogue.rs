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
}

const UBO_SLICE: &str = "slice 10 (YouTube acceptance, two arms)";

macro_rules! adguard {
    ($id:literal, $title:literal, $n:literal, $default:expr) => {
        List {
            id: $id,
            title: $title,
            url: concat!("https://filters.adtidy.org/extension/ublock/filters/", $n, ".txt"),
            licence: "GPL-3.0-only",
            default: $default,
            trusted: true,
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

/// The lists the user's choice names, in catalogue order; None means the
/// defaults. An id no catalogue row has (an older or newer app) is ignored.
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
        }
        assert!(LISTS.iter().filter(|l| l.url.starts_with(ADGUARD_UBO)).count() >= 3);
        assert!(LISTS.iter().filter(|l| l.url.starts_with(UASSETS)).count() == 3);
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
