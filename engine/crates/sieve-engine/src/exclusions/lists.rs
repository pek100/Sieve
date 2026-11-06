//! Which lists feed the store (task D7). Sources are data, and the user's
//! decision is the default: Sieve's own `sensitive` list decides, seeded at
//! build time and replaced by a signed update when one is on disk. AdGuard's
//! HttpsExclusions files are built and tested behind `enabled: false` until the
//! user answers Q1, so turning them on is one word here.
//!
//! A tampered list can only add pass-through (plan 4.1).

use std::path::Path;

use sieve_filter::exclusions::{Exclusion, parse};
use sieve_filter::lists::{Applied, FetchState};

use crate::lists::Fetcher;
use crate::lists::cache::Cache;
use crate::update::{self, Kind};

/// Plan 4.2: every 24 h with `If-None-Match`.
pub const REFRESH_MS: u64 = 24 * 3_600_000;
/// The folder name prefix keeps these copies apart from the filter lists' cache.
const CACHE_PREFIX: &str = "https-";
const HTTPS_EXCLUSIONS: &str = "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/";

/// Where a source's text comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Compiled in, replaced by the signed copy of this list when present.
    Seed(&'static str),
    /// Fetched at run time, never vendored (plan 4.2).
    Fetched(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source {
    /// The reason's slug is `list:<id>`.
    pub id: &'static str,
    pub origin: Origin,
    pub enabled: bool,
}

/// The file name of a signed list and of its seed.
const OWN_LIST: &str = "sensitive";
const SEED: &str = include_str!("../../../sieve-filter/data/sensitive.txt");

macro_rules! https_exclusions {
    ($($id:literal),*) => { [$(Source { id: concat!("hx-", $id), origin: Origin::Fetched(concat!($id, ".txt")), enabled: false }),*] };
}

const OWN: [Source; 1] = [Source { id: OWN_LIST, origin: Origin::Seed(SEED), enabled: true }];
const FETCHED: [Source; 5] = https_exclusions!("banks", "sensitive", "issues", "windows", "firefox");

/// Every source, in the order a flow's reason prefers them.
pub fn sources() -> Vec<Source> {
    OWN.into_iter().chain(FETCHED).collect()
}

/// A source's text once loaded.
pub fn entries_of(text: &str) -> Vec<Exclusion> {
    parse(text).entries
}

/// A seed's entries, from the signed copy when one is on disk and parses to
/// at least one entry. A broken copy keeps the seed: an empty list here would
/// mean every sensitive site is decrypted.
pub fn seed_entries(engine_dir: Option<&Path>, id: &str, seed: &str) -> Vec<Exclusion> {
    let signed = engine_dir
        .and_then(|dir| update::data_path(dir, &Kind::List(id.to_string())))
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|text| entries_of(&text))
        .filter(|entries| !entries.is_empty());
    signed.unwrap_or_else(|| entries_of(seed))
}

fn url_of(file: &str) -> String {
    format!("{HTTPS_EXCLUSIONS}{file}")
}

/// One fetched source's cached copy: the last good one, if any.
pub fn cached_entries(cache: &Cache, id: &str) -> Option<Vec<Exclusion>> {
    cache.read_text(&format!("{CACHE_PREFIX}{id}")).map(|text| entries_of(&text))
}

/// One look at one fetched source (24 h, conditional). True when a new copy
/// replaced the old. A failure keeps the copy and only records the time.
pub async fn fetch_one<F: Fetcher>(cache: &Cache, id: &str, file: &str, fetcher: &F, now_ms: u64) -> bool {
    let name = format!("{CACHE_PREFIX}{id}");
    let mut state: FetchState = cache.read_state(&name);
    let fresh = state.fetched_at_ms.is_some_and(|at| now_ms < at.saturating_add(REFRESH_MS));
    let retry_later = state.failed_at_ms.is_some() && !state.is_due(now_ms);
    if fresh || retry_later {
        return false;
    }
    let replaced = match fetcher.fetch(&url_of(file), state.conditional_headers()).await {
        Ok(response) => {
            let mut next = state.clone();
            let written = match next.apply(response, now_ms) {
                Applied::Replaced(text) => cache.write_text(&name, &text).map(|()| true),
                Applied::NotModified | Applied::Refused => Ok(false),
            };
            match written {
                Ok(wrote) => {
                    state = next;
                    wrote
                }
                Err(why) => {
                    state.failed(why, now_ms);
                    false
                }
            }
        }
        Err(why) => {
            state.failed(why, now_ms);
            false
        }
    };
    // Lost on a full disk: the next start only asks again.
    let _ = cache.write_state(&name, &state);
    replaced
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::Mutex;

    use sieve_filter::lists::FetchResponse;

    use super::*;

    type Headers = Vec<(&'static str, String)>;

    #[derive(Default)]
    struct FakeFetcher {
        answers: Mutex<Vec<Result<FetchResponse, String>>>,
        asked: Mutex<Vec<(String, Headers)>>,
    }

    impl Fetcher for FakeFetcher {
        fn fetch(&self, url: &str, headers: Vec<(&'static str, String)>) -> impl Future<Output = Result<FetchResponse, String>> + Send {
            self.asked.lock().unwrap().push((url.to_string(), headers));
            let answer = self.answers.lock().unwrap().remove(0);
            async move { answer }
        }
    }

    const NOW: u64 = 1_793_000_000_000;

    fn ok(body: &str) -> Result<FetchResponse, String> {
        Ok(FetchResponse { status: 200, etag: Some("\"v1\"".into()), body: body.as_bytes().to_vec(), ..FetchResponse::default() })
    }

    #[test]
    fn the_seed_parses_with_nothing_skipped() {
        let parsed = parse(SEED);
        assert!(parsed.skipped.is_empty(), "{:?}", parsed.skipped);
        assert!(!parsed.entries.is_empty());
    }

    #[test]
    fn signed_copy_replaces_the_seed() {
        let dir = tempfile::tempdir().unwrap();
        let path = update::data_path(dir.path(), &Kind::List(OWN_LIST.into())).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "signed.example\n").unwrap();
        let entries = seed_entries(Some(dir.path()), OWN_LIST, SEED);
        assert_eq!(entries, parse("signed.example").entries);
    }

    #[test]
    fn broken_signed_copy_keeps_the_seed() {
        let dir = tempfile::tempdir().unwrap();
        let path = update::data_path(dir.path(), &Kind::List(OWN_LIST.into())).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        for broken in [&b"\xff\xfe not text"[..], b"", b"// only a comment\nbad host.example\n"] {
            std::fs::write(&path, broken).unwrap();
            assert_eq!(seed_entries(Some(dir.path()), OWN_LIST, SEED), parse(SEED).entries);
        }
        assert_eq!(seed_entries(None, OWN_LIST, SEED), parse(SEED).entries, "no folder");
    }

    #[tokio::test]
    async fn https_exclusions_source_fetches_conditionally_and_keeps_the_last_good_copy() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path());
        let f = FakeFetcher::default();
        *f.answers.lock().unwrap() = vec![
            ok("bank.example\n"),
            Ok(FetchResponse { status: 304, ..FetchResponse::default() }),
            Err("no network".into()),
            Ok(FetchResponse { status: 200, body: b"<html>not a list".to_vec(), ..FetchResponse::default() }),
        ];
        assert!(fetch_one(&cache, "hx-banks", "banks.txt", &f, NOW).await, "the first copy");
        assert_eq!(cached_entries(&cache, "hx-banks").unwrap(), parse("bank.example").entries);
        assert!(!fetch_one(&cache, "hx-banks", "banks.txt", &f, NOW + 1_000).await, "within 24 h nothing is asked");
        assert_eq!(f.asked.lock().unwrap().len(), 1);
        let day = NOW + REFRESH_MS;
        assert!(!fetch_one(&cache, "hx-banks", "banks.txt", &f, day).await, "not modified");
        {
            let asked = f.asked.lock().unwrap();
            assert!(asked[1].0.ends_with("/exclusions/banks.txt"));
            assert_eq!(asked[1].1, [("If-None-Match", "\"v1\"".to_string())]);
        }
        assert!(!fetch_one(&cache, "hx-banks", "banks.txt", &f, day + REFRESH_MS).await, "a failure");
        assert_eq!(cached_entries(&cache, "hx-banks").unwrap(), parse("bank.example").entries, "the last good copy stays");
        assert!(!fetch_one(&cache, "hx-banks", "banks.txt", &f, day + 2 * REFRESH_MS).await, "a page that is not a list");
        assert_eq!(cached_entries(&cache, "hx-banks").unwrap(), parse("bank.example").entries);
    }

    #[test]
    fn the_decided_defaults_are_our_own_list_alone() {
        let on: Vec<&str> = sources().iter().filter(|s| s.enabled).map(|s| s.id).collect();
        assert_eq!(on, [OWN_LIST], "the user's decision: AdGuard's list is not used");
        assert_eq!(sources().iter().filter(|s| matches!(s.origin, Origin::Fetched(_))).count(), 5);
    }
}
