//! The default lists at run time (plan 5.4, D10 to D13 of
//! docs/tasks/2026-11-02-domain-policy.md). `sieve-filter` judges; this module
//! does the I/O: asks a [`Fetcher`], keeps the last good copy on disk, compiles
//! off the hot path and swaps the snapshot.
//!
//! Lists refresh only while routes are up: [`Lists::run`] is started by
//! `bring_up` and aborted by `take_down`, so the switch off means no timer. A
//! missing, broken or uncompiled list means fewer blocks, never a failed
//! connection: flows pass until the first snapshot lands, and a compile that
//! panics keeps the previous snapshot.

pub mod cache;
#[cfg(windows)]
pub mod https;

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sieve_filter::catalogue::{self, LISTS, List};
use sieve_filter::lists::{Applied, FetchResponse, FetchState};
use sieve_filter::rules::{ListReport, ListText, RuleEngine, USER_LIST};
use sieve_ipc::{ListStatus, MAX_LISTED_LINE_BYTES, cap_text};
use tokio::sync::Notify;

use crate::domain::{DomainFilter, FilterSlot};
use crate::policy::wall_ms;
use cache::Cache;

/// One download gets this long, connect and body included. Generous: the
/// largest default list is about 10 MiB and some connections are slow.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(120);
/// The loop looks again at least this often, so a suspended machine or a
/// moved wall clock delays a refresh by no more than this. Plan 6's idle cost:
/// one wake an hour, only while routes are up.
const MAX_SLEEP: Duration = Duration::from_secs(3_600);

/// How a list is downloaded: the real client (`https`), or a fake in tests.
pub trait Fetcher: Send + Sync {
    fn fetch(&self, url: &str, headers: Vec<(&'static str, String)>) -> impl Future<Output = Result<FetchResponse, String>> + Send;
}

type Compile = fn(&[ListText<'_>]) -> RuleEngine;

#[derive(Debug, Default)]
struct Inner {
    selection: Option<Vec<String>>,
    states: HashMap<&'static str, FetchState>,
    compile_ms: Option<u64>,
    compile_error: Option<String>,
}

pub struct Lists {
    cache: Option<Cache>,
    slot: Arc<FilterSlot>,
    compile: Compile,
    inner: Mutex<Inner>,
    force: AtomicBool,
    wake: Notify,
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn counted(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn status_of(id: &str, enabled: bool, state: Option<&FetchState>, report: Option<&ListReport>) -> ListStatus {
    let reasons = report.map(|r| r.skip_reasons.iter().map(|(why, n)| (why.clone(), counted(*n))).collect()).unwrap_or_default();
    ListStatus {
        id: id.to_string(),
        enabled,
        fetched_at_ms: state.and_then(|s| s.fetched_at_ms),
        refresh_s: state.filter(|s| s.fetched_at_ms.is_some()).map(|s| s.refresh.as_secs()),
        last_error: state.and_then(|s| s.last_error.clone()),
        network: report.map_or(0, |r| counted(r.network)),
        cosmetic: report.map_or(0, |r| counted(r.cosmetic)),
        skipped: report.map_or(0, |r| counted(r.skipped)),
        skip_reasons: reasons,
        skipped_exceptions: report.map(|r| r.skipped_exceptions.iter().map(|l| cap_text(l, MAX_LISTED_LINE_BYTES).to_string()).collect()).unwrap_or_default(),
        skipped_exceptions_total: report.map_or(0, |r| counted(r.skipped_exceptions_total)),
    }
}

impl Lists {
    /// `engine_dir` is the state folder; None (tests of the policy alone)
    /// keeps nothing. Saved states are read now, the copies when compiling.
    pub fn new(engine_dir: Option<&Path>, slot: Arc<FilterSlot>, selection: Option<Vec<String>>) -> Self {
        Self::with_compile(engine_dir, slot, selection, RuleEngine::compile)
    }

    fn with_compile(engine_dir: Option<&Path>, slot: Arc<FilterSlot>, selection: Option<Vec<String>>, compile: Compile) -> Self {
        let cache = engine_dir.map(Cache::new);
        let states = cache.as_ref().map(|c| LISTS.iter().map(|l| (l.id, c.read_state(l.id))).collect()).unwrap_or_default();
        Self { cache, slot, compile, inner: Mutex::new(Inner { selection, states, ..Inner::default() }), force: AtomicBool::new(false), wake: Notify::new() }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn selected(&self) -> Vec<&'static List> {
        catalogue::selected(self.inner().selection.as_deref())
    }

    /// The policy's selection changed: fetch and compile what it names now.
    pub fn set_selection(&self, selection: Option<Vec<String>>) {
        let mut inner = self.inner();
        if inner.selection != selection {
            inner.selection = selection;
            self.wake.notify_one();
        }
    }

    /// Every selected list downloads at the next look, whatever its age.
    pub fn refresh_now(&self) {
        self.force.store(true, Ordering::Relaxed);
        self.wake.notify_one();
    }

    /// Why the last compile produced nothing, while that is so.
    pub fn compile_error(&self) -> Option<String> {
        self.inner().compile_error.clone()
    }

    /// The per-list report: every catalogue row, then the user's rules.
    pub fn report(&self) -> (Vec<ListStatus>, Option<u64>) {
        let filter = self.slot.get();
        let selected = self.selected();
        let inner = self.inner();
        let find = |reports: &'_ [ListReport], id: &str| reports.iter().find(|r| r.id == id).cloned();
        let mut rows: Vec<ListStatus> = LISTS
            .iter()
            .map(|l| {
                let enabled = selected.iter().any(|s| s.id == l.id);
                status_of(l.id, enabled, inner.states.get(l.id), find(filter.rules.lists.reports(), l.id).as_ref())
            })
            .collect();
        rows.push(status_of(USER_LIST, true, None, find(filter.rules.user.reports(), USER_LIST).as_ref()));
        (rows, inner.compile_ms)
    }

    /// Asks for every list that is due, in catalogue order. True when a copy
    /// was replaced. A failure keeps the copy and only its time is recorded.
    pub async fn fetch_due<F: Fetcher>(&self, fetcher: &F, now_ms: u64) -> bool {
        let force = self.force.swap(false, Ordering::Relaxed);
        let mut replaced = false;
        for list in self.selected() {
            let mut state = self.inner().states.get(list.id).cloned().unwrap_or_default();
            if !force && !state.is_due(now_ms) {
                continue;
            }
            let answer = tokio::time::timeout(FETCH_TIMEOUT, fetcher.fetch(list.url, state.conditional_headers())).await;
            match answer {
                Ok(Ok(response)) => {
                    // The state describes the copy on disk, so a new one only
                    // counts once it is written.
                    let mut next = state.clone();
                    let written = match (next.apply(response, now_ms), &self.cache) {
                        (Applied::Replaced(text), Some(cache)) => cache.write_text(list.id, &text).map(|()| true),
                        _ => Ok(false),
                    };
                    match written {
                        Ok(wrote) => {
                            state = next;
                            replaced |= wrote;
                        }
                        Err(why) => state.failed(why, now_ms),
                    }
                }
                Ok(Err(why)) => state.failed(why, now_ms),
                Err(_) => state.failed(format!("no answer in {} s", FETCH_TIMEOUT.as_secs()), now_ms),
            }
            if let Some(cache) = &self.cache {
                // Lost on a full disk: the next start only asks again.
                let _ = cache.write_state(list.id, &state);
            }
            self.inner().states.insert(list.id, state);
        }
        replaced
    }

    /// Compiles the selected copies off the runtime and swaps the snapshot. A
    /// compile that panics keeps the previous snapshot and says so. A copy
    /// found corrupt is forgotten, so the next look downloads it.
    pub async fn compile_and_swap(&self) {
        let started = Instant::now();
        let cache = self.cache.clone();
        let compile = self.compile;
        let selected = self.selected();
        let job = tokio::task::spawn_blocking(move || {
            let copies: Vec<(&'static List, Option<String>)> = selected.into_iter().map(|l| (l, cache.as_ref().and_then(|c| c.read_text(l.id)))).collect();
            let texts: Vec<ListText<'_>> = copies.iter().filter_map(|(l, t)| t.as_deref().map(|text| ListText { id: l.id, text, trusted: l.trusted })).collect();
            let engine = compile(&texts);
            let missing: Vec<&'static str> = copies.iter().filter(|(_, t)| t.is_none()).map(|(l, _)| l.id).collect();
            (engine, missing)
        });
        match job.await {
            Ok((engine, missing)) => {
                let engine = Arc::new(engine);
                self.slot.update(|f| DomainFilter::with_lists(f, engine.clone()));
                let mut inner = self.inner();
                inner.compile_ms = Some(millis(started.elapsed()));
                inner.compile_error = None;
                for id in missing {
                    if inner.states.get(id).is_some_and(|s| s.fetched_at_ms.is_some()) {
                        inner.states.insert(id, FetchState::default());
                    }
                }
            }
            Err(e) => self.inner().compile_error = Some(format!("the lists did not compile: {e}")),
        }
    }

    fn next_sleep(&self, now_ms: u64) -> Duration {
        let selected = self.selected();
        let inner = self.inner();
        let next = selected.iter().map(|l| inner.states.get(l.id).map_or(0, FetchState::due_at_ms)).min();
        next.map_or(MAX_SLEEP, |due| Duration::from_millis(due.saturating_sub(now_ms)).min(MAX_SLEEP))
    }

    /// The refresh task, for as long as routes are up.
    pub async fn run<F: Fetcher>(self: Arc<Self>, fetcher: F) {
        self.compile_and_swap().await;
        let mut compiled_for = self.selected();
        loop {
            let replaced = self.fetch_due(&fetcher, wall_ms()).await;
            let selected = self.selected();
            if replaced || selected != compiled_for {
                self.compile_and_swap().await;
                compiled_for = selected;
            }
            tokio::select! {
                () = tokio::time::sleep(self.next_sleep(wall_ms())) => {}
                () = self.wake.notified() => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Flow, Owner};
    use crate::flow::flows::Action;
    use sieve_filter::lists::{MAX_LIST_BYTES, MIN_REFRESH, NO_COPY_RETRY};
    use sieve_filter::rules::RuleSet;
    use sieve_ipc::Policy;
    use std::collections::VecDeque;

    const LIST_A: &str = "adguard-dns";
    const HOUR_MS: u64 = 3_600_000;
    const BODY: &str = "! Expires: 12 hours\n||ads.example^\n";
    const BODY_2: &str = "! Expires: 6 hours\n||other.example^\n";
    const SECOND_DEFAULT: &str = "adguard-base";

    type Answer = Result<FetchResponse, String>;
    type Asked = (String, Vec<(&'static str, String)>);

    /// Answers each URL from a script and records every request.
    #[derive(Default)]
    struct FakeFetcher {
        answers: Mutex<HashMap<String, VecDeque<Answer>>>,
        asked: Mutex<Vec<Asked>>,
        hang: bool,
    }

    impl FakeFetcher {
        fn answering(id: &str, answers: Vec<Answer>) -> Self {
            let fake = Self::default();
            fake.queue(id, answers);
            fake
        }

        fn queue(&self, id: &str, answers: Vec<Answer>) {
            self.answers.lock().unwrap().entry(catalogue::find(id).unwrap().url.to_string()).or_default().extend(answers);
        }

        fn asked_urls(&self) -> Vec<String> {
            self.asked.lock().unwrap().iter().map(|(u, _)| u.clone()).collect()
        }
    }

    impl Fetcher for FakeFetcher {
        async fn fetch(&self, url: &str, headers: Vec<(&'static str, String)>) -> Answer {
            self.asked.lock().unwrap().push((url.to_string(), headers));
            if self.hang {
                std::future::pending::<()>().await;
            }
            self.answers.lock().unwrap().get_mut(url).and_then(VecDeque::pop_front).unwrap_or_else(|| Err("no scripted answer".into()))
        }
    }

    fn ok(body: &str) -> Answer {
        Ok(FetchResponse { status: 200, etag: Some("\"v1\"".into()), last_modified: Some("then".into()), body: body.as_bytes().to_vec(), ..FetchResponse::default() })
    }

    fn slot() -> Arc<FilterSlot> {
        let policy = Policy { sieving: true, ..Policy::default() };
        Arc::new(FilterSlot::new(DomainFilter::new(&policy, RuleSet::empty())))
    }

    fn lists_at(dir: &Path, selection: &[&str]) -> Lists {
        Lists::new(Some(dir), slot(), Some(selection.iter().map(|s| s.to_string()).collect()))
    }

    fn state(l: &Lists, id: &str) -> FetchState {
        l.inner().states.get(id).cloned().unwrap_or_default()
    }

    fn blocks(l: &Lists, host: &str) -> bool {
        let names = Mutex::default();
        let flow = Flow { dns: false, name: Some(host), remote: "192.0.2.1".parse().unwrap(), owner: Owner::Unknown };
        l.slot.get().decide(flow, &names, 0).action == Action::Drop
    }

    #[tokio::test]
    async fn first_download_is_cached_compiled_and_swapped() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[LIST_A]);
        assert!(!blocks(&l, "ads.example"), "flows pass until the first snapshot lands");
        let f = FakeFetcher::answering(LIST_A, vec![ok(BODY)]);
        assert!(l.fetch_due(&f, 1_000).await);
        assert_eq!(Cache::new(dir.path()).read_text(LIST_A).as_deref(), Some(BODY));
        l.compile_and_swap().await;
        assert!(blocks(&l, "x.ads.example"));
        let (rows, compile_ms) = l.report();
        let row = rows.iter().find(|r| r.id == LIST_A).unwrap();
        assert_eq!((row.enabled, row.fetched_at_ms, row.refresh_s, row.network), (true, Some(1_000), Some(12 * 3_600), 1));
        assert!(compile_ms.is_some());
    }

    #[tokio::test]
    async fn not_modified_keeps_the_copy_and_renews_the_time() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[LIST_A]);
        l.fetch_due(&FakeFetcher::answering(LIST_A, vec![ok(BODY)]), 0).await;
        let later = 13 * HOUR_MS;
        let f = FakeFetcher::answering(LIST_A, vec![Ok(FetchResponse { status: 304, ..FetchResponse::default() })]);
        assert!(!l.fetch_due(&f, later).await, "nothing to recompile");
        assert_eq!(state(&l, LIST_A).fetched_at_ms, Some(later));
        assert_eq!(Cache::new(dir.path()).read_text(LIST_A).as_deref(), Some(BODY));
        assert!(!state(&l, LIST_A).is_due(later + 1));
    }

    #[tokio::test(start_paused = true)]
    async fn failed_download_keeps_the_last_good_copy() {
        let dir = tempfile::tempdir().unwrap();
        let bad: Vec<(&str, Answer)> = vec![
            ("500", Ok(FetchResponse { status: 500, ..FetchResponse::default() })),
            ("HTML 200", ok("<!doctype html><html>portal</html>")),
            ("empty", ok("")),
            ("oversized", Ok(FetchResponse { status: 200, body: vec![b'a'; MAX_LIST_BYTES + 1], ..FetchResponse::default() })),
            ("invalid UTF-8", Ok(FetchResponse { status: 200, body: vec![0xff, 0xfe], ..FetchResponse::default() })),
            ("connect error", Err("connect: refused".into())),
        ];
        let l = lists_at(dir.path(), &[LIST_A]);
        l.fetch_due(&FakeFetcher::answering(LIST_A, vec![ok(BODY)]), 0).await;
        l.compile_and_swap().await;
        let mut now = 13 * HOUR_MS;
        for (name, answer) in bad {
            assert!(!l.fetch_due(&FakeFetcher::answering(LIST_A, vec![answer]), now).await, "{name}");
            let s = state(&l, LIST_A);
            assert_eq!((s.fetched_at_ms, s.failed_at_ms), (Some(0), Some(now)), "{name}");
            assert!(s.last_error.is_some(), "{name}");
            assert_eq!(Cache::new(dir.path()).read_text(LIST_A).as_deref(), Some(BODY), "{name}");
            l.compile_and_swap().await;
            assert!(blocks(&l, "ads.example"), "{name}");
            now += MIN_REFRESH.as_millis() as u64;
        }
        // Timeout, on the fake clock.
        let hang = FakeFetcher { hang: true, ..FakeFetcher::default() };
        assert!(!l.fetch_due(&hang, now).await);
        assert!(state(&l, LIST_A).last_error.unwrap().contains("no answer"));
        assert_eq!(Cache::new(dir.path()).read_text(LIST_A).as_deref(), Some(BODY));
    }

    /// `<id>.txt` as a directory makes the rename of the new copy fail.
    fn block_the_copy(dir: &Path) -> std::path::PathBuf {
        let copy = dir.join(cache::FOLDER).join(format!("{LIST_A}.txt"));
        std::fs::create_dir_all(&copy).unwrap();
        copy
    }

    #[tokio::test]
    async fn a_copy_that_cannot_be_written_is_a_failed_attempt_with_no_copy() {
        let dir = tempfile::tempdir().unwrap();
        let copy = block_the_copy(dir.path());
        let l = lists_at(dir.path(), &[LIST_A]);
        assert!(!l.fetch_due(&FakeFetcher::answering(LIST_A, vec![ok(BODY)]), 1_000).await, "nothing to compile");
        let s = state(&l, LIST_A);
        assert_eq!((s.etag.as_deref(), s.fetched_at_ms, s.failed_at_ms), (None, None, Some(1_000)));
        assert!(s.last_error.is_some());

        let retry_at = 1_000 + NO_COPY_RETRY.as_millis() as u64;
        let f = FakeFetcher::answering(LIST_A, vec![ok(BODY)]);
        assert!(!l.fetch_due(&f, retry_at - 1).await);
        assert!(f.asked_urls().is_empty(), "not before the retry");
        std::fs::remove_dir(&copy).unwrap();
        assert!(l.fetch_due(&f, retry_at).await);
        assert!(f.asked.lock().unwrap()[0].1.is_empty(), "an ETag now would earn a 304 and no list");
        assert_eq!(Cache::new(dir.path()).read_text(LIST_A).as_deref(), Some(BODY));
        assert_eq!(state(&l, LIST_A).last_error, None);
    }

    #[tokio::test]
    async fn a_new_copy_that_cannot_be_written_keeps_the_state_of_the_old_one() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[LIST_A]);
        l.fetch_due(&FakeFetcher::answering(LIST_A, vec![ok(BODY)]), 0).await;
        let old = state(&l, LIST_A);
        let copy = dir.path().join(cache::FOLDER).join(format!("{LIST_A}.txt"));
        std::fs::remove_file(&copy).unwrap();
        block_the_copy(dir.path());

        let at = 12 * HOUR_MS;
        let new = Ok(FetchResponse { status: 200, etag: Some("\"v2\"".into()), body: BODY_2.as_bytes().to_vec(), ..FetchResponse::default() });
        assert!(!l.fetch_due(&FakeFetcher::answering(LIST_A, vec![new]), at).await);
        let s = state(&l, LIST_A);
        assert_eq!((s.etag, s.fetched_at_ms, s.refresh), (old.etag, old.fetched_at_ms, old.refresh), "the state describes the copy on disk");
        assert_eq!(s.failed_at_ms, Some(at));
        assert!(s.last_error.is_some());
        let saved = std::fs::read_to_string(dir.path().join(cache::FOLDER).join(format!("{LIST_A}.json"))).unwrap();
        assert!(saved.contains("v1") && !saved.contains("v2"), "{saved}");
    }

    #[tokio::test]
    async fn conditional_headers_come_from_the_saved_state() {
        let dir = tempfile::tempdir().unwrap();
        lists_at(dir.path(), &[LIST_A]).fetch_due(&FakeFetcher::answering(LIST_A, vec![ok(BODY)]), 0).await;
        let reopened = lists_at(dir.path(), &[LIST_A]);
        let f = FakeFetcher::answering(LIST_A, vec![Ok(FetchResponse { status: 304, ..FetchResponse::default() })]);
        assert!(!reopened.fetch_due(&f, 13 * HOUR_MS).await);
        let asked = f.asked.lock().unwrap();
        assert_eq!(asked[0].1, [("If-None-Match", "\"v1\"".to_string()), ("If-Modified-Since", "then".to_string())]);
    }

    #[tokio::test]
    async fn refresh_follows_the_lists_expires() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[LIST_A]);
        let f = FakeFetcher::answering(LIST_A, vec![ok(BODY), ok(BODY_2)]);
        l.fetch_due(&f, 0).await;
        l.fetch_due(&f, 12 * HOUR_MS - 1).await;
        assert_eq!(f.asked_urls().len(), 1, "12 hours is what the list said");
        assert_eq!(l.next_sleep(12 * HOUR_MS - 1).as_millis(), 1);
        l.fetch_due(&f, 12 * HOUR_MS).await;
        assert_eq!(f.asked_urls().len(), 2);
        assert_eq!(state(&l, LIST_A).refresh.as_secs(), 6 * 3_600, "the new copy said 6 hours");
    }

    #[tokio::test]
    async fn no_copy_retries_sooner_than_a_failed_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[LIST_A]);
        let f = FakeFetcher::default();
        l.fetch_due(&f, 0).await;
        assert_eq!(l.next_sleep(0), NO_COPY_RETRY);
        l.fetch_due(&f, NO_COPY_RETRY.as_millis() as u64 - 1).await;
        assert_eq!(f.asked_urls().len(), 1);
        l.fetch_due(&f, NO_COPY_RETRY.as_millis() as u64).await;
        assert_eq!(f.asked_urls().len(), 2);

        let good = lists_at(dir.path(), &[LIST_A]);
        good.fetch_due(&FakeFetcher::answering(LIST_A, vec![ok(BODY)]), 0).await;
        let at = 12 * HOUR_MS;
        good.fetch_due(&f, at).await;
        assert_eq!(good.next_sleep(at), MIN_REFRESH.min(MAX_SLEEP));
    }

    #[tokio::test]
    async fn a_copy_found_corrupt_at_compile_is_forgotten_and_downloaded_again() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[LIST_A]);
        l.fetch_due(&FakeFetcher::answering(LIST_A, vec![ok(BODY)]), 0).await;
        std::fs::write(dir.path().join(cache::FOLDER).join(format!("{LIST_A}.txt")), [0xff, 0xfe]).unwrap();
        l.compile_and_swap().await;
        assert!(!blocks(&l, "ads.example"), "fewer blocks, never a failed compile");
        assert_eq!(state(&l, LIST_A), FetchState::default());
        let f = FakeFetcher::answering(LIST_A, vec![ok(BODY)]);
        assert!(l.fetch_due(&f, 1).await);
        assert!(f.asked.lock().unwrap()[0].1.is_empty(), "an ETag now would earn a 304 and no list");
    }

    #[tokio::test]
    async fn a_panicking_compile_keeps_the_previous_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let s = slot();
        let selection = Some(vec![LIST_A.to_string()]);
        let good = Lists::with_compile(Some(dir.path()), s.clone(), selection.clone(), RuleEngine::compile);
        good.fetch_due(&FakeFetcher::answering(LIST_A, vec![ok(BODY)]), 0).await;
        good.compile_and_swap().await;
        assert!(blocks(&good, "ads.example"));
        fn panics(_: &[ListText<'_>]) -> RuleEngine {
            panic!("compile");
        }
        let bad = Lists::with_compile(Some(dir.path()), s, selection, panics);
        bad.compile_and_swap().await;
        assert!(bad.compile_error().unwrap().contains("did not compile"));
        assert!(blocks(&bad, "ads.example"), "the previous snapshot still decides");
        bad.slot.update(|f| DomainFilter::with_lists(f, Arc::new(RuleEngine::empty())));
        assert!(!blocks(&bad, "ads.example"));
    }

    #[tokio::test]
    async fn only_selected_lists_are_fetched() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[LIST_A]);
        let f = FakeFetcher::answering(LIST_A, vec![ok(BODY)]);
        l.fetch_due(&f, 0).await;
        assert_eq!(f.asked_urls(), [catalogue::find(LIST_A).unwrap().url]);
        let (rows, _) = l.report();
        assert_eq!(rows.iter().filter(|r| r.enabled).map(|r| r.id.as_str()).collect::<Vec<_>>(), [LIST_A, USER_LIST]);
        assert_eq!(rows.len(), LISTS.len() + 1, "every catalogue row is reported");
        l.set_selection(Some(vec![]));
        let f = FakeFetcher::default();
        l.fetch_due(&f, 13 * HOUR_MS).await;
        assert!(f.asked_urls().is_empty(), "the user turned every list off");
        l.compile_and_swap().await;
        assert!(!blocks(&l, "ads.example"));
    }

    #[tokio::test]
    async fn none_selects_the_catalogue_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let l = Lists::new(Some(dir.path()), slot(), None);
        let f = FakeFetcher::default();
        l.fetch_due(&f, 0).await;
        let expected: Vec<&str> = catalogue::defaults_on().map(|l| l.url).collect();
        assert_eq!(f.asked_urls(), expected);
    }

    #[tokio::test]
    async fn a_requested_refresh_asks_a_fresh_list_once() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[LIST_A, SECOND_DEFAULT]);
        let f = FakeFetcher::answering(LIST_A, vec![ok(BODY), ok(BODY_2)]);
        f.queue(SECOND_DEFAULT, vec![ok(BODY), ok(BODY_2)]);
        l.fetch_due(&f, 0).await;
        assert_eq!(f.asked_urls().len(), 2);
        l.refresh_now();
        l.fetch_due(&f, 1).await;
        assert_eq!(f.asked_urls().len(), 4);
        l.fetch_due(&f, 2).await;
        assert_eq!(f.asked_urls().len(), 4, "once");
    }

    /// The refresh task itself: compile the cached copy first, then fetch, swap,
    /// sleep, and wake on a change of selection.
    #[tokio::test]
    async fn the_task_compiles_the_cache_then_refreshes_and_follows_the_selection() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path());
        cache.write_text(LIST_A, BODY).unwrap();
        let l = Arc::new(lists_at(dir.path(), &[LIST_A]));
        let f = FakeFetcher::answering(LIST_A, vec![ok(BODY_2)]);
        let task = tokio::spawn(l.clone().run(f));
        let wait_for = async |host: &str, want: bool| {
            for _ in 0..500 {
                if blocks(&l, host) == want {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            false
        };
        assert!(wait_for("other.example", true).await, "the download landed");
        l.set_selection(Some(vec![]));
        assert!(wait_for("other.example", false).await, "the new selection compiled");
        task.abort();
    }
}
