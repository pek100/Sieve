//! The lists at run time (plan 5.4, D10 to D13 of
//! docs/tasks/2026-11-02-domain-policy.md): the catalogue's selection and the
//! user's own lists, by address or imported from a file. `sieve-filter` judges;
//! this module does the I/O: asks a [`Fetcher`], keeps the last good copy on
//! disk, compiles off the hot path and swaps the snapshot.
//!
//! Lists refresh only while routes are up: [`Lists::run`] is started by
//! `bring_up` and aborted by `take_down`, so the switch off means no timer. A
//! missing, broken or uncompiled list means fewer blocks, never a failed
//! connection: flows pass until the first snapshot lands, and a compile that
//! panics keeps the previous snapshot. A user's list is compiled untrusted, so
//! it can never use a `trusted-*` scriptlet.

pub mod cache;
#[cfg(windows)]
pub mod https;
pub mod resources;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sieve_filter::catalogue::{self, LISTS};
use sieve_filter::lists::{Applied, FetchResponse, FetchState, judge_text, list_version};
use sieve_filter::rules::{ListReport, ListText, RuleEngine, USER_LIST, rule_lines};
use sieve_ipc::{CUSTOM_LIST_PREFIX, CustomList, FilterFacts, LIST_QUERY_MAX, LIST_RULES_SHOWN, ListFact, ListStatus, MAX_IMPORT_BYTES, custom_id_problem, listed_line};
use tokio::sync::Notify;

use crate::domain::{DomainFilter, FilterSlot, UserRules, user_engine};
use sieve_filter::resources::ResourceBundle;
use crate::policy::wall_ms;
use cache::Cache;

/// One download gets this long, connect and body included. Generous: the
/// largest default list is about 10 MiB and some connections are slow.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(120);
/// The loop looks again at least this often, so a suspended machine or a
/// moved wall clock delays a refresh by no more than this. Plan 6's idle cost:
/// one wake an hour, only while routes are up.
const MAX_SLEEP: Duration = Duration::from_secs(3_600);
/// A copy no policy names is kept this long after it was written: an import's
/// policy follows it, and may only arrive after the engine restarted.
const UNNAMED_COPY_KEPT: Duration = Duration::from_secs(5 * 60);

pub const UNKNOWN_LIST: &str = "the engine knows no list by that id";
pub const LIST_OFF: &str = "the list is off: Sieve downloads a list only while it is on";
pub const NO_COPY: &str = "Sieve has no copy of this list yet: it downloads a list while the list is on and the engine routes traffic";
pub const FILE_NOT_DOWNLOADED: &str = "a list from a file is not downloaded: import the file again to update it";
pub const NOTHING_USABLE: &str = "no rule Sieve can use: every line was skipped";
pub const NO_STATE_FOLDER: &str = "the engine keeps no lists in this run";

/// How a list is downloaded: the real client (`https`), or a fake in tests.
pub trait Fetcher: Send + Sync {
    fn fetch(&self, url: &str, headers: Vec<(&'static str, String)>) -> impl Future<Output = Result<FetchResponse, String>> + Send;
}

type Compile = fn(&[ListText<'_>]) -> RuleEngine;

/// One list the engine fetches and compiles: a catalogue row or one of the
/// user's own (`url` None: imported from a file, never downloaded).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Source {
    id: String,
    url: Option<String>,
    trusted: bool,
}

#[derive(Debug, Default)]
struct Inner {
    selection: Option<Vec<String>>,
    custom: Vec<CustomList>,
    states: HashMap<String, FetchState>,
    /// Lists asked to download at the next look, whatever their age.
    forced: HashSet<String>,
    compile_ms: Option<u64>,
    compile_error: Option<String>,
    /// Each compiled list's own `! Version:`.
    versions: HashMap<String, String>,
    /// The resource bundle in use, as the report quotes it.
    resource_pin: Option<String>,
    resource_error: Option<String>,
    /// The bundle itself: the user's engine gets it too.
    bundle: Option<ResourceBundle>,
    /// What the user's engine is compiled from, to recompile it when the bundle changes.
    user: UserRules,
}

pub struct Lists {
    dir: Option<PathBuf>,
    cache: Option<Cache>,
    slot: Arc<FilterSlot>,
    compile: Compile,
    inner: Mutex<Inner>,
    force: AtomicBool,
    /// A copy changed outside a download (an import): compile at the next look.
    dirty: AtomicBool,
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
        skipped_exceptions: report.map(|r| r.skipped_exceptions.iter().map(|l| listed_line(l)).collect()).unwrap_or_default(),
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
        let states = cache.as_ref().map(|c| LISTS.iter().map(|l| (l.id.to_string(), c.read_state(l.id))).collect()).unwrap_or_default();
        Self {
            dir: engine_dir.map(Path::to_path_buf),
            cache,
            slot,
            compile,
            inner: Mutex::new(Inner { selection, states, ..Inner::default() }),
            force: AtomicBool::new(false),
            dirty: AtomicBool::new(false),
            wake: Notify::new(),
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// What is fetched and compiled now: the selected catalogue rows, then the
    /// user's own lists that are on, in the policy's order.
    fn sources(&self) -> Vec<Source> {
        let inner = self.inner();
        let rows = catalogue::selected(inner.selection.as_deref()).into_iter().map(|l| Source { id: l.id.to_string(), url: Some(l.url.to_string()), trusted: l.trusted });
        let own = inner.custom.iter().filter(|c| c.enabled).map(|c| Source { id: c.id.clone(), url: c.url.clone(), trusted: false });
        rows.chain(own).collect()
    }

    /// The user's engine for these rules, with the bundle in use. The rules are
    /// kept, so a bundle that changes later reaches this engine's successor at
    /// the same swap as the lists ([`Self::compile_and_swap`]).
    pub fn user_engine_for(&self, user: UserRules) -> RuleEngine {
        let bundle = {
            let mut inner = self.inner();
            inner.user = user.clone();
            inner.bundle.clone()
        };
        user_engine(&user, bundle.as_ref())
    }

    /// The policy's selection changed: fetch and compile what it names now.
    pub fn set_selection(&self, selection: Option<Vec<String>>) {
        let mut inner = self.inner();
        if inner.selection != selection {
            inner.selection = selection;
            self.wake.notify_one();
        }
    }

    /// The policy's own lists changed. A list that left (or whose address
    /// changed) is forgotten with its copy, so removing a list removes what the
    /// engine kept of it; so is a copy on disk no policy names, unless it was
    /// written less than [`UNNAMED_COPY_KEPT`] before `now_ms` (an import whose
    /// policy has not arrived yet, across a restart too).
    pub fn set_custom(&self, custom: Vec<CustomList>, now_ms: u64) {
        let mut inner = self.inner();
        if inner.custom == custom {
            return;
        }
        let kept = |c: &CustomList| inner.custom.iter().any(|old| old.id == c.id && old.url == c.url);
        let fresh: Vec<String> = custom.iter().filter(|c| !kept(c)).map(|c| c.id.clone()).collect();
        let forget: Vec<String> = inner.custom.iter().filter(|old| !custom.iter().any(|c| c.id == old.id && c.url == old.url)).map(|c| c.id.clone()).collect();
        for id in &forget {
            inner.states.remove(id);
            inner.versions.remove(id);
        }
        if let Some(cache) = &self.cache {
            for id in &forget {
                cache.remove(id);
            }
            let young = |id: &str| cache.read_state(id).fetched_at_ms.is_some_and(|at| now_ms.saturating_sub(at) < millis(UNNAMED_COPY_KEPT));
            for id in cache.ids_with_prefix(CUSTOM_LIST_PREFIX) {
                if !custom.iter().any(|c| c.id == id) && !young(&id) {
                    cache.remove(&id);
                    inner.states.remove(&id);
                }
            }
            for id in fresh {
                if !inner.states.contains_key(&id) {
                    inner.states.insert(id.clone(), cache.read_state(&id));
                }
            }
        }
        inner.custom = custom;
        self.wake.notify_one();
    }

    /// Every selected list downloads at the next look, whatever its age.
    pub fn refresh_now(&self) {
        self.force.store(true, Ordering::Relaxed);
        self.wake.notify_one();
    }

    /// List `id` downloads at the next look, whatever its age. Refused for an
    /// id the engine does not know, for a list from a file, and for a list that
    /// is off, which the loop would never ask for.
    pub fn refresh_one(&self, id: &str) -> Result<(), String> {
        let known = catalogue::find(id).is_some() || self.inner().custom.iter().any(|c| c.id == id);
        if !known {
            return Err(UNKNOWN_LIST.to_string());
        }
        match self.sources().into_iter().find(|s| s.id == id) {
            None => Err(LIST_OFF.to_string()),
            Some(Source { url: None, .. }) => Err(FILE_NOT_DOWNLOADED.to_string()),
            Some(_) => {
                self.inner().forced.insert(id.to_string());
                self.wake.notify_one();
                Ok(())
            }
        }
    }

    /// Judges and keeps a list the user picked from a file, as a download is
    /// judged, and compiles it untrusted alone, off the runtime, to count what
    /// it holds. It takes effect once the policy names it. The rules and
    /// skipped counts it holds.
    pub async fn import(&self, id: &str, text: String, now_ms: u64) -> Result<(u64, u64), String> {
        if let Some(why) = custom_id_problem(id) {
            return Err(why);
        }
        let owned_id = id.to_string();
        let judged = tokio::task::spawn_blocking(move || {
            let judged = judge_text(text.as_bytes(), MAX_IMPORT_BYTES, false)?.to_string();
            let compiled = RuleEngine::compile(&[ListText { id: &owned_id, text: &judged, trusted: false }]);
            Ok::<_, String>((judged, compiled.reports().first().cloned().unwrap_or_default()))
        });
        let (text, report) = judged.await.map_err(|e| format!("the list did not compile: {e}"))??;
        let rules = counted(report.network + report.cosmetic);
        if rules == 0 {
            return Err(NOTHING_USABLE.to_string());
        }
        let cache = self.cache.as_ref().ok_or(NO_STATE_FOLDER)?;
        let state = FetchState::fetched(&text, None, None, now_ms);
        cache.write_text(id, &text)?;
        cache.write_state(id, &state)?;
        self.inner().states.insert(id.to_string(), state);
        self.dirty.store(true, Ordering::Relaxed);
        self.wake.notify_one();
        Ok((rules, counted(report.skipped)))
    }

    /// The rules of the engine's copy of list `id` that hold `query` (case
    /// folded), the first [`LIST_RULES_SHOWN`] of them, how many match and how
    /// many rules the copy holds.
    pub fn rules(&self, id: &str, query: &str) -> Result<(Vec<String>, u64, u64), String> {
        if query.len() > LIST_QUERY_MAX {
            return Err(format!("a search of {} bytes is over the {LIST_QUERY_MAX} byte limit", query.len()));
        }
        let known = catalogue::find(id).is_some() || self.inner().custom.iter().any(|c| c.id == id);
        if !known {
            return Err(UNKNOWN_LIST.to_string());
        }
        let text = self.cache.as_ref().and_then(|c| c.read_text(id)).ok_or(NO_COPY)?;
        let needle = query.trim().to_lowercase();
        let (mut total, mut matched, mut lines) = (0u64, 0u64, Vec::new());
        for rule in rule_lines(&text) {
            total += 1;
            if needle.is_empty() || rule.to_lowercase().contains(&needle) {
                matched += 1;
                if lines.len() < LIST_RULES_SHOWN {
                    lines.push(listed_line(rule));
                }
            }
        }
        Ok((lines, matched, total))
    }

    /// Why the last compile produced nothing, or why it went without a resource
    /// bundle that is there, while that is so.
    pub fn compile_error(&self) -> Option<String> {
        let inner = self.inner();
        match (&inner.compile_error, &inner.resource_error) {
            (Some(a), Some(b)) => Some(format!("{a}; {b}")),
            (a, b) => a.clone().or_else(|| b.clone()),
        }
    }

    /// What the engine filters with, for the Status: the lists the snapshot in
    /// force holds, whatever the selection has since become. None until a
    /// compile finished. The user's rules and own lists are not here: they have
    /// no project page and are never what a report names.
    pub fn facts(&self) -> Option<FilterFacts> {
        let filter = self.slot.get();
        let inner = self.inner();
        inner.compile_ms?;
        let lists = filter
            .rules
            .lists
            .reports()
            .iter()
            .filter_map(|report| {
                let l = catalogue::find(&report.id)?;
                Some(ListFact {
                    id: l.id.to_string(),
                    title: l.title.to_string(),
                    homepage: l.homepage.to_string(),
                    version: inner.versions.get(l.id).cloned(),
                    applied: counted(report.network),
                    skipped: counted(report.skipped),
                })
            })
            .collect();
        Some(FilterFacts { lists, resource_pin: inner.resource_pin.clone() })
    }

    /// The per-list report: every catalogue row, the user's own lists, then the
    /// user's rules.
    pub fn report(&self) -> (Vec<ListStatus>, Option<u64>) {
        let filter = self.slot.get();
        let sources = self.sources();
        let inner = self.inner();
        let find = |reports: &'_ [ListReport], id: &str| reports.iter().find(|r| r.id == id).cloned();
        let row = |id: &str| {
            let enabled = sources.iter().any(|s| s.id == id);
            status_of(id, enabled, inner.states.get(id), find(filter.rules.lists.reports(), id).as_ref())
        };
        let mut rows: Vec<ListStatus> = LISTS.iter().map(|l| row(l.id)).chain(inner.custom.iter().map(|c| row(&c.id))).collect();
        rows.push(status_of(USER_LIST, true, None, find(filter.rules.user.reports(), USER_LIST).as_ref()));
        (rows, inner.compile_ms)
    }

    /// Asks for every list that is due, in order. True when a copy was
    /// replaced. A failure keeps the copy and only its time is recorded. A list
    /// from a file is never asked for.
    pub async fn fetch_due<F: Fetcher>(&self, fetcher: &F, now_ms: u64) -> bool {
        let force = self.force.swap(false, Ordering::Relaxed);
        let mut replaced = false;
        let sources = self.sources();
        // A list turned off after its "Update now" is not downloaded: forget the ask.
        self.inner().forced.retain(|id| sources.iter().any(|s| s.id == *id && s.url.is_some()));
        for source in sources {
            let Some(url) = source.url.as_deref() else { continue };
            let forced = self.inner().forced.remove(&source.id);
            let mut state = self.inner().states.get(&source.id).cloned().unwrap_or_default();
            if !force && !forced && !state.is_due(now_ms) {
                continue;
            }
            let answer = tokio::time::timeout(FETCH_TIMEOUT, fetcher.fetch(url, state.conditional_headers())).await;
            match answer {
                Ok(Ok(response)) => {
                    // The state describes the copy on disk, so a new one only
                    // counts once it is written.
                    let mut next = state.clone();
                    let written = match (next.apply(response, now_ms), &self.cache) {
                        (Applied::Replaced(text), Some(cache)) => cache.write_text(&source.id, &text).map(|()| true),
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
                let _ = cache.write_state(&source.id, &state);
            }
            self.inner().states.insert(source.id, state);
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
        let sources = self.sources();
        let dir = self.dir.clone();
        let job = tokio::task::spawn_blocking(move || {
            let copies: Vec<(Source, Option<String>)> = sources.into_iter().map(|s| {
                let text = cache.as_ref().and_then(|c| c.read_text(&s.id));
                (s, text)
            }).collect();
            let texts: Vec<ListText<'_>> = copies.iter().filter_map(|(s, t)| t.as_deref().map(|text| ListText { id: &s.id, text, trusted: s.trusted })).collect();
            let mut engine = compile(&texts);
            let (loaded, resource_error) = dir.as_deref().map_or((None, None), |d| resources::load(d, resources::RESOURCE_PIN));
            if let Some(l) = &loaded {
                engine.use_resources(&l.bundle);
            }
            let versions: HashMap<String, String> = copies.iter().filter_map(|(s, t)| Some((s.id.clone(), list_version(t.as_deref()?)?))).collect();
            let missing: Vec<String> = copies.iter().filter(|(_, t)| t.is_none()).map(|(s, _)| s.id.clone()).collect();
            (engine, missing, versions, loaded, resource_error)
        });
        match job.await {
            Ok((engine, missing, versions, loaded, resource_error)) => {
                let engine = Arc::new(engine);
                let (resource_pin, bundle) = loaded.map_or((None, None), |l| (Some(l.pin), Some(l.bundle)));
                // The user's engine follows a changed bundle in the same swap.
                let (user_rules, bundle_changed) = {
                    let inner = self.inner();
                    (inner.user.clone(), inner.resource_pin != resource_pin)
                };
                let user = bundle_changed.then(|| Arc::new(user_engine(&user_rules, bundle.as_ref())));
                self.slot.update(|f| {
                    let mut next = DomainFilter::with_lists(f, engine.clone());
                    if let Some(user) = &user {
                        next.rules.user = user.clone();
                    }
                    next
                });
                let mut inner = self.inner();
                inner.compile_ms = Some(millis(started.elapsed()));
                inner.compile_error = None;
                inner.versions = versions;
                inner.resource_pin = resource_pin;
                inner.resource_error = resource_error;
                inner.bundle = bundle;
                for id in missing {
                    if inner.states.get(&id).is_some_and(|s| s.fetched_at_ms.is_some()) {
                        inner.states.insert(id, FetchState::default());
                    }
                }
            }
            Err(e) => self.inner().compile_error = Some(format!("the lists did not compile: {e}")),
        }
    }

    /// Until the next list is due: now for a list asked for, if it is still on.
    /// A list from a file is never due.
    fn next_sleep(&self, now_ms: u64) -> Duration {
        let sources = self.sources();
        let inner = self.inner();
        let due = |s: &Source| if inner.forced.contains(&s.id) { 0 } else { inner.states.get(&s.id).map_or(0, FetchState::due_at_ms) };
        let next = sources.iter().filter(|s| s.url.is_some()).map(due).min();
        next.map_or(MAX_SLEEP, |due| Duration::from_millis(due.saturating_sub(now_ms)).min(MAX_SLEEP))
    }

    /// The refresh task, for as long as routes are up.
    pub async fn run<F: Fetcher>(self: Arc<Self>, fetcher: F) {
        // Read before compiling: a change during the compile mismatches below.
        let mut compiled_for = self.sources();
        self.dirty.store(false, Ordering::Relaxed);
        self.compile_and_swap().await;
        loop {
            let replaced = self.fetch_due(&fetcher, wall_ms()).await;
            let sources = self.sources();
            if replaced || sources != compiled_for || self.dirty.swap(false, Ordering::Relaxed) {
                self.compile_and_swap().await;
                compiled_for = sources;
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
        let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.path().join(cache::FOLDER).join(format!("{LIST_A}.json"))).unwrap()).unwrap();
        assert_eq!(saved["etag"], "\"v1\"", "the file too: {saved}");
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

    /// Plan 7.5 meets plan 5.5: a bundle the signed path placed is what the next
    /// compile uses, and the report quotes it. A broken one costs scriptlets and
    /// is said; filtering carries on.
    #[tokio::test]
    async fn a_compile_prefers_the_signed_resource_copy_and_says_which_it_used() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path());
        cache.write_text(LIST_A, BODY).unwrap();
        let l = lists_at(dir.path(), &[LIST_A]);
        l.compile_and_swap().await;
        assert_eq!(l.facts().unwrap().resource_pin, None, "no bundle yet");

        let path = crate::update::data_path(dir.path(), &crate::update::Kind::Resources).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"[]").unwrap();
        l.compile_and_swap().await;
        assert_eq!(l.facts().unwrap().resource_pin, Some(format!("sha256:{}", sieve_filter::resources::sha256_hex(b"[]"))));
        assert_eq!(l.compile_error(), None);

        std::fs::write(&path, b"not json").unwrap();
        l.compile_and_swap().await;
        assert_eq!(l.facts().unwrap().resource_pin, None);
        assert!(l.compile_error().unwrap().contains("signed resource library"));
        assert!(blocks(&l, "ads.example"), "the lists still decide");
    }

    /// Live run 2026-11-08: a user's `+js()` rule injected nothing, because only
    /// the lists' engine was given the bundle.
    #[tokio::test]
    async fn the_users_own_scriptlet_rules_get_the_bundle_too() {
        const URL: &str = "https://sieve-test.invalid/";
        const FIXTURE: &[u8] = include_bytes!("../../../sieve-filter/testdata/resources-fixture.json");
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[]);
        let policy = Policy { user_rules: vec!["sieve-test.invalid##+js(sieve-set-flag, a, b)".into()], ..Policy::default() };
        let user = Arc::new(l.user_engine_for(UserRules::of(&policy)));
        l.slot.update(|f| DomainFilter::new(&policy, RuleSet { user, lists: f.rules.lists.clone() }));
        let scriptlets = |l: &Lists| l.slot.get().rules.page_cosmetics(URL).scriptlets;
        l.compile_and_swap().await;
        assert!(!scriptlets(&l).contains("sieveSetFlag"), "the control: no bundle, no scriptlet");

        let path = crate::update::data_path(dir.path(), &crate::update::Kind::Resources).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, FIXTURE).unwrap();
        l.compile_and_swap().await;
        assert!(scriptlets(&l).contains("sieveSetFlag"), "the bundle reaches the user's engine at the swap");
        assert!(l.user_engine_for(UserRules::of(&policy)).page_cosmetics(URL).scriptlets.contains("sieveSetFlag"), "and a later policy's engine");
    }

    #[tokio::test]
    async fn the_facts_hold_the_selected_lists_of_the_last_compile() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[LIST_A]);
        assert_eq!(l.facts(), None);
        l.compile_and_swap().await;
        assert_eq!(l.facts().unwrap().lists, [], "compiled with no copy: no list in force");
        Cache::new(dir.path()).write_text(LIST_A, BODY).unwrap();
        l.compile_and_swap().await;
        let facts = l.facts().unwrap();
        assert_eq!(facts.lists.iter().map(|f| (f.id.as_str(), f.applied)).collect::<Vec<_>>(), [(LIST_A, 1)]);
        l.set_selection(Some(vec![]));
        assert_eq!(l.facts().unwrap().lists.len(), 1, "turned off, but it enforces until the next compile");
        assert!(blocks(&l, "ads.example"), "the fact and the filter agree");
        l.compile_and_swap().await;
        assert_eq!(l.facts().unwrap().lists, [], "gone with the snapshot that held it");
    }

    #[test]
    fn a_listed_line_carries_no_control_characters() {
        let report = ListReport { skipped_exceptions: vec!["@@a\u{1}b".into()], ..ListReport::default() };
        let row = status_of(LIST_A, true, None, Some(&report));
        assert_eq!(row.skipped_exceptions, ["@@ab"]);
    }

    /// The list the first compile is holding, for [`deselects_while_compiling`].
    static COMPILING: Mutex<Option<Arc<Lists>>> = Mutex::new(None);

    /// A user who turns every list off while the first compile runs.
    fn deselects_while_compiling(texts: &[ListText<'_>]) -> RuleEngine {
        if let Some(l) = COMPILING.lock().unwrap().take() {
            l.set_selection(Some(vec![]));
        }
        RuleEngine::compile(texts)
    }

    #[tokio::test]
    async fn a_selection_changed_during_the_first_compile_is_compiled_next() {
        let dir = tempfile::tempdir().unwrap();
        Cache::new(dir.path()).write_text(LIST_A, BODY).unwrap();
        let selection = Some(vec![LIST_A.to_string()]);
        let l = Arc::new(Lists::with_compile(Some(dir.path()), slot(), selection, deselects_while_compiling));
        *COMPILING.lock().unwrap() = Some(l.clone());
        let task = tokio::spawn(l.clone().run(FakeFetcher::default()));
        let mut compiled_twice = false;
        for _ in 0..500 {
            if COMPILING.lock().unwrap().is_none() && l.inner().compile_ms.is_some() && !blocks(&l, "ads.example") {
                compiled_twice = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();
        assert!(compiled_twice, "the deselected list still drops hosts");
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

    const OWN_URL: &str = "https://lists.example/own.txt";

    fn own(id: &str, url: Option<&str>) -> CustomList {
        CustomList { id: id.into(), title: "Mine".into(), url: url.map(str::to_string), enabled: true }
    }

    impl FakeFetcher {
        fn answering_url(url: &str, answers: Vec<Answer>) -> Self {
            let fake = Self::default();
            fake.answers.lock().unwrap().entry(url.to_string()).or_default().extend(answers);
            fake
        }
    }

    #[tokio::test]
    async fn an_own_list_by_address_is_downloaded_compiled_untrusted_reported_and_forgotten_when_removed() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[]);
        l.set_custom(vec![own("custom-a1", Some(OWN_URL))], 0);
        assert!(l.sources().iter().all(|s| !s.trusted), "a user's list never gets trusted scriptlets");
        let f = FakeFetcher::answering_url(OWN_URL, vec![ok(BODY)]);
        assert!(l.fetch_due(&f, 1_000).await);
        assert_eq!(f.asked_urls(), [OWN_URL]);
        l.compile_and_swap().await;
        assert!(blocks(&l, "ads.example"));
        let (rows, _) = l.report();
        let row = rows.iter().find(|r| r.id == "custom-a1").unwrap();
        assert_eq!((row.enabled, row.fetched_at_ms, row.network), (true, Some(1_000), 1));
        assert_eq!(rows.len(), LISTS.len() + 2, "the catalogue, the own list, the user's rules");

        l.set_custom(vec![CustomList { enabled: false, ..own("custom-a1", Some(OWN_URL)) }], 1_000);
        assert!(Cache::new(dir.path()).read_text("custom-a1").is_some(), "off keeps the copy");
        l.compile_and_swap().await;
        assert!(!blocks(&l, "ads.example"), "off stops it");
        l.set_custom(vec![], 1_000);
        assert_eq!(Cache::new(dir.path()).read_text("custom-a1"), None, "removed, and its copy with it, however young");
        assert!(l.report().0.iter().all(|r| r.id != "custom-a1"));
    }

    #[tokio::test]
    async fn an_own_list_that_is_a_web_page_is_refused_with_the_reason_and_keeps_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[]);
        l.set_custom(vec![own("custom-a1", Some(OWN_URL))], 0);
        assert!(!l.fetch_due(&FakeFetcher::answering_url(OWN_URL, vec![ok("<!doctype html><p>sign in")]), 0).await);
        let (rows, _) = l.report();
        let row = rows.iter().find(|r| r.id == "custom-a1").unwrap();
        assert_eq!(row.last_error.as_deref(), Some("an HTML page, not a filter list"));
        assert_eq!(row.fetched_at_ms, None);
    }

    #[tokio::test]
    async fn an_imported_file_is_judged_kept_compiled_once_named_and_never_downloaded() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[]);
        let too_big = "||a.example^\n".repeat(MAX_IMPORT_BYTES / 13 + 1);
        for (text, why) in [
            ("<html><body>no</body></html>", "an HTML page"),
            ("! only a comment\n", "no rule in the response"),
            (too_big.as_str(), "byte limit"),
            ("||bad$unknown-option-xyz\n", "no rule in the response"),
        ] {
            assert!(l.import("custom-b2", text.into(), 5).await.unwrap_err().contains(why), "{why}");
        }
        assert!(l.import("adguard-base", BODY.into(), 5).await.unwrap_err().contains("custom list id"), "never over a catalogue row");
        assert!(l.import("custom-../x", BODY.into(), 5).await.is_err(), "never a path");
        assert_eq!(Cache::new(dir.path()).read_text("custom-b2"), None, "nothing kept from a refusal");

        assert_eq!(l.import("custom-b2", "||ads.example^\n||bad$unknown-option-xyz\n".into(), 5).await.unwrap(), (1, 1));
        l.set_custom(vec![own("custom-a1", Some(OWN_URL))], 5);
        assert!(Cache::new(dir.path()).read_text("custom-b2").is_some(), "imported, its policy not here yet: kept");
        l.set_custom(vec![own("custom-b2", None)], 5);
        let f = FakeFetcher::default();
        assert!(!l.fetch_due(&f, 10 * HOUR_MS).await);
        assert!(f.asked_urls().is_empty(), "a file is never downloaded");
        assert_eq!(l.next_sleep(0), MAX_SLEEP, "nor ever due");
        l.compile_and_swap().await;
        assert!(blocks(&l, "ads.example"));
        assert_eq!(l.refresh_one("custom-b2").unwrap_err(), FILE_NOT_DOWNLOADED);
    }

    #[test]
    fn a_copy_no_policy_names_is_swept() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path());
        cache.write_text("custom-old", BODY).unwrap();
        cache.write_text(LIST_A, BODY).unwrap();
        let l = lists_at(dir.path(), &[]);
        l.set_custom(vec![own("custom-a1", Some(OWN_URL))], 0);
        assert_eq!(cache.read_text("custom-old"), None, "left by an import that was never added");
        assert!(cache.read_text(LIST_A).is_some(), "a catalogue copy is never swept");
    }

    /// An import, then a restart before the policy naming it arrives.
    #[tokio::test]
    async fn a_fresh_import_outlives_a_restart_and_a_stale_one_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let at = 10 * HOUR_MS;
        lists_at(dir.path(), &[]).import("custom-b2", BODY.into(), at).await.unwrap();
        let policy = || vec![own("custom-a1", Some(OWN_URL))];
        let minute = 60_000;
        lists_at(dir.path(), &[]).set_custom(policy(), at + minute);
        assert!(Cache::new(dir.path()).read_text("custom-b2").is_some(), "a minute old: its policy may still come");
        lists_at(dir.path(), &[]).set_custom(policy(), at + millis(UNNAMED_COPY_KEPT));
        assert_eq!(Cache::new(dir.path()).read_text("custom-b2"), None, "no policy named it in time");
    }

    /// The compile of an import must leave the pipe's runtime free: a task
    /// beside it runs while it compiles.
    #[tokio::test(flavor = "current_thread")]
    async fn an_import_compiles_off_the_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[]);
        let ticks = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let ticker = tokio::spawn({
            let ticks = ticks.clone();
            async move {
                loop {
                    ticks.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            }
        });
        tokio::task::yield_now().await;
        let before = ticks.load(Ordering::Relaxed);
        let text = "||a.example^\n".repeat(MAX_IMPORT_BYTES / 13);
        l.import("custom-b2", text, 5).await.unwrap();
        assert!(ticks.load(Ordering::Relaxed) > before, "the runtime ran nothing else during the compile");
        ticker.abort();
    }

    #[tokio::test]
    async fn update_now_on_a_list_that_is_off_is_refused_and_never_spins_the_loop() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[LIST_A]);
        l.fetch_due(&FakeFetcher::answering(LIST_A, vec![ok(BODY)]), 0).await;
        assert_eq!(l.refresh_one(SECOND_DEFAULT).unwrap_err(), LIST_OFF, "a catalogue row not selected");
        assert!(l.next_sleep(1) > Duration::ZERO);

        l.refresh_one(LIST_A).unwrap();
        l.set_selection(Some(vec![]));
        assert_eq!(l.next_sleep(1), MAX_SLEEP, "asked, then turned off: nothing is due");
        let f = FakeFetcher::default();
        l.fetch_due(&f, 1).await;
        assert!(f.asked_urls().is_empty());
        assert!(l.inner().forced.is_empty(), "the ask is forgotten");
        l.set_selection(Some(vec![LIST_A.to_string()]));
        assert!(l.next_sleep(1) > Duration::ZERO, "on again: due when its copy says, not at once");
    }

    #[tokio::test]
    async fn one_list_can_be_downloaded_now_and_only_that_one() {
        let dir = tempfile::tempdir().unwrap();
        let l = lists_at(dir.path(), &[LIST_A, SECOND_DEFAULT]);
        let f = FakeFetcher::answering(LIST_A, vec![ok(BODY), ok(BODY_2)]);
        f.queue(SECOND_DEFAULT, vec![ok(BODY)]);
        l.fetch_due(&f, 0).await;
        assert_eq!(f.asked_urls().len(), 2);
        l.refresh_one(LIST_A).unwrap();
        assert_eq!(l.next_sleep(1), Duration::ZERO, "the loop looks at once");
        l.fetch_due(&f, 1).await;
        assert_eq!(f.asked_urls().len(), 3);
        assert_eq!(f.asked_urls()[2], catalogue::find(LIST_A).unwrap().url);
        assert_eq!(l.refresh_one("nope").unwrap_err(), UNKNOWN_LIST);
    }

    #[tokio::test]
    async fn a_lists_rules_are_searched_and_capped() {
        let dir = tempfile::tempdir().unwrap();
        let body: String = std::iter::once("! Title: Big\n[Adblock Plus 2.0]\n".to_string()).chain((0..LIST_RULES_SHOWN + 50).map(|i| format!("||host{i}.ads.example^\n"))).chain(["||Other.example^\n".to_string()]).collect();
        Cache::new(dir.path()).write_text(LIST_A, &body).unwrap();
        let l = lists_at(dir.path(), &[LIST_A]);
        let (lines, matched, total) = l.rules(LIST_A, "").unwrap();
        assert_eq!((lines.len(), matched, total), (LIST_RULES_SHOWN, LIST_RULES_SHOWN as u64 + 51, LIST_RULES_SHOWN as u64 + 51), "comments and the header are not rules");
        let (lines, matched, _) = l.rules(LIST_A, "OTHER").unwrap();
        assert_eq!((lines, matched), (vec!["||Other.example^".to_string()], 1), "case folded");
        assert_eq!(l.rules(SECOND_DEFAULT, "").unwrap_err(), NO_COPY);
        assert_eq!(l.rules("custom-zz", "").unwrap_err(), UNKNOWN_LIST);
        assert!(l.rules(LIST_A, &"x".repeat(LIST_QUERY_MAX + 1)).is_err());
    }
}