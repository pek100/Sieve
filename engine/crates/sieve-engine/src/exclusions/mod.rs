//! The exclusion store at run time (plan 4.1, task D6): three layers behind one
//! snapshot, swapped like `domain::FilterSlot`, read once per flow.
//! - `user`: the policy's `exclusions`, never persisted a second time;
//! - `list:<id>`: [`lists`], replaced at each refresh;
//! - `auto:*`: [`auto`], `engine\exclusions.json`.
//!
//! The decision itself is `sieve_filter::exclusions::decrypt`. The slot adds
//! only what that pure function must be told: [`ExclusionSlot::switches`] and
//! the browser set behind `app_in_scope`.

pub mod auto;
pub mod browsers;
pub mod lists;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sieve_filter::exclusions::{Exclusion, ExclusionSet, Pattern, Scope, Source as EntrySource, Switches, parse_line};

pub use auto::AutoEntry;
use browsers::BrowserSet;
use lists::{Origin, Source};

use crate::lists::Fetcher;
use crate::lists::cache::Cache;
use crate::policy::wall_ms;

/// `https.skipEv` (plan 2.6): on, with no setting until a UI shows it (S35).
pub const SKIP_EV: bool = true;
/// Browsers first (the user's decision); `All` after slice 7 is proven live.
pub const SCOPE: Scope = Scope::Browsers;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The layers a snapshot is built from.
#[derive(Debug, Default)]
struct Layers {
    user: Vec<Exclusion>,
    /// By source id, in source order.
    lists: Vec<(&'static str, Option<Vec<Exclusion>>)>,
    auto: Vec<AutoEntry>,
    /// Why `exclusions.json` cannot be believed: the floor holds (S24).
    auto_error: Option<String>,
    browsers: BrowserSet,
}

impl Layers {
    /// The set, and the earliest expiry in it.
    fn build(&self, now_ms: u64) -> (ExclusionSet, Option<u64>) {
        let mut set = ExclusionSet::default();
        set.add(self.user.iter().cloned(), &EntrySource::User);
        for (id, entries) in &self.lists {
            set.add(entries.iter().flatten().cloned(), &EntrySource::List((*id).to_string()));
        }
        let mut next = None;
        for entry in self.auto.iter().filter(|e| !e.expired(now_ms)) {
            set.add([entry.exclusion()], &EntrySource::Auto(entry.reason));
            next = match (next, entry.expires_ms) {
                (Some(a), Some(b)) => Some(u64::min(a, b)),
                (a, b) => a.or(b),
            };
        }
        (set, next)
    }

    fn lists_ready(&self) -> bool {
        self.auto_error.is_none() && self.lists.iter().all(|(_, entries)| entries.is_some())
    }
}

#[derive(Debug)]
struct Snapshot {
    set: Arc<ExclusionSet>,
    next_expiry: Option<u64>,
}

/// The current store.
#[derive(Debug)]
pub struct ExclusionSlot {
    dir: Option<PathBuf>,
    /// None without a folder, and for a file that could not be read: only a
    /// person may decide what a damaged record meant.
    writer: Option<auto::Writer>,
    sources: Vec<Source>,
    skip_ev: bool,
    layers: Mutex<Layers>,
    snapshot: Mutex<Snapshot>,
}

/// The policy's lines as entries. A line that does not parse decrypts nothing
/// new: it was never an exclusion (`ipc` already bounds the text).
fn user_entries(lines: &[String]) -> Vec<Exclusion> {
    lines.iter().filter_map(|l| parse_line(l.trim()).ok()).collect()
}

impl ExclusionSlot {
    pub fn new(dir: Option<&Path>, policy_exclusions: &[String], now_ms: u64) -> Self {
        Self::with_sources(dir, policy_exclusions, lists::sources(), now_ms)
    }

    /// `sources` is a parameter so a test can enable what production does not.
    pub fn with_sources(dir: Option<&Path>, policy_exclusions: &[String], sources: Vec<Source>, now_ms: u64) -> Self {
        let (auto, auto_error) = match dir.map(auto::load) {
            Some(Ok(entries)) => (entries, None),
            Some(Err(why)) => (Vec::new(), Some(why)),
            None => (Vec::new(), None),
        };
        let cache = dir.map(Cache::new);
        let enabled: Vec<Source> = sources.into_iter().filter(|s| s.enabled).collect();
        let list_layers = enabled
            .iter()
            .map(|s| {
                let entries = match s.origin {
                    Origin::Seed(seed) => Some(lists::seed_entries(dir, s.id, seed)),
                    Origin::Fetched(_) => cache.as_ref().and_then(|c| lists::cached_entries(c, s.id)),
                };
                (s.id, entries)
            })
            .collect();
        let writer = dir.filter(|_| auto_error.is_none()).map(auto::Writer::for_dir);
        let layers = Layers { user: user_entries(policy_exclusions), lists: list_layers, auto, auto_error, browsers: BrowserSet::default() };
        let (set, next_expiry) = layers.build(now_ms);
        Self { dir: dir.map(Path::to_path_buf), writer, sources: enabled, skip_ev: SKIP_EV, layers: Mutex::new(layers), snapshot: Mutex::new(Snapshot { set: Arc::new(set), next_expiry }) }
    }

    /// The other value of the one dial with no setting yet.
    #[cfg(test)]
    pub fn without_ev_skip(self) -> Self {
        Self { skip_ev: false, ..self }
    }

    fn rebuild(&self, layers: &Layers, now_ms: u64) {
        let (set, next_expiry) = layers.build(now_ms);
        *lock(&self.snapshot) = Snapshot { set: Arc::new(set), next_expiry };
    }

    /// The snapshot, read once per flow.
    pub fn get(&self) -> Arc<ExclusionSet> {
        self.get_at(wall_ms())
    }

    /// The snapshot at `now_ms`: an `auto:ev` past its end is gone (and off
    /// the disk at the next write).
    pub fn get_at(&self, now_ms: u64) -> Arc<ExclusionSet> {
        let due = lock(&self.snapshot).next_expiry.is_some_and(|at| now_ms >= at);
        if due {
            self.rebuild(&lock(&self.layers), now_ms);
        }
        lock(&self.snapshot).set.clone()
    }

    /// The switches a flow is judged by. `root_ready` is the minter's to say.
    pub fn switches(&self, https: bool, root_ready: bool) -> Switches {
        Switches { https, root_ready, lists_ready: lock(&self.layers).lists_ready(), skip_ev: self.skip_ev, scope: SCOPE }
    }

    /// What is wrong with the file, for the status file: why the store holds the
    /// floor, or why the last write failed (which holds nothing up).
    pub fn error(&self) -> Option<String> {
        lock(&self.layers).auto_error.clone().or_else(|| self.writer.as_ref().and_then(auto::Writer::failure))
    }

    pub fn in_scope(&self, exe: Option<&str>) -> bool {
        exe.is_some_and(|e| lock(&self.layers).browsers.contains(e))
    }

    pub fn set_browsers(&self, browsers: BrowserSet) {
        lock(&self.layers).browsers = browsers;
    }

    /// The policy's exclusions changed.
    pub fn set_user(&self, lines: &[String], now_ms: u64) {
        let mut layers = lock(&self.layers);
        let user = user_entries(lines);
        if layers.user != user {
            layers.user = user;
            self.rebuild(&layers, now_ms);
        }
    }

    /// Slice 7 writes here too. Holds from this call on; the disk follows on the
    /// writer's thread, and a write that fails is reported by [`Self::error`].
    /// The newest [`auto::MAX_PER_REASON`] of a reason stay.
    pub fn add_auto(&self, entry: AutoEntry, now_ms: u64) {
        let mut layers = lock(&self.layers);
        layers.auto.retain(|e| !e.expired(now_ms));
        // A held entry moves to the newest place.
        layers.auto.retain(|e| e.pattern != entry.pattern || e.app != entry.app || e.reason != entry.reason);
        layers.auto.push(entry);
        auto::cap(&mut layers.auto);
        self.rebuild(&layers, now_ms);
        self.write(&layers);
    }

    /// True when an entry was removed ("Try decrypting again", plan 4.3).
    pub fn remove_auto(&self, pattern: &Pattern, app: Option<&str>) -> bool {
        let mut layers = lock(&self.layers);
        let before = layers.auto.len();
        layers.auto.retain(|e| !(&e.pattern == pattern && e.app.as_deref() == app));
        if layers.auto.len() == before {
            return false;
        }
        self.rebuild(&layers, wall_ms());
        self.write(&layers);
        true
    }

    fn write(&self, layers: &Layers) {
        if let Some(writer) = &self.writer {
            writer.queue(layers.auto.clone());
        }
    }

    /// Waits for the disk to hold everything added so far: a clean stop loses nothing.
    pub fn flush(&self) {
        if let Some(writer) = &self.writer {
            writer.flush();
        }
    }

    /// One look at every enabled fetched source; a new copy lands in the next
    /// snapshot, and the first copy of the last missing source ends the floor.
    pub async fn refresh<F: Fetcher>(&self, fetcher: &F, now_ms: u64) {
        let Some(cache) = self.dir.as_deref().map(Cache::new) else { return };
        let fetched: Vec<(&'static str, &'static str)> = self.sources.iter().filter_map(|s| if let Origin::Fetched(file) = s.origin { Some((s.id, file)) } else { None }).collect();
        for (id, file) in fetched {
            let replaced = lists::fetch_one(&cache, id, file, fetcher, now_ms).await;
            if !replaced {
                continue;
            }
            let entries = lists::cached_entries(&cache, id);
            let mut layers = lock(&self.layers);
            if let Some(slot) = layers.lists.iter_mut().find(|(have, _)| *have == id) {
                slot.1 = entries;
            }
            self.rebuild(&layers, now_ms);
        }
    }

    /// True when anything enabled is fetched, so there is a loop worth running.
    pub fn fetches(&self) -> bool {
        self.sources.iter().any(|s| matches!(s.origin, Origin::Fetched(_)))
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::IpAddr;
    use std::sync::Mutex as StdMutex;

    use sieve_filter::exclusions::{AutoReason, Source as Src, parse};
    use sieve_filter::lists::FetchResponse;

    use super::*;

    const NOW: u64 = 1_793_000_000_000;
    const DAY: u64 = 86_400_000;

    fn ip() -> IpAddr {
        "192.0.2.1".parse().unwrap()
    }

    fn find(slot: &ExclusionSlot, host: &str, now: u64) -> Option<Src> {
        slot.get_at(now).find(Some(host), ip(), Some(r"C:\b\browser.exe"), true).cloned()
    }

    fn pinned(host: &str) -> AutoEntry {
        AutoEntry::host(host, AutoReason::Pinning, NOW, None)
    }

    #[test]
    fn auto_entries_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let slot = ExclusionSlot::new(Some(dir.path()), &[], NOW);
        slot.add_auto(AutoEntry::host("cert.example", AutoReason::ClientCert, NOW, None), NOW);
        slot.add_auto(pinned("pin.example"), NOW);
        slot.flush();
        let again = ExclusionSlot::new(Some(dir.path()), &[], NOW + DAY);
        assert_eq!(find(&again, "cert.example", NOW + DAY), Some(Src::Auto(AutoReason::ClientCert)));
        assert_eq!(find(&again, "pin.example", NOW + DAY), Some(Src::Auto(AutoReason::Pinning)));
        assert!(again.remove_auto(&Pattern::Exact("pin.example".into()), None));
        assert!(!again.remove_auto(&Pattern::Exact("pin.example".into()), None));
        again.flush();
        let third = ExclusionSlot::new(Some(dir.path()), &[], NOW + DAY);
        assert_eq!(find(&third, "pin.example", NOW + DAY), None, "try again removed it");
    }

    #[test]
    fn an_unreadable_store_reads_as_no_exclusion_list() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [&b"{ not json"[..], br#"{"v":99,"entries":[]}"#, br#"{"v":1}"#] {
            std::fs::write(auto::path(dir.path()), bad).unwrap();
            let slot = ExclusionSlot::new(Some(dir.path()), &[], NOW);
            assert!(!slot.switches(true, true).lists_ready, "{:?}", String::from_utf8_lossy(bad));
            assert!(slot.error().is_some());
            slot.add_auto(pinned("pin.example"), NOW);
            slot.flush();
            drop(slot);
            assert_eq!(std::fs::read(auto::path(dir.path())).unwrap(), bad, "a damaged record is not overwritten");
        }
        std::fs::remove_file(auto::path(dir.path())).unwrap();
        assert!(ExclusionSlot::new(Some(dir.path()), &[], NOW).switches(true, true).lists_ready, "no file is no entries, not damage");
    }

    #[test]
    fn expired_auto_entry_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let slot = ExclusionSlot::new(Some(dir.path()), &[], NOW);
        slot.add_auto(AutoEntry::host("ev.example", AutoReason::Ev, NOW, Some(NOW + DAY)), NOW);
        slot.flush();
        assert_eq!(find(&slot, "ev.example", NOW + DAY - 1), Some(Src::Auto(AutoReason::Ev)));
        assert_eq!(find(&slot, "ev.example", NOW + DAY), None, "at its end");
        let again = ExclusionSlot::new(Some(dir.path()), &[], NOW + DAY);
        assert_eq!(find(&again, "ev.example", NOW + DAY), None, "and after a restart");
    }

    #[test]
    fn user_exclusions_come_from_the_policy_only() {
        let dir = tempfile::tempdir().unwrap();
        let slot = ExclusionSlot::new(Some(dir.path()), &["bank.example".to_string()], NOW);
        assert_eq!(find(&slot, "www.bank.example", NOW), Some(Src::User));
        slot.add_auto(pinned("pin.example"), NOW);
        slot.flush();
        assert!(!String::from_utf8(std::fs::read(auto::path(dir.path())).unwrap()).unwrap().contains("bank.example"), "never persisted a second time");
        slot.set_user(&[], NOW);
        assert_eq!(find(&slot, "www.bank.example", NOW), None);
    }

    #[test]
    fn a_flood_of_hosts_stays_bounded_and_spares_the_other_reasons() {
        const FLOOD: usize = 3 * auto::MAX_PER_REASON;
        let dir = tempfile::tempdir().unwrap();
        let slot = ExclusionSlot::new(Some(dir.path()), &[], NOW);
        slot.add_auto(pinned("pin.example"), NOW);
        let began = std::time::Instant::now();
        for i in 0..FLOOD {
            slot.add_auto(AutoEntry::host(&format!("h{i}.flood.example"), AutoReason::ClientCert, NOW, None), NOW);
        }
        println!("{FLOOD} add_auto: {:?}", began.elapsed());
        slot.flush();
        assert_eq!(lock(&slot.layers).auto.len(), auto::MAX_PER_REASON + 1);
        assert_eq!(find(&slot, "pin.example", NOW), Some(Src::Auto(AutoReason::Pinning)), "its own budget");
        assert_eq!(find(&slot, "h0.flood.example", NOW), None, "the oldest went");
        let newest = format!("h{}.flood.example", FLOOD - 1);
        assert_eq!(find(&slot, &newest, NOW), Some(Src::Auto(AutoReason::ClientCert)));
        let again = ExclusionSlot::new(Some(dir.path()), &[], NOW);
        assert_eq!(find(&again, &newest, NOW), Some(Src::Auto(AutoReason::ClientCert)), "the disk has the last state");
    }

    #[test]
    fn adding_a_held_entry_again_makes_it_the_newest() {
        let slot = ExclusionSlot::new(None, &[], NOW);
        slot.add_auto(pinned("a.example"), NOW);
        slot.add_auto(pinned("b.example"), NOW);
        slot.add_auto(AutoEntry::host("a.example", AutoReason::Pinning, NOW + 1, None), NOW + 1);
        let auto = &lock(&slot.layers).auto;
        assert_eq!(auto.iter().map(|e| (e.pattern.clone(), e.created_ms)).collect::<Vec<_>>(), [(Pattern::Exact("b.example".into()), NOW), (Pattern::Exact("a.example".into()), NOW + 1)]);
    }

    #[test]
    fn a_write_that_fails_is_reported_and_the_entry_still_holds() {
        let dir = tempfile::tempdir().unwrap();
        // `write_atomic` writes `exclusions.tmp` first; a folder there makes that fail.
        std::fs::create_dir(auto::path(dir.path()).with_extension("tmp")).unwrap();
        let slot = ExclusionSlot::new(Some(dir.path()), &[], NOW);
        assert_eq!(slot.error(), None);
        slot.add_auto(pinned("pin.example"), NOW);
        slot.flush();
        assert!(slot.error().is_some());
        assert_eq!(find(&slot, "pin.example", NOW), Some(Src::Auto(AutoReason::Pinning)));
        assert!(slot.switches(true, true).lists_ready, "a failed write is not a damaged record");
    }

    #[test]
    fn the_seed_loads_by_default_and_holds_nothing_up() {
        let slot = ExclusionSlot::new(None, &[], NOW);
        assert!(slot.switches(true, true).lists_ready);
        let first_entry = include_str!("../../../sieve-filter/data/sensitive.txt").lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with("//")).unwrap();
        assert_eq!(find(&slot, &format!("www.{first_entry}"), NOW), Some(Src::List("sensitive".into())));
        assert!(!slot.fetches());
    }

    #[derive(Default)]
    struct Fetch {
        answers: StdMutex<Vec<Result<FetchResponse, String>>>,
        asked: StdMutex<usize>,
    }

    impl Fetcher for Fetch {
        fn fetch(&self, _url: &str, _h: Vec<(&'static str, String)>) -> impl Future<Output = Result<FetchResponse, String>> + Send {
            *self.asked.lock().unwrap() += 1;
            let answer = self.answers.lock().unwrap().pop().unwrap_or(Err("nothing scripted".into()));
            async move { answer }
        }
    }

    fn fetched(enabled: bool) -> Vec<Source> {
        vec![Source { id: "hx-banks", origin: Origin::Fetched("banks.txt"), enabled }]
    }

    #[tokio::test]
    async fn disabled_source_never_fetches() {
        let dir = tempfile::tempdir().unwrap();
        let slot = ExclusionSlot::with_sources(Some(dir.path()), &[], fetched(false), NOW);
        let f = Fetch::default();
        slot.refresh(&f, NOW).await;
        assert_eq!(*f.asked.lock().unwrap(), 0);
        assert!(slot.switches(true, true).lists_ready, "disabled holds nothing up");
    }

    #[tokio::test]
    async fn an_enabled_source_not_yet_loaded_holds_the_floor() {
        let dir = tempfile::tempdir().unwrap();
        let slot = ExclusionSlot::with_sources(Some(dir.path()), &[], fetched(true), NOW);
        assert!(!slot.switches(true, true).lists_ready, "nothing fetched yet");
        let f = Fetch::default();
        slot.refresh(&f, NOW).await;
        assert_eq!(*f.asked.lock().unwrap(), 1);
        assert!(!slot.switches(true, true).lists_ready, "a failed fetch keeps the floor");
        f.answers.lock().unwrap().push(Ok(FetchResponse { status: 200, body: b"bank.example\n".to_vec(), ..FetchResponse::default() }));
        slot.refresh(&f, NOW + lists::REFRESH_MS).await;
        assert!(slot.switches(true, true).lists_ready, "the first copy ends it");
        assert_eq!(find(&slot, "bank.example", NOW + lists::REFRESH_MS), Some(Src::List("hx-banks".into())));
        let again = ExclusionSlot::with_sources(Some(dir.path()), &[], fetched(true), NOW + lists::REFRESH_MS);
        assert!(again.switches(true, true).lists_ready, "the cached copy counts after a restart");
        assert_eq!(parse("bank.example").entries.len(), 1);
    }

    #[test]
    fn scope_follows_the_browser_set() {
        struct One;
        impl browsers::BrowserRegistry for One {
            fn commands(&self) -> Vec<String> {
                vec![r"C:\b\browser.exe".to_string()]
            }
        }
        let slot = ExclusionSlot::new(None, &[], NOW);
        assert!(!slot.in_scope(Some(r"C:\b\browser.exe")), "nothing read yet");
        slot.set_browsers(BrowserSet::read(&One));
        assert!(slot.in_scope(Some(r"c:\B\browser.exe")));
        assert!(!slot.in_scope(Some(r"C:\b\other.exe")) && !slot.in_scope(None));
    }
}
