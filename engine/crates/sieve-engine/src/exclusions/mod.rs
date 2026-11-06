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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sieve_filter::exclusions::{AutoReason, Exclusion, ExclusionSet, Pattern, Scope, Source as EntrySource, Switches, parse_line};
use sieve_ipc::{ExclusionRow, ExclusionScope, ExclusionsView};

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

/// The file a `live-scope` build reads at start (task D10): slice 7's live check
/// needs a client that is not a browser to be intercepted at all, and browsers
/// first means none is. A diagnostic build's alone; a release build has neither
/// this code nor the file's meaning.
#[cfg(feature = "live-scope")]
pub const LIVE_SCOPE_FILE: &str = "live-scope.json";

/// `{"scope":"all"}` in the engine's folder widens this run; anything else is
/// the production floor, so a damaged file cannot widen anything (S24).
#[cfg(feature = "live-scope")]
fn start_scope(dir: Option<&Path>) -> Scope {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LiveScope {
        scope: String,
    }
    let asked = dir.and_then(|d| std::fs::read(d.join(LIVE_SCOPE_FILE)).ok()).and_then(|bytes| serde_json::from_slice::<LiveScope>(&bytes).ok());
    if asked.is_some_and(|a| a.scope == "all") { Scope::All } else { SCOPE }
}

#[cfg(not(feature = "live-scope"))]
fn start_scope(_dir: Option<&Path>) -> Scope {
    SCOPE
}

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
        for entry in self.auto.iter().filter(|e| e.is_held(now_ms)) {
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

    /// The rows the app shows from the engine: the lists, then what the engine wrote.
    fn rows(&self, now_ms: u64) -> Vec<ExclusionRow> {
        let listed = self.lists.iter().flat_map(|(id, entries)| {
            entries.iter().flatten().map(move |e| ExclusionRow { line: e.pattern.line(), apps: e.apps.clone(), reason: EntrySource::List((*id).to_string()).slug(), created_ms: None, retries: 0 })
        });
        let written = self.auto.iter().filter(|e| e.is_held(now_ms)).map(|e| ExclusionRow { line: e.pattern.line(), apps: e.app.iter().cloned().collect(), reason: e.reason.slug().to_string(), created_ms: Some(e.created_ms), retries: e.retries });
        listed.chain(written).collect()
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
    scope: Scope,
    layers: Mutex<Layers>,
    snapshot: Mutex<Snapshot>,
    /// Raised by every rebuild: the app reads the rows only when this moved.
    revision: AtomicU64,
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
        Self { dir: dir.map(Path::to_path_buf), writer, sources: enabled, skip_ev: SKIP_EV, scope: start_scope(dir), layers: Mutex::new(layers), snapshot: Mutex::new(Snapshot { set: Arc::new(set), next_expiry }), revision: AtomicU64::new(0) }
    }

    /// The other value of the one dial with no setting yet.
    #[cfg(test)]
    pub fn without_ev_skip(self) -> Self {
        Self { skip_ev: false, ..self }
    }

    fn rebuild(&self, layers: &Layers, now_ms: u64) {
        let (set, next_expiry) = layers.build(now_ms);
        *lock(&self.snapshot) = Snapshot { set: Arc::new(set), next_expiry };
        self.revision.fetch_add(1, Ordering::Relaxed);
    }

    /// Moves when the rows may have.
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }

    /// The `list:*` and held `auto:*` rows. The `user` layer is the app's own.
    pub fn rows(&self, now_ms: u64) -> Vec<ExclusionRow> {
        lock(&self.layers).rows(now_ms)
    }

    /// What the app is told of the store and of this engine's reach, the fact
    /// `decrypt` uses (S14).
    pub fn view(&self, now_ms: u64) -> ExclusionsView {
        // Read before the rows: a change in between shows as a newer revision.
        let revision = self.revision();
        let layers = lock(&self.layers);
        let scope = match self.scope {
            Scope::Browsers => ExclusionScope::Browsers,
            Scope::All => ExclusionScope::All,
        };
        ExclusionsView { revision, rows: layers.rows(now_ms), scope, browsers: layers.browsers.paths() }
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
        Switches { https, root_ready, lists_ready: lock(&self.layers).lists_ready(), skip_ev: self.skip_ev, scope: self.scope }
    }

    /// What is wrong with the file, for the status file: why the store holds the
    /// floor, or why the last write failed (which holds nothing up).
    pub fn error(&self) -> Option<String> {
        lock(&self.layers).auto_error.clone().or_else(|| self.writer.as_ref().and_then(auto::Writer::failure))
    }

    pub fn in_scope(&self, exe: Option<&str>) -> bool {
        exe.is_some_and(|e| lock(&self.layers).browsers.contains(e))
    }

    /// A changed set is news to the app's "in scope" line.
    pub fn set_browsers(&self, browsers: BrowserSet) {
        let mut layers = lock(&self.layers);
        if layers.browsers != browsers {
            layers.browsers = browsers;
            self.revision.fetch_add(1, Ordering::Relaxed);
        }
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

    /// An entry the engine writes: `tls::intercept` and `heal`. Holds from this call
    /// on; the disk follows on the writer's thread, and a write that fails is
    /// reported by [`Self::error`]. The newest [`auto::MAX_PER_REASON`] of a reason
    /// stay. True when this newly excludes something. Over any entry of the same
    /// pattern, app and reason it keeps the first date and the count: the entry comes
    /// back with its history, and another refusal of it changes neither.
    pub fn add_auto(&self, mut entry: AutoEntry, now_ms: u64) -> bool {
        let mut layers = lock(&self.layers);
        layers.auto.retain(|e| !e.expired(now_ms));
        let same = |e: &AutoEntry| e.pattern == entry.pattern && e.app == entry.app && e.reason == entry.reason;
        let before = layers.auto.iter().position(same).map(|at| layers.auto.remove(at));
        // Its place is the newest: `cap` goes by position, not by date.
        if let Some(before) = &before {
            entry.retries = before.retries;
            entry.created_ms = before.created_ms;
        }
        let newly = before.is_none_or(|b| b.retrying);
        layers.auto.push(entry);
        auto::cap(&mut layers.auto);
        self.rebuild(&layers, now_ms);
        self.write(&layers);
        newly
    }

    /// "Try decrypting again" (plan 4.3) on one row: the entry stops excluding and
    /// remembers the try. Only that row: another reason's entry for the same pattern
    /// and app stands. It can only touch this layer: not a user line, not a list line,
    /// not a floor fact (S24). False when there is no such entry held.
    pub fn try_again(&self, pattern: &Pattern, app: Option<&str>, reason: AutoReason, now_ms: u64) -> bool {
        !self.take_back(now_ms, |e| &e.pattern == pattern && e.app.as_deref() == app && e.reason == reason).is_empty()
    }

    /// The bulk form, for one app's entries of one reason. The patterns taken back.
    pub fn try_again_app(&self, app: &str, reason: AutoReason, now_ms: u64) -> Vec<Pattern> {
        self.take_back(now_ms, |e| e.reason == reason && e.app.as_deref() == Some(app))
    }

    fn take_back(&self, now_ms: u64, named: impl Fn(&AutoEntry) -> bool) -> Vec<Pattern> {
        let mut layers = lock(&self.layers);
        let mut taken = Vec::new();
        for entry in layers.auto.iter_mut().filter(|e| e.is_held(now_ms) && named(e)) {
            entry.retrying = true;
            entry.retries = entry.retries.saturating_add(1);
            taken.push(entry.pattern.clone());
        }
        if !taken.is_empty() {
            self.rebuild(&layers, now_ms);
            self.write(&layers);
        }
        taken
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
        assert!(again.try_again(&Pattern::Exact("pin.example".into()), None, AutoReason::Pinning, NOW + DAY));
        assert!(!again.try_again(&Pattern::Exact("pin.example".into()), None, AutoReason::Pinning, NOW + DAY), "already taken back");
        again.flush();
        let third = ExclusionSlot::new(Some(dir.path()), &[], NOW + DAY);
        assert_eq!(find(&third, "pin.example", NOW + DAY), None, "try again removed it");
    }

    #[test]
    fn a_retrying_entry_survives_a_restart_and_is_not_an_exclusion() {
        let dir = tempfile::tempdir().unwrap();
        let slot = ExclusionSlot::new(Some(dir.path()), &[], NOW);
        slot.add_auto(pinned("pin.example"), NOW);
        assert!(slot.try_again(&Pattern::Exact("pin.example".into()), None, AutoReason::Pinning, NOW + 1));
        slot.flush();
        let again = ExclusionSlot::new(Some(dir.path()), &[], NOW + DAY);
        assert_eq!(find(&again, "pin.example", NOW + DAY), None, "not an exclusion");
        assert!(again.rows(NOW + DAY).iter().all(|r| !r.reason.starts_with("auto:")), "and no row");
        assert!(again.add_auto(AutoEntry::host("pin.example", AutoReason::Pinning, NOW + DAY, None), NOW + DAY), "it newly excludes");
        let row = again.rows(NOW + DAY).into_iter().find(|r| r.reason == "auto:pinning").unwrap();
        assert_eq!((row.created_ms, row.retries), (Some(NOW), 1), "with its history, across the restart");
    }

    #[test]
    fn add_auto_says_when_it_newly_excludes() {
        let slot = ExclusionSlot::new(None, &[], NOW);
        assert!(slot.add_auto(pinned("a.example"), NOW), "new");
        assert!(!slot.add_auto(pinned("a.example"), NOW), "held");
        assert!(slot.add_auto(AutoEntry::host("a.example", AutoReason::ClientCert, NOW, None), NOW), "another reason is another entry");
        assert!(slot.try_again(&Pattern::Exact("a.example".into()), None, AutoReason::Pinning, NOW));
        assert!(slot.add_auto(pinned("a.example"), NOW), "back from a retry");
    }

    #[test]
    fn retry_cannot_touch_a_user_line_a_list_line_or_a_floor_fact() {
        use sieve_filter::exclusions::restricted_suffix;
        let slot = ExclusionSlot::new(None, &["bank.example".to_string()], NOW);
        assert_eq!(find(&slot, "bank.example", NOW), Some(Src::User));
        assert!(!slot.try_again(&Pattern::Subdomains("bank.example".into()), None, AutoReason::Pinning, NOW), "a user line");
        assert_eq!(find(&slot, "bank.example", NOW), Some(Src::User));
        // The seed's own line: it names a real exclusion the test need not spell.
        let listed = slot.rows(NOW).into_iter().find(|r| r.reason == "list:sensitive").expect("the seed has rows");
        let entry = parse_line(&listed.line).unwrap();
        assert!(!slot.try_again(&entry.pattern, None, AutoReason::Pinning, NOW), "a list line");
        assert_eq!(slot.rows(NOW).iter().filter(|r| r.line == listed.line).count(), 1);
        assert!(!slot.try_again(&Pattern::Exact("service.gov.uk".into()), None, AutoReason::Pinning, NOW), "a floor fact has no entry to take back");
        assert!(restricted_suffix("service.gov.uk"), "and stands whatever the store says");
    }

    #[test]
    fn retry_of_nothing_is_false() {
        let slot = ExclusionSlot::new(None, &[], NOW);
        assert!(!slot.try_again(&Pattern::Exact("pin.example".into()), None, AutoReason::Pinning, NOW));
        slot.add_auto(AutoEntry::for_app("pin.example", "client.exe", AutoReason::Pinning, NOW), NOW);
        assert!(!slot.try_again(&Pattern::Exact("pin.example".into()), Some("other.exe"), AutoReason::Pinning, NOW), "another app's");
        assert!(!slot.try_again(&Pattern::Exact("pin.example".into()), None, AutoReason::Pinning, NOW), "every app's is another entry");
        assert!(slot.try_again(&Pattern::Exact("pin.example".into()), Some("client.exe"), AutoReason::Pinning, NOW), "the control");
    }

    #[test]
    fn try_again_takes_back_that_row_and_not_another_reason_on_the_same_host() {
        let slot = ExclusionSlot::new(None, &[], NOW);
        let host = Pattern::Exact("both.example".into());
        slot.add_auto(AutoEntry::host("both.example", AutoReason::ClientCert, NOW, None), NOW);
        slot.add_auto(AutoEntry::host("both.example", AutoReason::Ev, NOW, Some(NOW + DAY)), NOW);
        assert!(!slot.try_again(&host, None, AutoReason::Pinning, NOW), "no such row");
        assert!(slot.try_again(&host, None, AutoReason::Ev, NOW));
        let rows = slot.rows(NOW);
        let left: Vec<&str> = rows.iter().filter(|r| r.reason.starts_with("auto:")).map(|r| r.reason.as_str()).collect();
        assert_eq!(left, ["auto:client-cert"]);
        assert_eq!(find(&slot, "both.example", NOW), Some(Src::Auto(AutoReason::ClientCert)), "still excluded, by the row left");
    }

    #[test]
    fn the_revision_moves_when_the_rows_do() {
        let slot = ExclusionSlot::new(None, &[], NOW);
        let start = slot.revision();
        slot.add_auto(pinned("a.example"), NOW);
        let added = slot.revision();
        assert!(added > start);
        assert!(!slot.try_again(&Pattern::Exact("none.example".into()), None, AutoReason::Pinning, NOW));
        assert_eq!(slot.revision(), added, "nothing changed");
        slot.try_again(&Pattern::Exact("a.example".into()), None, AutoReason::Pinning, NOW);
        assert!(slot.revision() > added);
    }

    #[test]
    fn the_user_layer_is_not_sent() {
        let slot = ExclusionSlot::new(None, &["mine.example".to_string()], NOW);
        slot.add_auto(AutoEntry::for_app("pin.example", "client.exe", AutoReason::Pinning, NOW), NOW);
        slot.add_auto(AutoEntry::host("ev.example", AutoReason::Ev, NOW, Some(NOW + DAY)), NOW);
        let rows = slot.rows(NOW);
        assert!(rows.iter().all(|r| !r.line.contains("mine.example") && r.reason != "user"), "the user layer is not sent");
        assert!(rows.iter().any(|r| r.line == "\"pin.example\"" && r.apps == ["client.exe"] && r.reason == "auto:pinning"));
        assert!(rows.iter().any(|r| r.reason == "list:sensitive" && r.created_ms.is_none()));
        assert!(!slot.rows(NOW + DAY).iter().any(|r| r.reason == "auto:ev"), "gone at its end");
    }

    #[test]
    fn the_view_says_the_scope_and_the_browsers_decrypt_uses() {
        struct One;
        impl browsers::BrowserRegistry for One {
            fn commands(&self) -> Vec<String> {
                vec![r"C:\B\Browser.exe".to_string()]
            }
        }
        let slot = ExclusionSlot::new(None, &[], NOW);
        assert_eq!(slot.view(NOW).scope, ExclusionScope::Browsers);
        let before = slot.revision();
        slot.set_browsers(BrowserSet::read(&One));
        assert_eq!(slot.view(NOW).browsers, [r"c:\b\browser.exe"]);
        assert!(slot.view(NOW).revision > before, "the app's in-scope line reads it");
    }

    #[cfg(feature = "live-scope")]
    #[test]
    fn a_live_scope_file_widens_this_run_and_nothing_else_does() {
        let dir = tempfile::tempdir().unwrap();
        let scope_of = |dir: &Path| ExclusionSlot::new(Some(dir), &[], NOW).switches(true, true).scope;
        assert_eq!(scope_of(dir.path()), Scope::Browsers, "no file");
        for bad in ["not json", r#"{"scope":"browsers"}"#, r#"{"scope":"all","x":1}"#] {
            std::fs::write(dir.path().join(LIVE_SCOPE_FILE), bad).unwrap();
            assert_eq!(scope_of(dir.path()), Scope::Browsers, "{bad}");
        }
        std::fs::write(dir.path().join(LIVE_SCOPE_FILE), r#"{"scope":"all"}"#).unwrap();
        assert_eq!(scope_of(dir.path()), Scope::All);
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
        assert_eq!(auto.iter().map(|e| (e.pattern.clone(), e.created_ms)).collect::<Vec<_>>(), [(Pattern::Exact("b.example".into()), NOW), (Pattern::Exact("a.example".into()), NOW)], "the newest place, its first date");
    }

    #[test]
    fn retry_refuse_refuse_keeps_the_first_date() {
        let slot = ExclusionSlot::new(None, &[], NOW);
        let again = |at| slot.add_auto(AutoEntry::host("a.example", AutoReason::Pinning, at, None), at);
        assert!(again(NOW));
        assert!(slot.try_again(&Pattern::Exact("a.example".into()), None, AutoReason::Pinning, NOW + 1));
        assert!(again(NOW + 2), "back from the retry");
        assert!(!again(NOW + 3), "held");
        let row = slot.rows(NOW + 3).into_iter().find(|r| r.reason == "auto:pinning").unwrap();
        assert_eq!((row.created_ms, row.retries), (Some(NOW), 1));
    }

    #[test]
    fn an_entry_past_its_end_starts_a_new_date() {
        let slot = ExclusionSlot::new(None, &[], NOW);
        slot.add_auto(AutoEntry::host("ev.example", AutoReason::Ev, NOW, Some(NOW + 1)), NOW);
        assert!(slot.add_auto(AutoEntry::host("ev.example", AutoReason::Ev, NOW + 2, Some(NOW + 3)), NOW + 2), "gone, so new");
        let row = slot.rows(NOW + 2).into_iter().find(|r| r.reason == "auto:ev").unwrap();
        assert_eq!(row.created_ms, Some(NOW + 2));
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
        assert_eq!(find(&slot, "www.paypal.com", NOW), Some(Src::List("sensitive".into())));
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
