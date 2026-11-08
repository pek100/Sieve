//! Each app's recent problems (the owner's rule: Sieve must never break another
//! app's traffic, and when an app has trouble the user can see whether Sieve is
//! the likely cause). What went wrong, how often, when, with whom, and the cause
//! from the one table, `sieve_ipc::Signal::cause`.
//!
//! Pure: the flow book feeds it with the time, the pipe reads [`Issues::view`].
//! Memory is bounded by [`MAX_TRACKED_APPS`] records of at most
//! `MAX_APP_PROBLEMS` problems; whatever a bound lets go is counted in
//! [`Issues::dropped`]. Memory only: nothing is written to disk or sent anywhere
//! but the local pipe.

use std::collections::HashMap;

use sieve_ipc::{AppIssues, ISSUE_HOST_MAX, ISSUE_NAME_MAX, MAX_APP_PROBLEMS, MAX_ISSUE_APPS, Problem, Signal, cap_text};

/// A problem not heard again for this long is let go: "recent" is the last hour,
/// long enough to cover an updater that retries on its own schedule and short
/// enough that a problem fixed this morning no longer reads as one.
pub const KEEP_MS: u64 = 60 * 60_000;
/// Apps held at once, problems or not: a record also holds the app's flow count
/// and when Sieve first saw it, which the app's notice reads, so an app is not
/// forgotten just because others have no trouble. A bound with room for every
/// app one PC runs, not a tuned value; the pipe shows at most `MAX_ISSUE_APPS`.
pub const MAX_TRACKED_APPS: usize = 512;

/// One app: its `apps.levels` key and its flows' session (None for a VM).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AppId {
    pub key: String,
    pub session: Option<u32>,
}

#[derive(Debug, Default)]
struct Record {
    exe: Option<String>,
    /// The app's first flow since the routes last came up.
    since_ms: Option<u64>,
    flows: u64,
    retried: u64,
    recovered: u64,
    /// Oldest first in no order that matters; at most `MAX_APP_PROBLEMS`.
    problems: Vec<Problem>,
    touched_ms: u64,
}

impl Record {
    fn live(&self, now_ms: u64) -> impl Iterator<Item = &Problem> {
        self.problems.iter().filter(move |p| p.last_ms.saturating_add(KEEP_MS) > now_ms)
    }

    fn newest(&self, now_ms: u64) -> Option<u64> {
        self.live(now_ms).map(|p| p.last_ms).max()
    }
}

#[derive(Debug, Default)]
pub struct Issues {
    apps: HashMap<AppId, Record>,
    /// Moves when a problem or a retry is heard, or the routes come up again.
    revision: u64,
    /// Problems let go to keep the bounds (not those that only grew old).
    dropped: u64,
}

impl Issues {
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The app's record, made room for at the cap: an app with no live problem
    /// goes first, then the one touched longest ago, its problems counted.
    fn record(&mut self, app: &AppId, exe: Option<&str>, now_ms: u64) -> &mut Record {
        let app = AppId { key: cap_text(&app.key, ISSUE_NAME_MAX).to_string(), session: app.session };
        if !self.apps.contains_key(&app) && self.apps.len() >= MAX_TRACKED_APPS {
            let victim = self.apps.iter().min_by_key(|(_, r)| (r.newest(now_ms).is_some(), r.touched_ms)).map(|(id, r)| (id.clone(), r.live(now_ms).count()));
            if let Some((id, lost)) = victim {
                self.apps.remove(&id);
                self.dropped += lost as u64;
            }
        }
        let record = self.apps.entry(app).or_default();
        if let Some(exe) = exe {
            record.exe = Some(cap_text(exe, ISSUE_NAME_MAX).to_string());
        }
        record.touched_ms = now_ms;
        record
    }

    /// A flow of the app opened.
    pub fn seen(&mut self, app: &AppId, exe: Option<&str>, now_ms: u64) {
        self.record(app, exe, now_ms).since_ms.get_or_insert(now_ms);
    }

    /// A flow of the app ended. Counted, not a revision: the count is context
    /// for the problems and is read with them.
    pub fn ended(&mut self, app: &AppId, now_ms: u64) {
        let record = self.record(app, None, now_ms);
        record.flows = record.flows.saturating_add(1);
    }

    /// One problem of one flow.
    pub fn problem(&mut self, app: &AppId, exe: Option<&str>, signal: Signal, host: Option<&str>, now_ms: u64) {
        let host = host.map(|h| cap_text(h, ISSUE_HOST_MAX).to_string());
        let record = self.record(app, exe, now_ms);
        record.since_ms.get_or_insert(now_ms);
        record.problems.retain(|p| p.last_ms.saturating_add(KEEP_MS) > now_ms);
        let mut lost = 0;
        if let Some(p) = record.problems.iter_mut().find(|p| p.signal == signal && p.host == host) {
            p.count = p.count.saturating_add(1);
            p.last_ms = p.last_ms.max(now_ms);
        } else {
            if record.problems.len() >= MAX_APP_PROBLEMS
                && let Some(oldest) = record.problems.iter().enumerate().min_by_key(|(_, p)| p.last_ms).map(|(i, _)| i)
            {
                record.problems.swap_remove(oldest);
                lost = 1;
            }
            record.problems.push(Problem { signal, cause: signal.cause(), host, count: 1, first_ms: now_ms, last_ms: now_ms });
        }
        self.dropped += lost;
        self.revision += 1;
    }

    /// Sieve tried one of the app's connections again (`stack::retry`).
    pub fn retried(&mut self, app: &AppId, exe: Option<&str>, recovered: bool, now_ms: u64) {
        let record = self.record(app, exe, now_ms);
        record.retried = record.retried.saturating_add(1);
        record.recovered = record.recovered.saturating_add(u64::from(recovered));
        self.revision += 1;
    }

    /// The routes came up again: "since Sieve started filtering it" starts over,
    /// and the problems stay until they grow old.
    pub fn restart(&mut self) {
        for record in self.apps.values_mut() {
            record.since_ms = None;
            record.flows = 0;
        }
        self.revision += 1;
    }

    /// The apps with a live problem that `visible` lets through, newest problem
    /// first, at most `MAX_ISSUE_APPS`; each app's problems newest first.
    pub fn view(&self, visible: impl Fn(Option<u32>) -> bool, now_ms: u64) -> Vec<AppIssues> {
        let mut apps: Vec<(u64, AppIssues)> = self
            .apps
            .iter()
            .filter(|(id, _)| visible(id.session))
            .filter_map(|(id, r)| {
                let newest = r.newest(now_ms)?;
                let mut problems: Vec<Problem> = r.live(now_ms).cloned().collect();
                problems.sort_by_key(|p| std::cmp::Reverse(p.last_ms));
                let since_ms = r.since_ms.unwrap_or_else(|| problems.iter().map(|p| p.first_ms).min().unwrap_or(now_ms));
                Some((newest, AppIssues { key: id.key.clone(), exe: r.exe.clone(), session: id.session, since_ms, flows: r.flows, retried: r.retried, recovered: r.recovered, problems }))
            })
            .collect();
        apps.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.key.cmp(&b.1.key)));
        apps.truncate(MAX_ISSUE_APPS);
        apps.into_iter().map(|(_, a)| a).collect()
    }
}

#[cfg(test)]
mod tests {
    use sieve_ipc::{Cause, EngineMessage, MAX_FRAME, encode};

    use super::*;

    const NOW: u64 = 1_793_000_000_000;

    fn app(key: &str) -> AppId {
        AppId { key: key.into(), session: Some(1) }
    }

    fn everyone(_: Option<u32>) -> bool {
        true
    }

    #[test]
    fn a_problem_carries_its_signals_cause_and_counts_repeats_by_host() {
        let mut i = Issues::default();
        i.seen(&app("game"), Some("launcher.exe"), NOW);
        for t in [1, 2, 3] {
            i.problem(&app("game"), None, Signal::ConnectTimeout, Some("cdn.example"), NOW + t);
        }
        i.problem(&app("game"), None, Signal::Blocked, Some("ads.example"), NOW + 9);
        let view = i.view(everyone, NOW + 10);
        assert_eq!(view.len(), 1);
        let a = &view[0];
        assert_eq!((a.key.as_str(), a.exe.as_deref(), a.since_ms), ("game", Some("launcher.exe"), NOW));
        assert_eq!(a.problems.iter().map(|p| (p.signal, p.cause, p.count)).collect::<Vec<_>>(), [(Signal::Blocked, Cause::Sieve, 1), (Signal::ConnectTimeout, Cause::Network, 3)], "newest first");
        assert_eq!((a.problems[1].first_ms, a.problems[1].last_ms), (NOW + 1, NOW + 3));
    }

    #[test]
    fn an_app_without_problems_is_not_shown_and_old_problems_go() {
        let mut i = Issues::default();
        i.seen(&app("quiet"), None, NOW);
        i.ended(&app("quiet"), NOW);
        i.problem(&app("old"), None, Signal::Stall, Some("x.example"), NOW);
        assert_eq!(i.view(everyone, NOW + 1).len(), 1, "the control: the old one is still recent");
        assert!(i.view(everyone, NOW + KEEP_MS).is_empty(), "an hour later neither shows");
        assert_eq!(i.dropped(), 0, "growing old is not a drop");
    }

    #[test]
    fn the_view_shows_only_what_the_client_may_see() {
        let mut i = Issues::default();
        i.problem(&AppId { key: "mine".into(), session: Some(1) }, None, Signal::Stall, None, NOW);
        i.problem(&AppId { key: "theirs".into(), session: Some(2) }, None, Signal::Stall, None, NOW);
        let keys: Vec<String> = i.view(|s| s == Some(1), NOW).into_iter().map(|a| a.key).collect();
        assert_eq!(keys, ["mine"]);
    }

    #[test]
    fn a_restart_starts_since_and_flows_over_and_keeps_problems() {
        let mut i = Issues::default();
        i.seen(&app("game"), None, NOW);
        i.ended(&app("game"), NOW);
        i.problem(&app("game"), None, Signal::Stall, None, NOW);
        i.restart();
        i.seen(&app("game"), None, NOW + 50);
        let a = &i.view(everyone, NOW + 60)[0];
        assert_eq!((a.since_ms, a.flows, a.problems.len()), (NOW + 50, 0, 1));
    }

    #[test]
    fn retries_count_what_recovered() {
        let mut i = Issues::default();
        i.retried(&app("game"), None, true, NOW);
        i.retried(&app("game"), None, false, NOW);
        i.problem(&app("game"), None, Signal::ConnectRefused, Some("192.0.2.1"), NOW);
        let a = &i.view(everyone, NOW)[0];
        assert_eq!((a.retried, a.recovered), (2, 1));
    }

    #[test]
    fn revision_moves_with_problems_and_retries_but_not_flow_counts() {
        let mut i = Issues::default();
        i.seen(&app("game"), None, NOW);
        i.ended(&app("game"), NOW);
        assert_eq!(i.revision(), 0);
        i.problem(&app("game"), None, Signal::Stall, None, NOW);
        i.retried(&app("game"), None, true, NOW);
        assert_eq!(i.revision(), 2);
    }

    /// A flood of apps, hosts and signals: memory stays at the caps, every
    /// problem a bound let go is counted, and the answer still fits one frame.
    #[test]
    fn a_flood_stays_within_the_caps_and_counts_what_it_lets_go() {
        let mut i = Issues::default();
        let long = "h".repeat(ISSUE_HOST_MAX + 100);
        let apps = MAX_TRACKED_APPS * 2;
        let per_app = MAX_APP_PROBLEMS * 3;
        for a in 0..apps {
            let id = AppId { key: format!("{a}-{}", "k".repeat(ISSUE_NAME_MAX)), session: Some(1) };
            for p in 0..per_app {
                let host = format!("{p}{long}");
                i.problem(&id, Some(&"e".repeat(ISSUE_NAME_MAX + 9)), Signal::ALL[p % Signal::ALL.len()], Some(&host), NOW + (a * per_app + p) as u64);
            }
        }
        assert_eq!(i.apps.len(), MAX_TRACKED_APPS);
        assert!(i.apps.values().all(|r| r.problems.len() <= MAX_APP_PROBLEMS));
        assert!(i.apps.values().flat_map(|r| &r.problems).all(|p| p.host.as_ref().is_some_and(|h| h.len() <= ISSUE_HOST_MAX)));
        let within_apps = (apps * (per_app - MAX_APP_PROBLEMS)) as u64;
        let whole_apps = ((apps - MAX_TRACKED_APPS) * MAX_APP_PROBLEMS) as u64;
        assert_eq!(i.dropped(), within_apps + whole_apps, "each lost problem is counted once");
        let view = i.view(everyone, NOW + (apps * per_app) as u64);
        assert_eq!(view.len(), MAX_ISSUE_APPS);
        assert!(view.windows(2).all(|w| w[0].problems[0].last_ms >= w[1].problems[0].last_ms), "newest first");
        let frame = encode(&EngineMessage::Issues { run: NOW, revision: i.revision(), apps: view, dropped: i.dropped() }).unwrap();
        assert!(frame.len() <= MAX_FRAME);
    }

    #[test]
    fn an_app_with_trouble_outlasts_quiet_apps_at_the_cap() {
        let mut i = Issues::default();
        i.problem(&app("troubled"), None, Signal::Stall, None, NOW);
        for a in 0..MAX_TRACKED_APPS {
            i.seen(&app(&format!("quiet{a}")), None, NOW + 1 + a as u64);
        }
        assert_eq!(i.view(everyone, NOW + 10_000).iter().map(|a| a.key.as_str()).collect::<Vec<_>>(), ["troubled"]);
        assert_eq!(i.dropped(), 0, "a quiet app holds no problem to lose");
    }
}
