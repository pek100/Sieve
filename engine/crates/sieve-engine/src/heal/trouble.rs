//! The per-app pass-through (the owner's fail-open rule): an app that refuses
//! Sieve's certificate for [`TROUBLE_HOSTS`] different sites within
//! [`TROUBLE_WINDOW_MS`], starting within [`TROUBLE_AFTER_START_MS`] of Sieve first
//! decrypting it, is refusing Sieve itself (its own trust store, or pinning
//! everywhere), not one site. It then goes through untouched, every site, for
//! [`FAIL_OPEN_MS`]: one `auto:failing` entry for its exe's full path in its session
//! (`exclusions::WholeApp`). No decryption means no content change either; a host
//! block is the filter's and stays.
//!
//! What self-healing already covers is left to it: `score` still excludes each
//! (app, site) by its own rule, unchanged. This adds only the step from "each site
//! costs a failure" to "the app's next sites cost nothing". A site counts only when
//! the client sent an alert refusing Sieve and `score` excluded the site for it
//! (P1-1 of the 2026-11-08 second review): a client that just goes away mid
//! handshake (a tab closed, a laptop asleep, the handshake timed out) says nothing
//! about Sieve's certificate. Only a flow Sieve decrypted is evidence, so a floor
//! site (never decrypted), a block and a network failure never are.
//!
//! When the pass-through ends, or the user takes it back, decrypting begins again
//! and so does [`TROUBLE_AFTER_START_MS`].

use std::collections::HashMap;

/// Different sites refused that make it the app and not a site. Self-healing
/// excludes a site at its first fatal refusal, so two can be two pinned sites;
/// three in a couple of minutes, all fresh, is an app that trusts nothing Sieve
/// signs.
pub const TROUBLE_HOSTS: usize = 3;
/// See [`TROUBLE_HOSTS`]: a fixed window from the first refusal, so refusals
/// spread over an hour of use never add up.
pub const TROUBLE_WINDOW_MS: u64 = 2 * 60_000;
/// "Right after Sieve began decrypting it": a window may start this long after
/// the app's first decrypted connection of the run at most. Later, an app worked
/// with Sieve, and a site that starts refusing is self-healing's case alone.
pub const TROUBLE_AFTER_START_MS: u64 = 10 * 60_000;
/// How long the app goes through untouched. A day: long enough for an update or
/// a game session to finish, short enough that decryption comes back by itself;
/// the user can keep it so or try again sooner.
pub const FAIL_OPEN_MS: u64 = 24 * 60 * 60_000;
/// Apps watched at once, oldest first out (counted). A memory bound with room for
/// every app one person runs; an app let go only starts its count over.
pub const MAX_TROUBLE_APPS: usize = 256;

#[derive(Debug)]
struct App {
    /// When Sieve began decrypting it: its first decrypted connection of the run,
    /// or the end of its last pass-through, when decrypting began again.
    first_ms: u64,
    /// The window's start and the sites refused in it.
    window: Option<(u64, Vec<String>)>,
    /// The end of the pass-through this rule gave it, while it lasts.
    open_until: Option<u64>,
}

/// One app as the rule counts it: the exe's full path, lower case, and its
/// Windows session (P2-5 of the 2026-11-08 second review). A file name alone would
/// let any exe named like a browser, or the same app of another user, add to the
/// real app's count.
pub type AppKey = (String, u32);

pub fn key(exe: &str, session: u32) -> AppKey {
    (exe.to_ascii_lowercase(), session)
}

#[derive(Debug, Default)]
pub struct Trouble {
    apps: HashMap<AppKey, App>,
    dropped: u64,
}

impl Trouble {
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    fn app(&mut self, key: &AppKey, now_ms: u64) -> &mut App {
        if !self.apps.contains_key(key)
            && self.apps.len() >= MAX_TROUBLE_APPS
            && let Some(oldest) = self.apps.iter().min_by_key(|(_, a)| a.first_ms).map(|(k, _)| k.clone())
        {
            self.apps.remove(&oldest);
            self.dropped += 1;
        }
        let app = self.apps.entry(key.clone()).or_insert(App { first_ms: now_ms, window: None, open_until: None });
        // Past its pass-through, Sieve begins decrypting it again: the rule arms
        // again from then, as at the start.
        if let Some(end) = app.open_until.filter(|end| now_ms >= *end) {
            (app.first_ms, app.window, app.open_until) = (end, None, None);
        }
        app
    }

    /// Any evidence of a decrypted connection of the app.
    pub fn heard(&mut self, key: &AppKey, now_ms: u64) {
        self.app(key, now_ms);
    }

    /// The app passes through until `until`; see [`Self::rearm`].
    pub fn opened(&mut self, key: &AppKey, until: u64, now_ms: u64) {
        self.app(key, now_ms).open_until = Some(until);
    }

    /// "Try decrypting again" took the pass-through back at `now_ms`: decrypting
    /// begins again now, and so does the rule's window.
    pub fn rearm(&mut self, key: &AppKey, now_ms: u64) {
        let app = self.app(key, now_ms);
        (app.first_ms, app.window, app.open_until) = (now_ms, None, None);
    }

    /// The app refused Sieve's certificate for `host`. True exactly when this makes
    /// the app's case: the caller lets the app through; the window starts over.
    pub fn refused(&mut self, key: &AppKey, host: &str, now_ms: u64) -> bool {
        let app = self.app(key, now_ms);
        let open = app.window.as_ref().is_some_and(|(start, _)| now_ms.saturating_sub(*start) < TROUBLE_WINDOW_MS);
        if !open {
            if now_ms.saturating_sub(app.first_ms) > TROUBLE_AFTER_START_MS {
                app.window = None;
                return false;
            }
            app.window = Some((now_ms, Vec::new()));
        }
        let Some((_, hosts)) = app.window.as_mut() else { return false };
        let host = host.to_ascii_lowercase();
        if !hosts.contains(&host) {
            hosts.push(host);
        }
        if hosts.len() < TROUBLE_HOSTS {
            return false;
        }
        app.window = None;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_793_000_000_000;
    const SITES: [&str; 3] = ["a.example", "b.example", "c.example"];

    fn game() -> AppKey {
        key(r"C:\Games\Game.exe", 1)
    }

    /// True when the three sites, one ms apart from `at`, make the app's case.
    fn three(t: &mut Trouble, app: &AppKey, at: u64) -> bool {
        SITES.iter().enumerate().any(|(i, h)| t.refused(app, h, at + i as u64))
    }

    #[test]
    fn three_sites_soon_after_the_start_make_the_apps_case() {
        let mut t = Trouble::default();
        t.heard(&game(), NOW);
        assert!(!t.refused(&game(), "a.example", NOW + 1));
        assert!(!t.refused(&game(), "A.example", NOW + 2), "one site twice is still one");
        assert!(!t.refused(&game(), "b.example", NOW + 3));
        assert!(t.refused(&game(), "c.example", NOW + 4));
        assert!(!t.refused(&game(), "d.example", NOW + 5), "it fires once; the window starts over");
    }

    #[test]
    fn sites_spread_past_the_window_never_add_up() {
        let mut t = Trouble::default();
        t.heard(&game(), NOW);
        for (i, host) in SITES.iter().enumerate() {
            assert!(!t.refused(&game(), host, NOW + i as u64 * TROUBLE_WINDOW_MS));
        }
    }

    #[test]
    fn an_app_that_worked_for_a_while_is_self_healings_case_alone() {
        let mut t = Trouble::default();
        t.heard(&game(), NOW);
        assert!(!three(&mut t, &game(), NOW + TROUBLE_AFTER_START_MS + 1));
        let mut control = Trouble::default();
        control.heard(&game(), NOW);
        assert!(three(&mut control, &game(), NOW + TROUBLE_AFTER_START_MS), "the control: a window that opens in time");
    }

    /// P3 of the 2026-11-08 second review: after its day the app is decrypted
    /// again, which is a start again; so is "Try decrypting again".
    #[test]
    fn the_rule_arms_again_when_the_pass_through_ends_or_is_taken_back() {
        let mut t = Trouble::default();
        t.heard(&game(), NOW);
        assert!(three(&mut t, &game(), NOW + 1));
        let end = NOW + 1 + FAIL_OPEN_MS;
        t.opened(&game(), end, NOW + 3);
        assert!(three(&mut t, &game(), end + TROUBLE_AFTER_START_MS), "ten minutes from its end, not from the run's start");
        let mut late = Trouble::default();
        late.heard(&game(), NOW);
        late.opened(&game(), end, NOW + 3);
        assert!(!three(&mut late, &game(), end + TROUBLE_AFTER_START_MS + 1), "the control: past those ten minutes");
        let mut retried = Trouble::default();
        retried.heard(&game(), NOW);
        let at = NOW + 5 * TROUBLE_AFTER_START_MS;
        retried.rearm(&game(), at);
        assert!(three(&mut retried, &game(), at + 1), "taken back: armed from the try");
    }

    #[test]
    fn apps_are_counted_apart_by_full_path_and_session() {
        let mut t = Trouble::default();
        assert!(!t.refused(&key(r"C:\a\a.exe", 1), "x.example", NOW));
        assert!(!t.refused(&key(r"C:\a\b.exe", 1), "y.example", NOW));
        assert!(!t.refused(&key(r"C:\a\c.exe", 1), "z.example", NOW));
        let browser = key(r"C:\Browser\browser.exe", 1);
        let fake = key(r"C:\Users\x\Downloads\browser.exe", 1);
        let other_user = key(r"C:\Browser\browser.exe", 2);
        for (i, app) in [&browser, &fake, &other_user].iter().enumerate() {
            assert!(!t.refused(app, SITES[i], NOW));
        }
        assert!(!t.refused(&key(r"c:\browser\BROWSER.exe", 1), "d.example", NOW), "the same exe, case folded: its second site, not its third");
    }

    #[test]
    fn a_flood_of_apps_stays_within_the_cap_and_is_counted() {
        let mut t = Trouble::default();
        for i in 0..MAX_TROUBLE_APPS + 10 {
            t.heard(&key(&format!(r"C:\x\app{i}.exe"), 1), NOW + i as u64);
        }
        assert_eq!((t.apps.len(), t.dropped()), (MAX_TROUBLE_APPS, 10));
    }
}
