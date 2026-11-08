//! The per-app pass-through (the owner's fail-open rule): an app that refuses
//! Sieve's certificate for [`TROUBLE_HOSTS`] different sites within
//! [`TROUBLE_WINDOW_MS`], starting within [`TROUBLE_AFTER_START_MS`] of Sieve first
//! decrypting it, is refusing Sieve itself (its own trust store, or pinning
//! everywhere), not one site. It then goes through untouched, every site, for
//! [`FAIL_OPEN_MS`]: one `auto:failing` entry, `*` for its exe. No decryption means
//! no content change either; a host block is the filter's and stays.
//!
//! What self-healing already covers is left to it: `score` still excludes each
//! (app, site) by its own rule, unchanged. This adds only the step from "each site
//! costs a failure" to "the app's next sites cost nothing". Only a refusal on a
//! flow Sieve decrypted is evidence, so a floor site (never decrypted), a block
//! and a network failure never are.

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
    first_ms: u64,
    /// The window's start and the sites refused in it.
    window: Option<(u64, Vec<String>)>,
}

#[derive(Debug, Default)]
pub struct Trouble {
    apps: HashMap<String, App>,
    dropped: u64,
}

impl Trouble {
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    fn app(&mut self, exe: &str, now_ms: u64) -> &mut App {
        if !self.apps.contains_key(exe)
            && self.apps.len() >= MAX_TROUBLE_APPS
            && let Some(oldest) = self.apps.iter().min_by_key(|(_, a)| a.first_ms).map(|(k, _)| k.clone())
        {
            self.apps.remove(&oldest);
            self.dropped += 1;
        }
        self.apps.entry(exe.to_string()).or_insert(App { first_ms: now_ms, window: None })
    }

    /// Any evidence of a decrypted connection of `exe` (its file name).
    pub fn heard(&mut self, exe: &str, now_ms: u64) {
        self.app(exe, now_ms);
    }

    /// `exe` refused Sieve's certificate for `host`. True exactly when this makes
    /// the app's case: the caller lets the app through; the window starts over.
    pub fn refused(&mut self, exe: &str, host: &str, now_ms: u64) -> bool {
        let app = self.app(exe, now_ms);
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

    #[test]
    fn three_sites_soon_after_the_start_make_the_apps_case() {
        let mut t = Trouble::default();
        t.heard("game.exe", NOW);
        assert!(!t.refused("game.exe", "a.example", NOW + 1));
        assert!(!t.refused("game.exe", "A.example", NOW + 2), "one site twice is still one");
        assert!(!t.refused("game.exe", "b.example", NOW + 3));
        assert!(t.refused("game.exe", "c.example", NOW + 4));
        assert!(!t.refused("game.exe", "d.example", NOW + 5), "it fires once; the window starts over");
    }

    #[test]
    fn sites_spread_past_the_window_never_add_up() {
        let mut t = Trouble::default();
        t.heard("game.exe", NOW);
        for (i, host) in ["a.example", "b.example", "c.example"].iter().enumerate() {
            assert!(!t.refused("game.exe", host, NOW + i as u64 * TROUBLE_WINDOW_MS));
        }
    }

    #[test]
    fn an_app_that_worked_for_a_while_is_self_healings_case_alone() {
        let mut t = Trouble::default();
        t.heard("game.exe", NOW);
        let late = NOW + TROUBLE_AFTER_START_MS + 1;
        for (i, host) in ["a.example", "b.example", "c.example"].iter().enumerate() {
            assert!(!t.refused("game.exe", host, late + i as u64));
        }
        let mut control = Trouble::default();
        control.heard("game.exe", NOW);
        let early = NOW + TROUBLE_AFTER_START_MS;
        assert!(["a.example", "b.example", "c.example"].iter().enumerate().any(|(i, h)| control.refused("game.exe", h, early + i as u64)), "the control: a window that opens in time");
    }

    #[test]
    fn apps_are_counted_apart() {
        let mut t = Trouble::default();
        assert!(!t.refused("a.exe", "x.example", NOW));
        assert!(!t.refused("b.exe", "y.example", NOW));
        assert!(!t.refused("c.exe", "z.example", NOW));
    }

    #[test]
    fn a_flood_of_apps_stays_within_the_cap_and_is_counted() {
        let mut t = Trouble::default();
        for i in 0..MAX_TROUBLE_APPS + 10 {
            t.heard(&format!("app{i}.exe"), NOW + i as u64);
        }
        assert_eq!((t.apps.len(), t.dropped()), (MAX_TROUBLE_APPS, 10));
    }
}
