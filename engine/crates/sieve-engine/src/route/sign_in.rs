//! A Wi-Fi that wants a sign-in (a captive portal), and the user's one-click
//! pause of the DNS Client capture ([`super::capture`]) for it.
//!
//! On a hotel or café Wi-Fi the encrypted resolvers cannot be reached before the
//! sign-in, and with the capture held the DNS Client cannot resolve the portal's
//! name either, so its page never opens. The engine says so, and only when two
//! independent facts agree ([`SignIn::observe`]): Windows' own verdict on the
//! network the engine's traffic leaves by (the Network List Manager, read by
//! `nlm`: the captive-portal flag, or connected with no internet), and Sieve's
//! encrypted DNS failing its lookups (`dns::service::Service::unreachable`).
//! Neither alone shows anything: Windows says "no internet" whenever the capture
//! keeps its connectivity test from resolving, and encrypted DNS also fails on a
//! network that blocks the resolvers without any sign-in page.
//!
//! Sieve never pauses by itself. A pause is the user's click, for the network the
//! notice named and no other ([`SignIn::pause`] refuses anything else); while it
//! holds, the routing loop treats the capture as not wanted, so the DNS Client
//! asks the network's DNS servers as it does without Sieve. Nothing else changes:
//! a query an app sends through Sieve's routes still goes encrypted or nowhere
//! (`dns::service`). It ends by itself, at the first of: an encrypted query
//! answered (a real lookup through the resolvers, [`SignIn::probe_due`]), the
//! network changing (Windows' network id or the adapter), [`PAUSE_FOR`], or the
//! capture's setting going off. "Resume now" ends it too.
//!
//! Memory only: an engine restart, a reboot or the routes going down forgets it,
//! and nothing of it is written to Windows or to disk.
//!
//! The network is named by the NLM network id (a GUID Windows keeps per network
//! profile: the same Wi-Fi reads the same id, another Wi-Fi another), together
//! with the adapter's LUID. The routing loop's own "network moved" compares the
//! whole adapter and route tables, which also move on an address renewal or a
//! virtual switch coming up, and would end a pause the user is still using.

use std::time::{Duration, Instant};

use sieve_ipc::{NETWORK_ID_MAX, SIGN_IN_PAUSE_MAX_S, WifiSignIn};

/// The longest a pause lasts.
pub const PAUSE_FOR: Duration = Duration::from_secs(SIGN_IN_PAUSE_MAX_S as u64);
/// The notice stays this long after the facts stop agreeing, so a moment of the
/// portal page loading (an answer that slipped through, Windows re-testing the
/// network) does not take it away and bring it back.
pub const CLEAR_AFTER: Duration = Duration::from_secs(15);
/// While paused, an encrypted query is tried this often: the first that is
/// answered ends the pause.
pub const PROBE_EVERY: Duration = Duration::from_secs(10);

/// The refusals of [`SignIn::pause`], as the pipe sends them.
pub const NOT_WANTED: &str = "Windows' own lookups are not being encrypted, so there is nothing to pause";
pub const NO_SIGN_IN: &str = "this network does not look like one that wants a sign-in, so the capture stays";
pub const OTHER_NETWORK: &str = "that is not the network Sieve sees now, so the capture stays";

/// `NLM_CONNECTIVITY`'s internet bits, IPv4 and IPv6.
pub const NLM_IPV4_INTERNET: i32 = 0x40;
pub const NLM_IPV6_INTERNET: i32 = 0x400;
/// `NLM_INTERNET_CONNECTIVITY_WEBHIJACK`: Windows found a captive portal.
pub const NLM_WEBHIJACK: u32 = 0x1;

/// Windows' verdict on one network connection, as the seam reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The NLM network id, `{...}`.
    pub network: String,
    /// The adapter it is on.
    pub luid: u64,
    /// [`wants_sign_in`] of what Windows said.
    pub wants_sign_in: bool,
}

/// Windows says this connection has a sign-in page, or is up with no internet in
/// either family. `connectivity` is the connection's `NLM_CONNECTIVITY`; `v4` and
/// `v6` its `NA_InternetConnectivityV4`/`V6` flags, when Windows has them.
pub fn wants_sign_in(connectivity: i32, v4: Option<u32>, v6: Option<u32>) -> bool {
    let hijacked = [v4, v6].into_iter().flatten().any(|f| f & NLM_WEBHIJACK != 0);
    let no_internet = connectivity != 0 && connectivity & (NLM_IPV4_INTERNET | NLM_IPV6_INTERNET) == 0;
    hijacked || no_internet
}

/// What one routing pass saw.
#[derive(Debug, Clone, Copy)]
pub struct Seen<'a> {
    /// The capture's setting: on, with encryption on.
    pub wanted: bool,
    /// Windows' verdict on the network the engine's traffic leaves by; None when
    /// there is none or it could not be read.
    pub network: Option<&'a Verdict>,
    /// Sieve's encrypted DNS failed its last lookups.
    pub encrypted_unreachable: bool,
}

/// Why a pause ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// An encrypted query was answered.
    Answered,
    NetworkChanged,
    TimeUp,
    /// The capture's setting went off (or encryption did).
    SettingOff,
    /// "Resume now".
    User,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Shown {
    network: String,
    luid: u64,
    /// The facts stopped agreeing then; the notice goes [`CLEAR_AFTER`] later.
    fading_since: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pause {
    network: String,
    luid: u64,
    until: Instant,
    next_probe: Instant,
}

/// The state of one engine run, in memory.
#[derive(Debug, Default)]
pub struct SignIn {
    shown: Option<Shown>,
    paused: Option<Pause>,
}

impl SignIn {
    /// The capture is paused: the routing loop holds none.
    pub fn paused(&self) -> bool {
        self.paused.is_some()
    }

    /// Whether this pass needs Windows' verdict: only while something is shown or
    /// paused, or encrypted DNS fails. A working network never asks.
    pub fn needs_verdict(&self, encrypted_unreachable: bool) -> bool {
        encrypted_unreachable || self.shown.is_some() || self.paused.is_some()
    }

    /// One routing pass: ends a pause whose network changed, whose time is up or
    /// whose setting went off, and shows or (after [`CLEAR_AFTER`]) clears the
    /// notice by whether both facts agree. Never starts a pause.
    pub fn observe(&mut self, now: Instant, seen: Seen<'_>) -> Option<Ended> {
        let ended = self.paused.as_ref().and_then(|p| {
            if !seen.wanted {
                Some(Ended::SettingOff)
            } else if seen.network.is_none_or(|v| v.network != p.network || v.luid != p.luid) {
                Some(Ended::NetworkChanged)
            } else if now >= p.until {
                Some(Ended::TimeUp)
            } else {
                None
            }
        });
        if ended.is_some() {
            self.paused = None;
        }
        let agree = seen.wanted && seen.encrypted_unreachable && seen.network.is_some_and(|v| v.wants_sign_in);
        match (agree, seen.network) {
            (true, Some(v)) => self.shown = Some(Shown { network: v.network.clone(), luid: v.luid, fading_since: None }),
            _ => {
                let same = |s: &Shown| seen.wanted && seen.network.is_some_and(|v| v.network == s.network && v.luid == s.luid);
                self.shown = match self.shown.take() {
                    Some(s) if !same(&s) => None,
                    Some(Shown { fading_since: None, network, luid }) => Some(Shown { network, luid, fading_since: Some(now) }),
                    Some(s) if s.fading_since.is_some_and(|t| now.saturating_duration_since(t) >= CLEAR_AFTER) => None,
                    other => other,
                };
            }
        }
        ended
    }

    /// The user's click on "Sign in to this Wi-Fi" for `network`. Refused unless
    /// the capture is wanted and the notice stands for that very network. Asked
    /// again for the network already paused, it changes nothing (no longer pause).
    pub fn pause(&mut self, now: Instant, network: &str, wanted: bool) -> Result<(), &'static str> {
        if !wanted {
            return Err(NOT_WANTED);
        }
        if self.paused.as_ref().is_some_and(|p| p.network == network) {
            return Ok(());
        }
        let Some(shown) = &self.shown else { return Err(NO_SIGN_IN) };
        if network.len() > NETWORK_ID_MAX || shown.network != network {
            return Err(OTHER_NETWORK);
        }
        self.paused = Some(Pause { network: shown.network.clone(), luid: shown.luid, until: now + PAUSE_FOR, next_probe: now + PROBE_EVERY });
        Ok(())
    }

    /// "Resume now": ends a pause, if there is one.
    pub fn resume(&mut self) -> Option<Ended> {
        self.paused.take().map(|_| Ended::User)
    }

    /// An encrypted query is due while paused (and is then counted as tried).
    pub fn probe_due(&mut self, now: Instant) -> bool {
        match &mut self.paused {
            Some(p) if now >= p.next_probe => {
                p.next_probe = now + PROBE_EVERY;
                true
            }
            _ => false,
        }
    }

    /// An encrypted query was answered: encrypted DNS works here, so this is no
    /// network that keeps it out. The pause ends and the notice goes at once.
    pub fn encrypted_answered(&mut self) -> Option<Ended> {
        self.shown = None;
        self.paused.take().map(|_| Ended::Answered)
    }

    /// The routes went down: everything is forgotten.
    pub fn forget(&mut self) {
        *self = Self::default();
    }

    /// What the status says: the pause and the seconds left, else the notice, else nothing.
    pub fn report(&self, now: Instant) -> Option<WifiSignIn> {
        if let Some(p) = &self.paused {
            let left = p.until.saturating_duration_since(now).as_secs().min(u64::from(SIGN_IN_PAUSE_MAX_S));
            return Some(WifiSignIn { network: p.network.clone(), paused_left_s: Some(u32::try_from(left).unwrap_or(SIGN_IN_PAUSE_MAX_S)) });
        }
        self.shown.as_ref().map(|s| WifiSignIn { network: s.network.clone(), paused_left_s: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOTEL: &str = "{6f1c2a9e-0b7d-4c55-9a31-2f1d8e4b7c10}";
    const CAFE: &str = "{0d4b7e21-5a3c-4e8f-b1d2-9c6a5f3e8b47}";
    const WIFI: u64 = 0x0047_0000_0000_0001;
    const ETHERNET: u64 = 0x0006_0000_0000_0002;

    fn portal(network: &str, luid: u64) -> Verdict {
        Verdict { network: network.into(), luid, wants_sign_in: true }
    }

    fn online(network: &str, luid: u64) -> Verdict {
        Verdict { network: network.into(), luid, wants_sign_in: false }
    }

    fn seen(v: &Verdict, unreachable: bool) -> Seen<'_> {
        Seen { wanted: true, network: Some(v), encrypted_unreachable: unreachable }
    }

    fn at(t0: Instant, s: u64) -> Instant {
        t0 + Duration::from_secs(s)
    }

    /// A shown notice, ready to be clicked.
    fn detected(t0: Instant) -> SignIn {
        let mut s = SignIn::default();
        assert_eq!(s.observe(t0, seen(&portal(HOTEL, WIFI), true)), None);
        s
    }

    #[test]
    fn windows_verdict_reads_a_portal_or_no_internet() {
        assert!(wants_sign_in(0x20 | 0x200, None, None), "local network only, both families");
        assert!(wants_sign_in(0x40, Some(NLM_WEBHIJACK), None), "internet by the flags, but Windows found a portal");
        assert!(wants_sign_in(0x400, None, Some(NLM_WEBHIJACK | 0x2)));
        assert!(!wants_sign_in(0x40 | 0x20, Some(0), Some(0)), "IPv4 internet");
        assert!(!wants_sign_in(0x400, None, None), "IPv6 internet");
        assert!(!wants_sign_in(0, None, None), "disconnected says nothing");
        assert!(!wants_sign_in(0x40, Some(0x2 | 0x4), None), "proxied or corporate is no portal");
    }

    /// Both facts, and only both: Windows alone, or failing DNS alone, shows nothing.
    #[test]
    fn the_notice_needs_windows_verdict_and_failing_encrypted_dns_together() {
        let t0 = Instant::now();
        let hotel = portal(HOTEL, WIFI);
        let mut s = SignIn::default();
        s.observe(t0, seen(&hotel, false));
        assert_eq!(s.report(t0), None, "Windows alone");
        s.observe(t0, seen(&online(HOTEL, WIFI), true));
        assert_eq!(s.report(t0), None, "failing DNS alone: a network that blocks the resolvers");
        s.observe(t0, Seen { wanted: false, network: Some(&hotel), encrypted_unreachable: true });
        assert_eq!(s.report(t0), None, "the setting off: nothing to pause, nothing to say");
        s.observe(t0, Seen { wanted: true, network: None, encrypted_unreachable: true });
        assert_eq!(s.report(t0), None, "no verdict");
        s.observe(t0, seen(&hotel, true));
        assert_eq!(s.report(t0), Some(WifiSignIn { network: HOTEL.into(), paused_left_s: None }));
        assert!(!s.paused(), "Sieve never pauses by itself");
        assert!(SignIn::default().needs_verdict(true) && !SignIn::default().needs_verdict(false), "a working network never asks Windows");
    }

    /// Portal Wi-Fi and working Ethernet: the traffic leaves by Ethernet, whose
    /// verdict is online, and encrypted DNS answers: no notice.
    #[test]
    fn a_portal_wifi_beside_working_ethernet_shows_nothing() {
        let t0 = Instant::now();
        let mut s = SignIn::default();
        s.observe(t0, seen(&online(CAFE, ETHERNET), false));
        assert_eq!(s.report(t0), None);
        assert_eq!(s.pause(t0, HOTEL, true), Err(NO_SIGN_IN));
    }

    /// While the user is on the portal page the facts may disagree for a moment:
    /// the notice stays through it, and goes only after they disagree for long.
    #[test]
    fn the_notice_does_not_flap_and_goes_once_sign_in_is_done() {
        let t0 = Instant::now();
        let mut s = detected(t0);
        s.observe(at(t0, 5), seen(&online(HOTEL, WIFI), true));
        s.observe(at(t0, 10), seen(&portal(HOTEL, WIFI), false));
        assert!(s.report(at(t0, 10)).is_some(), "a moment's disagreement keeps it");
        s.observe(at(t0, 15), seen(&portal(HOTEL, WIFI), true));
        s.observe(at(t0, 20), seen(&online(HOTEL, WIFI), false));
        s.observe(at(t0, 20 + CLEAR_AFTER.as_secs() - 1), seen(&online(HOTEL, WIFI), false));
        assert!(s.report(at(t0, 34)).is_some(), "the fade starts over after they agreed again");
        s.observe(at(t0, 20 + CLEAR_AFTER.as_secs()), seen(&online(HOTEL, WIFI), false));
        assert_eq!(s.report(at(t0, 35)), None, "signed in: gone");
        let mut s = detected(t0);
        assert_eq!(s.encrypted_answered(), None);
        assert_eq!(s.report(t0), None, "an encrypted answer takes it away at once");
        let mut s = detected(t0);
        s.observe(at(t0, 1), seen(&online(CAFE, WIFI), false));
        assert_eq!(s.report(at(t0, 1)), None, "another network: at once");
    }

    #[test]
    fn a_pause_is_one_click_for_the_network_shown_and_nothing_else() {
        let t0 = Instant::now();
        assert_eq!(SignIn::default().pause(t0, HOTEL, true), Err(NO_SIGN_IN), "nothing detected");
        let mut s = detected(t0);
        assert_eq!(s.pause(t0, CAFE, true), Err(OTHER_NETWORK));
        assert_eq!(s.pause(t0, &"x".repeat(NETWORK_ID_MAX + 1), true), Err(OTHER_NETWORK));
        assert_eq!(s.pause(t0, HOTEL, false), Err(NOT_WANTED), "the setting is the off switch, not this");
        assert!(!s.paused());
        assert_eq!(s.pause(t0, HOTEL, true), Ok(()));
        assert!(s.paused());
        assert_eq!(s.report(t0), Some(WifiSignIn { network: HOTEL.into(), paused_left_s: Some(SIGN_IN_PAUSE_MAX_S) }));
        assert_eq!(s.pause(at(t0, 60), HOTEL, true), Ok(()), "a second click");
        assert_eq!(s.report(at(t0, 60)).unwrap().paused_left_s, Some(SIGN_IN_PAUSE_MAX_S - 60), "does not make it longer");
        assert_eq!(s.pause(at(t0, 60), CAFE, true), Err(OTHER_NETWORK));
        assert_eq!(s.report(at(t0, 60)).unwrap().network, HOTEL);
    }

    /// The notice fading (the user on the portal page) still takes the click.
    #[test]
    fn a_click_while_the_notice_fades_still_pauses() {
        let t0 = Instant::now();
        let mut s = detected(t0);
        s.observe(at(t0, 5), seen(&portal(HOTEL, WIFI), false));
        assert_eq!(s.pause(at(t0, 6), HOTEL, true), Ok(()));
    }

    #[test]
    fn resume_cause_one_an_encrypted_answer_found_by_the_probe() {
        let t0 = Instant::now();
        let mut s = detected(t0);
        s.pause(t0, HOTEL, true).unwrap();
        assert!(!s.probe_due(at(t0, PROBE_EVERY.as_secs() - 1)));
        assert!(s.probe_due(at(t0, PROBE_EVERY.as_secs())));
        assert!(!s.probe_due(at(t0, PROBE_EVERY.as_secs() + 1)), "counted as tried");
        assert!(s.probe_due(at(t0, 2 * PROBE_EVERY.as_secs())));
        assert_eq!(s.encrypted_answered(), Some(Ended::Answered));
        assert!(!s.paused() && s.report(t0).is_none(), "resumed without a click, no notice");
        assert!(!s.probe_due(at(t0, 100)), "nothing to probe for");
    }

    #[test]
    fn resume_cause_two_the_network_changes() {
        let t0 = Instant::now();
        for (next, why) in [(Some(online(CAFE, WIFI)), "another Wi-Fi"), (Some(portal(HOTEL, ETHERNET)), "another adapter"), (None, "no network")] {
            let mut s = detected(t0);
            s.pause(t0, HOTEL, true).unwrap();
            let ended = s.observe(at(t0, 30), Seen { wanted: true, network: next.as_ref(), encrypted_unreachable: true });
            assert_eq!(ended, Some(Ended::NetworkChanged), "{why}");
            assert!(!s.paused(), "{why}");
        }
        // The same network, still a portal: holds.
        let mut s = detected(t0);
        s.pause(t0, HOTEL, true).unwrap();
        assert_eq!(s.observe(at(t0, 30), seen(&online(HOTEL, WIFI), true)), None, "signed in, encrypted not yet answered");
        assert!(s.paused());
    }

    #[test]
    fn resume_cause_three_fifteen_minutes() {
        let t0 = Instant::now();
        let mut s = detected(t0);
        s.pause(t0, HOTEL, true).unwrap();
        assert_eq!(s.observe(at(t0, PAUSE_FOR.as_secs() - 1), seen(&portal(HOTEL, WIFI), true)), None);
        assert_eq!(s.report(at(t0, PAUSE_FOR.as_secs() - 1)).unwrap().paused_left_s, Some(1));
        assert_eq!(s.observe(at(t0, PAUSE_FOR.as_secs()), seen(&portal(HOTEL, WIFI), true)), Some(Ended::TimeUp));
        assert!(!s.paused());
        assert_eq!(s.report(at(t0, PAUSE_FOR.as_secs())), Some(WifiSignIn { network: HOTEL.into(), paused_left_s: None }), "still a portal: the notice is back, the next pause is the user's");
    }

    /// The setting flipped off ends the pause; on again, the capture is wanted and
    /// opens, with no pause left over.
    #[test]
    fn the_setting_off_and_on_mid_pause_ends_it() {
        let t0 = Instant::now();
        let mut s = detected(t0);
        s.pause(t0, HOTEL, true).unwrap();
        assert_eq!(s.observe(at(t0, 5), Seen { wanted: false, network: Some(&portal(HOTEL, WIFI)), encrypted_unreachable: true }), Some(Ended::SettingOff));
        assert!(!s.paused() && s.report(at(t0, 5)).is_none());
        s.observe(at(t0, 10), seen(&portal(HOTEL, WIFI), true));
        assert!(!s.paused(), "back on: shown again, not paused");
        assert!(s.report(at(t0, 10)).is_some());
    }

    #[test]
    fn resume_now_and_a_restart_or_routes_down_forget_it() {
        let t0 = Instant::now();
        let mut s = detected(t0);
        assert_eq!(s.resume(), None, "nothing to resume");
        s.pause(t0, HOTEL, true).unwrap();
        assert_eq!(s.resume(), Some(Ended::User));
        assert!(!s.paused());
        s.pause(t0, HOTEL, true).unwrap();
        s.forget();
        assert!(!s.paused() && s.report(t0).is_none());
        // A restart is a new engine: its state starts empty, so the capture opens.
        let restarted = SignIn::default();
        assert!(!restarted.paused());
    }
}
