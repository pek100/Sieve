//! A network that wants a sign-in (a captive portal), and the user's one-click
//! pause of the DNS Client capture ([`super::capture`]) for it.
//!
//! On a hotel or café network the encrypted resolvers cannot be reached before
//! the sign-in, and with the capture held the DNS Client cannot resolve the
//! portal's name either, so its page never opens. The engine says so only when
//! two independent facts agree ([`SignIn::observe`]): Sieve's encrypted DNS
//! failing its lookups (`dns::service::Service::unreachable`), and a sign-in page
//! seen without DNS, either by Sieve's own check (`route::portal`: something on
//! the network answers port 80 for addresses that lead nowhere) or by Windows
//! (the Network List Manager's captive-portal flag, read by `nlm`). Windows'
//! "connected, no internet" is no such fact: while the capture holds, Windows'
//! own test resolves through Sieve, so it says that whenever encrypted DNS fails,
//! on a network that only blocks the resolvers and in an outage too. Both
//! facts count only while the capture is really held: when it is not, the DNS
//! Client already asks the network's servers and the page opens by itself.
//!
//! Sieve never pauses by itself. A pause is the user's click, for the network the
//! notice named and no other ([`SignIn::pause`] refuses anything else); while it
//! holds, the routing loop treats the capture as not wanted, so the DNS Client
//! asks the network's DNS servers in plain text, as it does without Sieve. That
//! carries nearly every app's lookups (Windows resolves names for them); only an
//! app that looks names up itself is unaffected. It ends by itself, at the first
//! of: an encrypted query answered (a real lookup through the resolvers,
//! [`SignIn::probe_due`]), the network changing (Windows' network id or the
//! adapter), [`PAUSE_FOR`], or the capture's setting going off. "Resume now"
//! ends it too. Pauses are bounded per network and engine run: after one runs
//! its full time, another needs the facts agreeing afresh, and there are at most
//! [`PAUSES_PER_NETWORK`] (a pipe client cannot renew it forever).
//!
//! Memory only: an engine restart forgets it and the routes going down end it;
//! nothing of it is written to Windows, and nothing is read back (the status file
//! the live check reads shows it, as the pipe does).
//!
//! The network is named by the NLM network id (a GUID Windows keeps per network
//! profile: the same Wi-Fi reads the same id, another Wi-Fi another), together
//! with the adapter's LUID. The routing loop's own "network moved" compares the
//! whole adapter and route tables, which also move on an address renewal or a
//! virtual switch coming up, and would end a pause the user is still using.

use std::time::{Duration, Instant};

use sieve_ipc::{NETWORK_ID_MAX, SIGN_IN_PAUSE_MAX_S, WifiSignIn};

use super::table::if_type;

/// The longest a pause lasts.
pub const PAUSE_FOR: Duration = Duration::from_secs(SIGN_IN_PAUSE_MAX_S as u64);
/// The notice stays this long after the facts stop agreeing, so a moment of the
/// portal page loading (an answer that slipped through, a check that missed)
/// does not take it away and bring it back.
pub const CLEAR_AFTER: Duration = Duration::from_secs(15);
/// While paused, an encrypted query is tried this often: the first that is
/// answered ends the pause.
pub const PROBE_EVERY: Duration = Duration::from_secs(10);
/// The DNS-free portal check (`route::portal`) runs at most this often, and only
/// while [`SignIn::needs_verdict`].
pub const PORTAL_EVERY: Duration = Duration::from_secs(15);
/// A portal check's answer counts this long: two missed checks, then it is gone.
pub const PORTAL_FRESH: Duration = Duration::from_secs(3 * 15);
/// Pauses one network gets per engine run. One sign-in, a second when the first
/// ran out of time mid-way, a third for a portal that asks again later the same
/// day: at most 45 minutes of plain lookups. Past it the setting is the way.
pub const PAUSES_PER_NETWORK: u8 = 3;
/// Networks whose pauses are counted; past it the oldest is forgotten.
const NETWORKS_KEPT: usize = 16;

/// The refusals of [`SignIn::pause`], as the pipe sends them.
pub const NOT_WANTED: &str = "Windows' own lookups are not being encrypted, so there is nothing to pause";
pub const NOT_HELD: &str = "Windows' own lookups are not being caught right now, so there is nothing to pause";
pub const NO_SIGN_IN: &str = "this network does not look like one that wants a sign-in, so the capture stays";
pub const OTHER_NETWORK: &str = "that is not the network Sieve sees now, so the capture stays";
pub const NOT_AGAIN: &str = "the last pause on this network ran its full time and Sieve does not see a sign-in page there now, so the capture stays";
pub const PAUSES_USED: &str = "this network had its three pauses since Sieve started; to go without encrypting Windows' own lookups, turn that setting off";

/// `NLM_INTERNET_CONNECTIVITY_WEBHIJACK`: Windows found a captive portal.
pub const NLM_WEBHIJACK: u32 = 0x1;

/// Windows' word on one network connection, as the seam reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The NLM network id, `{...}`.
    pub network: String,
    /// The adapter it is on.
    pub luid: u64,
    /// Windows found a sign-in page there ([`hijacked`]).
    pub hijacked: bool,
}

/// Windows says this connection has a sign-in page: the WEBHIJACK flag of its
/// `NA_InternetConnectivityV4`/`V6`, when Windows has them. "No internet" is no
/// such word (see the module).
pub fn hijacked(v4: Option<u32>, v6: Option<u32>) -> bool {
    [v4, v6].into_iter().flatten().any(|f| f & NLM_WEBHIJACK != 0)
}

/// The adapter is Wi-Fi: a LUID's top 16 bits are its IANA ifType.
pub fn is_wifi(luid: u64) -> bool {
    luid >> 48 == u64::from(if_type::IEEE80211)
}

/// One answer of the DNS-free portal check (`route::portal`), for the network
/// and adapter it ran on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probed {
    pub network: String,
    pub luid: u64,
    pub at: Instant,
    pub portal: bool,
}

impl Probed {
    /// It found a portal on `v`'s network, recently enough to count.
    pub fn portal_on(&self, v: &Verdict, now: Instant) -> bool {
        self.portal && self.network == v.network && self.luid == v.luid && now.saturating_duration_since(self.at) < PORTAL_FRESH
    }
}

/// What one routing pass saw.
#[derive(Debug, Clone, Copy)]
pub struct Seen<'a> {
    /// The capture's setting: on, with encryption on.
    pub wanted: bool,
    /// The capture really holds now (opened and proven), not only wanted.
    pub held: bool,
    /// Windows' word on the network the engine's traffic leaves by; None when
    /// there is none or it could not be read.
    pub network: Option<&'a Verdict>,
    /// The DNS-free check found a sign-in page on that network ([`Probed::portal_on`]).
    pub portal: bool,
    /// Sieve's encrypted DNS failed its last lookups.
    pub encrypted_unreachable: bool,
}

/// Why a pause ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// An encrypted query was answered.
    Answered,
    /// Another network, or none that could be read. A read that fails for a
    /// moment ends it too: the safe way, the capture comes back.
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

/// What one network used of its pauses this engine run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Spent {
    pauses: u8,
    /// A pause ran its full [`PAUSE_FOR`] here: the next needs the facts afresh.
    timed_out: bool,
}

/// The state of one engine run, in memory.
#[derive(Debug, Default)]
pub struct SignIn {
    shown: Option<Shown>,
    paused: Option<Pause>,
    /// Per network id, oldest first, at most [`NETWORKS_KEPT`].
    spent: Vec<(String, Spent)>,
}

impl SignIn {
    /// The capture is paused: the routing loop holds none.
    pub fn paused(&self) -> bool {
        self.paused.is_some()
    }

    /// Whether this pass needs Windows' word and the portal check: only while
    /// something is shown or paused, or encrypted DNS fails. A working network
    /// never asks.
    pub fn needs_verdict(&self, encrypted_unreachable: bool) -> bool {
        encrypted_unreachable || self.shown.is_some() || self.paused.is_some()
    }

    /// One routing pass: ends a pause whose network changed, whose time is up or
    /// whose setting went off, and shows or (after [`CLEAR_AFTER`]) clears the
    /// notice by whether the facts agree. Never starts a pause.
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
            let p = self.paused.take();
            if let Some(p) = p.filter(|_| ended == Some(Ended::TimeUp)) {
                self.spent_on(&p.network).timed_out = true;
            }
        }
        let agree = seen.wanted && seen.held && seen.encrypted_unreachable && seen.network.is_some_and(|v| v.hijacked || seen.portal);
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

    /// The user's click on "Sign in" for `network`. Refused unless the capture is
    /// wanted and really held, the notice stands for that very network, and the
    /// network has a pause left ([`PAUSES_PER_NETWORK`]; after one ran its full
    /// time, only while the facts agree now). Asked again for the network already
    /// paused, it changes nothing (no longer pause, no pause spent).
    pub fn pause(&mut self, now: Instant, network: &str, wanted: bool, held: bool) -> Result<(), &'static str> {
        if !wanted {
            return Err(NOT_WANTED);
        }
        if self.paused.as_ref().is_some_and(|p| p.network == network) {
            return Ok(());
        }
        if !held {
            return Err(NOT_HELD);
        }
        let Some(shown) = &self.shown else { return Err(NO_SIGN_IN) };
        if network.len() > NETWORK_ID_MAX || shown.network != network {
            return Err(OTHER_NETWORK);
        }
        let (luid, agree_now) = (shown.luid, shown.fading_since.is_none());
        let spent = self.spent_on(network);
        if spent.pauses >= PAUSES_PER_NETWORK {
            return Err(PAUSES_USED);
        }
        if spent.timed_out && !agree_now {
            return Err(NOT_AGAIN);
        }
        spent.pauses += 1;
        self.paused = Some(Pause { network: network.to_string(), luid, until: now + PAUSE_FOR, next_probe: now + PROBE_EVERY });
        Ok(())
    }

    fn spent_on(&mut self, network: &str) -> &mut Spent {
        let at = match self.spent.iter().position(|(n, _)| n == network) {
            Some(at) => at,
            None => {
                if self.spent.len() >= NETWORKS_KEPT {
                    self.spent.remove(0);
                }
                self.spent.push((network.to_string(), Spent::default()));
                self.spent.len() - 1
            }
        };
        &mut self.spent[at].1
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

    /// The routes went down: the notice and a pause end. What each network used
    /// of its pauses stays for this engine run.
    pub fn forget(&mut self) {
        self.shown = None;
        self.paused = None;
    }

    /// What the status says: the pause and the seconds left, else the notice, else nothing.
    pub fn report(&self, now: Instant) -> Option<WifiSignIn> {
        if let Some(p) = &self.paused {
            let left = p.until.saturating_duration_since(now).as_secs().min(u64::from(SIGN_IN_PAUSE_MAX_S));
            return Some(WifiSignIn { network: p.network.clone(), paused_left_s: Some(u32::try_from(left).unwrap_or(SIGN_IN_PAUSE_MAX_S)), wifi: is_wifi(p.luid) });
        }
        self.shown.as_ref().map(|s| WifiSignIn { network: s.network.clone(), paused_left_s: None, wifi: is_wifi(s.luid) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOTEL: &str = "{6f1c2a9e-0b7d-4c55-9a31-2f1d8e4b7c10}";
    const CAFE: &str = "{0d4b7e21-5a3c-4e8f-b1d2-9c6a5f3e8b47}";
    const WIFI: u64 = 0x0047_0000_0000_0001;
    const ETHERNET: u64 = 0x0006_0000_0000_0002;

    fn net(network: &str, luid: u64) -> Verdict {
        Verdict { network: network.into(), luid, hijacked: false }
    }

    /// A pass with the capture held, encrypted DNS as given, and the DNS-free
    /// check's answer as given.
    fn seen(v: &Verdict, unreachable: bool, portal: bool) -> Seen<'_> {
        Seen { wanted: true, held: true, network: Some(v), portal, encrypted_unreachable: unreachable }
    }

    /// The same, while the user's pause holds the capture closed.
    fn paused_pass(v: &Verdict, portal: bool) -> Seen<'_> {
        Seen { held: false, ..seen(v, true, portal) }
    }

    fn at(t0: Instant, s: u64) -> Instant {
        t0 + Duration::from_secs(s)
    }

    fn notice(network: &str, wifi: bool) -> Option<WifiSignIn> {
        Some(WifiSignIn { network: network.into(), paused_left_s: None, wifi })
    }

    /// A shown notice, ready to be clicked.
    fn detected(t0: Instant) -> SignIn {
        let mut s = SignIn::default();
        assert_eq!(s.observe(t0, seen(&net(HOTEL, WIFI), true, true)), None);
        s
    }

    #[test]
    fn windows_word_is_its_portal_flag_alone() {
        assert!(hijacked(Some(NLM_WEBHIJACK), None));
        assert!(hijacked(None, Some(NLM_WEBHIJACK | 0x2)));
        assert!(!hijacked(Some(0), Some(0)));
        assert!(!hijacked(None, None), "untested, or connected with no internet: no word");
        assert!(!hijacked(Some(0x2 | 0x4), None), "proxied or corporate is no portal");
        assert!(is_wifi(WIFI) && !is_wifi(ETHERNET));
    }

    /// The finding's cases: encrypted DNS failing alone (a network that blocks the
    /// resolvers but serves plain DNS, or an outage) shows nothing; a portal seen
    /// without DNS shows the notice; signed in, it goes.
    #[test]
    fn the_notice_needs_failing_encrypted_dns_and_a_sign_in_page_seen_without_dns() {
        let t0 = Instant::now();
        let hotel = net(HOTEL, WIFI);
        let mut s = SignIn::default();
        s.observe(t0, seen(&hotel, true, false));
        assert_eq!(s.report(t0), None, "resolvers blocked, plain DNS fine: no notice, the unreachable banner stays");
        assert!(s.needs_verdict(true), "and the check goes on while encrypted DNS fails");
        s.observe(at(t0, 5), seen(&hotel, true, false));
        assert_eq!(s.report(at(t0, 5)), None, "an outage: nothing answers port 80 for addresses that lead nowhere either");
        s.observe(at(t0, 6), seen(&hotel, false, true));
        assert_eq!(s.report(at(t0, 6)), None, "a portal page seen while encrypted DNS works: nothing to do");
        s.observe(at(t0, 7), Seen { wanted: true, held: true, network: None, portal: true, encrypted_unreachable: true });
        assert_eq!(s.report(at(t0, 7)), None, "no network to name");
        s.observe(at(t0, 10), seen(&hotel, true, true));
        assert_eq!(s.report(at(t0, 10)), notice(HOTEL, true), "a real portal");
        assert!(!s.paused(), "Sieve never pauses by itself");
        let windows_saw_it = Verdict { hijacked: true, ..net(CAFE, ETHERNET) };
        let mut s = SignIn::default();
        s.observe(t0, seen(&windows_saw_it, true, false));
        assert_eq!(s.report(t0), notice(CAFE, false), "Windows' own portal flag counts too; on Ethernet it says so");
        // Signed in: the portal lets port 80 through, so the check finds nothing.
        let mut s = detected(t0);
        s.observe(at(t0, 5), seen(&hotel, true, false));
        s.observe(at(t0, 5 + CLEAR_AFTER.as_secs()), seen(&hotel, true, false));
        assert_eq!(s.report(at(t0, 20)), None, "signed in, before encrypted DNS answers: gone");
        assert!(SignIn::default().needs_verdict(true) && !SignIn::default().needs_verdict(false), "a working network never asks");
    }

    /// The notice and the click stand only while the capture really holds: failed,
    /// refused or IPv6 off, the DNS Client already asks the network's servers.
    #[test]
    fn nothing_is_said_or_paused_while_the_capture_does_not_hold() {
        let t0 = Instant::now();
        let hotel = net(HOTEL, WIFI);
        let mut s = SignIn::default();
        s.observe(t0, Seen { held: false, ..seen(&hotel, true, true) });
        assert_eq!(s.report(t0), None, "wanted but not held");
        assert_eq!(s.pause(t0, HOTEL, true, false), Err(NOT_HELD));
        s.observe(t0, Seen { wanted: false, ..seen(&hotel, true, true) });
        assert_eq!(s.report(t0), None, "the setting off");
        let mut s = detected(t0);
        s.observe(at(t0, 1), Seen { held: false, ..seen(&hotel, true, true) });
        assert_eq!(s.pause(at(t0, 1), HOTEL, true, false), Err(NOT_HELD), "the capture failed after the notice showed");
        s.observe(at(t0, 1 + CLEAR_AFTER.as_secs()), Seen { held: false, ..seen(&hotel, true, true) });
        assert_eq!(s.report(at(t0, 16)), None, "and the notice goes");
    }

    /// Portal Wi-Fi and working Ethernet: the traffic leaves by Ethernet, where
    /// encrypted DNS answers: no notice.
    #[test]
    fn a_portal_wifi_beside_working_ethernet_shows_nothing() {
        let t0 = Instant::now();
        let mut s = SignIn::default();
        s.observe(t0, seen(&net(CAFE, ETHERNET), false, false));
        assert_eq!(s.report(t0), None);
        assert_eq!(s.pause(t0, HOTEL, true, true), Err(NO_SIGN_IN));
    }

    /// While the user is on the portal page the facts may disagree for a moment:
    /// the notice stays through it, and goes only after they disagree for long.
    #[test]
    fn the_notice_does_not_flap_and_goes_once_sign_in_is_done() {
        let t0 = Instant::now();
        let hotel = net(HOTEL, WIFI);
        let mut s = detected(t0);
        s.observe(at(t0, 5), seen(&hotel, true, false));
        s.observe(at(t0, 10), seen(&hotel, false, true));
        assert!(s.report(at(t0, 10)).is_some(), "a moment's disagreement keeps it");
        s.observe(at(t0, 15), seen(&hotel, true, true));
        s.observe(at(t0, 20), seen(&hotel, false, false));
        s.observe(at(t0, 20 + CLEAR_AFTER.as_secs() - 1), seen(&hotel, false, false));
        assert!(s.report(at(t0, 34)).is_some(), "the fade starts over after they agreed again");
        s.observe(at(t0, 20 + CLEAR_AFTER.as_secs()), seen(&hotel, false, false));
        assert_eq!(s.report(at(t0, 35)), None, "signed in: gone");
        let mut s = detected(t0);
        assert_eq!(s.encrypted_answered(), None);
        assert_eq!(s.report(t0), None, "an encrypted answer takes it away at once");
        let mut s = detected(t0);
        s.observe(at(t0, 1), seen(&net(CAFE, WIFI), false, false));
        assert_eq!(s.report(at(t0, 1)), None, "another network: at once");
    }

    #[test]
    fn a_portal_check_counts_for_its_own_network_and_only_while_fresh() {
        let t0 = Instant::now();
        let p = Probed { network: HOTEL.into(), luid: WIFI, at: t0, portal: true };
        assert!(p.portal_on(&net(HOTEL, WIFI), at(t0, PORTAL_FRESH.as_secs() - 1)));
        assert!(!p.portal_on(&net(HOTEL, WIFI), at(t0, PORTAL_FRESH.as_secs())), "stale");
        assert!(!p.portal_on(&net(CAFE, WIFI), t0), "the same adapter on another Wi-Fi");
        assert!(!p.portal_on(&net(HOTEL, ETHERNET), t0));
        assert!(!Probed { portal: false, ..p }.portal_on(&net(HOTEL, WIFI), t0));
    }

    #[test]
    fn a_pause_is_one_click_for_the_network_shown_and_nothing_else() {
        let t0 = Instant::now();
        assert_eq!(SignIn::default().pause(t0, HOTEL, true, true), Err(NO_SIGN_IN), "nothing detected");
        let mut s = detected(t0);
        assert_eq!(s.pause(t0, CAFE, true, true), Err(OTHER_NETWORK));
        assert_eq!(s.pause(t0, &"x".repeat(NETWORK_ID_MAX + 1), true, true), Err(OTHER_NETWORK));
        assert_eq!(s.pause(t0, HOTEL, false, true), Err(NOT_WANTED), "the setting is the off switch, not this");
        assert!(!s.paused());
        assert_eq!(s.pause(t0, HOTEL, true, true), Ok(()));
        assert!(s.paused());
        assert_eq!(s.report(t0), Some(WifiSignIn { network: HOTEL.into(), paused_left_s: Some(SIGN_IN_PAUSE_MAX_S), wifi: true }));
        assert_eq!(s.pause(at(t0, 60), HOTEL, true, false), Ok(()), "a second click, with the capture closed by the pause");
        assert_eq!(s.report(at(t0, 60)).unwrap().paused_left_s, Some(SIGN_IN_PAUSE_MAX_S - 60), "does not make it longer");
        assert_eq!(s.pause(at(t0, 60), CAFE, true, true), Err(OTHER_NETWORK));
        assert_eq!(s.report(at(t0, 60)).unwrap().network, HOTEL);
    }

    /// The notice fading (the user on the portal page) still takes the first click.
    #[test]
    fn a_click_while_the_notice_fades_still_pauses() {
        let t0 = Instant::now();
        let mut s = detected(t0);
        s.observe(at(t0, 5), seen(&net(HOTEL, WIFI), false, true));
        assert_eq!(s.pause(at(t0, 6), HOTEL, true, true), Ok(()));
    }

    /// A pipe client cannot renew the pause forever: after one ran its full time,
    /// another needs the facts agreeing now, and a network has
    /// [`PAUSES_PER_NETWORK`] in an engine run, which the routes going down does
    /// not give back.
    #[test]
    fn pauses_are_bounded_per_network_and_run() {
        let t0 = Instant::now();
        let hotel = net(HOTEL, WIFI);
        let mut s = detected(t0);
        s.pause(t0, HOTEL, true, true).unwrap();
        let up = PAUSE_FOR.as_secs();
        assert_eq!(s.observe(at(t0, up), paused_pass(&hotel, true)), Some(Ended::TimeUp));
        // The capture opens again; the check has not found the page afresh yet.
        s.observe(at(t0, up + 5), seen(&hotel, true, false));
        assert!(s.report(at(t0, up + 5)).is_some(), "the notice fades");
        assert_eq!(s.pause(at(t0, up + 5), HOTEL, true, true), Err(NOT_AGAIN), "but a fading notice is no fresh fact");
        s.observe(at(t0, up + 10), seen(&hotel, true, true));
        assert_eq!(s.pause(at(t0, up + 10), HOTEL, true, true), Ok(()), "the facts agree now: the second pause");
        assert_eq!(s.resume(), Some(Ended::User));
        s.forget();
        s.observe(at(t0, up + 30), seen(&hotel, true, true));
        assert_eq!(s.pause(at(t0, up + 30), HOTEL, true, true), Ok(()), "the third");
        assert_eq!(s.resume(), Some(Ended::User));
        s.observe(at(t0, up + 40), seen(&hotel, true, true));
        assert_eq!(s.pause(at(t0, up + 40), HOTEL, true, true), Err(PAUSES_USED));
        // Another network has its own.
        let cafe = net(CAFE, WIFI);
        s.observe(at(t0, up + 50), seen(&cafe, true, true));
        assert_eq!(s.pause(at(t0, up + 50), CAFE, true, true), Ok(()));
    }

    #[test]
    fn resume_cause_one_an_encrypted_answer_found_by_the_probe() {
        let t0 = Instant::now();
        let mut s = detected(t0);
        s.pause(t0, HOTEL, true, true).unwrap();
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
        for (next, why) in [(Some(net(CAFE, WIFI)), "another Wi-Fi"), (Some(net(HOTEL, ETHERNET)), "another adapter"), (None, "no network, or Windows' word not read")] {
            let mut s = detected(t0);
            s.pause(t0, HOTEL, true, true).unwrap();
            let ended = s.observe(at(t0, 30), Seen { wanted: true, held: false, network: next.as_ref(), portal: true, encrypted_unreachable: true });
            assert_eq!(ended, Some(Ended::NetworkChanged), "{why}");
            assert!(!s.paused(), "{why}");
        }
        // The same network, signed in, encrypted not yet answered: holds.
        let mut s = detected(t0);
        s.pause(t0, HOTEL, true, true).unwrap();
        assert_eq!(s.observe(at(t0, 30), paused_pass(&net(HOTEL, WIFI), false)), None);
        assert!(s.paused());
    }

    #[test]
    fn resume_cause_three_fifteen_minutes() {
        let t0 = Instant::now();
        let hotel = net(HOTEL, WIFI);
        let mut s = detected(t0);
        s.pause(t0, HOTEL, true, true).unwrap();
        assert_eq!(s.observe(at(t0, PAUSE_FOR.as_secs() - 1), paused_pass(&hotel, true)), None);
        assert_eq!(s.report(at(t0, PAUSE_FOR.as_secs() - 1)).unwrap().paused_left_s, Some(1));
        assert_eq!(s.observe(at(t0, PAUSE_FOR.as_secs()), paused_pass(&hotel, true)), Some(Ended::TimeUp));
        assert!(!s.paused());
        s.observe(at(t0, PAUSE_FOR.as_secs() + 5), seen(&hotel, true, true));
        assert_eq!(s.report(at(t0, PAUSE_FOR.as_secs() + 5)), notice(HOTEL, true), "the capture back and still a portal: the notice is back, the next pause is the user's");
    }

    /// The setting flipped off ends the pause; on again, the capture is wanted and
    /// opens, with no pause left over.
    #[test]
    fn the_setting_off_and_on_mid_pause_ends_it() {
        let t0 = Instant::now();
        let hotel = net(HOTEL, WIFI);
        let mut s = detected(t0);
        s.pause(t0, HOTEL, true, true).unwrap();
        assert_eq!(s.observe(at(t0, 5), Seen { wanted: false, ..paused_pass(&hotel, true) }), Some(Ended::SettingOff));
        assert!(!s.paused() && s.report(at(t0, 5)).is_none());
        s.observe(at(t0, 10), seen(&hotel, true, true));
        assert!(!s.paused(), "back on: shown again, not paused");
        assert!(s.report(at(t0, 10)).is_some());
    }

    #[test]
    fn resume_now_and_routes_down_end_it() {
        let t0 = Instant::now();
        let mut s = detected(t0);
        assert_eq!(s.resume(), None, "nothing to resume");
        s.pause(t0, HOTEL, true, true).unwrap();
        assert_eq!(s.resume(), Some(Ended::User));
        assert!(!s.paused());
        s.pause(t0, HOTEL, true, true).unwrap();
        s.forget();
        assert!(!s.paused() && s.report(t0).is_none());
    }
}
