//! Sieve's upstream connect, tried again when it fails before the app saw
//! anything. ipstack has already completed the app's handshake, so a connect
//! Sieve makes again costs the app nothing it can see: no byte has reached it,
//! and no decision has been made (the first bytes are read after this).
//!
//! What is tried, within one [`BUDGET`] for all of it, and at most
//! [`MAX_ATTEMPTS`] connects:
//! - a first connect still unanswered after [`RACE_AFTER`] is raced by one
//!   address of the other family, the first to connect wins (happy eyeballs);
//! - once a connect has failed, the next address its name resolved to, the other
//!   family first (as happy eyeballs orders them);
//! - a connect the server reset is tried once more after [`RECONNECT_AFTER`].
//!
//! Why Sieve races at all: ipstack completes the app's handshake before this runs
//! (`vendor/ipstack/src/stream/tcp.rs`), so the app's own happy eyeballs sees its
//! first address connect at once and never tries the other family. Without the race,
//! a network that drops IPv6 would hold every IPv6 flow for the whole budget.
//!
//! Every other address, raced or after a failure, comes from [`alternates`]: only
//! the addresses recorded for the one name the flow's address maps to, never for an
//! address several names share, and none for a name the filter blocks (P2-4 of the
//! 2026-11-08 second review). The name map is shared, and nothing says the flow's
//! own app resolved that name, but an address only one name ever resolved to is that
//! name's server, and the other family's address of the same name is the same site
//! by another road. The app's own TLS still checks whom it reached.
//!
//! Never more: no attempt is made past the budget or the count, the race is run
//! once, an address is reconnected once, and nothing here runs once the flow is
//! decided or a byte was delivered: no byte moves before [`connect`] returns, and the
//! connects that lost are dropped then. So a block always holds and nothing loops.

use std::collections::VecDeque;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use sieve_ipc::{RetryHow, Signal};
use tokio::time::Instant;

use crate::dns::NameMap;

/// Every attempt together. The relay's one connect always had this long
/// (`egress`), so with retries the app never waits longer than it did without
/// them, and less than Windows' own connect gives up after (about 21 s).
pub const BUDGET: Duration = Duration::from_secs(10);
/// A reset to the connect is tried once more this much later: a server that is
/// restarting or shedding load often takes the next one.
pub const RECONNECT_AFTER: Duration = Duration::from_millis(250);
/// A first connect not answered this long is raced by the other family. Longer
/// than a connect to a far server takes on a working network, so a working family is
/// almost never doubled, and short beside the budget a dropped family would cost.
pub const RACE_AFTER: Duration = Duration::from_secs(2);
/// Connects per flow at most, the first one included.
pub const MAX_ATTEMPTS: u32 = 3;

/// Why one connect failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The server reset the connect.
    Refused,
    /// No answer within the budget.
    Timeout,
    /// The network said there is no way to the server.
    Unreachable,
    /// Sieve had no way out for it (`route::pin`).
    Egress(String),
    Other(String),
}

impl Failure {
    pub fn from_io(e: &std::io::Error) -> Self {
        use std::io::ErrorKind;
        match e.kind() {
            ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => Self::Refused,
            ErrorKind::TimedOut => Self::Timeout,
            ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable | ErrorKind::AddrNotAvailable => Self::Unreachable,
            _ => Self::Other(e.to_string()),
        }
    }

    pub fn signal(&self) -> Signal {
        match self {
            Self::Refused => Signal::ConnectRefused,
            Self::Timeout => Signal::ConnectTimeout,
            Self::Unreachable => Signal::Unreachable,
            Self::Egress(_) => Signal::EgressFailed,
            Self::Other(_) => Signal::ConnectFailed,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused => f.write_str("refused"),
            Self::Timeout => f.write_str("timeout"),
            Self::Unreachable => f.write_str("unreachable"),
            Self::Egress(e) | Self::Other(e) => f.write_str(e),
        }
    }
}

pub type AttemptFuture<'a, S> = Pin<Box<dyn Future<Output = Result<S, Failure>> + Send + 'a>>;

/// One connect with no deadline of its own: `stack::egress::Egress` in
/// production, a scripted one in tests.
pub trait Attempt: Sync {
    type Stream: Send;
    fn attempt(&self, target: SocketAddr) -> AttemptFuture<'_, Self::Stream>;
}

/// How the connect ended.
#[derive(Debug)]
pub struct Connected<S> {
    pub result: Result<S, Failure>,
    /// Connects started, the first one included.
    pub attempts: u32,
    /// How the connect that answered was made, or the last one tried when none
    /// did; None when the first connect answered by itself.
    pub how: Option<RetryHow>,
}

impl<S> Connected<S> {
    /// What the log says: Sieve tried again, and whether it connected. The first
    /// connect winning is no retry, whatever else was started beside it.
    pub fn retry(&self) -> Option<RetryHow> {
        match (&self.result, self.how) {
            _ if self.attempts <= 1 => None,
            (Ok(_), None) => None,
            (_, how) => how.or(Some(RetryHow::NextAddress)),
        }
    }
}

/// The other addresses of the one name `ip` was resolved for, the other family
/// first. None when the address serves several names (the flow's own name is not
/// known before its first bytes, and another name's address may not serve it), and
/// none for a name `blocked` says the filter blocks: that flow is closed once its
/// bytes are read, and another connect would only reach the blocked server again.
pub fn alternates(names: &NameMap, ip: IpAddr, now_ms: u64, blocked: impl Fn(&str) -> bool) -> Vec<IpAddr> {
    let [name] = names.names(ip, now_ms)[..] else { return Vec::new() };
    if blocked(name) {
        return Vec::new();
    }
    let mut all: Vec<IpAddr> = names.addresses(name, now_ms).into_iter().filter(|a| *a != ip).collect();
    all.sort_by_key(|a| (a.is_ipv4() == ip.is_ipv4(), *a));
    all
}

struct Running<'a, S> {
    target: SocketAddr,
    how: Option<RetryHow>,
    connect: AttemptFuture<'a, S>,
}

/// Connects to `target` as the module says. `alternates` is asked at most once,
/// and only once a connect failed or the race is due.
pub async fn connect<A: Attempt>(dialer: &A, target: SocketAddr, alternates: impl FnOnce() -> Vec<IpAddr>) -> Connected<A::Stream> {
    let start = Instant::now();
    let deadline = start + BUDGET;
    let mut running = vec![Running { target, how: None, connect: dialer.attempt(target) }];
    let mut attempts = 1;
    let mut alternates = Some(alternates);
    let mut addresses: VecDeque<SocketAddr> = VecDeque::new();
    let mut ask = |addresses: &mut VecDeque<SocketAddr>| {
        if let Some(ask) = alternates.take() {
            addresses.extend(ask().into_iter().map(|ip| SocketAddr::new(ip, target.port())));
        }
    };
    let mut reconnects: Vec<(Instant, SocketAddr)> = Vec::new();
    let mut reconnected: Vec<SocketAddr> = Vec::new();
    // Set by a failure: the next address is tried then.
    let mut next_address: Option<Instant> = None;
    // Once, while the first connect is still waiting.
    let mut race: Option<Instant> = Some(start + RACE_AFTER);
    let mut last = (Failure::Timeout, None);
    loop {
        let wake = [Some(deadline), next_address, race, reconnects.iter().map(|(at, _)| *at).min()].into_iter().flatten().min().unwrap_or(deadline);
        let answered = tokio::select! {
            answered = std::future::poll_fn(|cx| {
                for (i, r) in running.iter_mut().enumerate() {
                    if let Poll::Ready(result) = r.connect.as_mut().poll(cx) {
                        return Poll::Ready((i, result));
                    }
                }
                Poll::Pending
            }) => Some(answered),
            () = tokio::time::sleep_until(wake) => None,
        };
        let now = Instant::now();
        if let Some((i, result)) = answered {
            let done = running.swap_remove(i);
            match result {
                Ok(stream) => return Connected { result: Ok(stream), attempts, how: done.how },
                Err(failure) => {
                    if failure == Failure::Refused && !reconnected.contains(&done.target) {
                        reconnected.push(done.target);
                        reconnects.push((now + RECONNECT_AFTER, done.target));
                    } else {
                        next_address = Some(now);
                    }
                    last = (failure, done.how);
                }
            }
        }
        if now >= deadline {
            // A connect still waiting at the end is what failed last: it timed out.
            if let Some(waiting) = running.last() {
                return Connected { result: Err(Failure::Timeout), attempts, how: waiting.how };
            }
            return Connected { result: Err(last.0), attempts, how: last.1 };
        }
        if race.is_some_and(|at| now >= at) {
            race = None;
            // Only beside the first connect, and only by the other family: the same
            // family's next address most likely goes the same dropped way.
            if attempts < MAX_ATTEMPTS && running.iter().any(|r| r.how.is_none()) {
                ask(&mut addresses);
                if let Some(at) = addresses.iter().position(|a| a.is_ipv4() != target.is_ipv4()) {
                    let other = addresses.remove(at).expect("a position in the queue");
                    running.push(Running { target: other, how: Some(RetryHow::NextAddress), connect: dialer.attempt(other) });
                    attempts += 1;
                }
            }
        }
        if attempts < MAX_ATTEMPTS && next_address.is_some_and(|at| now >= at) {
            ask(&mut addresses);
            next_address = None;
            if let Some(next) = addresses.pop_front() {
                running.push(Running { target: next, how: Some(RetryHow::NextAddress), connect: dialer.attempt(next) });
                attempts += 1;
            }
        }
        while attempts < MAX_ATTEMPTS
            && let Some(at) = reconnects.iter().position(|(at, _)| now >= *at)
        {
            let (_, again) = reconnects.swap_remove(at);
            running.push(Running { target: again, how: Some(RetryHow::Reconnect), connect: dialer.attempt(again) });
            attempts += 1;
        }
        if attempts >= MAX_ATTEMPTS {
            reconnects.clear();
            next_address = None;
        }
        if running.is_empty() && reconnects.is_empty() && next_address.is_none() {
            return Connected { result: Err(last.0), attempts, how: last.1 };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    const V6: &str = "[2001:db8::1]:443";
    const V4: &str = "192.0.2.1:443";

    /// What one address does when asked: answer after a while, or never.
    #[derive(Clone, Copy)]
    enum Script {
        After(Duration, Result<(), Failure2>),
        Never,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Failure2 {
        Refused,
        Unreachable,
    }

    /// A fake dialer on tokio's paused clock: each address answers by its script,
    /// a reconnect by its second entry, and every attempt is recorded.
    struct Fake {
        scripts: Vec<(SocketAddr, Vec<Script>)>,
        asked: Mutex<Vec<(SocketAddr, Duration)>>,
        start: Instant,
    }

    impl Fake {
        fn new(scripts: &[(&str, &[Script])]) -> Self {
            Self { scripts: scripts.iter().map(|(a, s)| (a.parse().unwrap(), s.to_vec())).collect(), asked: Mutex::default(), start: Instant::now() }
        }

        fn asked(&self) -> Vec<(SocketAddr, Duration)> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl Attempt for Fake {
        type Stream = SocketAddr;

        fn attempt(&self, target: SocketAddr) -> AttemptFuture<'_, SocketAddr> {
            let mut asked = self.asked.lock().unwrap();
            let nth = asked.iter().filter(|(a, _)| *a == target).count();
            asked.push((target, self.start.elapsed()));
            let script = self.scripts.iter().find(|(a, _)| *a == target).and_then(|(_, s)| s.get(nth).copied()).unwrap_or(Script::Never);
            Box::pin(async move {
                match script {
                    Script::Never => std::future::pending().await,
                    Script::After(wait, answer) => {
                        tokio::time::sleep(wait).await;
                        answer.map(|()| target).map_err(|f| match f {
                            Failure2::Refused => Failure::Refused,
                            Failure2::Unreachable => Failure::Unreachable,
                        })
                    }
                }
            })
        }
    }

    const OK_FAST: Script = Script::After(Duration::from_millis(30), Ok(()));
    const REFUSED: Script = Script::After(Duration::from_millis(20), Err(Failure2::Refused));
    const UNREACHABLE: Script = Script::After(Duration::from_millis(20), Err(Failure2::Unreachable));

    fn addr(a: &str) -> SocketAddr {
        a.parse().unwrap()
    }

    fn v4_alternate() -> Vec<IpAddr> {
        vec![addr(V4).ip()]
    }

    #[tokio::test(start_paused = true)]
    async fn a_first_connect_that_answers_asks_nothing_else() {
        let fake = Fake::new(&[(V6, &[OK_FAST])]);
        let asked_alternates = std::cell::Cell::new(false);
        let out = connect(&fake, addr(V6), || {
            asked_alternates.set(true);
            v4_alternate()
        })
        .await;
        assert_eq!((out.retry(), out.attempts, out.result), (None, 1, Ok(addr(V6))));
        assert!(!asked_alternates.get(), "the name map is read only on trouble");
    }

    /// ipstack answered the app's handshake, so its own happy eyeballs never runs:
    /// a family the network drops is raced by the other at [`RACE_AFTER`], not
    /// waited on for the whole budget (2026-11-09 verifier of bdd761a, P2).
    #[tokio::test(start_paused = true)]
    async fn a_silent_first_address_loses_to_the_other_family_at_the_race() {
        let fake = Fake::new(&[(V6, &[Script::Never]), (V4, &[OK_FAST])]);
        let start = Instant::now();
        let out = connect(&fake, addr(V6), v4_alternate).await;
        assert_eq!((out.retry(), out.attempts, out.result), (Some(RetryHow::NextAddress), 2, Ok(addr(V4))));
        assert_eq!(fake.asked()[1], (addr(V4), RACE_AFTER));
        assert_eq!(Instant::now() - start, RACE_AFTER + Duration::from_millis(30));
    }

    /// The race takes the other family only, and only once: the same family's
    /// next address waits for a failure.
    #[tokio::test(start_paused = true)]
    async fn the_race_takes_only_the_other_family() {
        let fake = Fake::new(&[(V6, &[Script::Never]), ("[2001:db8::2]:443", &[OK_FAST])]);
        let start = Instant::now();
        let out = connect(&fake, addr(V6), || vec!["2001:db8::2".parse().unwrap()]).await;
        assert_eq!((out.attempts, out.result.unwrap_err()), (1, Failure::Timeout));
        assert_eq!(Instant::now() - start, BUDGET);
    }

    /// The race asks the same rule as a failure does: an address several names
    /// share, or a blocked name, gets no other address, so the one connect waits
    /// the budget as it always did.
    #[tokio::test(start_paused = true)]
    async fn an_ambiguous_address_or_a_blocked_name_is_not_raced() {
        let ip6 = addr(V6).ip();
        let mut names = NameMap::default();
        for ip in [ip6, addr(V4).ip()] {
            names.record("cdn.example", ip, 300, 0);
        }
        // The control: one name, not blocked, races.
        let fake = Fake::new(&[(V6, &[Script::Never]), (V4, &[OK_FAST])]);
        let out = connect(&fake, addr(V6), || alternates(&names, ip6, 1, |_| false)).await;
        assert_eq!(out.result, Ok(addr(V4)));

        let fake = Fake::new(&[(V6, &[Script::Never]), (V4, &[OK_FAST])]);
        let out = connect(&fake, addr(V6), || alternates(&names, ip6, 1, |n| n == "cdn.example")).await;
        assert_eq!((out.attempts, out.result.unwrap_err()), (1, Failure::Timeout), "a blocked name");

        names.record("other.example", ip6, 300, 0);
        let fake = Fake::new(&[(V6, &[Script::Never]), (V4, &[OK_FAST])]);
        let start = Instant::now();
        let out = connect(&fake, addr(V6), || alternates(&names, ip6, 1, |_| false)).await;
        assert_eq!((out.attempts, out.result.unwrap_err()), (1, Failure::Timeout), "an address two names share");
        assert_eq!(Instant::now() - start, BUDGET);
        assert_eq!(fake.asked().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_first_connect_that_answers_is_no_retry() {
        let slow = Script::After(RACE_AFTER - Duration::from_millis(1), Ok(()));
        let fake = Fake::new(&[(V6, &[slow]), (V4, &[OK_FAST])]);
        let out = connect(&fake, addr(V6), v4_alternate).await;
        assert_eq!((out.retry(), out.attempts, out.result), (None, 1, Ok(addr(V6))));
        // Raced, and the first still wins: no retry either.
        let later = Script::After(RACE_AFTER + Duration::from_millis(500), Ok(()));
        let fake = Fake::new(&[(V6, &[later]), (V4, &[Script::Never])]);
        let out = connect(&fake, addr(V6), v4_alternate).await;
        assert_eq!((out.retry(), out.attempts, out.result), (None, 2, Ok(addr(V6))));
    }

    #[test]
    fn the_first_connect_winning_is_reported_as_no_retry() {
        let won = Connected { result: Ok(()), attempts: 2, how: None };
        assert_eq!(won.retry(), None);
        let other = Connected { result: Ok(()), attempts: 2, how: Some(RetryHow::NextAddress) };
        assert_eq!(other.retry(), Some(RetryHow::NextAddress));
        let failed: Connected<()> = Connected { result: Err(Failure::Timeout), attempts: 2, how: None };
        assert_eq!(failed.retry(), Some(RetryHow::NextAddress), "tried again, and nothing connected");
    }

    #[tokio::test(start_paused = true)]
    async fn an_unreachable_address_moves_to_the_next_at_once() {
        let fake = Fake::new(&[(V6, &[UNREACHABLE]), (V4, &[OK_FAST])]);
        let out = connect(&fake, addr(V6), v4_alternate).await;
        assert_eq!(out.result, Ok(addr(V4)));
        assert_eq!(fake.asked()[1], (addr(V4), Duration::from_millis(20)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_reset_is_tried_once_more_after_a_short_wait() {
        let fake = Fake::new(&[(V4, &[REFUSED, OK_FAST])]);
        let out = connect(&fake, addr(V4), Vec::new).await;
        assert_eq!((out.retry(), out.attempts, out.result), (Some(RetryHow::Reconnect), 2, Ok(addr(V4))));
        assert_eq!(fake.asked()[1].1, Duration::from_millis(20) + RECONNECT_AFTER);
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_reset_is_the_answer_and_names_the_signal() {
        let fake = Fake::new(&[(V4, &[REFUSED, REFUSED])]);
        let out = connect(&fake, addr(V4), Vec::new).await;
        assert_eq!((out.result.clone().unwrap_err(), out.attempts, out.retry()), (Failure::Refused, 2, Some(RetryHow::Reconnect)));
        assert_eq!(out.result.unwrap_err().signal(), Signal::ConnectRefused);
    }

    /// The bound the owner set: never longer than without Sieve's retries.
    #[tokio::test(start_paused = true)]
    async fn nothing_answers_within_the_budget_and_no_more_than_the_attempts() {
        let many: Vec<IpAddr> = (2..10).map(|i| format!("192.0.2.{i}").parse().unwrap()).collect();
        let fake = Fake::new(&[(V6, &[UNREACHABLE])]);
        let start = Instant::now();
        let out = connect(&fake, addr(V6), || many.clone()).await;
        assert_eq!(Instant::now() - start, BUDGET);
        assert_eq!((out.result.unwrap_err(), out.attempts), (Failure::Timeout, 2), "the next address is silent: none after it");
        let unreachable: Vec<(&str, &[Script])> = vec![(V6, &[UNREACHABLE]), ("192.0.2.2:443", &[UNREACHABLE]), ("192.0.2.3:443", &[UNREACHABLE]), ("192.0.2.4:443", &[UNREACHABLE])];
        let fake = Fake::new(&unreachable);
        let out = connect(&fake, addr(V6), || many.clone()).await;
        assert_eq!((out.result.unwrap_err(), out.attempts), (Failure::Unreachable, MAX_ATTEMPTS));
        assert_eq!(fake.asked().len(), MAX_ATTEMPTS as usize, "failures in a row stop at the count");
    }

    #[tokio::test(start_paused = true)]
    async fn with_no_other_address_a_failure_ends_at_once() {
        let fake = Fake::new(&[(V4, &[UNREACHABLE])]);
        let start = Instant::now();
        let out = connect(&fake, addr(V4), Vec::new).await;
        assert_eq!((out.retry(), out.attempts, out.result.unwrap_err()), (None, 1, Failure::Unreachable));
        assert_eq!(Instant::now() - start, Duration::from_millis(20), "no waiting for nothing");
    }

    #[test]
    fn alternates_come_only_from_an_unambiguous_name_other_family_first() {
        let mut names = NameMap::default();
        let ip6: IpAddr = "2001:db8::1".parse().unwrap();
        for ip in ["2001:db8::1", "2001:db8::2", "192.0.2.1", "192.0.2.2"] {
            names.record("cdn.example", ip.parse().unwrap(), 300, 0);
        }
        let none = |_: &str| false;
        assert_eq!(alternates(&names, ip6, 1, none), ["192.0.2.1", "192.0.2.2", "2001:db8::2"].map(|a| a.parse::<IpAddr>().unwrap()));
        assert!(alternates(&names, ip6, 1, |n| n == "cdn.example").is_empty(), "a blocked name gets no other address");
        names.record("other.example", ip6, 300, 0);
        assert!(alternates(&names, ip6, 1, none).is_empty(), "a shared address could be another name's");
        assert!(alternates(&names, "198.51.100.1".parse().unwrap(), 1, none).is_empty(), "no name, no alternates");
    }
}
