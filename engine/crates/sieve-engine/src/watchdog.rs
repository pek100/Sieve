//! The watchdog (plan 1.6.2): a plain thread outside the tokio runtime that
//! guards against a hung engine. Two heartbeats: the TUN reader's (it marks
//! a packet as pending while it enqueues it) and the relay
//! scheduler's (the watchdog posts a ping into the runtime, which a task
//! answers). When either stays pending for [`STALL_MS`], the watchdog
//! deletes Sieve's routes first, then exits the process; the service
//! manager restarts it, and the crash-loop stop counts that restart.
//!
//! "Pending", not "advancing": an idle adapter is not a stall, so the TUN
//! reader can block on its read event and use no CPU (plan 6: idle CPU 0).
//! The watchdog runs only while routes are up; otherwise it waits on a
//! condition variable.
//!
//! [`PathWatch`] additionally follows admitted adapter arrivals through the
//! packet loop and device writes. Runtime pings and successful enqueueing do
//! not demonstrate packet progress. A worker exit also uses the existing trip.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

mod path;
#[cfg(test)]
mod path_tests;
pub use path::{Offered, PathWatch};

/// A component stalled when it stayed pending this long (plan
/// `watchdog.stallMs`, declared 5000 ms: long enough for a busy relay to
/// answer a ping, short enough that a hang costs seconds of network).
pub const STALL_MS: u64 = 5_000;
/// How often the watchdog looks while armed.
pub const CHECK_EVERY_MS: u64 = 1_000;

/// Milliseconds since the first call in this process, from the monotonic
/// clock: the heartbeats' and the watchdog's one time base.
pub fn monotonic_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    u64::try_from(START.get_or_init(std::time::Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// One heartbeat: when its current piece of work began (none while idle),
/// and how many pieces finished.
#[derive(Debug, Default)]
pub struct Beat {
    /// Start time plus one, 0 while idle.
    pending: AtomicU64,
    done: AtomicU64,
}

impl Beat {
    /// Work began at `now_ms` (kept when already pending: the oldest counts).
    pub fn begin(&self, now_ms: u64) {
        let _ = self.pending.compare_exchange(0, now_ms.saturating_add(1), Ordering::AcqRel, Ordering::Acquire);
    }

    pub fn end(&self) {
        self.pending.store(0, Ordering::Release);
        self.done.fetch_add(1, Ordering::Relaxed);
    }

    pub fn pending_since(&self) -> Option<u64> {
        match self.pending.load(Ordering::Acquire) {
            0 => None,
            v => Some(v - 1),
        }
    }

    pub fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }
}

/// Scheduler/reader heartbeats and the current routing run's packet path.
#[derive(Debug, Default)]
pub struct Beats {
    pub tun: Beat,
    pub relay: Beat,
    /// Replaced for each routing run. Only the watchdog/status reader lock it,
    /// never the packet loop, a flow task, or an OS call.
    pub path: Mutex<Option<PathWatch>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stall {
    pub what: &'static str,
    pub ms: u64,
    /// The stalled component's own error, when it ended with one.
    pub detail: Option<String>,
}

impl Stall {
    pub fn reason(&self) -> String {
        let detail = self.detail.as_deref().map(|d| format!(" ({d})")).unwrap_or_default();
        format!("the watchdog stopped the engine: the {} did not answer for {} ms{detail}", self.what, self.ms)
    }
}

/// The first heartbeat pending for `stall_ms` or longer at `now_ms`.
pub fn stalled(beats: &Beats, now_ms: u64, stall_ms: u64) -> Option<Stall> {
    [("TUN reader", &beats.tun), ("relay", &beats.relay)].into_iter().find_map(|(what, b)| {
        let ms = now_ms.saturating_sub(b.pending_since()?);
        (ms >= stall_ms).then_some(Stall { what, ms, detail: None })
    })
}

/// What the watchdog does on a stall, in this order (injected for tests).
pub trait Trip {
    /// Deletes Sieve's routes; returns what happened, for the record.
    fn delete_routes(&self) -> String;
    /// Ends the process (in the service: `std::process::exit`).
    fn exit(&self, stall: &Stall, routes: &str);
}

/// Armed while routes are up.
#[derive(Debug, Default)]
pub struct Arm {
    armed: Mutex<bool>,
    changed: Condvar,
}

impl Arm {
    pub fn set(&self, on: bool) {
        *self.armed.lock().unwrap_or_else(|p| p.into_inner()) = on;
        self.changed.notify_all();
    }

    pub fn is_armed(&self) -> bool {
        *self.armed.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Blocks until armed (no CPU while disarmed).
    fn wait(&self) {
        let mut on = self.armed.lock().unwrap_or_else(|p| p.into_inner());
        while !*on {
            on = self.changed.wait(on).unwrap_or_else(|p| p.into_inner());
        }
    }
}

/// One look: when armed, posts a relay ping if none is pending (`ping`
/// must make the runtime call `beats.relay.end()`), then checks the path and beats.
pub fn check(arm: &Arm, beats: &Beats, now_ms: u64, ping: &dyn Fn()) -> Option<Stall> {
    if !arm.is_armed() {
        return None;
    }
    if beats.relay.pending_since().is_none() {
        beats.relay.begin(now_ms);
        ping();
    }
    // Prefer the specific packet stage over the reader's queue backpressure.
    let path = beats.path.lock().unwrap_or_else(|p| p.into_inner()).as_mut().and_then(|p| p.check(now_ms));
    path.or_else(|| stalled(beats, now_ms, STALL_MS))
}

/// The watchdog thread's loop: wait to be armed, look every
/// [`CHECK_EVERY_MS`], and on a stall delete the routes, then exit.
pub fn run(arm: &Arm, beats: &Beats, now_ms: &dyn Fn() -> u64, ping: &dyn Fn(), trip: &dyn Trip) {
    loop {
        arm.wait();
        std::thread::sleep(Duration::from_millis(CHECK_EVERY_MS));
        if let Some(stall) = check(arm, beats, now_ms(), ping) {
            let routes = trip.delete_routes();
            trip.exit(&stall, &routes);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn idle_beats_never_stall_and_a_finished_one_counts() {
        let beats = Beats::default();
        assert_eq!(stalled(&beats, u64::MAX, STALL_MS), None);
        beats.tun.begin(10);
        beats.tun.begin(20);
        assert_eq!(beats.tun.pending_since(), Some(10), "the oldest pending start counts");
        beats.tun.end();
        assert_eq!((beats.tun.pending_since(), beats.tun.done()), (None, 1));
    }

    /// A fake clock: the relay answers its pings until it hangs; the
    /// watchdog trips exactly STALL_MS after the unanswered ping, and
    /// deletes the routes before it exits.
    #[test]
    fn a_hung_relay_trips_the_watchdog_routes_first() {
        let arm = Arm::default();
        let beats = Beats::default();
        let answering = std::cell::Cell::new(true);
        let ping = || {
            if answering.get() {
                beats.relay.end();
            }
        };
        assert_eq!(check(&arm, &beats, 0, &ping), None, "disarmed: nothing is checked");
        assert_eq!(beats.relay.pending_since(), None);
        arm.set(true);
        for t in (0..10_000).step_by(1_000) {
            assert_eq!(check(&arm, &beats, t, &ping), None, "answered at {t}");
        }
        answering.set(false);
        let hung_at = 10_000;
        assert_eq!(check(&arm, &beats, hung_at, &ping), None);
        assert_eq!(check(&arm, &beats, hung_at + STALL_MS - 1, &ping), None);
        let stall = check(&arm, &beats, hung_at + STALL_MS, &ping).expect("tripped");
        assert_eq!(stall, Stall { what: "relay", ms: STALL_MS, detail: None });

        struct Record(RefCell<Vec<String>>);
        impl Trip for Record {
            fn delete_routes(&self) -> String {
                self.0.borrow_mut().push("delete routes".into());
                "3 deleted".into()
            }
            fn exit(&self, stall: &Stall, routes: &str) {
                self.0.borrow_mut().push(format!("exit: {}; routes {routes}", stall.reason()));
            }
        }
        let record = Record(RefCell::new(Vec::new()));
        // One pass of the loop with the same fake time (the sleep is real but short-circuited by the trip).
        let now = || hung_at + STALL_MS;
        run(&arm, &beats, &now, &ping, &record);
        assert_eq!(
            record.0.into_inner(),
            ["delete routes", "exit: the watchdog stopped the engine: the relay did not answer for 5000 ms; routes 3 deleted"]
        );
    }

    #[test]
    fn a_stuck_tun_reader_trips_too() {
        let arm = Arm::default();
        arm.set(true);
        let beats = Beats::default();
        let ping = || beats.relay.end();
        beats.tun.begin(100);
        assert_eq!(check(&arm, &beats, 100 + STALL_MS, &ping), Some(Stall { what: "TUN reader", ms: STALL_MS, detail: None }));
    }
}
