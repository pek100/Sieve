//! Self-healing's declared dials (plan 4.3, task D1), each with why it has the
//! value it has (S25). Nothing else in `heal` holds a number.

use rustls::AlertDescription;

/// A close later than this after the handshake says nothing about the client.
///
/// TENSION (S18, S50): a hard edge on an evidence weight, kept on purpose. A
/// client that rejected the certificate closes at once; one that idles for
/// longer has simply not needed its connection, and "a little evidence" would
/// tax every idle preconnect. The plan's policy choice, recorded here.
pub const SILENT_CLOSE_MS: u64 = 2_000;
/// Refusals, or quiet closes, of one pair within this long of the first of them are
/// one piece of evidence: a burst. A client that gives up on several parallel
/// connections at once (a browser exiting with handshakes in flight, a tab closing)
/// does it in one burst, and one decision of the client is one piece of evidence
/// however many sockets carry it. A client that retries a rejection retries after
/// the burst, so this delays its exclusion by this long at most. Anchored at the
/// burst's first, so a client retrying faster than this still opens a new burst
/// every this long.
pub const BURST_MS: u64 = 500;
/// Quiet closes of one pair that exclude it, each in a burst of its own, when they
/// fall within [`QUIET_WINDOW_MS`] of the first. A quiet close is one after a
/// completed handshake, under [`SILENT_CLOSE_MS`], with no alert, while no other
/// connection of the pair is open, by a pair that carried no request since the
/// count began. A browser's unused preconnects and the sockets it drops at a tab's or
/// its own close were taken for rejections by the rule before (2026-11-08: Edge and
/// Chrome 157 excluded a search engine; plan 4.3); what is left is an app that checks
/// its pin after TLS and drops the socket, then tries again. Never a registered
/// browser's closes (`heal::silence_only_for_apps`, run 7): a browser refuses with an alert.
///
/// Another connection of the pair open blocks the evidence even when it is from
/// the same burst: a browser's preconnect round holds one of its sockets idle and
/// drops the rest at once, which is exactly a same-burst socket staying open.
pub const QUIET_CLOSES: u32 = 3;
/// See [`QUIET_CLOSES`]. A fixed window from the first quiet close, so closes spread
/// over a browsing session never add up. Minutes, not seconds: a pinning app that
/// retries on its own schedule (a sync client every minute or two) heals too, and
/// what a browser does on a host it never sends a request to (a preconnect dropped
/// while nothing else is open, at a tab's close) does not repeat three times in this.
///
/// TENSION (S18, S50): a count in a window, not the half-life law, kept on purpose.
/// The half-life law at this time scale either forgets a slow retry or sums an hour
/// of preconnects; the evidence wanted is "repeats soon", which is the window.
/// Unmeasured against real clients (task U4, U5).
pub const QUIET_WINDOW_MS: u64 = 10 * 60_000;
/// Quiet closes that exclude a pair that carried a request in this run, within
/// [`USED_QUIET_WINDOW_MS`]. A request resets the count, so these are closes with
/// no request between them. Higher and quicker than for a pair never used: a request
/// says the client once took the leaf, so only a client that now drops connection
/// after connection at once is believed (one that updated to start pinning, or the
/// pinned half of an app whose other half shares its exe), and a browser's tab
/// closes on a site it uses never come this densely.
pub const USED_QUIET_CLOSES: u32 = 2 * QUIET_CLOSES;
/// See [`USED_QUIET_CLOSES`]: "repeats at once", the window the quiet-close rule had
/// for every pair before (2026-11-08).
pub const USED_QUIET_WINDOW_MS: u64 = 60_000;
/// The score of refused handshakes halves every this long, credit included (plan 4.3).
pub const HALF_LIFE_MS: u64 = 30 * 60_000;
/// Excluded at this score. Exactly "the second refusal arrives within one half-life
/// of the first": `0.5^(gap / half life) + 1 >= 1.5` is `gap <= half life`, for any
/// gap past one [`BURST_MS`]. The plan's 2 could be reached only by two refusals in
/// one millisecond (task F1), which are now one burst.
pub const EXCLUDE_AT: f64 = 1.5;
/// The most credit used connections can buy: a request clears every refusal heard
/// before it, and a pair that carried requests then takes up to 4 refusals instead
/// of 2. Bounded, so a client that starts pinning after an update still heals, and
/// fatal alerts ignore it (task F4, Q2, U5).
pub const MAX_CREDIT: f64 = 2.0;
/// One of these from the client excludes the pair at once (plan 4.3). `ech_required`
/// says the hello was real ECH that task D9 took for GREASE: the name is not one to
/// decrypt, and each further attempt would cost the client its privacy again.
pub const FATAL_ALERTS: [AlertDescription; 7] = [
    AlertDescription::BadCertificate,
    AlertDescription::UnsupportedCertificate,
    AlertDescription::CertificateUnknown,
    AlertDescription::UnknownCA,
    AlertDescription::DecryptError,
    AlertDescription::AccessDenied,
    AlertDescription::EncryptedClientHelloRequired,
];
/// Exclusions of one app this close to its group's first join that group: a fixed
/// window, so a slow trickle cannot hold one group open for ever (plan 4.3).
pub const NOTICE_WINDOW_MS: u64 = 10 * 60_000;
/// Pairs scored at once. A lost score costs one more close, so this is a memory
/// bound with room for far more pairs than one person uses, not a tuned value.
pub const MAX_PAIRS: usize = 4096;
/// Hosts a notice names; `total` still counts them all.
pub const NOTICE_HOSTS_MAX: usize = 20;
/// Notices kept, oldest out first. A client polls every few seconds, so this
/// outlasts any burst it would read.
pub const NOTICE_RING: usize = 64;
