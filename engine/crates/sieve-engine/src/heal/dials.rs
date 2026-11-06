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
/// The score halves every this long, credit included (plan 4.3).
pub const HALF_LIFE_MS: u64 = 30 * 60_000;
/// Excluded at this score. Exactly "the second close arrives within one half-life
/// of the first": `0.5^(gap / half life) + 1 >= 1.5` is `gap <= half life`. The
/// plan's 2 could be reached only by two closes in one millisecond (task F1).
pub const EXCLUDE_AT: f64 = 1.5;
/// The most credit used connections can buy: a pair that carried requests takes
/// 4 quick closes instead of 2. Bounded, so a client that starts pinning after an
/// update still heals, and fatal alerts ignore it (task F4, Q2, U5).
pub const MAX_CREDIT: f64 = 2.0;
/// One of these from the client excludes the pair at once (plan 4.3).
pub const FATAL_ALERTS: [AlertDescription; 6] = [
    AlertDescription::BadCertificate,
    AlertDescription::UnsupportedCertificate,
    AlertDescription::CertificateUnknown,
    AlertDescription::UnknownCA,
    AlertDescription::DecryptError,
    AlertDescription::AccessDenied,
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
