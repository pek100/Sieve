//! Per-device rules and limits, and the address classes denied by default.
//!
//! The hub sees only `host:port`, never payload, so rules are by domain, by
//! address and by port. Order of evaluation for a stream:
//!
//! 0. Port: the default-denied ports (25, SMTP) refuse unless the device's
//!    `allow_ports` lists them.
//! 1. Domain: a `deny_suffixes` match refuses. If `allow_suffixes` is not
//!    empty, a name must match one of them, and an address literal must fall
//!    inside `allow_cidrs`. A name that is not a public DNS name (one label,
//!    `localhost`, `.local`, `.home.arpa`, `.internal`, `.lan`) refuses unless
//!    an `allow_suffixes` entry names it: on Windows such names resolve
//!    through LLMNR, NetBIOS or mDNS to machines on the hub's own network.
//! 2. The name is resolved AT THE HUB, and each address is checked; the hub
//!    connects only to an address that passes (so a name cannot be made to
//!    point somewhere else between check and connect):
//!    `deny_cidrs` refuses; `allow_cidrs` admits; the hub's LAN blocks refuse
//!    (detected from its interfaces, plus the owner's manual ones); then the
//!    default-denied classes refuse (see `denied_class`).
//!
//! So a device cannot reach the host's own machine or local network unless
//! the owner adds an `allow_cidrs` entry for it.
//!
//! A refusal's text, which goes back to the device, names the class only;
//! the resolved address goes to the audit log.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::LinkError;

/// An address block, `addr/prefix` (a bare address is a /32 or /128).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let bits = self.prefix.min(32) as u32;
                let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let bits = self.prefix.min(128) as u32;
                let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = LinkError;
    fn from_str(s: &str) -> Result<Self, LinkError> {
        let bad = || LinkError::Store(format!("not an address block: {s}"));
        let (a, p) = match s.trim().split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s.trim(), None),
        };
        let addr: IpAddr = a.parse().map_err(|_| bad())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p.parse::<u8>().map_err(|_| bad())?,
            None => max,
        };
        if prefix > max {
            return Err(bad());
        }
        Ok(Cidr { addr: addr.to_canonical(), prefix })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Serialize for Cidr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rules {
    /// If not empty, only names under these suffixes (and only literals in
    /// `allow_cidrs`) are allowed.
    #[serde(default)]
    pub allow_suffixes: Vec<String>,
    #[serde(default)]
    pub deny_suffixes: Vec<String>,
    /// Admits addresses otherwise denied by class or LAN (e.g. one NAS).
    #[serde(default)]
    pub allow_cidrs: Vec<Cidr>,
    #[serde(default)]
    pub deny_cidrs: Vec<Cidr>,
    /// Admits ports that are denied by default (`DEFAULT_DENIED_PORTS`).
    #[serde(default)]
    pub allow_ports: Vec<u16>,
}

/// Ports refused unless a device's `allow_ports` lists them: 25 (SMTP), so a
/// device cannot send mail from the hub's address by default.
pub const DEFAULT_DENIED_PORTS: &[u16] = &[25];

/// Upper bounds accepted for limits (the CLI refuses more; the hub clamps a
/// hand-edited store to them).
pub const MAX_CONCURRENT: u32 = 256;
pub const MAX_OPENS_PER_MINUTE: u32 = 60_000;
pub const MAX_BYTES_PER_SEC: u64 = 10_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Streams open at once.
    pub max_concurrent: u32,
    /// New streams per minute (token bucket, burst = the same number).
    pub opens_per_minute: u32,
    /// Relay bytes per second, both directions together; 0 = unlimited.
    #[serde(default)]
    pub bytes_per_sec: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_concurrent: 64, opens_per_minute: 600, bytes_per_sec: 0 }
    }
}

impl Limits {
    /// Refuses values outside the accepted ranges.
    pub fn validate(&self) -> Result<(), LinkError> {
        if !(1..=MAX_CONCURRENT).contains(&self.max_concurrent) {
            return Err(LinkError::Store(format!("concurrent must be 1..={MAX_CONCURRENT}")));
        }
        if !(1..=MAX_OPENS_PER_MINUTE).contains(&self.opens_per_minute) {
            return Err(LinkError::Store(format!("per-minute must be 1..={MAX_OPENS_PER_MINUTE}")));
        }
        if self.bytes_per_sec > MAX_BYTES_PER_SEC {
            return Err(LinkError::Store(format!("bytes-per-sec must be 0..={MAX_BYTES_PER_SEC}")));
        }
        Ok(())
    }

    /// The same limits forced into the accepted ranges (for a store that was
    /// edited by hand).
    pub fn clamped(self) -> Limits {
        Limits {
            max_concurrent: self.max_concurrent.clamp(1, MAX_CONCURRENT),
            opens_per_minute: self.opens_per_minute.clamp(1, MAX_OPENS_PER_MINUTE),
            bytes_per_sec: self.bytes_per_sec.min(MAX_BYTES_PER_SEC),
        }
    }
}

fn normalize(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Suffixes that never name a public DNS host: they resolve through mDNS,
/// LLMNR, NetBIOS or the local network's own resolver.
const NON_PUBLIC_SUFFIXES: &[&str] = &["localhost", "local", "home.arpa", "internal", "lan"];

/// Why `host` (a name, not a literal) is not a public DNS name, if it is not.
pub fn non_public_name(host: &str) -> Option<&'static str> {
    let h = normalize(host);
    if !h.contains('.') {
        return Some("a single-label name (resolved on the hub's local network)");
    }
    NON_PUBLIC_SUFFIXES
        .iter()
        .any(|s| suffix_matches(&h, s))
        .then_some("a local-only name (resolved on the hub's local network)")
}

/// Stage 0: the port.
pub fn check_port(rules: &Rules, port: u16) -> Result<(), String> {
    if DEFAULT_DENIED_PORTS.contains(&port) && !rules.allow_ports.contains(&port) {
        return Err(format!("port {port} is denied by default"));
    }
    Ok(())
}

/// `suffix` matches the name itself and every name under it, on label
/// boundaries ("example.com" matches "a.example.com", not "badexample.com").
pub fn suffix_matches(host: &str, suffix: &str) -> bool {
    let h = normalize(host);
    let s = normalize(suffix.trim_start_matches("*.").trim_start_matches('.'));
    !s.is_empty() && (h == s || h.ends_with(&format!(".{s}")))
}

/// Stage 1: the name (or literal) as the device sent it.
pub fn check_host(rules: &Rules, host: &str) -> Result<(), String> {
    let literal = host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().ok();
    if literal.is_none()
        && let Some(s) = rules.deny_suffixes.iter().find(|s| suffix_matches(host, s))
    {
        return Err(format!("domain denied ({s})"));
    }
    let allowed_name = literal.is_none() && rules.allow_suffixes.iter().any(|s| suffix_matches(host, s));
    if literal.is_none()
        && !allowed_name
        && let Some(why) = non_public_name(host)
    {
        return Err(why.into());
    }
    if !rules.allow_suffixes.is_empty() {
        match literal {
            Some(ip) if rules.allow_cidrs.iter().any(|c| c.contains(ip)) => {}
            Some(_) => return Err("address literals are not allowed for this device".into()),
            None if allowed_name => {}
            None => return Err("domain not on this device's allow list".into()),
        }
    }
    Ok(())
}

/// Stage 2: one resolved address. The error names the class only, never
/// the address (the caller logs the address).
pub fn check_addr(rules: &Rules, lan: &[Cidr], ip: IpAddr) -> Result<(), String> {
    let ip = ip.to_canonical();
    if rules.deny_cidrs.iter().any(|c| c.contains(ip)) {
        return Err("address denied by this device's rules".into());
    }
    if rules.allow_cidrs.iter().any(|c| c.contains(ip)) {
        return Ok(());
    }
    if lan.iter().any(|c| c.contains(ip)) {
        return Err("the hub's local network".into());
    }
    if let Some(class) = denied_class(ip) {
        return Err(format!("{class} address"));
    }
    Ok(())
}

/// The default-denied class of `ip`, if any.
pub fn denied_class(ip: IpAddr) -> Option<&'static str> {
    match ip.to_canonical() {
        IpAddr::V4(v4) => class_v4(v4),
        IpAddr::V6(v6) => class_v6(v6),
    }
}

fn class_v4(ip: Ipv4Addr) -> Option<&'static str> {
    let o = ip.octets();
    Some(match o {
        [0, ..] => "unspecified",
        [127, ..] => "loopback",
        [10, ..] => "private",
        [172, b, ..] if (16..=31).contains(&b) => "private",
        [192, 168, ..] => "private",
        [169, 254, ..] => "link-local",
        [100, b, ..] if (64..=127).contains(&b) => "shared (CGNAT)",
        [192, 0, 0, _] => "protocol assignment",
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _] => "documentation",
        [192, 88, 99, _] => "6to4 relay anycast",
        [198, b, ..] if b == 18 || b == 19 => "benchmarking",
        [a, ..] if (224..=239).contains(&a) => "multicast",
        [a, ..] if a >= 240 => "reserved",
        _ => return None,
    })
}

fn class_v6(ip: Ipv6Addr) -> Option<&'static str> {
    let s = ip.segments();
    if ip.is_unspecified() {
        return Some("unspecified");
    }
    if ip.is_loopback() {
        return Some("loopback");
    }
    if s[0] & 0xfe00 == 0xfc00 {
        return Some("unique-local");
    }
    if s[0] & 0xffc0 == 0xfe80 || s[0] & 0xffc0 == 0xfec0 {
        return Some("link-local");
    }
    if s[0] & 0xff00 == 0xff00 {
        return Some("multicast");
    }
    // ::/96, IPv4-compatible (deprecated; :: and ::1 are caught above).
    if s[..6] == [0; 6] {
        return Some("IPv4-compatible");
    }
    // ::ffff:0:0/96, SIIT IPv4-translated (::ffff:0:0:0/96 is IPv4-mapped,
    // which `to_canonical` already turned into IPv4).
    if s[..4] == [0; 4] && s[4] == 0xffff && s[5] == 0 {
        return Some("IPv4-translated");
    }
    // 100::/64, discard-only.
    if s[..4] == [0x100, 0, 0, 0] {
        return Some("discard-only");
    }
    // 64:ff9b:1::/48, local-use NAT64 (RFC 8215): translated by a local box.
    if s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1 {
        return Some("local-use NAT64");
    }
    // 2001::/32, Teredo (an IPv4 address and port inside, tunnelled).
    if s[0] == 0x2001 && s[1] == 0 {
        return Some("Teredo");
    }
    // 2001:2::/48, benchmarking.
    if s[0] == 0x2001 && s[1] == 2 && s[2] == 0 {
        return Some("benchmarking");
    }
    // 2001:db8::/32, documentation.
    if s[0] == 0x2001 && s[1] == 0xdb8 {
        return Some("documentation");
    }
    // ISATAP interface ids (::0:5efe:a.b.c.d and ::200:5efe:a.b.c.d in any
    // prefix): an IPv4 address inside, tunnelled.
    if s[4] & 0xfdff == 0 && s[5] == 0x5efe {
        return Some("ISATAP");
    }
    // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) carry an IPv4 address.
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        let v4 = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
        return class_v4(v4);
    }
    if s[0] == 0x2002 {
        let v4 = Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8);
        return class_v4(v4);
    }
    None
}

/// A token bucket. `take` refuses when empty; `debit` always takes and
/// returns how long the caller should wait to stay within the rate.
#[derive(Debug)]
pub struct Bucket {
    capacity: f64,
    tokens: f64,
    per_sec: f64,
    last: Instant,
}

impl Bucket {
    pub fn new(capacity: f64, per_sec: f64) -> Self {
        Self::new_at(capacity, per_sec, Instant::now())
    }

    pub fn new_at(capacity: f64, per_sec: f64, now: Instant) -> Self {
        Bucket { capacity, tokens: capacity, per_sec, last: now }
    }

    pub fn is_full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= self.capacity
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * self.per_sec).min(self.capacity);
        self.last = now;
    }

    pub fn take(&mut self, n: f64, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// A rate of 0 means unlimited: nothing is debited.
    pub fn debit(&mut self, n: f64, now: Instant) -> Duration {
        if self.per_sec <= 0.0 {
            return Duration::ZERO;
        }
        self.refill(now);
        self.tokens -= n;
        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.per_sec)
        }
    }

    /// Changes capacity and rate without forgetting what was already taken:
    /// the level is kept, cut to the new capacity (a debt stays a debt).
    pub fn set_rate(&mut self, capacity: f64, per_sec: f64, now: Instant) {
        if self.per_sec > 0.0 {
            self.refill(now);
        } else {
            self.tokens = capacity;
            self.last = now;
        }
        self.capacity = capacity;
        self.per_sec = per_sec;
        self.tokens = self.tokens.min(capacity);
    }

    /// Returns tokens taken for something that turned out not to count.
    pub fn refund(&mut self, n: f64) {
        self.tokens = (self.tokens + n).min(self.capacity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn default_classes_are_denied() {
        let r = Rules::default();
        // (address, expected class), one row per form.
        let denied: &[(&str, &str)] = &[
            ("127.0.0.1", "loopback"),
            ("10.1.2.3", "private"),
            ("172.16.0.1", "private"),
            ("172.31.255.255", "private"),
            ("192.168.1.1", "private"),
            ("169.254.1.1", "link-local"),
            ("100.64.0.1", "shared (CGNAT)"),
            ("0.0.0.0", "unspecified"),
            ("255.255.255.255", "reserved"),
            ("224.0.0.1", "multicast"),
            ("192.0.0.8", "protocol assignment"),
            ("192.0.2.1", "documentation"),
            ("198.51.100.7", "documentation"),
            ("203.0.113.9", "documentation"),
            ("192.88.99.1", "6to4 relay anycast"),
            ("198.18.0.1", "benchmarking"),
            ("::1", "loopback"),
            ("::", "unspecified"),
            ("fe80::1", "link-local"),
            ("fec0::1", "link-local"),
            ("fd00::1", "unique-local"),
            ("ff02::1", "multicast"),
            ("::ffff:192.168.0.1", "private"),
            ("::8.8.8.8", "IPv4-compatible"),
            ("::0.0.0.2", "IPv4-compatible"),
            ("::ffff:0:8.8.8.8", "IPv4-translated"),
            ("::ffff:0:a00:1", "IPv4-translated"),
            ("64:ff9b::a00:1", "private"),
            ("64:ff9b:1::808:808", "local-use NAT64"),
            ("2002:c0a8:0101::1", "private"),
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", "Teredo"),
            ("2001:db8::1", "documentation"),
            ("2001:2::1", "benchmarking"),
            ("100::1", "discard-only"),
            ("2a01:4f8::5efe:c0a8:101", "ISATAP"),
            ("2a01:4f8::200:5efe:808:808", "ISATAP"),
        ];
        for (a, class) in denied {
            assert_eq!(denied_class(ip(a)), Some(*class), "{a}");
            let why = check_addr(&r, &[], ip(a)).unwrap_err();
            assert!(!why.contains(a.trim_start_matches("::ffff:")), "the refusal must not carry the address: {why}");
        }
        for a in ["1.1.1.1", "172.32.0.1", "100.128.0.1", "2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1", "2001:4860::8888"] {
            assert!(check_addr(&r, &[], ip(a)).is_ok(), "{a} should be allowed");
        }
    }

    #[test]
    fn non_public_names_are_refused_unless_allowed_by_name() {
        let r = Rules::default();
        for h in ["printer", "printer.", "localhost", "LOCALHOST.", "a.localhost", "nas.local", "router.home.arpa", "x.internal", "box.lan"] {
            assert!(check_host(&r, h).is_err(), "{h} should be refused");
        }
        for h in ["example.com", "a.b.example.org", "1.2.3.4", "2001:4860::8888", "[2001:4860::8888]"] {
            assert!(check_host(&r, h).is_ok(), "{h} should pass the name stage");
        }
        let r = Rules { allow_suffixes: vec!["printer".into(), "nas.local".into()], ..Default::default() };
        assert!(check_host(&r, "printer").is_ok());
        assert!(check_host(&r, "nas.local").is_ok());
        assert!(check_host(&r, "other.local").is_err());
    }

    #[test]
    fn port_25_is_denied_unless_allowed() {
        assert!(check_port(&Rules::default(), 25).is_err());
        assert!(check_port(&Rules::default(), 443).is_ok());
        let r = Rules { allow_ports: vec![25], ..Default::default() };
        assert!(check_port(&r, 25).is_ok());
    }

    #[test]
    fn limits_are_range_checked() {
        assert!(Limits::default().validate().is_ok());
        assert!(Limits { max_concurrent: 0, ..Default::default() }.validate().is_err());
        assert!(Limits { max_concurrent: MAX_CONCURRENT + 1, ..Default::default() }.validate().is_err());
        assert!(Limits { opens_per_minute: 0, ..Default::default() }.validate().is_err());
        assert!(Limits { bytes_per_sec: MAX_BYTES_PER_SEC + 1, ..Default::default() }.validate().is_err());
        let c = Limits { max_concurrent: u32::MAX, opens_per_minute: 0, bytes_per_sec: u64::MAX }.clamped();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn bucket_rate_change_keeps_what_was_taken() {
        let t0 = Instant::now();
        let mut b = Bucket::new(10.0, 1.0);
        for _ in 0..8 {
            assert!(b.take(1.0, t0));
        }
        // 2 left; a larger capacity does not refill it.
        b.set_rate(100.0, 1.0, t0);
        assert!(b.take(2.0, t0));
        assert!(!b.take(1.0, t0));
        // A smaller capacity cuts the level.
        let mut b = Bucket::new(10.0, 1.0);
        b.set_rate(3.0, 1.0, t0);
        assert!(b.take(3.0, t0));
        assert!(!b.take(1.0, t0));
        // Unlimited debits nothing; a later limit starts full.
        let mut b = Bucket::new(0.0, 0.0);
        assert_eq!(b.debit(1e9, t0), Duration::ZERO);
        b.set_rate(100.0, 100.0, t0);
        assert_eq!(b.debit(100.0, t0), Duration::ZERO);
        assert!(b.debit(50.0, t0) > Duration::ZERO);
    }

    #[test]
    fn allow_overrides_class_and_deny_overrides_allow() {
        let mut r = Rules { allow_cidrs: vec!["192.168.1.10/32".parse().unwrap()], ..Default::default() };
        assert!(check_addr(&r, &[], ip("192.168.1.10")).is_ok());
        assert!(check_addr(&r, &[], ip("192.168.1.11")).is_err());
        r.deny_cidrs.push("192.168.1.0/24".parse().unwrap());
        assert!(check_addr(&r, &[], ip("192.168.1.10")).is_err());
    }

    #[test]
    fn hub_lan_is_denied() {
        let lan: Vec<Cidr> = vec!["81.2.69.160/28".parse().unwrap(), "2a01:4f8:1:2::/64".parse().unwrap()];
        let r = Rules::default();
        assert_eq!(check_addr(&r, &lan, ip("81.2.69.161")).unwrap_err(), "the hub's local network");
        assert!(check_addr(&r, &lan, ip("2a01:4f8:1:2::99")).is_err());
        assert!(check_addr(&r, &lan, ip("81.2.69.200")).is_ok());
    }

    #[test]
    fn suffixes_match_on_label_boundaries() {
        assert!(suffix_matches("a.example.com", "example.com"));
        assert!(suffix_matches("EXAMPLE.com.", "example.com"));
        assert!(suffix_matches("a.example.com", "*.example.com"));
        assert!(!suffix_matches("badexample.com", "example.com"));
        let r = Rules { deny_suffixes: vec!["tracker.test".into()], ..Default::default() };
        assert!(check_host(&r, "x.tracker.test").is_err());
        assert!(check_host(&r, "tracker.testing").is_ok());
        let r = Rules { allow_suffixes: vec!["api.test".into()], ..Default::default() };
        assert!(check_host(&r, "api.test").is_ok());
        assert!(check_host(&r, "other.test").is_err());
        assert!(check_host(&r, "1.2.3.4").is_err());
    }

    #[test]
    fn cidr_parse_and_contains() {
        let c: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(c.contains(ip("10.255.0.1")));
        assert!(c.contains(ip("::ffff:10.0.0.1")));
        assert!(!c.contains(ip("11.0.0.1")));
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        let c: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(c.contains(ip("2001:db8:1::1")));
        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(ip("8.8.8.8")));
    }

    #[test]
    fn bucket_refuses_when_empty_and_refills() {
        let t0 = Instant::now();
        let mut b = Bucket::new(2.0, 1.0);
        assert!(b.take(1.0, t0));
        assert!(b.take(1.0, t0));
        assert!(!b.take(1.0, t0));
        assert!(b.take(1.0, t0 + Duration::from_millis(1100)));
        let mut b = Bucket::new(100.0, 100.0);
        assert_eq!(b.debit(100.0, t0), Duration::ZERO);
        let wait = b.debit(50.0, t0);
        assert!((wait.as_secs_f64() - 0.5).abs() < 0.01);
    }
}
