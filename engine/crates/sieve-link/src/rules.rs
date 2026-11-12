//! Per-device rules and limits, and the address classes denied by default.
//!
//! The hub sees only `host:port`, never payload, so rules are by domain and
//! by address. Order of evaluation for a stream:
//!
//! 1. Domain: a `deny_suffixes` match refuses. If `allow_suffixes` is not
//!    empty, a name must match one of them, and an address literal must fall
//!    inside `allow_cidrs`.
//! 2. The name is resolved AT THE HUB, and each address is checked; the hub
//!    connects only to an address that passes (so a name cannot be made to
//!    point somewhere else between check and connect):
//!    `deny_cidrs` refuses; `allow_cidrs` admits; the hub's LAN list refuses;
//!    then the default-denied classes refuse (loopback, private, link-local,
//!    shared/CGNAT, unique-local, multicast, unspecified, reserved and
//!    broadcast, plus those embedded in IPv4-mapped and NAT64 addresses).
//!
//! So a device cannot reach the host's own machine or local network unless
//! the owner adds an `allow_cidrs` entry for it.

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
}

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

fn normalize(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
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
    if !rules.allow_suffixes.is_empty() {
        match literal {
            Some(ip) if rules.allow_cidrs.iter().any(|c| c.contains(ip)) => {}
            Some(_) => return Err("address literals are not allowed for this device".into()),
            None if rules.allow_suffixes.iter().any(|s| suffix_matches(host, s)) => {}
            None => return Err("domain not on this device's allow list".into()),
        }
    }
    Ok(())
}

/// Stage 2: one resolved address.
pub fn check_addr(rules: &Rules, lan: &[Cidr], ip: IpAddr) -> Result<(), String> {
    let ip = ip.to_canonical();
    if rules.deny_cidrs.iter().any(|c| c.contains(ip)) {
        return Err(format!("address denied ({ip})"));
    }
    if rules.allow_cidrs.iter().any(|c| c.contains(ip)) {
        return Ok(());
    }
    if lan.iter().any(|c| c.contains(ip)) {
        return Err(format!("the hub's local network ({ip})"));
    }
    if let Some(class) = denied_class(ip) {
        return Err(format!("{class} address ({ip})"));
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
        Bucket { capacity, tokens: capacity, per_sec, last: Instant::now() }
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

    pub fn debit(&mut self, n: f64, now: Instant) -> Duration {
        self.refill(now);
        self.tokens -= n;
        if self.tokens >= 0.0 || self.per_sec <= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.per_sec)
        }
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
        for a in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.1.1", "100.64.0.1",
            "0.0.0.0", "255.255.255.255", "224.0.0.1", "::1", "::", "fe80::1", "fd00::1", "ff02::1",
            "::ffff:192.168.0.1", "64:ff9b::a00:1", "2002:c0a8:0101::1",
        ] {
            assert!(check_addr(&r, &[], ip(a)).is_err(), "{a} should be denied");
        }
        for a in ["1.1.1.1", "172.32.0.1", "100.128.0.1", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(check_addr(&r, &[], ip(a)).is_ok(), "{a} should be allowed");
        }
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
        let lan: Vec<Cidr> = vec!["203.0.113.0/24".parse().unwrap()];
        assert!(check_addr(&Rules::default(), &lan, ip("203.0.113.9")).is_err());
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
