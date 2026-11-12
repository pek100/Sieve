//! Per-device rules and limits, and the address classes denied by default.
//!
//! The hub sees only `host:port`, never payload, so rules are by domain, by
//! address and by port. Order of evaluation for a stream:
//!
//! 0. Port: the default-denied ports (25, SMTP) refuse unless the device's
//!    `allow_ports` lists them.
//! 1. Domain: a `deny_suffixes` match refuses. If `allow_suffixes` is not
//!    empty, a name must match one of them, and an address literal must fall
//!    inside `allow_cidrs` (or `allow_lan` / `allow_self`). A name that is not
//!    a public DNS name (one label, `localhost`, `.local`, `.home.arpa`,
//!    `.internal`, `.lan`) refuses unless an `allow_suffixes` entry names it:
//!    on Windows such names resolve through LLMNR, NetBIOS or mDNS to machines
//!    on the hub's own network.
//! 2. The name is resolved AT THE HUB, and each address is checked; the hub
//!    connects only to an address that passes (so a name cannot be made to
//!    point somewhere else between check and connect), in this order:
//!    - an unspecified address refuses, always;
//!    - `deny_cidrs` refuses;
//!    - the hub itself (loopback, and the hub's own addresses: those on its
//!      interfaces and the public addresses learned for this link) refuses
//!      unless `allow_self` covers it;
//!    - the hub's LAN blocks (detected from its interfaces and routes, plus
//!      the owner's manual ones) and the local classes (private, link-local,
//!      unique-local, CGNAT) refuse unless `allow_lan` covers the address;
//!    - every other default-denied class refuses (see `denied_class`).
//!
//! `allow_cidrs` opens NOTHING local, whatever its width: it only lets a
//! device with an allow list name address literals. Reaching the hub's
//! network takes `allow_lan` (no wider than /16 or /48), reaching the hub
//! machine takes `allow_self` as well; wider entries are ignored. A store
//! from before the split keeps its `allow_cidrs` as plain entries, which
//! closes the local network to them (`legacy_notes` says so).
//!
//! Every block check also looks at the IPv4 address inside an IPv4-mapped,
//! NAT64 (64:ff9b::/96) or 6to4 (2002::/16) address.
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

    /// The block with only `prefix` bits kept.
    pub fn new(addr: IpAddr, prefix: u8) -> Cidr {
        let addr = addr.to_canonical();
        let (max, prefix) = if addr.is_ipv4() { (32u8, prefix.min(32)) } else { (128u8, prefix.min(128)) };
        let addr = match addr {
            IpAddr::V4(v4) => {
                let mask = u32::MAX.checked_shl((max - prefix) as u32).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
            }
            IpAddr::V6(v6) => {
                let mask = u128::MAX.checked_shl((max - prefix) as u32).unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
            }
        };
        Cidr { addr, prefix }
    }

    /// One address.
    pub fn host(addr: IpAddr) -> Cidr {
        let addr = addr.to_canonical();
        Cidr { addr, prefix: if addr.is_ipv4() { 32 } else { 128 } }
    }

    /// Whether this block is narrow enough for `allow_lan` / `allow_self`
    /// (at most a /16 of IPv4, a /48 of IPv6).
    pub fn narrow_enough_for_lan(&self) -> bool {
        match self.addr {
            IpAddr::V4(_) => self.prefix >= MAX_LAN_WIDTH_V4,
            IpAddr::V6(_) => self.prefix >= MAX_LAN_WIDTH_V6,
        }
    }

    /// Whether the two blocks share any address.
    pub fn overlaps(&self, other: &Cidr) -> bool {
        self.addr.is_ipv4() == other.addr.is_ipv4() && (self.contains(other.addr) || other.contains(self.addr))
    }
}

/// The widest `allow_lan` / `allow_self` entry accepted: a /16 of IPv4.
pub const MAX_LAN_WIDTH_V4: u8 = 16;
/// The widest `allow_lan` / `allow_self` entry accepted: a /48 of IPv6.
pub const MAX_LAN_WIDTH_V6: u8 = 48;

/// The forms one address is checked in: itself, and the IPv4 address inside
/// it when it is IPv4-mapped (already canonical), NAT64 (64:ff9b::/96) or
/// 6to4 (2002::/16).
fn forms(ip: IpAddr) -> [Option<IpAddr>; 2] {
    let ip = ip.to_canonical();
    let inner = match ip {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
                Some(IpAddr::V4(Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8)))
            } else if s[0] == 0x2002 {
                Some(IpAddr::V4(Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8)))
            } else {
                None
            }
        }
        IpAddr::V4(_) => None,
    };
    [Some(ip), inner]
}

fn any_covers(blocks: &[Cidr], ip: IpAddr) -> bool {
    forms(ip).into_iter().flatten().any(|f| blocks.iter().any(|c| c.contains(f)))
}

/// The hub's own network as the rules see it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalNet {
    /// The machines around the hub: on-link prefixes, gateways, routed
    /// prefixes, the IPv6 site prefix, the owner's manual blocks.
    pub lan: Vec<Cidr>,
    /// The hub itself: its interface addresses, and public addresses learned
    /// for one link (what the router answers on, port forwards included).
    pub own: Vec<Cidr>,
}

impl LocalNet {
    pub fn is_own(&self, ip: IpAddr) -> bool {
        any_covers(&self.own, ip)
    }

    pub fn in_lan(&self, ip: IpAddr) -> bool {
        any_covers(&self.lan, ip)
    }

    /// Every block, own ones first (for display and tests).
    pub fn all(&self) -> Vec<Cidr> {
        let mut v = self.own.clone();
        for c in &self.lan {
            if !v.contains(c) {
                v.push(*c);
            }
        }
        v
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
    /// `allow_cidrs`, `allow_lan` or `allow_self`) are allowed.
    #[serde(default)]
    pub allow_suffixes: Vec<String>,
    #[serde(default)]
    pub deny_suffixes: Vec<String>,
    /// Address literals a device with an allow list may name. Opens nothing
    /// local: loopback, the hub, its LAN and the denied classes stay denied
    /// whatever the width.
    #[serde(default)]
    pub allow_cidrs: Vec<Cidr>,
    #[serde(default)]
    pub deny_cidrs: Vec<Cidr>,
    /// Parts of the hub's local network this device may reach (e.g. one
    /// NAS): the LAN blocks and the local classes inside these. Each at most
    /// a /16 or /48; never the hub itself (that takes `allow_self`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_lan: Vec<Cidr>,
    /// The hub machine itself (its own addresses and loopback) inside these.
    /// Each at most a /16 or /48. Never the unspecified address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_self: Vec<Cidr>,
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
        let listed = |ip: IpAddr| rules.allow_cidrs.iter().chain(&rules.allow_lan).chain(&rules.allow_self).any(|c| c.contains(ip));
        match literal {
            Some(ip) if listed(ip) => {}
            Some(_) => return Err("address literals are not allowed for this device".into()),
            None if allowed_name => {}
            None => return Err("domain not on this device's allow list".into()),
        }
    }
    Ok(())
}

/// Stage 2: one resolved address. The error names the class only, never
/// the address (the caller logs the address).
pub fn check_addr(rules: &Rules, local: &LocalNet, ip: IpAddr) -> Result<(), String> {
    let ip = ip.to_canonical();
    if forms(ip).into_iter().flatten().any(|f| f.is_unspecified()) {
        return Err("unspecified address".into());
    }
    if any_covers(&rules.deny_cidrs, ip) {
        return Err("address denied by this device's rules".into());
    }
    let class = denied_class(ip);
    let narrow_covers = |list: &[Cidr]| list.iter().any(|c| c.narrow_enough_for_lan() && c.contains(ip));
    let loopback = class == Some("loopback");
    if loopback || local.is_own(ip) {
        if narrow_covers(&rules.allow_self) {
            return Ok(());
        }
        return Err(if loopback { "loopback address".into() } else { "the hub itself".into() });
    }
    let in_lan = local.in_lan(ip);
    let local_class = matches!(class, None | Some("private" | "link-local" | "unique-local" | "shared (CGNAT)"));
    if (in_lan || class.is_some()) && local_class && narrow_covers(&rules.allow_lan) {
        return Ok(());
    }
    if in_lan {
        return Err("the hub's local network".into());
    }
    if let Some(class) = class {
        return Err(format!("{class} address"));
    }
    Ok(())
}

/// What the owner should be told about a device's rules: every way it can
/// reach the hub's network or the hub itself, entries that are ignored for
/// being too wide, and old `allow_cidrs` entries that no longer open the
/// local network.
pub fn rule_notes(device: &str, rules: &Rules) -> Vec<String> {
    let mut out = Vec::new();
    for c in &rules.allow_lan {
        if c.narrow_enough_for_lan() {
            out.push(format!("WARNING: device {device} may reach {c} on this hub's LOCAL NETWORK (allow-lan)"));
        } else {
            out.push(format!("device {device}: allow-lan {c} is IGNORED: wider than /{MAX_LAN_WIDTH_V4} (IPv4) or /{MAX_LAN_WIDTH_V6} (IPv6)"));
        }
    }
    for c in &rules.allow_self {
        if c.narrow_enough_for_lan() {
            out.push(format!("WARNING: device {device} may reach THIS MACHINE itself at {c} (allow-self): every service listening on it"));
        } else {
            out.push(format!("device {device}: allow-self {c} is IGNORED: wider than /{MAX_LAN_WIDTH_V4} (IPv4) or /{MAX_LAN_WIDTH_V6} (IPv6)"));
        }
    }
    for c in &rules.allow_cidrs {
        let wide = c.prefix < if c.addr.is_ipv4() { 8 } else { 16 };
        if wide || denied_class(c.addr).is_some() {
            out.push(format!(
                "device {device}: allow-cidr {c} opens nothing local (the hub, its network and special addresses stay denied); \
                 use `allow-lan` for a part of the local network"
            ));
        }
    }
    out
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
        let none = LocalNet::default();
        for (a, class) in denied {
            assert_eq!(denied_class(ip(a)), Some(*class), "{a}");
            let why = check_addr(&r, &none, ip(a)).unwrap_err();
            assert!(!why.contains(a.trim_start_matches("::ffff:")), "the refusal must not carry the address: {why}");
        }
        for a in ["1.1.1.1", "172.32.0.1", "100.128.0.1", "2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1", "2001:4860::8888"] {
            assert!(check_addr(&r, &none, ip(a)).is_ok(), "{a} should be allowed");
        }
    }

    fn home() -> LocalNet {
        LocalNet {
            lan: vec!["192.168.1.0/24".parse().unwrap(), "81.2.69.160/28".parse().unwrap(), "2a01:4f8:1:200::/56".parse().unwrap()],
            own: vec!["192.168.1.10/32".parse().unwrap(), "81.2.69.163/32".parse().unwrap(), "2a01:4f8:1:200::10/128".parse().unwrap()],
        }
    }

    /// (rules, address, admitted?) for the allow kinds: a plain allow-cidr
    /// never opens anything local whatever its width; allow-lan opens the
    /// LAN but never the hub; allow-self opens the hub; nothing opens the
    /// unspecified address; too-wide entries are ignored.
    #[test]
    fn allow_kinds_table() {
        let c = |s: &str| -> Cidr { s.parse().unwrap() };
        let plain = |s: &str| Rules { allow_cidrs: vec![c(s)], ..Default::default() };
        let lan = |s: &str| Rules { allow_lan: vec![c(s)], ..Default::default() };
        let me = |s: &str| Rules { allow_self: vec![c(s)], ..Default::default() };
        let both = |l: &str, s: &str| Rules { allow_lan: vec![c(l)], allow_self: vec![c(s)], ..Default::default() };
        let rows: Vec<(&str, Rules, &str, bool)> = vec![
            // A plain allow-cidr reopens nothing, even 0.0.0.0/0 and ::/0.
            ("0/0 plain, loopback", plain("0.0.0.0/0"), "127.0.0.1", false),
            ("0/0 plain, hub address", plain("0.0.0.0/0"), "192.168.1.10", false),
            ("0/0 plain, LAN neighbour", plain("0.0.0.0/0"), "192.168.1.20", false),
            ("0/0 plain, public /28 neighbour", plain("0.0.0.0/0"), "81.2.69.170", false),
            ("0/0 plain, other private", plain("0.0.0.0/0"), "10.9.9.9", false),
            ("0/0 plain, multicast", plain("0.0.0.0/0"), "224.0.0.1", false),
            ("::/0 plain, v6 LAN", plain("::/0"), "2a01:4f8:1:2ff::1", false),
            ("::/0 plain, ::1", plain("::/0"), "::1", false),
            ("/32 plain, the NAS", plain("192.168.1.20/32"), "192.168.1.20", false),
            ("0/0 plain, public internet", plain("0.0.0.0/0"), "8.8.8.8", true),
            // allow-lan: the LAN inside it, never the hub, never loopback.
            ("lan /32, the NAS", lan("192.168.1.20/32"), "192.168.1.20", true),
            ("lan /32, another neighbour", lan("192.168.1.20/32"), "192.168.1.21", false),
            ("lan /24, the hub's own address", lan("192.168.1.0/24"), "192.168.1.10", false),
            ("lan /16, private class off-LAN", lan("10.9.0.0/16"), "10.9.9.9", true),
            ("lan /8, too wide: ignored", lan("10.0.0.0/8"), "10.9.9.9", false),
            ("lan /0, too wide: ignored", lan("0.0.0.0/0"), "192.168.1.20", false),
            ("lan /8 loopback: never", lan("127.0.0.0/8"), "127.0.0.1", false),
            ("lan /16 loopback block", lan("127.0.0.0/16"), "127.0.0.1", false),
            ("lan v6 /56", lan("2a01:4f8:1:200::/56"), "2a01:4f8:1:2ff::1", true),
            ("lan v6 /32, too wide", lan("2a01:4f8::/32"), "2a01:4f8:1:2ff::1", false),
            ("lan, public /28 neighbour", lan("81.2.69.160/28"), "81.2.69.170", true),
            ("lan, NAT64 form of a neighbour", lan("81.2.69.160/28"), "64:ff9b::5102:45aa", false),
            ("lan does not open multicast", lan("224.0.0.0/16"), "224.0.0.1", false),
            // allow-self: the hub itself and loopback.
            ("self /32 loopback", me("127.0.0.1/32"), "127.0.0.1", true),
            ("self /32, hub address", me("192.168.1.10/32"), "192.168.1.10", true),
            ("self alone does not open the LAN", me("192.168.1.0/24"), "192.168.1.20", false),
            ("self /8, too wide", me("127.0.0.0/8"), "127.0.0.1", false),
            ("lan + self", both("192.168.1.0/24", "192.168.1.10/32"), "192.168.1.10", true),
            ("unspecified, never", both("0.0.0.0/16", "0.0.0.0/16"), "0.0.0.0", false),
            ("unspecified v6, never", me("::/48"), "::", false),
        ];
        for (what, r, a, want) in rows {
            assert_eq!(check_addr(&r, &home(), ip(a)).is_ok(), want, "{what}: {a} -> {:?}", check_addr(&r, &home(), ip(a)));
        }
        // The hub's own address is "the hub itself", not just "local".
        assert_eq!(check_addr(&Rules::default(), &home(), ip("192.168.1.10")).unwrap_err(), "the hub itself");
        // A learned public address in NAT64 and mapped forms is still the hub.
        let mut net = home();
        net.own.push("93.184.0.77/32".parse().unwrap());
        for a in ["93.184.0.77", "::ffff:93.184.0.77", "64:ff9b::5db8:4d", "2002:5db8:4d::1"] {
            assert_eq!(check_addr(&Rules::default(), &net, ip(a)).unwrap_err(), "the hub itself", "{a}");
        }
    }

    #[test]
    fn old_allow_cidrs_entries_load_as_plain_ones_and_are_explained() {
        // A store from before the split: allow_cidrs only.
        let old = r#"{"allow_cidrs":["192.168.1.20/32","0.0.0.0/0"],"deny_cidrs":[]}"#;
        let r: Rules = serde_json::from_str(old).unwrap();
        assert!(r.allow_lan.is_empty() && r.allow_self.is_empty());
        assert!(check_addr(&r, &home(), ip("192.168.1.20")).is_err(), "the old entry no longer opens the LAN");
        let notes = rule_notes("laptop", &r);
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert!(notes.iter().all(|n| n.contains("laptop") && n.contains("allow-lan")));
        // New kinds warn by name.
        let r = Rules { allow_lan: vec!["192.168.1.20/32".parse().unwrap()], allow_self: vec!["127.0.0.1/32".parse().unwrap()], ..Default::default() };
        let notes = rule_notes("laptop", &r);
        assert!(notes[0].starts_with("WARNING: device laptop") && notes[0].contains("LOCAL NETWORK"));
        assert!(notes[1].contains("THIS MACHINE"));
        // An empty allow_lan is not written, so old readers see the same file.
        assert!(!serde_json::to_string(&Rules::default()).unwrap().contains("allow_lan"));
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
    fn allow_lan_overrides_class_and_deny_overrides_allow() {
        let none = LocalNet::default();
        let mut r = Rules { allow_lan: vec!["192.168.1.10/32".parse().unwrap()], ..Default::default() };
        assert!(check_addr(&r, &none, ip("192.168.1.10")).is_ok());
        assert!(check_addr(&r, &none, ip("192.168.1.11")).is_err());
        r.deny_cidrs.push("192.168.1.0/24".parse().unwrap());
        assert!(check_addr(&r, &none, ip("192.168.1.10")).is_err());
    }

    #[test]
    fn hub_lan_is_denied() {
        let lan = LocalNet { lan: vec!["81.2.69.160/28".parse().unwrap(), "2a01:4f8:1:2::/64".parse().unwrap()], own: vec![] };
        let r = Rules::default();
        assert_eq!(check_addr(&r, &lan, ip("81.2.69.161")).unwrap_err(), "the hub's local network");
        assert!(check_addr(&r, &lan, ip("2a01:4f8:1:2::99")).is_err());
        assert!(check_addr(&r, &lan, ip("81.2.69.200")).is_ok());
        // Its NAT64 and 6to4 forms too.
        assert!(check_addr(&r, &lan, ip("64:ff9b::5102:45a1")).is_err());
        assert!(check_addr(&r, &lan, ip("2002:5102:45a1::1")).is_err());
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
        assert_eq!(Cidr::new(ip("2a01:4f8:1:2ab::10"), 56), "2a01:4f8:1:200::/56".parse().unwrap());
        assert!(Cidr::new(ip("10.1.2.3"), 8).overlaps(&"10.200.0.0/16".parse().unwrap()));
        assert!(!Cidr::new(ip("10.1.2.3"), 16).overlaps(&"10.200.0.0/16".parse().unwrap()));
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
