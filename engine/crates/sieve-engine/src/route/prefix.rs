//! IP prefixes (`addr/len`) and the one operation routing needs: the
//! complement of a set of holes inside a universe, as the fewest aligned
//! prefixes. Pure, both families.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A network prefix with its host bits cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Prefix {
    addr: IpAddr,
    len: u8,
}

fn width(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
}

fn bits(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn from_bits(v4: bool, b: u128) -> IpAddr {
    if v4 { IpAddr::V4(Ipv4Addr::from(u32::try_from(b).unwrap_or(u32::MAX))) } else { IpAddr::V6(Ipv6Addr::from(b)) }
}

/// The mask of the top `len` bits of a `w`-bit address.
fn mask(w: u8, len: u8) -> u128 {
    if len == 0 {
        return 0;
    }
    let all = if w == 128 { u128::MAX } else { (1u128 << w) - 1 };
    all & !((1u128 << (w - len)) - 1)
}

impl Prefix {
    /// `addr/len` with host bits cleared; None when `len` is too long.
    pub fn new(addr: IpAddr, len: u8) -> Option<Self> {
        let w = width(addr);
        (len <= w).then(|| Self { addr: from_bits(addr.is_ipv4(), bits(addr) & mask(w, len)), len })
    }

    /// The /32 or /128 of one address.
    pub fn host(ip: IpAddr) -> Self {
        Self { addr: ip, len: width(ip) }
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length in bits.
    pub fn length(&self) -> u8 {
        self.len
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn is_host(&self) -> bool {
        self.len == width(self.addr)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        ip.is_ipv4() == self.is_ipv4() && bits(ip) & mask(width(ip), self.len) == bits(self.addr)
    }

    /// True when every address of `other` is in `self`.
    pub fn covers(&self, other: &Prefix) -> bool {
        other.len >= self.len && self.contains(other.addr)
    }

    pub fn overlaps(&self, other: &Prefix) -> bool {
        self.covers(other) || other.covers(self)
    }

    /// The two halves, or None for a host prefix.
    fn halves(&self) -> Option<(Prefix, Prefix)> {
        if self.is_host() {
            return None;
        }
        let w = width(self.addr);
        let len = self.len + 1;
        let low = Prefix { addr: self.addr, len };
        let high = Prefix { addr: from_bits(self.is_ipv4(), bits(self.addr) | (1u128 << (w - len))), len };
        Some((low, high))
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl FromStr for Prefix {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let (a, l) = s.split_once('/').ok_or_else(|| format!("{s}: no /length"))?;
        let addr: IpAddr = a.parse().map_err(|e| format!("{s}: {e}"))?;
        let len: u8 = l.parse().map_err(|e| format!("{s}: {e}"))?;
        let p = Prefix::new(addr, len).ok_or_else(|| format!("{s}: length too long"))?;
        if p.addr != addr {
            return Err(format!("{s}: host bits set"));
        }
        Ok(p)
    }
}

impl Serialize for Prefix {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

/// `universe` minus every hole, as aligned prefixes in address order.
/// Holes of the other family or outside the universe change nothing.
pub fn complement(universe: Prefix, holes: &[Prefix]) -> Vec<Prefix> {
    let relevant: Vec<Prefix> = holes.iter().copied().filter(|h| h.is_ipv4() == universe.is_ipv4() && h.overlaps(&universe)).collect();
    let mut out = Vec::new();
    let mut stack = vec![universe];
    while let Some(p) = stack.pop() {
        if relevant.iter().any(|h| h.covers(&p)) {
            continue;
        }
        if !relevant.iter().any(|h| p.covers(h)) {
            out.push(p);
            continue;
        }
        if let Some((low, high)) = p.halves() {
            stack.push(high);
            stack.push(low);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn parses_prints_and_refuses_host_bits() {
        assert_eq!(p("10.0.0.0/8").to_string(), "10.0.0.0/8");
        assert_eq!(p("2000::/3").to_string(), "2000::/3");
        assert!("10.0.0.1/8".parse::<Prefix>().is_err());
        assert!("10.0.0.0/33".parse::<Prefix>().is_err());
        assert!("10.0.0.0".parse::<Prefix>().is_err());
        assert_eq!(Prefix::new("10.1.2.3".parse().unwrap(), 8), Some(p("10.0.0.0/8")));
        assert_eq!(Prefix::host("192.168.7.1".parse().unwrap()).to_string(), "192.168.7.1/32");
    }

    #[test]
    fn contains_and_covers_respect_the_family() {
        assert!(p("0.0.0.0/0").contains("8.8.8.8".parse().unwrap()));
        assert!(!p("0.0.0.0/0").contains("::1".parse().unwrap()));
        assert!(p("192.168.0.0/16").covers(&p("192.168.7.0/24")));
        assert!(!p("192.168.7.0/24").covers(&p("192.168.0.0/16")));
        assert!(p("fe80::/10").contains("fe80::1".parse().unwrap()));
    }

    #[test]
    fn nothing_excluded_is_the_universe_itself() {
        assert_eq!(complement(p("0.0.0.0/0"), &[]), vec![p("0.0.0.0/0")]);
        assert_eq!(complement(p("0.0.0.0/0"), &[p("2000::/3")]), vec![p("0.0.0.0/0")]);
        assert_eq!(complement(p("0.0.0.0/0"), &[p("0.0.0.0/0")]), vec![]);
    }

    #[test]
    fn one_hole_leaves_its_siblings_down_the_tree() {
        assert_eq!(complement(p("0.0.0.0/0"), &[p("128.0.0.0/1")]), vec![p("0.0.0.0/1")]);
        assert_eq!(
            complement(p("0.0.0.0/0"), &[p("10.0.0.0/8")]),
            ["0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1"]
                .map(p)
                .to_vec()
        );
    }

    proptest! {
        /// Exactly the addresses outside every hole are covered, once.
        #[test]
        fn the_complement_is_exact_and_disjoint(
            holes in proptest::collection::vec((any::<u32>(), 1u8..=32), 0..6),
            probes in proptest::collection::vec(any::<u32>(), 64),
        ) {
            let holes: Vec<Prefix> = holes.iter().map(|(a, l)| Prefix::new(IpAddr::V4(Ipv4Addr::from(*a)), *l).unwrap()).collect();
            let out = complement(p("0.0.0.0/0"), &holes);
            let mut probe_ips: Vec<IpAddr> = probes.into_iter().map(|a| IpAddr::V4(Ipv4Addr::from(a))).collect();
            probe_ips.extend(holes.iter().map(|h| h.addr()));
            for ip in probe_ips {
                let in_hole = holes.iter().any(|h| h.contains(ip));
                let covering = out.iter().filter(|o| o.contains(ip)).count();
                prop_assert_eq!(covering, usize::from(!in_hole), "{}", ip);
            }
        }
    }
}
