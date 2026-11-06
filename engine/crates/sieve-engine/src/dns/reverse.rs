//! Which reverse lookups name a private range. Such a name says which private
//! address is being looked up, so it must not reach a public resolver.
//!
//! "Private" is derived from `route::plan::EXCLUDED`, the one list of what is
//! never routed. `plan::holes`' live prefixes are not used: a split-tunnel VPN
//! can route public space, and that is not a private reverse zone.
//!
//! A name is read right to left under `in-addr.arpa` or `ip6.arpa`, taking labels
//! while they are valid. `n` usable labels are the prefix of `n * 8` or `n * 4`
//! bits, and the name is private when one range holds that whole prefix. So
//! `168.192.in-addr.arpa` is private, and `192.in-addr.arpa` is not: it also
//! holds public space. Labels left of the walk do not free a name, so
//! `b._dns-sd._udp.7.168.192.in-addr.arpa` is under the zone like any other.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::question_names;
use crate::route::plan::declared;
use crate::route::prefix::Prefix;

const V4_ZONE: &str = "in-addr.arpa";
const V6_ZONE: &str = "ip6.arpa";
const V4_LABELS: usize = 4;
const V6_LABELS: usize = 32;
const OCTET_BITS: u32 = 8;
const NIBBLE_BITS: u32 = 4;

/// The labels under `zone`, right to left. None for a name not under it.
fn under<'a>(name: &'a str, zone: &str) -> Option<impl Iterator<Item = &'a str>> {
    let rest = name.strip_suffix(zone)?.strip_suffix('.')?;
    Some(rest.rsplit('.'))
}

/// A decimal octet with no leading zero, as a reverse name writes it.
fn octet(label: &str) -> Option<u8> {
    let leading_zero = label.len() > 1 && label.starts_with('0');
    if leading_zero || !label.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    label.parse().ok()
}

/// One hex digit.
fn nibble(label: &str) -> Option<u8> {
    let [digit] = label.as_bytes() else { return None };
    char::from(*digit).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// The prefix a reverse name asks about, when it has at least one usable label.
fn prefix_of(name: &str) -> Option<Prefix> {
    if let Some(labels) = under(name, V4_ZONE) {
        let mut octets = [0u8; V4_LABELS];
        let mut count = 0;
        for (slot, value) in octets.iter_mut().zip(labels.map_while(octet)) {
            *slot = value;
            count += 1;
        }
        return (count > 0).then(|| Prefix::new(IpAddr::V4(Ipv4Addr::from(octets)), (count * OCTET_BITS) as u8)).flatten();
    }
    let labels = under(name, V6_ZONE)?;
    let (mut bits, mut count) = (0u128, 0);
    for value in labels.map_while(nibble).take(V6_LABELS) {
        bits |= u128::from(value) << (u128::BITS - NIBBLE_BITS * (count + 1));
        count += 1;
    }
    (count > 0).then(|| Prefix::new(IpAddr::V6(Ipv6Addr::from(bits)), (count * NIBBLE_BITS) as u8)).flatten()
}

/// The address a private reverse name asks about, its unnamed bits zero. None
/// for any other name (`name` is lower case, as `dns::parse` gives it).
pub fn private_address(name: &str) -> Option<IpAddr> {
    let prefix = prefix_of(name)?;
    declared().iter().any(|range| range.covers(&prefix)).then(|| prefix.addr())
}

/// The address of the first private reverse name among a query's questions, read
/// from the wire as `upstream::split_route` reads suffixes: a query's destination
/// must not depend on what `dns::parse` accepts. A raw label holding a dot reads as
/// two labels, which can only err towards private. None for a query that cannot be
/// walked, which `upstream::split_route` has already refused.
pub fn private_question(query: &[u8]) -> Option<IpAddr> {
    question_names(query)?.iter().find_map(|labels| {
        let name: Vec<String> = labels.iter().map(|label| String::from_utf8_lossy(label).to_ascii_lowercase()).collect();
        private_address(&name.join("."))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::plan::EXCLUDED;

    fn v4(prefix: &str) -> String {
        format!("{prefix}.in-addr.arpa")
    }

    fn v6(prefix: &str) -> String {
        format!("{prefix}.ip6.arpa")
    }

    #[test]
    fn names_of_private_ranges_are_private_and_others_are_not() {
        let ula = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f";
        let private = ["7.168.192", "1.7.168.192", "168.192", "10", "16.172", "31.172", "254.169", "127", "64.100"].map(v4);
        for name in private.into_iter().chain(["d.f", "8.e.f", ula].map(v6)) {
            assert!(private_address(&name).is_some(), "{name}");
        }
        let public = ["192", "172", "15.172", "32.172", "8.8.8.8", "1.0.0.2"].map(v4);
        let global = v6("1.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2");
        for name in public.into_iter().chain([global, "in-addr.arpa".into(), "ip6.arpa".into(), "example.arpa".into(), "www.example".into()]) {
            assert_eq!(private_address(&name), None, "{name}");
        }
    }

    #[test]
    fn the_address_is_the_one_the_name_spells() {
        assert_eq!(private_address(&v4("5.7.168.192")), Some("192.168.7.5".parse().unwrap()));
        assert_eq!(private_address(&v4("7.168.192")), Some("192.168.7.0".parse().unwrap()));
        assert_eq!(private_address(&v6("d.f")), Some("fd00::".parse().unwrap()));
    }

    /// The shortest reverse name of a range: whole labels that fit inside it.
    fn name_of(range: &Prefix) -> String {
        let (bits, zone) = if range.is_ipv4() { (OCTET_BITS, V4_ZONE) } else { (NIBBLE_BITS, V6_ZONE) };
        let labels = u32::from(range.length()).div_ceil(bits) as usize;
        let spelled: Vec<String> = match range.addr() {
            IpAddr::V4(ip) => ip.octets().iter().map(u8::to_string).collect(),
            IpAddr::V6(ip) => ip.octets().iter().flat_map(|b| [format!("{:x}", b >> 4), format!("{:x}", b & 0xf)]).collect(),
        };
        let mut used: Vec<&str> = spelled[..labels].iter().map(String::as_str).collect();
        used.reverse();
        format!("{}.{zone}", used.join("."))
    }

    #[test]
    fn every_excluded_range_has_a_private_reverse_name() {
        assert_eq!(declared().len(), EXCLUDED.len(), "every range parses");
        for range in declared() {
            let name = name_of(&range);
            assert!(private_address(&name).is_some(), "{range:?} as {name}");
        }
    }

    #[test]
    fn labels_left_of_the_zone_do_not_free_a_name() {
        let at = |name: &str| private_address(name);
        let zone = "192.168.0.0".parse().ok();
        assert_eq!(at("b._dns-sd._udp.7.168.192.in-addr.arpa"), "192.168.7.0".parse().ok());
        assert_eq!(at("300.168.192.in-addr.arpa"), zone);
        assert_eq!(at("07.168.192.in-addr.arpa"), zone, "reads as 168.192");
        assert_eq!(at("x.d.f.ip6.arpa"), "fd00::".parse().ok());
        assert_eq!(at("www.8.8.8.8.in-addr.arpa"), None, "a public zone stays public");
    }

    #[test]
    fn a_name_that_only_ends_like_a_zone_is_not_one() {
        assert_eq!(private_address("10.xin-addr.arpa"), None);
        assert_eq!(private_address("d.f.xip6.arpa"), None);
    }
}
