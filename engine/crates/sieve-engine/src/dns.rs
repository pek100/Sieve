//! DNS on the TUN (plan 1.4, slice 3): every lookup that enters the adapter
//! is forwarded to the server it was sent to (encryption comes in slice 4),
//! and every answer is read for the IP-to-names map with TTL, which later
//! decides flows that carry no name of their own. The engine never blocks in
//! DNS and never writes a DNS setting.
//!
//! The parser reads only what the map needs: the question name, and A and
//! AAAA answers with their TTL (compressed names, RFC 1035 4.1.4). Anything
//! malformed is None, never a guess.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::flow::Reader;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
/// Pointer hops allowed in one name (a loop guard).
const MAX_POINTERS: usize = 16;
/// The longest name (RFC 1035 3.1).
const MAX_NAME: usize = 255;

/// A message's question name and its address answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub response: bool,
    pub question: Option<String>,
    /// (address, TTL in seconds).
    pub answers: Vec<(IpAddr, u32)>,
}

fn name_at(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            end.get_or_insert(pos + 1);
            break;
        }
        if len & 0xc0 == 0xc0 {
            let target = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            jumps += 1;
            if jumps > MAX_POINTERS || target >= pos {
                return None;
            }
            pos = target;
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
        if labels.iter().map(|l| l.len() + 1).sum::<usize>() > MAX_NAME {
            return None;
        }
    }
    Some((labels.join("."), end?))
}

/// Parses a DNS message over UDP (or one TCP message without its length).
pub fn parse(msg: &[u8]) -> Option<Message> {
    let mut r = Reader::new(msg);
    let id = r.u16()?;
    let flags = r.u16()?;
    let qd = r.u16()?;
    let an = r.u16()?;
    let _ns = r.u16()?;
    let _ar = r.u16()?;
    let mut pos = 12;
    let mut question = None;
    for _ in 0..qd {
        let (name, next) = name_at(msg, pos)?;
        question.get_or_insert(name);
        pos = next + 4;
    }
    let mut answers = Vec::new();
    for _ in 0..an {
        let (_, next) = name_at(msg, pos)?;
        let mut r = Reader::new(msg.get(next..)?);
        let (ty, class, ttl, len) = (r.u16()?, r.u16()?, r.u32()?, usize::from(r.u16()?));
        let data = r.bytes(len)?;
        pos = next + 10 + len;
        match (ty, class, len) {
            (TYPE_A, CLASS_IN, 4) => answers.push((IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])), ttl)),
            (TYPE_AAAA, CLASS_IN, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(data);
                answers.push((IpAddr::V6(Ipv6Addr::from(b)), ttl));
            }
            _ => {}
        }
    }
    Some(Message { id, response: flags & 0x8000 != 0, question, answers })
}

/// At most this many addresses are remembered; past it the soonest to
/// expire are dropped first (memory stays bounded, plan 6).
pub const NAME_MAP_CAP: usize = 100_000;
/// A TTL is honoured up to a day, so a bogus huge TTL cannot pin an entry.
pub const MAX_TTL_S: u32 = 86_400;

/// Which names each address was resolved for, until their TTL runs out.
#[derive(Debug, Default)]
pub struct NameMap {
    entries: HashMap<IpAddr, Vec<(String, u64)>>,
}

impl NameMap {
    /// Records an answer at `now_ms`.
    pub fn record(&mut self, name: &str, ip: IpAddr, ttl_s: u32, now_ms: u64) {
        let expires = now_ms.saturating_add(u64::from(ttl_s.min(MAX_TTL_S)) * 1_000);
        let names = self.entries.entry(ip).or_default();
        match names.iter_mut().find(|(n, _)| n == name) {
            Some(e) => e.1 = e.1.max(expires),
            None => names.push((name.to_string(), expires)),
        }
        if self.entries.len() > NAME_MAP_CAP {
            self.prune(now_ms);
        }
        while self.entries.len() > NAME_MAP_CAP {
            let soonest = self.entries.iter().min_by_key(|(_, v)| v.iter().map(|e| e.1).max().unwrap_or(0)).map(|(ip, _)| *ip);
            match soonest {
                Some(ip) => self.entries.remove(&ip),
                None => break,
            };
        }
    }

    /// Records every address answer of a response.
    pub fn record_message(&mut self, m: &Message, now_ms: u64) -> usize {
        let Some(name) = m.question.as_deref().filter(|_| m.response) else { return 0 };
        for (ip, ttl) in &m.answers {
            self.record(name, *ip, *ttl, now_ms);
        }
        m.answers.len()
    }

    /// The live names of `ip` at `now_ms`.
    pub fn names(&self, ip: IpAddr, now_ms: u64) -> Vec<&str> {
        self.entries.get(&ip).map(|v| v.iter().filter(|(_, exp)| *exp > now_ms).map(|(n, _)| n.as_str()).collect()).unwrap_or_default()
    }

    /// Drops every expired name and every address left with none.
    pub fn prune(&mut self, now_ms: u64) {
        self.entries.retain(|_, v| {
            v.retain(|(_, exp)| *exp > now_ms);
            !v.is_empty()
        });
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
pub(crate) mod build {
    /// A response for `name` with A/AAAA answers, the answer names
    /// compressed to the question (pointer 0xc00c), as resolvers send.
    pub fn response(id: u16, name: &str, answers: &[(std::net::IpAddr, u32)]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&0x8180u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1]);
        for (ip, ttl) in answers {
            m.extend_from_slice(&[0xc0, 0x0c]);
            let (ty, data): (u16, Vec<u8>) = match ip {
                std::net::IpAddr::V4(v4) => (1, v4.octets().to_vec()),
                std::net::IpAddr::V6(v6) => (28, v6.octets().to_vec()),
            };
            m.extend_from_slice(&ty.to_be_bytes());
            m.extend_from_slice(&1u16.to_be_bytes());
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&(data.len() as u16).to_be_bytes());
            m.extend_from_slice(&data);
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn reads_the_question_and_compressed_address_answers() {
        let msg = build::response(7, "Example.COM", &[(ip("93.184.215.14"), 300), (ip("2606:2800:21f:cb07:6820:80da:af6b:8b2c"), 60)]);
        let m = parse(&msg).unwrap();
        assert_eq!((m.id, m.response), (7, true));
        assert_eq!(m.question.as_deref(), Some("example.com"));
        assert_eq!(m.answers, vec![(ip("93.184.215.14"), 300), (ip("2606:2800:21f:cb07:6820:80da:af6b:8b2c"), 60)]);
    }

    #[test]
    fn a_query_has_its_name_and_no_answers() {
        let mut q = build::response(9, "router.lan", &[]);
        q[2] = 0x01; // QR cleared: a query
        let m = parse(&q).unwrap();
        assert!(!m.response);
        assert_eq!(m.question.as_deref(), Some("router.lan"));
        let mut map = NameMap::default();
        assert_eq!(map.record_message(&m, 0), 0, "a query records nothing");
    }

    #[test]
    fn truncated_and_looping_messages_are_refused() {
        let msg = build::response(1, "a.example", &[(ip("192.0.2.1"), 5)]);
        for cut in 0..msg.len() {
            assert!(parse(&msg[..cut]).is_none_or(|m| m.answers.is_empty()), "cut at {cut}");
        }
        let mut looping = build::response(1, "a.example", &[]);
        looping.truncate(12);
        looping.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        assert_eq!(parse(&looping), None, "a pointer to itself");
    }

    #[test]
    fn the_map_keeps_names_for_their_ttl_and_capped_at_a_day() {
        let mut map = NameMap::default();
        let m = parse(&build::response(1, "cdn.example", &[(ip("192.0.2.7"), 30)])).unwrap();
        map.record_message(&m, 1_000);
        map.record("other.example", ip("192.0.2.7"), 10, 1_000);
        assert_eq!(map.names(ip("192.0.2.7"), 5_000), vec!["cdn.example", "other.example"]);
        assert_eq!(map.names(ip("192.0.2.7"), 12_000), vec!["cdn.example"]);
        assert!(map.names(ip("192.0.2.7"), 31_000).is_empty());
        map.record("long.example", ip("192.0.2.8"), u32::MAX, 0);
        assert!(map.names(ip("192.0.2.8"), u64::from(MAX_TTL_S) * 1_000).is_empty());
        map.prune(u64::MAX);
        assert!(map.is_empty());
    }

    #[test]
    fn the_map_stays_under_its_cap() {
        let mut map = NameMap::default();
        for i in 0..(NAME_MAP_CAP as u32 + 10) {
            map.record("x.example", IpAddr::V4(Ipv4Addr::from(i)), 60 + (i % 7), 0);
        }
        assert!(map.len() <= NAME_MAP_CAP);
    }

    proptest! {
        #[test]
        fn parsing_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = parse(&bytes);
        }
    }
}
