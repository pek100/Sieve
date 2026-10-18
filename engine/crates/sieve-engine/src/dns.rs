//! DNS on the TUN (plan 1.4, slice 3): every lookup that enters the adapter
//! is forwarded to the server it was sent to (encryption comes in slice 4),
//! and every answer is read for the IP-to-names map with TTL, which later
//! decides flows that carry no name of their own. The engine never blocks in
//! DNS and never writes a DNS setting.
//!
//! The parser reads only what the map needs: the question name, and A and
//! AAAA answers with their TTL (compressed names, RFC 1035 4.1.4). Anything
//! malformed is None, never a guess.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::flow::Reader;

pub mod upstream;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_CNAME: u16 = 5;
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
    pub question_type: u16,
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
        // Only names usable as domain evidence enter the map. Arbitrary DNS
        // octets are still forwarded by the relay, but never guessed as UTF-8.
        let label = std::str::from_utf8(label).ok()?;
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        labels.push(label.to_ascii_lowercase());
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
    // One question is the only unambiguous association for this cache.
    if qd != 1 || flags & 0x7800 != 0 {
        return None;
    }
    let (question, next) = name_at(msg, 12)?;
    let mut q = Reader::new(msg.get(next..)?);
    let (qtype, qclass) = (q.u16()?, q.u16()?);
    if question.is_empty() || qclass != CLASS_IN {
        return None;
    }
    let mut pos = next + 4;
    let mut addresses = Vec::new();
    let mut aliases: HashMap<String, (String, u32)> = HashMap::new();
    for _ in 0..an {
        let (owner, next) = name_at(msg, pos)?;
        let mut r = Reader::new(msg.get(next..)?);
        let (ty, class, ttl, len) = (r.u16()?, r.u16()?, r.u32()?, usize::from(r.u16()?));
        let data = r.bytes(len)?;
        pos = next + 10 + len;
        match (ty, class, len) {
            (TYPE_A, CLASS_IN, 4) => addresses.push((
                owner,
                IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                ttl,
            )),
            (TYPE_AAAA, CLASS_IN, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(data);
                addresses.push((owner, IpAddr::V6(Ipv6Addr::from(b)), ttl));
            }
            (TYPE_CNAME, CLASS_IN, _) => {
                let (target, end) = name_at(msg, next + 10)?;
                if end != pos || target.is_empty() {
                    return None;
                }
                if let Some((previous, previous_ttl)) = aliases.get_mut(&owner) {
                    if previous != &target {
                        return None;
                    }
                    *previous_ttl = (*previous_ttl).min(ttl);
                } else {
                    aliases.insert(owner, (target, ttl));
                }
            }
            _ => {}
        }
    }
    let response = flags & 0x8000 != 0;
    let mut answers = Vec::new();
    // Error and truncated packets are not evidence that an address belongs
    // to a name. Only the question owner and its CNAME chain are evidence;
    // unrelated records in the answer section must not poison the IP map.
    if response && flags & 0x020f == 0 {
        let mut owner = question.as_str();
        let mut ttl_cap = u32::MAX;
        let mut seen = HashSet::new();
        while seen.insert(owner) && seen.len() <= MAX_POINTERS {
            if let Some((target, ttl)) = aliases.get(owner) {
                ttl_cap = ttl_cap.min(*ttl);
                owner = target;
            } else {
                answers.extend(
                    addresses
                        .iter()
                        .filter(|(name, _, _)| name == owner)
                        .map(|(_, ip, ttl)| (*ip, (*ttl).min(ttl_cap))),
                );
                break;
            }
        }
    }
    Some(Message {
        id,
        response,
        question: Some(question),
        question_type: qtype,
        answers,
    })
}

/// Per connected DNS flow, remember only a bounded set of requests. The
/// connected socket establishes the server; ID, name and type establish
/// which outstanding request an answer belongs to. Unmatched replies may
/// still be relayed, but must never become host-blocking evidence.
#[derive(Default)]
pub struct Transactions {
    pending: HashMap<u16, (String, u16, u64)>,
}

const TRANSACTION_CAP: usize = 256;
const TRANSACTION_LIFETIME_MS: u64 = 5_000;

impl Transactions {
    pub fn remember(&mut self, bytes: &[u8], now_ms: u64) {
        self.pending.retain(|_, (_, _, expires)| *expires > now_ms);
        // Even a malformed replacement must invalidate the old ID.
        if let Some(id) = bytes.get(..2) {
            self.pending.remove(&u16::from_be_bytes([id[0], id[1]]));
        }
        let Some(m) = parse(bytes).filter(|m| !m.response) else {
            return;
        };
        let Some(name) = m.question else { return };
        if self.pending.len() < TRANSACTION_CAP {
            self.pending.insert(
                m.id,
                (
                    name,
                    m.question_type,
                    now_ms.saturating_add(TRANSACTION_LIFETIME_MS),
                ),
            );
        }
    }

    pub fn answer(&mut self, bytes: &[u8], now_ms: u64) -> Option<Message> {
        self.pending.retain(|_, (_, _, expires)| *expires > now_ms);
        let m = parse(bytes).filter(|m| m.response)?;
        let (name, ty, _) = self.pending.get(&m.id)?;
        if m.question.as_ref() != Some(name) || m.question_type != *ty {
            return None;
        }
        self.pending.remove(&m.id);
        Some(m)
    }
}

/// At most this many addresses are remembered; past it the soonest to
/// expire are dropped first (memory stays bounded, plan 6).
pub const NAME_MAP_CAP: usize = 100_000;
/// A TTL is honoured up to a day, so a bogus huge TTL cannot pin an entry.
pub const MAX_TTL_S: u32 = 86_400;
/// A shared CDN address cannot grow an unbounded vector. Overflow makes
/// its evidence ambiguous until the omitted names have expired.
pub const NAMES_PER_IP_CAP: usize = 32;

#[derive(Debug, Default)]
struct Names {
    live: Vec<(String, u64)>,
    ambiguous_until: u64,
}

/// Which names each address was resolved for, until their TTL runs out.
#[derive(Debug, Default)]
pub struct NameMap {
    entries: HashMap<IpAddr, Names>,
}

impl NameMap {
    /// Records an answer at `now_ms`.
    pub fn record(&mut self, name: &str, ip: IpAddr, ttl_s: u32, now_ms: u64) {
        let Some(name) = crate::flow::sni::host_name(name.as_bytes()) else {
            return;
        };
        let expires = now_ms.saturating_add(u64::from(ttl_s.min(MAX_TTL_S)) * 1_000);
        if ttl_s == 0 && !self.entries.contains_key(&ip) {
            return;
        }
        let entry = self.entries.entry(ip).or_default();
        entry.live.retain(|(_, exp)| *exp > now_ms);
        // The map is shared by every app and resolver: a shorter answer seen
        // by one client never cuts short an answer another client still caches.
        if let Some(e) = entry.live.iter_mut().find(|(n, _)| *n == name) {
            e.1 = e.1.max(expires);
        } else if ttl_s != 0 {
            if entry.live.len() < NAMES_PER_IP_CAP {
                entry.live.push((name, expires));
            } else {
                entry.ambiguous_until = entry.ambiguous_until.max(expires);
            }
        }
        if self.entries.len() > NAME_MAP_CAP {
            self.prune(now_ms);
        }
        while self.entries.len() > NAME_MAP_CAP {
            let soonest = self
                .entries
                .iter()
                .min_by_key(|(_, v)| {
                    v.live
                        .iter()
                        .map(|e| e.1)
                        .max()
                        .unwrap_or(0)
                        .max(v.ambiguous_until)
                })
                .map(|(ip, _)| *ip);
            match soonest {
                Some(ip) => self.entries.remove(&ip),
                None => break,
            };
        }
    }

    /// Records every address answer of a response.
    pub fn record_message(&mut self, m: &Message, now_ms: u64) -> usize {
        let Some(name) = m.question.as_deref().filter(|_| m.response) else {
            return 0;
        };
        for (ip, ttl) in &m.answers {
            self.record(name, *ip, *ttl, now_ms);
        }
        m.answers.len()
    }

    /// The live names of `ip` at `now_ms`.
    pub fn names(&self, ip: IpAddr, now_ms: u64) -> Vec<&str> {
        self.entries
            .get(&ip)
            .filter(|v| v.ambiguous_until <= now_ms)
            .map(|v| {
                v.live
                    .iter()
                    .filter(|(_, exp)| *exp > now_ms)
                    .map(|(n, _)| n.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Drops every expired name and every address left with none.
    pub fn prune(&mut self, now_ms: u64) {
        self.entries.retain(|_, v| {
            v.live.retain(|(_, exp)| *exp > now_ms);
            !v.live.is_empty() || v.ambiguous_until > now_ms
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
        let msg = build::response(
            7,
            "Example.COM",
            &[
                (ip("93.184.215.14"), 300),
                (ip("2606:2800:21f:cb07:6820:80da:af6b:8b2c"), 60),
            ],
        );
        let m = parse(&msg).unwrap();
        assert_eq!((m.id, m.response), (7, true));
        assert_eq!(m.question.as_deref(), Some("example.com"));
        assert_eq!(
            m.answers,
            vec![
                (ip("93.184.215.14"), 300),
                (ip("2606:2800:21f:cb07:6820:80da:af6b:8b2c"), 60)
            ]
        );
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

    fn query(id: u16, name: &str) -> Vec<u8> {
        let mut q = build::response(id, name, &[]);
        q[2] = 0x01;
        q
    }

    #[test]
    fn only_an_outstanding_matching_answer_is_evidence_once() {
        let mut tx = Transactions::default();
        let answer = build::response(7, "ads.example", &[(ip("192.0.2.1"), 30)]);
        assert!(tx.answer(&answer, 0).is_none());
        tx.remember(&query(7, "ads.example"), 0);
        assert!(
            tx.answer(&build::response(8, "ads.example", &[]), 1)
                .is_none()
        );
        assert!(
            tx.answer(&build::response(7, "other.example", &[]), 1)
                .is_none()
        );
        let mut wrong_type = build::response(7, "ads.example", &[]);
        let end = wrong_type.len();
        wrong_type[end - 4..end - 2].copy_from_slice(&TYPE_AAAA.to_be_bytes());
        assert!(tx.answer(&wrong_type, 1).is_none());
        assert_eq!(
            tx.answer(&answer, 2).unwrap().answers,
            vec![(ip("192.0.2.1"), 30)]
        );
        assert!(
            tx.answer(&answer, 3).is_none(),
            "a replay is not fresh evidence"
        );
    }

    #[test]
    fn replaced_expired_and_malformed_queries_cannot_validate_old_answers() {
        let mut tx = Transactions::default();
        let answer = build::response(7, "ads.example", &[]);
        tx.remember(&query(7, "ads.example"), 0);
        tx.remember(&query(7, "other.example"), 1);
        assert!(tx.answer(&answer, 2).is_none());
        tx.remember(&query(7, "ads.example"), 0);
        assert!(tx.answer(&answer, TRANSACTION_LIFETIME_MS).is_none());
        tx.remember(&query(7, "ads.example"), 0);
        tx.remember(&[0, 7], 1);
        assert!(tx.answer(&answer, 2).is_none());
    }

    #[test]
    fn outstanding_queries_are_bounded_and_expire() {
        let mut tx = Transactions::default();
        for id in 0..=TRANSACTION_CAP {
            tx.remember(&query(id as u16, "ads.example"), 0);
        }
        assert_eq!(tx.pending.len(), TRANSACTION_CAP);
        assert!(
            tx.answer(
                &build::response(TRANSACTION_CAP as u16, "ads.example", &[]),
                1
            )
            .is_none()
        );
        tx.remember(&query(500, "news.example"), TRANSACTION_LIFETIME_MS);
        assert_eq!(tx.pending.len(), 1);
    }

    #[test]
    fn truncated_and_looping_messages_are_refused() {
        let msg = build::response(1, "a.example", &[(ip("192.0.2.1"), 5)]);
        for cut in 0..msg.len() {
            assert!(
                parse(&msg[..cut]).is_none_or(|m| m.answers.is_empty()),
                "cut at {cut}"
            );
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
        assert_eq!(
            map.names(ip("192.0.2.7"), 5_000),
            vec!["cdn.example", "other.example"]
        );
        assert_eq!(map.names(ip("192.0.2.7"), 12_000), vec!["cdn.example"]);
        assert!(map.names(ip("192.0.2.7"), 31_000).is_empty());
        map.record("long.example", ip("192.0.2.8"), u32::MAX, 0);
        assert!(
            map.names(ip("192.0.2.8"), u64::from(MAX_TTL_S) * 1_000)
                .is_empty()
        );
        map.prune(u64::MAX);
        assert!(map.is_empty());
    }

    #[test]
    fn incomplete_question_error_and_truncated_responses_are_not_address_evidence() {
        let mut msg = build::response(1, "a.example", &[]);
        msg.pop();
        assert!(parse(&msg).is_none());
        for flags in [0x8380u16, 0x8183] {
            let mut msg = build::response(1, "a.example", &[(ip("192.0.2.1"), 60)]);
            msg[2..4].copy_from_slice(&flags.to_be_bytes());
            assert!(parse(&msg).unwrap().answers.is_empty());
        }
    }

    fn wire_name(name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes
    }

    fn append_rr(msg: &mut Vec<u8>, owner: &str, ty: u16, ttl: u32, data: &[u8]) {
        msg.extend(wire_name(owner));
        msg.extend_from_slice(&ty.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&ttl.to_be_bytes());
        msg.extend_from_slice(&(data.len() as u16).to_be_bytes());
        msg.extend_from_slice(data);
    }

    #[test]
    fn only_the_question_cname_chain_contributes_addresses_with_its_shortest_ttl() {
        let mut msg = build::response(1, "ads.example", &[]);
        msg[6..8].copy_from_slice(&4u16.to_be_bytes());
        append_rr(&mut msg, "unrelated.example", TYPE_A, 60, &[192, 0, 2, 9]);
        // The answer order need not be the chain order.
        append_rr(&mut msg, "cdn.example", TYPE_A, 300, &[192, 0, 2, 1]);
        append_rr(
            &mut msg,
            "alias.example",
            TYPE_CNAME,
            20,
            &wire_name("cdn.example"),
        );
        append_rr(
            &mut msg,
            "ads.example",
            TYPE_CNAME,
            50,
            &wire_name("alias.example"),
        );
        assert_eq!(parse(&msg).unwrap().answers, vec![(ip("192.0.2.1"), 20)]);
    }

    #[test]
    fn unrelated_answer_and_cname_cycles_cannot_poison_the_map() {
        let mut msg = build::response(1, "ads.example", &[]);
        msg[6..8].copy_from_slice(&1u16.to_be_bytes());
        append_rr(&mut msg, "unrelated.example", TYPE_A, 60, &[192, 0, 2, 9]);
        assert!(parse(&msg).unwrap().answers.is_empty());
        msg[6..8].copy_from_slice(&3u16.to_be_bytes());
        append_rr(
            &mut msg,
            "ads.example",
            TYPE_CNAME,
            50,
            &wire_name("alias.example"),
        );
        append_rr(
            &mut msg,
            "alias.example",
            TYPE_CNAME,
            50,
            &wire_name("ads.example"),
        );
        assert!(parse(&msg).unwrap().answers.is_empty());
    }

    #[test]
    fn a_shorter_answer_never_cuts_short_another_clients_cached_answer() {
        let mut map = NameMap::default();
        let address = ip("192.0.2.1");
        // Two clients share the address; one later sees a TTL 0 answer for
        // news.example. The other may use its 300 s answer until it expires,
        // so news.example must stay (else ads.example alone would block it).
        map.record("news.example", address, 300, 0);
        map.record("ads.example", address, 300, 0);
        map.record("news.example", address, 0, 1_000);
        map.record("news.example", address, 1, 1_000);
        assert_eq!(map.names(address, 2_000), vec!["news.example", "ads.example"]);
        map.record("news.example", address, 600, 100_000);
        assert_eq!(map.names(address, 400_000), vec!["news.example"]);
        assert!(map.names(address, 700_000).is_empty());
        // A TTL 0 answer for an unseen address records nothing.
        map.record("zero.example", ip("192.0.2.2"), 0, 0);
        assert!(map.names(ip("192.0.2.2"), 0).is_empty());
    }

    #[test]
    fn overflow_is_ambiguous_until_every_omitted_name_expires() {
        let mut map = NameMap::default();
        let address = ip("192.0.2.1");
        for i in 0..NAMES_PER_IP_CAP {
            map.record(&format!("{i}.ads.example"), address, 300, 0);
        }
        map.record("news.example", address, 60, 0);
        map.record("shop.example", address, 90, 0);
        assert_eq!(map.entries[&address].live.len(), NAMES_PER_IP_CAP);
        assert!(map.names(address, 60_000).is_empty());
        map.prune(89_999);
        assert!(map.names(address, 89_999).is_empty());
        assert_eq!(map.names(address, 90_000).len(), NAMES_PER_IP_CAP);
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
