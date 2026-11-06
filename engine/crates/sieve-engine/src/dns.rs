//! DNS on the TUN (plan 1.4): every lookup that enters the adapter is answered
//! through an encrypted upstream, or by the adapter's own LAN server for a name
//! under its own suffixes, and every answer is read for the IP-to-names map
//! with TTL, which later decides flows that carry no name of their own. The
//! engine never blocks in DNS, never writes a DNS setting and never sends plain
//! DNS beyond a private server excluded from routing.
//!
//! - [`service`]: one query to one answer, and the two flow loops;
//! - [`upstream`]: the resolver list, failover and the split-horizon rules;
//! - [`pool`]: one kept-open session per upstream, over [`doh`], [`dot`], [`doq`];
//! - [`lan`]: the one plain exchange, to a LAN server;
//! - [`config`]: the list as `dns.json` holds it.
//!
//! [`Connector`] is the only way this code opens a socket, so the production
//! connector's pinning and the tests' recording cover every socket.
//!
//! The parser reads only what the map needs: the question name, and A and
//! AAAA answers with their TTL (compressed names, RFC 1035 4.1.4); and what the
//! engine's own upstream hello needs: HTTPS records with their `ech` parameter.
//! Anything malformed is None, never a guess.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;

use tokio::net::TcpStream;

use crate::flow::Reader;

pub mod config;
pub mod doh;
pub mod doq;
pub mod dot;
pub mod lan;
pub mod pool;
pub mod service;
#[cfg(test)]
pub(crate) mod testing;
pub mod upstream;

pub(crate) const TYPE_A: u16 = 1;
pub(crate) const TYPE_AAAA: u16 = 28;
/// RFC 9460: the service binding record, where an ECH config lives.
pub(crate) const TYPE_HTTPS: u16 = 65;
const TYPE_CNAME: u16 = 5;
/// EDNS's pseudo-record (RFC 6891).
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;
/// RFC 9460 14.3.2: SvcParamKey `ech`.
const SVC_PARAM_ECH: u16 = 5;
/// Pointer hops allowed in one name (a loop guard).
const MAX_POINTERS: usize = 16;
/// The longest name (RFC 1035 3.1).
const MAX_NAME: usize = 255;
/// The fixed header of every message.
const HEADER: usize = 12;
/// The longest message any DNS transport carries (2-byte framing).
pub const MAX_MESSAGE: usize = 65_535;
/// What a UDP client without EDNS accepts (RFC 1035 4.2.1).
const UDP_DEFAULT: usize = 512;
/// IPv6 and UDP headers, the larger family, between the MTU and a reply.
const UDP_OVERHEAD: usize = 48;
const FLAG_QR: u16 = 0x8000;
const FLAG_OPCODE: u16 = 0x7800;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const RCODE_SERVFAIL: u16 = 2;
const RCODE_NOTIMP: u16 = 4;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The only way DNS code opens a socket. Production is `stack::egress::Egress`,
/// which binds and pins each socket to the interface Windows would use without
/// Sieve; tests use a loopback connector that records every target.
pub trait Connector: Send + Sync + 'static {
    fn tcp(&self, target: SocketAddr) -> BoxFuture<'_, Result<TcpStream, String>>;
    /// A bound, non-blocking UDP socket for traffic to `target`, not connected.
    fn udp(&self, target: SocketAddr) -> Result<socket2::Socket, String>;
    /// Where a socket for `target` sends. Only a test connector remaps it.
    fn address(&self, target: SocketAddr) -> SocketAddr {
        target
    }
}

/// A spawned task that ends with its owner, so nothing outlives the engine.
pub(crate) struct Owned(tokio::task::AbortHandle);

impl Owned {
    pub(crate) fn spawn(task: impl Future<Output = ()> + Send + 'static) -> Self {
        Self(tokio::spawn(task).abort_handle())
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// `msg` with its ID replaced.
pub(crate) fn with_id(msg: &[u8], id: u16) -> Vec<u8> {
    let mut out = msg.to_vec();
    if let Some(head) = out.get_mut(..2) {
        head.copy_from_slice(&id.to_be_bytes());
    }
    out
}

pub(crate) fn id_of(msg: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.first()?, *msg.get(1)?]))
}

/// A message's flags, for one at least as long as its header.
pub(crate) fn flags_of(msg: &[u8]) -> Option<u16> {
    (msg.len() >= HEADER).then(|| u16::from_be_bytes([msg[2], msg[3]]))
}

/// A recursive query for `name`, ID 0. None for a name that cannot be sent.
pub(crate) fn query_for(name: &str, ty: u16) -> Option<Vec<u8>> {
    let mut q = Vec::with_capacity(HEADER + name.len() + 6);
    q.extend_from_slice(&[0, 0]);
    q.extend_from_slice(&FLAG_RD.to_be_bytes());
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        q.push(u8::try_from(label.len()).ok().filter(|l| (1..64).contains(l))?);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&ty.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    Some(q)
}

/// The position after a name, walked without reading it (any octets).
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = usize::from(*msg.get(pos)?);
        match len & 0xc0 {
            0 if len == 0 => return Some(pos + 1),
            0 => pos += 1 + len,
            0xc0 => return Some(pos + 2),
            _ => return None,
        }
    }
}

/// The end of the question section, whatever its labels hold.
fn question_end(msg: &[u8]) -> Option<usize> {
    let count = u16::from_be_bytes([*msg.get(4)?, *msg.get(5)?]);
    let mut pos = HEADER;
    for _ in 0..count {
        pos = skip_name(msg, pos)? + 4;
    }
    (pos <= msg.len()).then_some(pos)
}

/// The same header flags and question with no records; the opcode and RD of
/// the query are kept, per RFC 1035 4.1.1.
fn answer_without_records(msg: &[u8], flags: u16) -> Option<Vec<u8>> {
    let id = msg.get(..2)?;
    let (question, count) = match question_end(msg) {
        Some(end) => (&msg[HEADER..end], [msg[4], msg[5]]),
        None => (&[][..], [0, 0]),
    };
    let mut out = Vec::with_capacity(HEADER + question.len());
    out.extend_from_slice(id);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&count);
    out.extend_from_slice(&[0; 6]);
    out.extend_from_slice(question);
    Some(out)
}

fn error_reply(query: &[u8], rcode: u16) -> Option<Vec<u8>> {
    let kept = flags_of(query)? & (FLAG_OPCODE | FLAG_RD);
    answer_without_records(query, FLAG_QR | FLAG_RA | kept | rcode)
}

/// SERVFAIL with the client's ID and question: nothing could answer.
pub fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    error_reply(query, RCODE_SERVFAIL)
}

/// NOTIMP with the client's ID and question: the engine answers this itself.
pub fn notimp(query: &[u8]) -> Option<Vec<u8>> {
    error_reply(query, RCODE_NOTIMP)
}

/// `reply` as header and question with TC set: the client retries over TCP.
pub fn truncated(reply: &[u8]) -> Option<Vec<u8>> {
    answer_without_records(reply, flags_of(reply)? | FLAG_TC)
}

pub fn is_truncated(reply: &[u8]) -> bool {
    flags_of(reply).is_some_and(|f| f & FLAG_TC != 0)
}

/// The payload size a query's EDNS record announces.
fn edns_payload(msg: &[u8]) -> Option<usize> {
    let count = |at: usize| Some(usize::from(u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?])));
    let before = count(6)? + count(8)?;
    let total = before + count(10)?;
    let mut pos = question_end(msg)?;
    for index in 0..total {
        let start = skip_name(msg, pos)?;
        let mut r = Reader::new(msg.get(start..)?);
        let (ty, class, _ttl, len) = (r.u16()?, r.u16()?, r.u32()?, usize::from(r.u16()?));
        if ty == TYPE_OPT && index >= before {
            return Some(usize::from(class));
        }
        pos = start + 10 + len;
    }
    None
}

/// The largest UDP reply this query's client accepts: its EDNS payload size or
/// 512, and never more than one packet of the adapter can carry.
pub fn udp_limit(query: &[u8], mtu: usize) -> usize {
    edns_payload(query).map_or(UDP_DEFAULT, |p| p.max(UDP_DEFAULT)).min(mtu.saturating_sub(UDP_OVERHEAD))
}

/// True when `reply` can stand as the answer to `query`: a response with its
/// ID, at most [`MAX_MESSAGE`], and the same question and type when the query
/// could be read. An opaque query has only the ID to compare.
pub fn reply_fits(query: &[u8], reply: &[u8]) -> bool {
    let response = flags_of(reply).is_some_and(|f| f & FLAG_QR != 0);
    if !response || reply.len() > MAX_MESSAGE || id_of(query) != id_of(reply) {
        return false;
    }
    match question_of(query) {
        Some((name, ty, class, _)) => question_of(reply).is_some_and(|(n, t, c, _)| n == name && t == ty && c == class),
        None => true,
    }
}

/// `reply` as evidence for the IP-to-names map: it fits a query that could be
/// read, and could be read itself. Anything else may still reach the client
/// but never becomes evidence.
pub fn reply_answers(query: &[u8], reply: &[u8]) -> Option<Message> {
    parse(query).filter(|q| !q.response)?;
    reply_fits(query, reply).then(|| parse(reply)).flatten().filter(|m| m.response)
}

/// A message's question name and its address answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub response: bool,
    pub question: Option<String>,
    pub question_type: u16,
    /// (address, TTL in seconds).
    pub answers: Vec<(IpAddr, u32)>,
    /// The HTTPS records of the question's chain.
    pub https: Vec<HttpsRecord>,
}

/// One HTTPS record, as the engine's upstream hello reads it (plan 2.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsRecord {
    pub priority: u16,
    /// The `ech` parameter's ECHConfigList. AliasMode (priority 0) gives none
    /// and is not followed.
    pub ech: Option<Vec<u8>>,
    pub ttl: u32,
}

/// The config to use: the lowest priority that has one.
pub fn best_ech(records: &[HttpsRecord]) -> Option<&HttpsRecord> {
    records.iter().filter(|r| r.ech.is_some()).min_by_key(|r| r.priority)
}

/// Priority and `ech` of an HTTPS record's RDATA (RFC 9460 2.2). The target is
/// never compressed and the keys strictly ascend. None when malformed, which
/// costs that record only.
fn https_rdata(data: &[u8]) -> Option<(u16, Option<Vec<u8>>)> {
    let (priority, mut rest) = data.split_first_chunk::<2>()?;
    loop {
        let (&length, after) = rest.split_first()?;
        if length & 0xc0 != 0 {
            return None;
        }
        rest = after.get(usize::from(length)..)?;
        if length == 0 {
            break;
        }
    }
    let mut last_key = None;
    let mut ech = None;
    while !rest.is_empty() {
        let (head, after) = rest.split_first_chunk::<4>()?;
        let key = u16::from_be_bytes([head[0], head[1]]);
        let length = usize::from(u16::from_be_bytes([head[2], head[3]]));
        let value = after.get(..length)?;
        if last_key.is_some_and(|last| key <= last) {
            return None;
        }
        last_key = Some(key);
        if key == SVC_PARAM_ECH && !value.is_empty() {
            ech = Some(value.to_vec());
        }
        rest = &after[length..];
    }
    let priority = u16::from_be_bytes(*priority);
    Some((priority, ech.filter(|_| priority != 0)))
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

/// The one question of a QUERY: its name, type, class and where it ends.
fn question_of(msg: &[u8]) -> Option<(String, u16, u16, usize)> {
    let mut r = Reader::new(msg);
    let (_id, flags, qd) = (r.u16()?, r.u16()?, r.u16()?);
    // One question is the only unambiguous association for this cache.
    if qd != 1 || flags & FLAG_OPCODE != 0 {
        return None;
    }
    let (question, next) = name_at(msg, HEADER)?;
    let mut q = Reader::new(msg.get(next..)?);
    let (qtype, qclass) = (q.u16()?, q.u16()?);
    (!question.is_empty()).then_some((question, qtype, qclass, next + 4))
}

/// Parses a DNS message over UDP (or one TCP message without its length).
pub fn parse(msg: &[u8]) -> Option<Message> {
    let mut r = Reader::new(msg);
    let id = r.u16()?;
    let flags = r.u16()?;
    let _qd = r.u16()?;
    let an = r.u16()?;
    let (question, qtype, qclass, mut pos) = question_of(msg)?;
    if qclass != CLASS_IN {
        return None;
    }
    let mut addresses = Vec::new();
    let mut services = Vec::new();
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
            (TYPE_HTTPS, CLASS_IN, _) => {
                if let Some((priority, ech)) = https_rdata(data) {
                    services.push((owner, HttpsRecord { priority, ech, ttl }));
                }
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
    let response = flags & FLAG_QR != 0;
    let mut answers = Vec::new();
    let mut https = Vec::new();
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
                https.extend(services.iter().filter(|(name, _)| name == owner).map(|(_, record)| HttpsRecord { ttl: record.ttl.min(ttl_cap), ..record.clone() }));
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
        https,
    })
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
    fn only_a_matching_answer_is_evidence() {
        let q = query(7, "ads.example");
        let answer = build::response(7, "ads.example", &[(ip("192.0.2.1"), 30)]);
        assert!(reply_answers(&q, &build::response(8, "ads.example", &[])).is_none());
        assert!(reply_answers(&q, &build::response(7, "other.example", &[])).is_none());
        let mut wrong_type = build::response(7, "ads.example", &[]);
        let end = wrong_type.len();
        wrong_type[end - 4..end - 2].copy_from_slice(&TYPE_AAAA.to_be_bytes());
        assert!(reply_answers(&q, &wrong_type).is_none());
        assert!(reply_answers(&q, &q).is_none(), "a query is no answer");
        assert_eq!(reply_answers(&q, &answer).unwrap().answers, vec![(ip("192.0.2.1"), 30)]);
    }

    #[test]
    fn a_reply_must_carry_the_id_and_the_question_of_its_query() {
        let q = query(7, "ads.example");
        assert!(reply_fits(&q, &build::response(7, "ADS.example", &[])), "names compare without case");
        assert!(!reply_fits(&q, &build::response(8, "ads.example", &[])));
        assert!(!reply_fits(&q, &build::response(7, "other.example", &[])));
        assert!(!reply_fits(&q, &q));
        assert!(!reply_fits(&q, &[0, 7, 0x80]), "shorter than a header");
        let mut oversized = build::response(7, "ads.example", &[]);
        oversized.resize(MAX_MESSAGE + 1, 0);
        assert!(!reply_fits(&q, &oversized));
    }

    #[test]
    fn an_opaque_query_has_only_its_id_to_compare_and_gives_no_evidence() {
        // A label the name parser refuses: still forwarded, never evidence.
        let mut q = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, b'a', 0xff, 0, 0, 1, 0, 1];
        assert!(parse(&q).is_none());
        let mut reply = q.clone();
        reply[2] = 0x81;
        assert!(reply_fits(&q, &reply));
        assert!(reply_answers(&q, &reply).is_none());
        q[1] = 8;
        assert!(!reply_fits(&q, &reply));
    }

    #[test]
    fn an_error_reply_keeps_the_id_and_the_question_and_states_its_code() {
        let q = query(7, "ads.example");
        let reply = servfail(&q).unwrap();
        assert_eq!(id_of(&reply), Some(7));
        let m = parse(&reply).unwrap();
        assert!(m.response && m.answers.is_empty());
        assert_eq!(m.question.as_deref(), Some("ads.example"));
        assert_eq!(flags_of(&reply).unwrap() & 0xf, RCODE_SERVFAIL);
        assert_eq!(flags_of(&reply).unwrap() & FLAG_RD, FLAG_RD);
        assert_eq!(flags_of(&notimp(&q).unwrap()).unwrap() & 0xf, RCODE_NOTIMP);
        // An UPDATE keeps its opcode; a query that cannot be walked keeps its ID.
        let mut update = q.clone();
        update[2] = 0x28;
        assert_eq!(flags_of(&notimp(&update).unwrap()).unwrap() & FLAG_OPCODE, 0x2800);
        let mut broken = q[..HEADER].to_vec();
        broken.push(200);
        let reply = servfail(&broken).unwrap();
        assert_eq!((id_of(&reply), reply.len()), (Some(7), HEADER));
        assert!(servfail(&q[..4]).is_none());
    }

    #[test]
    fn truncation_keeps_the_question_and_drops_the_records() {
        let reply = build::response(7, "ads.example", &[(ip("192.0.2.1"), 30)]);
        let short = truncated(&reply).unwrap();
        assert!(is_truncated(&short) && !is_truncated(&reply));
        let m = parse(&short).unwrap();
        assert_eq!((m.id, m.question.as_deref()), (7, Some("ads.example")));
        assert_eq!(short[6..12], [0; 6]);
    }

    /// A query with an EDNS record announcing `payload`.
    fn query_with_edns(id: u16, name: &str, payload: u16) -> Vec<u8> {
        let mut q = query(id, name);
        q[10..12].copy_from_slice(&1u16.to_be_bytes());
        q.push(0);
        q.extend_from_slice(&TYPE_OPT.to_be_bytes());
        q.extend_from_slice(&payload.to_be_bytes());
        q.extend_from_slice(&[0; 6]);
        q
    }

    #[test]
    fn the_udp_limit_is_the_clients_within_the_adapters_packet() {
        assert_eq!(udp_limit(&query(1, "a.example"), 1500), 512, "no EDNS");
        assert_eq!(udp_limit(&query_with_edns(1, "a.example", 1232), 1500), 1232);
        assert_eq!(udp_limit(&query_with_edns(1, "a.example", 100), 1500), 512, "RFC 6891: at least 512");
        assert_eq!(udp_limit(&query_with_edns(1, "a.example", 4096), 1500), 1452, "the MTU bound");
        let mut cut = query_with_edns(1, "a.example", 1232);
        cut.truncate(cut.len() - 3);
        assert_eq!(udp_limit(&cut, 1500), 512, "a broken record reads as no EDNS");
    }

    #[test]
    fn a_built_query_reads_back() {
        let q = query_for("dns.example", TYPE_AAAA).unwrap();
        let m = parse(&q).unwrap();
        assert_eq!((m.response, m.question.as_deref(), m.question_type), (false, Some("dns.example"), TYPE_AAAA));
        assert!(query_for("a..example", TYPE_A).is_none());
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

    /// RDATA of an HTTPS record with these SvcParams.
    fn https_data(priority: u16, target: &str, params: &[(u16, &[u8])]) -> Vec<u8> {
        let mut data = priority.to_be_bytes().to_vec();
        data.extend(if target.is_empty() { vec![0] } else { wire_name(target) });
        for (key, value) in params {
            data.extend_from_slice(&key.to_be_bytes());
            data.extend_from_slice(&(value.len() as u16).to_be_bytes());
            data.extend_from_slice(value);
        }
        data
    }

    /// A reply to an HTTPS question for `name` holding these records.
    fn https_reply(name: &str, flags: u16, records: &[(&str, u16, u32, Vec<u8>)]) -> Vec<u8> {
        let mut msg = build::response(1, name, &[]);
        msg[2..4].copy_from_slice(&flags.to_be_bytes());
        msg[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        let end = msg.len();
        msg[end - 4..end - 2].copy_from_slice(&TYPE_HTTPS.to_be_bytes());
        for (owner, ty, ttl, data) in records {
            append_rr(&mut msg, owner, *ty, *ttl, data);
        }
        msg
    }

    #[test]
    fn https_record_table() {
        const OK: u16 = 0x8180;
        const ALPN: (u16, &[u8]) = (1, b"\x02h2");
        const PORT: (u16, &[u8]) = (3, &[1, 187]);
        const ECH: u16 = 5;
        const NEXT: (u16, &[u8]) = (6, &[192, 0, 2, 1]);
        let config = |c: u8| vec![c; 4];
        let service = |priority: u16, c: u8| (priority, config(c));
        let with = |(priority, ech): (u16, Vec<u8>)| https_data(priority, "", &[(ECH, &ech)]);
        let row = |name: &str, want: Option<Vec<u8>>, msg: Vec<u8>| {
            let parsed = parse(&msg).unwrap_or_else(|| panic!("{name}: the message still parses"));
            assert_eq!(best_ech(&parsed.https).and_then(|r| r.ech.clone()), want, "{name}");
        };
        let host = "site.example";
        row("a service record with ech", Some(config(1)), https_reply(host, OK, &[(host, TYPE_HTTPS, 300, with(service(1, 1)))]));
        row(
            "the lowest priority with a config wins",
            Some(config(2)),
            https_reply(host, OK, &[(host, TYPE_HTTPS, 300, with(service(3, 3))), (host, TYPE_HTTPS, 300, https_data(1, "", &[ALPN])), (host, TYPE_HTTPS, 300, with(service(2, 2)))]),
        );
        row("AliasMode gives none", None, https_reply(host, OK, &[(host, TYPE_HTTPS, 300, https_data(0, "alias.example", &[(ECH, &config(1))]))]));
        let chain = https_reply(host, OK, &[(host, TYPE_CNAME, 50, wire_name("cdn.example")), ("cdn.example", TYPE_HTTPS, 300, with(service(1, 4)))]);
        row("a record on the CNAME chain counts", Some(config(4)), chain.clone());
        assert_eq!(parse(&chain).unwrap().https[0].ttl, 50, "with the chain's shortest TTL");
        row("a record on an unrelated owner does not", None, https_reply(host, OK, &[("unrelated.example", TYPE_HTTPS, 300, with(service(1, 5)))]));
        let ech = config(6);
        row("other params around key 5", Some(config(6)), https_reply(host, OK, &[(host, TYPE_HTTPS, 300, https_data(1, "svc.example", &[ALPN, PORT, (ECH, &ech), NEXT]))]));
        row("an error reply gives none", None, https_reply(host, 0x8182, &[(host, TYPE_HTTPS, 300, with(service(1, 7)))]));
        row("a truncated reply gives none", None, https_reply(host, 0x8380, &[(host, TYPE_HTTPS, 300, with(service(1, 8)))]));
        // A malformed record costs that record, and only that record.
        let mut cut = with(service(1, 9));
        cut.truncate(cut.len() - 1);
        let out_of_order = https_data(1, "", &[NEXT, (ECH, &ech)]);
        let compressed = vec![0, 1, 0xc0, 0x0c];
        row("malformed records beside a good one", Some(config(1)), https_reply(host, OK, &[(host, TYPE_HTTPS, 300, cut), (host, TYPE_HTTPS, 300, out_of_order), (host, TYPE_HTTPS, 300, compressed), (host, TYPE_HTTPS, 300, with(service(2, 1)))]));
        // The address path is unchanged by any of this.
        let mut both = https_reply(host, OK, &[(host, TYPE_HTTPS, 300, with(service(1, 1)))]);
        both[6..8].copy_from_slice(&2u16.to_be_bytes());
        append_rr(&mut both, host, TYPE_A, 60, &[192, 0, 2, 1]);
        assert_eq!(parse(&both).unwrap().answers, vec![(ip("192.0.2.1"), 60)]);
    }

    proptest! {
        #[test]
        fn https_record_parse_refuses_hostile_bytes(data in proptest::collection::vec(any::<u8>(), 0..512), whole in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = https_rdata(&data);
            let reply = https_reply("site.example", 0x8180, &[("site.example", TYPE_HTTPS, 300, data)]);
            prop_assert!(parse(&reply).is_some(), "bad RDATA never costs the message");
            let _ = parse(&whole);
        }
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
