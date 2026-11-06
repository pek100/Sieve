//! Removing the `ech` parameter from HTTPS and SVCB answers (plan 1.4, 2.9). The
//! browser then sends the real name, so the flow can be judged.
//!
//! Pure wire code, and anything it cannot prove safe leaves the reply byte for
//! byte as it came. That failure is safe: an unstripped ECH hello takes
//! `floor:ech` and passes through.
//!
//! Removing bytes moves everything after them, so every compression pointer whose
//! target lies past a cut has to shift. Pointers are found in owners and in the
//! rdata of the types that may hold a compressed name (RFC 1035 3.3). After the
//! first cut a record of any type outside those and [`NO_NAMES`] leaves the reply
//! unchanged, since its rdata might hold a pointer nobody can find (RFC 3597).

use std::ops::Range;

use super::{FLAG_AD, HEADER, MAX_NAME, MAX_POINTERS, TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_HTTPS, TYPE_OPT, TYPE_SVCB};

const TYPE_NS: u16 = 2;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_DS: u16 = 43;
const TYPE_RRSIG: u16 = 46;
const TYPE_NSEC: u16 = 47;
const TYPE_NSEC3: u16 = 50;
const TYPE_CAA: u16 = 257;
/// Types whose rdata never holds a compressed name (RFC 4034 forbids it for
/// those that hold a name at all).
const NO_NAMES: [u16; 9] = [TYPE_A, TYPE_AAAA, TYPE_TXT, TYPE_OPT, TYPE_DS, TYPE_RRSIG, TYPE_NSEC, TYPE_NSEC3, TYPE_CAA];
const PARAM_MANDATORY: u16 = 0;
const PARAM_ECH: u16 = 5;
/// Priority, then the two bytes MX puts before its name.
const PRIORITY: usize = 2;
/// A record's type, class and TTL, before its RDLENGTH.
const RDLENGTH_AT: usize = 8;
/// A record's fixed part after its owner.
const FIXED: usize = 10;
/// What follows SOA's two names: serial, refresh, retry, expire, minimum.
const SOA_NUMBERS: usize = 20;
const POINTER: u8 = 0xc0;

/// What became of one reply.
#[derive(Debug, PartialEq, Eq)]
pub enum Stripped {
    /// No `ech` was seen. Nothing was copied.
    Clean,
    /// An `ech` is there and stays: the reply cannot be safely rewritten.
    Left,
    /// The reply without its `ech` parameters.
    Cut(Vec<u8>),
}

fn u16_at(msg: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?]))
}

fn pointer_target(msg: &[u8], at: usize) -> Option<usize> {
    u16_at(msg, at).map(|word| usize::from(word & 0x3fff))
}

/// What one pass over the message found, in message order.
#[derive(Default)]
struct Walk {
    /// Where each pointer of a known name sits.
    pointers: Vec<usize>,
    /// The bytes to remove.
    cuts: Vec<Range<usize>>,
    /// Where the RDLENGTH of each cut's record sits, by cut.
    lengths: Vec<usize>,
    saw_ech: bool,
}

impl Walk {
    fn message(&mut self, msg: &[u8]) -> Option<()> {
        let mut pos = HEADER;
        for _ in 0..u16_at(msg, 4)? {
            pos = self.name(msg, pos)? + 4;
        }
        let records = usize::from(u16_at(msg, 6)?) + usize::from(u16_at(msg, 8)?) + usize::from(u16_at(msg, 10)?);
        for _ in 0..records {
            pos = self.record(msg, pos)?;
        }
        Some(())
    }

    /// The position after a name, noting its pointer. A pointer must look back
    /// past the header (RFC 1035 4.1.4 says a prior occurrence).
    fn name(&mut self, msg: &[u8], mut pos: usize) -> Option<usize> {
        loop {
            let len = *msg.get(pos)?;
            match len & POINTER {
                0 if len == 0 => return Some(pos + 1),
                0 => pos += 1 + usize::from(len),
                POINTER => {
                    let target = pointer_target(msg, pos)?;
                    if target >= pos || target < HEADER {
                        return None;
                    }
                    self.pointers.push(pos);
                    return Some(pos + 2);
                }
                _ => return None,
            }
        }
    }

    fn record(&mut self, msg: &[u8], pos: usize) -> Option<usize> {
        let owner_end = self.name(msg, pos)?;
        let ty = u16_at(msg, owner_end)?;
        let start = owner_end + FIXED;
        let end = start + usize::from(u16_at(msg, owner_end + RDLENGTH_AT)?);
        msg.get(start..end)?;
        let walked = match ty {
            TYPE_SVCB | TYPE_HTTPS => self.service(msg, start..end, owner_end + RDLENGTH_AT),
            TYPE_NS | TYPE_CNAME | TYPE_PTR => self.name(msg, start),
            TYPE_MX => self.name(msg, start + PRIORITY),
            TYPE_SOA => self.name(msg, start).and_then(|next| self.name(msg, next)).map(|next| next + SOA_NUMBERS),
            _ if self.cuts.is_empty() || NO_NAMES.contains(&ty) => Some(end),
            _ => None,
        }?;
        (walked == end).then_some(end)
    }

    /// One HTTPS or SVCB rdata (RFC 9460 2.2): priority, an uncompressed target,
    /// then parameters in strictly ascending key order. AliasMode has none that
    /// mean anything.
    fn service(&mut self, msg: &[u8], rdata: Range<usize>, rdlength_at: usize) -> Option<usize> {
        let priority = u16_at(msg, rdata.start)?;
        let mut pos = rdata.start + PRIORITY;
        loop {
            let len = usize::from(*msg.get(pos)?);
            pos += 1 + len;
            if len == 0 {
                break;
            }
            if len & usize::from(POINTER) != 0 {
                return None;
            }
        }
        if pos > rdata.end {
            return None;
        }
        if priority == 0 {
            return Some(rdata.end);
        }
        let mut last = None;
        while pos < rdata.end {
            let key = u16_at(msg, pos)?;
            let value = pos + 4..pos + 4 + usize::from(u16_at(msg, pos + 2)?);
            self.saw_ech |= key == PARAM_ECH;
            if value.end > rdata.end || last.is_some_and(|previous| previous >= key) {
                return None;
            }
            last = Some(key);
            if key == PARAM_MANDATORY && names_ech(&msg[value.clone()])? {
                self.saw_ech = true;
                return None;
            }
            if key == PARAM_ECH {
                self.cuts.push(pos..value.end);
                self.lengths.push(rdlength_at);
            }
            pos = value.end;
        }
        Some(rdata.end)
    }

    /// The first cut that ends after `at`.
    fn next_cut(&self, at: usize) -> usize {
        self.cuts.partition_point(|cut| cut.end <= at)
    }

    /// True when a cut touches `bytes`, the first of which is at `start`.
    fn touches(&self, start: usize, bytes: usize) -> bool {
        self.cuts.get(self.next_cut(start)).is_some_and(|cut| cut.start < start + bytes)
    }

    /// True when the name at `pos` reads the same after the cuts: none of its
    /// bytes goes, and each pointer on the way is one this walk will shift.
    fn name_survives(&self, msg: &[u8], mut pos: usize) -> bool {
        let (mut read, mut hops) = (0, 0);
        loop {
            let Some(&len) = msg.get(pos) else { return false };
            if len & POINTER == POINTER {
                hops += 1;
                let Some(target) = pointer_target(msg, pos) else { return false };
                if hops > MAX_POINTERS || self.touches(pos, 2) || self.pointers.binary_search(&pos).is_err() {
                    return false;
                }
                pos = target;
                continue;
            }
            if len & POINTER != 0 || self.touches(pos, 1 + usize::from(len)) {
                return false;
            }
            if len == 0 {
                return true;
            }
            read += 1 + usize::from(len);
            if read > MAX_NAME {
                return false;
            }
            pos += 1 + usize::from(len);
        }
    }

    /// `msg` with every cut applied. None when a pointer would no longer read.
    fn rewrite(&self, msg: &[u8]) -> Option<Vec<u8>> {
        // What comes off before the end of each cut, for the shift of a pointer.
        let removed: Vec<usize> = self.cuts.iter().scan(0, |sum, cut| { *sum += cut.len(); Some(*sum) }).collect();
        let mut edited = msg.to_vec();
        for &at in &self.pointers {
            let target = pointer_target(msg, at)?;
            if !self.name_survives(msg, target) {
                return None;
            }
            let shift = self.next_cut(target).checked_sub(1).map_or(0, |last| removed[last]);
            let moved = u16::try_from(target - shift).ok()?;
            edited[at..at + 2].copy_from_slice(&(moved | (u16::from(POINTER) << 8)).to_be_bytes());
        }
        for (at, cut) in self.lengths.iter().zip(&self.cuts) {
            let kept = u16_at(&edited, *at)? - u16::try_from(cut.len()).ok()?;
            edited[*at..*at + 2].copy_from_slice(&kept.to_be_bytes());
        }
        // The data changed, so the resolver's "authentic" no longer holds.
        let flags = u16_at(&edited, 2)? & !FLAG_AD;
        edited[2..4].copy_from_slice(&flags.to_be_bytes());
        let mut out = Vec::with_capacity(edited.len() - removed.last()?);
        let mut from = 0;
        for cut in &self.cuts {
            out.extend_from_slice(&edited[from..cut.start]);
            from = cut.end;
        }
        out.extend_from_slice(&edited[from..]);
        Some(out)
    }
}

/// True when a `mandatory` value lists `ech`. None for a value of odd length.
fn names_ech(value: &[u8]) -> Option<bool> {
    value.len().is_multiple_of(2).then(|| value.chunks_exact(2).any(|key| u16::from_be_bytes([key[0], key[1]]) == PARAM_ECH))
}

/// `reply` without its `ech` parameters, if that can be done safely.
pub fn strip(reply: &[u8]) -> Stripped {
    let mut walk = Walk::default();
    let left = |saw_ech: bool| if saw_ech { Stripped::Left } else { Stripped::Clean };
    if walk.message(reply).is_none() || walk.cuts.is_empty() {
        return left(walk.saw_ech);
    }
    walk.rewrite(reply).map_or(Stripped::Left, Stripped::Cut)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::name_at;
    use proptest::prelude::*;

    const ANSWER: usize = 6;
    const AUTHORITY: usize = 8;
    const ADDITIONAL: usize = 10;
    const ECH: &[u8] = &[0xfe, 0x0d, 0, 3, 1, 2, 3];
    const QUESTION_AT: u16 = 12;
    const TYPE_TSIG: u16 = 250;
    const TYPE_NAPTR: u16 = 35;

    fn name(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in text.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn pointer(to: u16) -> Vec<u8> {
        (to | 0xc000).to_be_bytes().to_vec()
    }

    /// A reply to `www.example`, type HTTPS, with AD set, records added in order.
    struct Reply(Vec<u8>);

    impl Reply {
        fn new() -> Self {
            let mut m = vec![0, 7, 0x81, 0xa0, 0, 1, 0, 0, 0, 0, 0, 0];
            m.extend(name("www.example"));
            m.extend_from_slice(&TYPE_HTTPS.to_be_bytes());
            m.extend_from_slice(&[0, 1]);
            Self(m)
        }

        /// Adds a record, returning where its owner begins.
        fn rr(&mut self, section: usize, owner: &[u8], ty: u16, rdata: &[u8]) -> u16 {
            let at = self.0.len() as u16;
            let count = u16_at(&self.0, section).unwrap() + 1;
            self.0[section..section + 2].copy_from_slice(&count.to_be_bytes());
            self.0.extend_from_slice(owner);
            self.0.extend_from_slice(&ty.to_be_bytes());
            self.0.extend_from_slice(&[0, 1, 0, 0, 1, 44]);
            self.0.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            self.0.extend_from_slice(rdata);
            at
        }
    }

    fn service(priority: u16, target: &[u8], params: &[(u16, &[u8])]) -> Vec<u8> {
        let mut out = priority.to_be_bytes().to_vec();
        out.extend_from_slice(target);
        for (key, value) in params {
            out.extend_from_slice(&key.to_be_bytes());
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
        }
        out
    }

    const ALPN: &[u8] = &[2, b'h', b'2'];
    const PORT: &[u8] = &[1, 0xbb];
    const HINT: &[u8] = &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    /// Alpn, port, ech and a hint, with the question as owner.
    fn with_ech() -> Vec<u8> {
        service(1, &[0], &[(1, ALPN), (3, PORT), (PARAM_ECH, ECH), (6, HINT)])
    }

    fn cut(reply: &[u8]) -> Vec<u8> {
        match strip(reply) {
            Stripped::Cut(out) => out,
            other => panic!("not cut: {other:?}"),
        }
    }

    /// Every record as text: owner, type, class, TTL, and rdata with names read
    /// through their pointers.
    fn dump(msg: &[u8]) -> Vec<String> {
        let mut pos = HEADER;
        pos = name_at(msg, pos).unwrap().1 + 4;
        let total = (u16_at(msg, 6).unwrap() + u16_at(msg, 8).unwrap() + u16_at(msg, 10).unwrap()) as usize;
        let mut out = Vec::new();
        for _ in 0..total {
            let (owner, next) = name_at(msg, pos).unwrap();
            let ty = u16_at(msg, next).unwrap();
            let start = next + FIXED;
            let end = start + usize::from(u16_at(msg, next + RDLENGTH_AT).unwrap());
            let text = |at: usize| name_at(msg, at).unwrap();
            let data = match ty {
                TYPE_NS | TYPE_CNAME | TYPE_PTR => text(start).0,
                TYPE_MX => text(start + 2).0,
                TYPE_SOA => {
                    let (first, next) = text(start);
                    format!("{first} {}", text(next).0)
                }
                _ => format!("{:?}", &msg[start..end]),
            };
            out.push(format!("{owner} {ty} {data}"));
            pos = end;
        }
        out
    }

    #[test]
    fn removes_ech_and_keeps_every_other_param_in_order() {
        for ty in [TYPE_HTTPS, TYPE_SVCB] {
            let mut reply = Reply::new();
            reply.rr(ANSWER, &pointer(QUESTION_AT), ty, &with_ech());
            let out = cut(&reply.0);
            let want = service(1, &[0], &[(1, ALPN), (3, PORT), (6, HINT)]);
            let mut expected = Reply::new();
            expected.rr(ANSWER, &pointer(QUESTION_AT), ty, &want);
            expected.0[3] &= !0x20;
            assert_eq!(out, expected.0, "RDLENGTH right, AD cleared, the rest the same bytes");
            assert_eq!(flags_ad(&reply.0), FLAG_AD, "the input had it");
            assert_eq!(flags_ad(&out), 0);
            assert_eq!(strip(&out), Stripped::Clean);
        }
    }

    fn flags_ad(msg: &[u8]) -> u16 {
        u16_at(msg, 2).unwrap() & FLAG_AD
    }

    #[test]
    fn a_reply_without_ech_is_untouched_and_not_copied() {
        let mut reply = Reply::new();
        reply.rr(ANSWER, &pointer(QUESTION_AT), TYPE_HTTPS, &service(1, &[0], &[(1, ALPN)]));
        // `Clean` holds no bytes: nothing was copied, and AD stays by not being touched.
        assert_eq!(strip(&reply.0), Stripped::Clean);
    }

    #[test]
    fn alias_mode_is_untouched() {
        let mut reply = Reply::new();
        reply.rr(ANSWER, &pointer(QUESTION_AT), TYPE_HTTPS, &service(0, &name("target.example"), &[]));
        assert_eq!(strip(&reply.0), Stripped::Clean);
    }

    #[test]
    fn every_record_with_ech_in_any_section_is_stripped() {
        let mut reply = Reply::new();
        for section in [ANSWER, ANSWER, AUTHORITY, ADDITIONAL] {
            reply.rr(section, &pointer(QUESTION_AT), TYPE_HTTPS, &with_ech());
        }
        let before = reply.0.len();
        let out = cut(&reply.0);
        assert_eq!(before - out.len(), 4 * (4 + ECH.len()));
        assert_eq!(strip(&out), Stripped::Clean);
        witness_agrees(&reply.0, &out);
    }

    /// A cut first, then every name-bearing type pointing at a name past the cut.
    fn pointers_past_a_cut() -> Vec<u8> {
        let mut reply = Reply::new();
        reply.rr(ANSWER, &pointer(QUESTION_AT), TYPE_HTTPS, &with_ech());
        let far = reply.rr(ANSWER, &name("far.example"), TYPE_A, &[192, 0, 2, 1]);
        reply.rr(ANSWER, &pointer(far), TYPE_CNAME, &pointer(far));
        reply.rr(ANSWER, &pointer(far), TYPE_HTTPS, &with_ech());
        let later = reply.rr(ANSWER, &name("later.example"), TYPE_A, &[192, 0, 2, 2]);
        // A name that goes on through a pointer past the cuts.
        let mut chained = vec![3];
        chained.extend_from_slice(b"sub");
        chained.extend(pointer(later));
        reply.rr(AUTHORITY, &chained, TYPE_NS, &pointer(later));
        let mut soa = pointer(far);
        soa.extend(pointer(later));
        soa.extend_from_slice(&[0; SOA_NUMBERS]);
        reply.rr(AUTHORITY, &pointer(later), TYPE_SOA, &soa);
        let mut mx = vec![0, 10];
        mx.extend(pointer(later));
        reply.rr(ADDITIONAL, &pointer(far), TYPE_MX, &mx);
        reply.0
    }

    #[test]
    fn pointers_past_a_cut_are_shifted() {
        let reply = pointers_past_a_cut();
        let out = cut(&reply);
        let (before, after) = (dump(&reply), dump(&out));
        let names = |lines: &[String]| lines.iter().map(|l| if l.contains(" 65 ") { l.split('[').next().unwrap().to_string() } else { l.clone() }).collect::<Vec<_>>();
        assert_eq!(names(&after), names(&before), "every name decodes to the same text");
        assert!(after.iter().any(|l| l.starts_with("sub.later.example 2 later.example")), "{after:?}");
        assert!(after.iter().any(|l| l.contains("far.example later.example")), "SOA {after:?}");
        assert!(after.iter().any(|l| l.starts_with("far.example 15 later.example")), "MX {after:?}");
        assert_eq!(strip(&out), Stripped::Clean);
        witness_agrees(&reply, &out);
    }

    #[test]
    fn pointers_before_a_cut_are_unchanged() {
        let mut reply = Reply::new();
        let near = reply.rr(ANSWER, &name("near.example"), TYPE_A, &[192, 0, 2, 1]);
        reply.rr(ANSWER, &pointer(near), TYPE_CNAME, &pointer(QUESTION_AT));
        let cname_at = reply.0.len();
        reply.rr(ANSWER, &pointer(near), TYPE_HTTPS, &with_ech());
        let out = cut(&reply.0);
        assert_eq!(out[HEADER..cname_at], reply.0[HEADER..cname_at]);
        assert_eq!(out[cname_at..cname_at + 2], pointer(near)[..]);
    }

    fn left_cases() -> Vec<(&'static str, Vec<u8>)> {
        let mut cases = Vec::new();
        let mut mandatory = Reply::new();
        mandatory.rr(ANSWER, &pointer(QUESTION_AT), TYPE_HTTPS, &service(1, &[0], &[(PARAM_MANDATORY, &[0, 1, 0, 5]), (1, ALPN), (PARAM_ECH, ECH)]));
        cases.push(("mandatory naming ech", mandatory.0));

        // A name read through a pointer into the ECH value.
        let mut into = Reply::new();
        let at = into.rr(ANSWER, &pointer(QUESTION_AT), TYPE_HTTPS, &service(1, &[0], &[(PARAM_ECH, &[0])]));
        let value = at as usize + 2 + FIXED + 2 + 1 + 4;
        into.rr(ANSWER, &pointer(value as u16), TYPE_A, &[192, 0, 2, 1]);
        cases.push(("a pointer into the cut", into.0));

        let mut descending = Reply::new();
        descending.rr(ANSWER, &pointer(QUESTION_AT), TYPE_HTTPS, &service(1, &[0], &[(PARAM_ECH, ECH), (3, PORT)]));
        cases.push(("descending keys", descending.0));

        let mut past = Reply::new();
        let mut rdata = service(1, &[0], &[(PARAM_ECH, ECH)]);
        let len_at = rdata.len() - ECH.len() - 2;
        rdata[len_at..len_at + 2].copy_from_slice(&((ECH.len() + 1) as u16).to_be_bytes());
        past.rr(ANSWER, &pointer(QUESTION_AT), TYPE_HTTPS, &rdata);
        past.rr(ANSWER, &pointer(QUESTION_AT), TYPE_A, &[192, 0, 2, 1]);
        cases.push(("a param past RDLENGTH", past.0));

        let mut unknown = Reply::new();
        unknown.rr(ANSWER, &pointer(QUESTION_AT), TYPE_HTTPS, &with_ech());
        unknown.rr(ANSWER, &pointer(QUESTION_AT), TYPE_NAPTR, &[0; 8]);
        cases.push(("an unknown type after the cut", unknown.0));

        let mut tsig = Reply::new();
        tsig.rr(ANSWER, &pointer(QUESTION_AT), TYPE_HTTPS, &with_ech());
        tsig.rr(ADDITIONAL, &[0], TYPE_TSIG, &[0; 8]);
        cases.push(("TSIG", tsig.0));
        cases
    }

    #[test]
    fn left_unchanged_byte_for_byte() {
        for (case, reply) in left_cases() {
            assert_eq!(strip(&reply), Stripped::Left, "{case}");
        }
        // A compressed target cannot be read as RFC 9460 says, so it holds no `ech` we saw.
        let mut compressed = Reply::new();
        compressed.rr(ANSWER, &pointer(QUESTION_AT), TYPE_HTTPS, &service(1, &pointer(QUESTION_AT), &[(PARAM_ECH, ECH)]));
        assert_eq!(strip(&compressed.0), Stripped::Clean, "a compressed target");
    }

    #[test]
    fn a_record_of_an_unknown_type_before_the_cut_is_fine() {
        let mut reply = Reply::new();
        reply.rr(ANSWER, &pointer(QUESTION_AT), TYPE_NAPTR, &[0; 8]);
        reply.rr(ANSWER, &pointer(QUESTION_AT), TYPE_HTTPS, &with_ech());
        cut(&reply.0);
    }

    #[test]
    fn a_name_that_runs_across_a_cut_leaves_the_reply_unchanged() {
        // The owner of the second record points at the last param before the ech,
        // whose value reads as a label running into the cut.
        let mut reply = Reply::new();
        let at = reply.rr(ANSWER, &pointer(QUESTION_AT), TYPE_HTTPS, &service(1, &[0], &[(1, &[40]), (PARAM_ECH, ECH)]));
        let label = at as usize + 2 + FIXED + 2 + 1 + 4;
        reply.rr(ANSWER, &pointer(label as u16), TYPE_A, &[192, 0, 2, 1]);
        assert_eq!(strip(&reply.0), Stripped::Left);
    }

    #[test]
    fn a_pointer_chain_through_an_unknown_rdata_leaves_the_reply_unchanged() {
        let mut reply = Reply::new();
        let opaque = reply.rr(ANSWER, &[0], TYPE_NAPTR, &pointer(QUESTION_AT));
        reply.rr(ANSWER, &pointer(QUESTION_AT), TYPE_HTTPS, &with_ech());
        reply.rr(ANSWER, &pointer(opaque + 1 + FIXED as u16), TYPE_A, &[192, 0, 2, 1]);
        assert_eq!(strip(&reply.0), Stripped::Left, "the pointer in there would not be shifted");
    }

    /// The cross-witness (S3): another library decodes the input and the output,
    /// and the only difference is the `ech` parameter.
    fn witness_agrees(reply: &[u8], out: &[u8]) {
        use hickory_proto::op::Message;
        use hickory_proto::rr::rdata::svcb::SvcParamKey;
        use hickory_proto::rr::{RData, Record};
        let without_ech = |records: &mut Vec<Record>| {
            for record in records {
                let svcb = match &mut record.data {
                    RData::HTTPS(https) => &mut https.0,
                    RData::SVCB(svcb) => svcb,
                    _ => continue,
                };
                svcb.svc_params.retain(|(key, _)| *key != SvcParamKey::EchConfigList);
            }
        };
        let mut before = Message::from_vec(reply).expect("the witness reads the input");
        let after = Message::from_vec(out).expect("the witness reads the output");
        let has_ech = |records: &[Record]| records.iter().any(|r| matches!(&r.data, RData::HTTPS(h) if h.0.svc_params.iter().any(|(k, _)| *k == SvcParamKey::EchConfigList)));
        assert!(has_ech(&before.answers), "the input must hold what the law is about");
        without_ech(&mut before.answers);
        without_ech(&mut before.authorities);
        without_ech(&mut before.additionals);
        assert_eq!(after.answers, before.answers);
        assert_eq!(after.authorities, before.authorities);
        assert_eq!(after.additionals, before.additionals);
        assert!(!has_ech(&after.answers) && !has_ech(&after.authorities) && !has_ech(&after.additionals));
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            if let Stripped::Cut(out) = strip(&bytes) {
                prop_assert!(out.len() < bytes.len());
                prop_assert_eq!(strip(&out), Stripped::Clean);
            }
        }

        #[test]
        fn a_damaged_reply_never_panics_and_any_output_walks_clean(at in 0usize..400, byte in any::<u8>()) {
            let mut reply = pointers_past_a_cut();
            let at = at % reply.len();
            reply[at] = byte;
            if let Stripped::Cut(out) = strip(&reply) {
                prop_assert!(out.len() < reply.len());
                prop_assert_eq!(strip(&out), Stripped::Clean);
            }
        }
    }
}
