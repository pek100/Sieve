//! Per-flow TCP payload reassembly for the first bytes of a connection.
//!
//! Only the start of the client's byte stream matters (the ClientHello or
//! the HTTP request head), so a flow keeps at most [`MAX_STREAM_BYTES`]
//! bytes. Segments are placed by sequence number relative to the first
//! payload segment seen: retransmits and overlaps are absorbed, an
//! out-of-order segment waits (bounded) until the gap before it fills.
//!
//! Limitation (spike): the base is the first *payload* segment observed.
//! If the very first segment is lost before capture and a later one is
//! seen first, the stream starts mid-hello and parses as `Invalid` or
//! `NotThis`; the decode-failure counter of the probe shows how often.

use std::collections::BTreeMap;

/// Most bytes kept per flow: the ClientHello cap plus record headers.
pub const MAX_STREAM_BYTES: usize = crate::flow::sni::MAX_HELLO_LEN + 4 + 5 * 4;

/// Most out-of-order segments held per flow.
const MAX_PENDING: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Push {
    /// The contiguous prefix grew (or stayed the same for a retransmit).
    Ok,
    /// The flow wants more than the cap; give up on it.
    Overflow,
}

#[derive(Debug, Clone, Default)]
pub struct StreamBuf {
    base: Option<u32>,
    data: Vec<u8>,
    pending: BTreeMap<u32, Vec<u8>>,
}

impl StreamBuf {
    pub fn new() -> Self {
        Self::default()
    }

    /// The contiguous bytes from the start.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Adds a segment with TCP sequence number `seq`.
    pub fn push(&mut self, seq: u32, payload: &[u8]) -> Push {
        if payload.is_empty() {
            return Push::Ok;
        }
        let base = *self.base.get_or_insert(seq);
        // Offset in wrapping sequence space; anything "before" the base
        // (offset in the upper half) is an old retransmit.
        let offset = seq.wrapping_sub(base);
        if offset >= 1 << 31 {
            return Push::Ok;
        }
        let offset = offset as usize;
        if offset > MAX_STREAM_BYTES {
            return Push::Overflow;
        }
        if offset > self.data.len() {
            if self.pending.len() >= MAX_PENDING {
                return Push::Overflow;
            }
            self.pending.insert(offset as u32, payload.to_vec());
            return Push::Ok;
        }
        if self.append_at(offset, payload) == Push::Overflow {
            return Push::Overflow;
        }
        // Drain pending segments that now touch the prefix.
        while let Some((&at, _)) = self.pending.iter().next() {
            if at as usize > self.data.len() {
                break;
            }
            let seg = self.pending.remove(&at).unwrap_or_default();
            if self.append_at(at as usize, &seg) == Push::Overflow {
                return Push::Overflow;
            }
        }
        Push::Ok
    }

    fn append_at(&mut self, offset: usize, payload: &[u8]) -> Push {
        let have = self.data.len();
        let skip = have - offset;
        if skip >= payload.len() {
            return Push::Ok;
        }
        let new = &payload[skip..];
        if have + new.len() > MAX_STREAM_BYTES {
            return Push::Overflow;
        }
        self.data.extend_from_slice(new);
        Push::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn in_order_segments_concatenate() {
        let mut s = StreamBuf::new();
        s.push(1000, b"hello ");
        s.push(1006, b"world");
        assert_eq!(s.bytes(), b"hello world");
    }

    #[test]
    fn retransmits_and_overlaps_are_absorbed() {
        let mut s = StreamBuf::new();
        s.push(10, b"abcd");
        s.push(10, b"abcd");
        s.push(12, b"cdef");
        s.push(5, b"zzzzz"); // before the base: old data
        assert_eq!(s.bytes(), b"abcdef");
    }

    #[test]
    fn out_of_order_segment_waits_for_the_gap() {
        let mut s = StreamBuf::new();
        s.push(0, b"ab");
        s.push(4, b"ef");
        assert_eq!(s.bytes(), b"ab");
        s.push(2, b"cd");
        assert_eq!(s.bytes(), b"abcdef");
    }

    #[test]
    fn sequence_wraparound_is_handled() {
        let mut s = StreamBuf::new();
        s.push(u32::MAX - 1, b"ab");
        s.push(0, b"cd");
        assert_eq!(s.bytes(), b"abcd");
    }

    #[test]
    fn cap_is_enforced() {
        let mut s = StreamBuf::new();
        assert_eq!(s.push(0, &vec![0; MAX_STREAM_BYTES]), Push::Ok);
        assert_eq!(s.push(MAX_STREAM_BYTES as u32, b"x"), Push::Overflow);
        let mut s = StreamBuf::new();
        s.push(0, b"a");
        assert_eq!(s.push(MAX_STREAM_BYTES as u32 + 10, b"x"), Push::Overflow);
        let mut s = StreamBuf::new();
        s.push(0, b"a");
        for i in 0..MAX_PENDING as u32 {
            assert_eq!(s.push(10 + i * 2, b"x"), Push::Ok);
        }
        assert_eq!(s.push(100, b"x"), Push::Overflow);
    }

    proptest! {
        #[test]
        fn any_segmentation_and_order_rebuilds_the_stream(
            data in proptest::collection::vec(any::<u8>(), 1..3000),
            cuts in proptest::collection::vec(1usize..300, 1..12),
            seed in any::<u64>(),
            isn in any::<u32>(),
        ) {
            let mut segs = Vec::new();
            let mut at = 0usize;
            for c in cuts {
                if at >= data.len() { break; }
                let end = (at + c).min(data.len());
                segs.push((at, end));
                at = end;
            }
            if at < data.len() { segs.push((at, data.len())); }
            // The first segment arrives first (it sets the base); the rest shuffle.
            let mut s = seed | 1;
            for i in (2..segs.len()).rev() {
                s ^= s << 13; s ^= s >> 7; s ^= s << 17;
                let j = 1 + (s % i as u64) as usize;
                segs.swap(i, j);
            }
            let mut buf = StreamBuf::new();
            for (a, b) in &segs {
                prop_assert_eq!(buf.push(isn.wrapping_add(*a as u32), &data[*a..*b]), Push::Ok);
            }
            prop_assert_eq!(buf.bytes(), &data[..]);
        }
    }
}
