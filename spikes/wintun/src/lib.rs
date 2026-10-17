//! Spike: can Sieve tell, per connection, which app opened it and which
//! domain it targets, and drop it only for apps that are not exempt? The
//! packets come from a Wintun TUN adapter (see the report).
//!
//! Pure, offline-tested pieces (no driver, no admin):
//! - [`sni`]: TLS ClientHello (records over a TCP stream) to SNI, ALPN, ECH.
//! - [`quic`]: QUIC v1 and v2 client Initial decryption and CRYPTO
//!   reassembly, then the same ClientHello parser.
//! - [`http`]: plaintext HTTP/1 request to Host.
//! - [`stream`]: per-flow TCP payload reassembly with a size cap.
//! - [`packet`]: IPv4/IPv6 + TCP/UDP header parsing of a raw IP packet.
//! - [`rules`]: the DNS filter's rule syntax and suffix-set matcher (copied).
//! - [`flows`]: flow -> pid from the IP Helper owner-pid tables, pid -> exe,
//!   and the pure per-app verdict.
//! - [`classify`]: one flow's first client bytes in, one decision out.
pub mod classify;
pub mod flows;
pub mod http;
pub mod packet;
pub mod probe_support;
pub mod quic;
pub mod rules;
pub mod sni;
pub mod stream;

/// The answer of an incremental parser that is fed bytes as they arrive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress<T> {
    /// The thing was parsed.
    Done(T),
    /// The bytes so far are a valid prefix; feed more.
    NeedMore,
    /// The bytes are not this protocol at all (wrong first byte, etc.).
    NotThis,
    /// The bytes claim to be this protocol but are malformed.
    Invalid(&'static str),
}

impl<T> Progress<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Progress<U> {
        match self {
            Progress::Done(t) => Progress::Done(f(t)),
            Progress::NeedMore => Progress::NeedMore,
            Progress::NotThis => Progress::NotThis,
            Progress::Invalid(why) => Progress::Invalid(why),
        }
    }
}

/// A big-endian cursor over a byte slice. Every read is bounds checked and
/// returns None past the end, so parsers built on it cannot panic on input.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u24(&mut self) -> Option<u32> {
        self.bytes(3).map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.bytes(4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A length-prefixed block: `len_bytes` (1, 2 or 3) of big-endian length,
    /// then that many bytes.
    pub fn vec(&mut self, len_bytes: usize) -> Option<&'a [u8]> {
        let n = match len_bytes {
            1 => usize::from(self.u8()?),
            2 => usize::from(self.u16()?),
            3 => self.u24()? as usize,
            _ => return None,
        };
        self.bytes(n)
    }

    /// A QUIC variable-length integer (RFC 9000 section 16).
    pub fn varint(&mut self) -> Option<u64> {
        let first = self.u8()?;
        let len = 1usize << (first >> 6);
        let mut v = u64::from(first & 0x3f);
        for b in self.bytes(len - 1)? {
            v = (v << 8) | u64::from(*b);
        }
        Some(v)
    }
}

/// Lower-case hex decoding for test vectors and CLI input. Whitespace is
/// skipped; any other non-hex character or an odd count is an error.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks_exact(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16)?;
            let lo = (p[1] as char).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_examples_from_rfc9000_appendix_a1() {
        let cases: [(&str, u64); 4] = [
            ("c2197c5eff14e88c", 151_288_809_941_952_652),
            ("9d7f3e7d", 494_878_333),
            ("7bbd", 15_293),
            ("25", 37),
        ];
        for (hex, want) in cases {
            let bytes = hex_decode(hex).unwrap();
            let mut r = Reader::new(&bytes);
            assert_eq!(r.varint(), Some(want), "{hex}");
            assert!(r.is_empty());
        }
        // The two-byte encoding of 37 is also valid.
        let bytes = hex_decode("4025").unwrap();
        assert_eq!(Reader::new(&bytes).varint(), Some(37));
    }

    #[test]
    fn reader_never_reads_past_the_end() {
        let mut r = Reader::new(&[0x40]);
        assert_eq!(r.varint(), None);
        let mut r = Reader::new(&[0x00, 0x05, 1, 2]);
        assert_eq!(r.vec(2), None);
        assert_eq!(Reader::new(&[]).u8(), None);
        assert_eq!(Reader::new(&[1, 2]).bytes(usize::MAX), None);
    }

    #[test]
    fn hex_decode_rejects_odd_and_non_hex() {
        assert_eq!(hex_decode("0a ff"), Some(vec![0x0a, 0xff]));
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
    }
}
