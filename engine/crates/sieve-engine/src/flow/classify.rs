//! One flow's first client bytes in, one decision-ready answer out.
//!
//! The userspace stack terminates the app's TCP connection, so a TCP flow
//! is classified on its in-order byte stream (chunks as `read` returns
//! them); a UDP flow on its datagrams. Each classifier buffers only until
//! the first ClientHello, QUIC Initial ClientHello or HTTP request head is
//! decoded, or a cap is hit, then answers once ([`Decoded`]) and stops
//! inspecting: later pushes return None without parsing.
//!
//! Caps: TCP keeps at most [`crate::flow::stream::MAX_STREAM_BYTES`] and
//! [`MAX_TCP_CHUNKS`] reads; UDP looks at most at [`MAX_UDP_DATAGRAMS`].
//! A cap, a parse failure or an unknown protocol all end in a `Decoded`
//! with `domain: None` (`crate::domain` then asks the shared IP map) and
//! the reason recorded for the probe's counters.
//!
//! The forwarder never waits on the classifier for server-first protocols:
//! it connects upstream at once and relays server bytes; only client bytes
//! wait (see the report, "forwarder").

use crate::flow::quic::{self, CryptoAssembler};
use crate::flow::stream::MAX_STREAM_BYTES;
use crate::flow::{Progress, http, sni};

pub const MAX_TCP_CHUNKS: u32 = 16;
pub const MAX_UDP_DATAGRAMS: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Tls,
    Quic,
    Http,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Tls => "tls",
            Kind::Quic => "quic",
            Kind::Http => "http",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decoded {
    /// The protocol recognised, if any.
    pub kind: Option<Kind>,
    /// The domain the flow targets, lower case, if read.
    pub domain: Option<String>,
    pub alpn: Vec<String>,
    /// ECH offered: `domain` is the outer (public) name only.
    pub ech: bool,
    /// Why no domain: "not tls/quic/http", "cap", or the parser's reason.
    pub failure: Option<&'static str>,
}

impl Decoded {
    fn from_hello(kind: Kind, h: sni::Hello) -> Self {
        let failure = if h.sni.is_none() { Some("no SNI") } else { None };
        Self { kind: Some(kind), domain: h.sni, alpn: h.alpn, ech: h.ech, failure }
    }

    fn failed(kind: Option<Kind>, why: &'static str) -> Self {
        Self { kind, failure: Some(why), ..Self::default() }
    }
}

/// TCP: client stream bytes in order.
#[derive(Debug, Default)]
pub struct TcpClassifier {
    buf: Vec<u8>,
    chunks: u32,
    done: bool,
}

impl TcpClassifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// True once a decision was returned; nothing is inspected after.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// The client bytes held so far (to forward once the flow passes).
    pub fn held(&self) -> &[u8] {
        &self.buf
    }

    pub fn take_held(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    /// Adds the next chunk of client bytes. Some(decision) exactly once.
    pub fn push(&mut self, bytes: &[u8]) -> Option<Decoded> {
        if self.done || bytes.is_empty() {
            return None;
        }
        self.chunks += 1;
        let room = MAX_STREAM_BYTES.saturating_sub(self.buf.len());
        let over = bytes.len() > room;
        self.buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
        let decided = match sni::parse_tls_stream(&self.buf) {
            Progress::Done(h) => Some(Decoded::from_hello(Kind::Tls, h)),
            Progress::Invalid(why) => Some(Decoded::failed(Some(Kind::Tls), why)),
            Progress::NeedMore => None,
            Progress::NotThis => match http::parse_request(&self.buf) {
                Progress::Done(r) => {
                    Some(Decoded { kind: Some(Kind::Http), domain: Some(r.host), ..Decoded::default() })
                }
                Progress::Invalid(why) => Some(Decoded::failed(Some(Kind::Http), why)),
                Progress::NeedMore => None,
                Progress::NotThis => Some(Decoded::failed(None, "not tls/quic/http")),
            },
        };
        let decided = decided.or_else(|| {
            (over || self.chunks >= MAX_TCP_CHUNKS || self.buf.len() >= MAX_STREAM_BYTES)
                .then(|| Decoded::failed(None, "cap"))
        });
        if decided.is_some() {
            self.done = true;
        }
        decided
    }
}

/// UDP: client datagrams in arrival order.
#[derive(Debug, Default)]
pub struct UdpClassifier {
    asm: CryptoAssembler,
    datagrams: u32,
    done: bool,
}

impl UdpClassifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Adds the next client datagram. Some(decision) exactly once.
    pub fn push(&mut self, datagram: &[u8]) -> Option<Decoded> {
        if self.done {
            return None;
        }
        self.datagrams += 1;
        let decided = match quic::push_datagram(&mut self.asm, datagram) {
            Progress::Done(h) => Some(Decoded::from_hello(Kind::Quic, h)),
            Progress::Invalid(why) => Some(Decoded::failed(Some(Kind::Quic), why)),
            // The first datagram of a QUIC flow is always a long-header
            // Initial; anything else first is not QUIC.
            Progress::NotThis if self.datagrams == 1 => Some(Decoded::failed(None, "not tls/quic/http")),
            Progress::NotThis | Progress::NeedMore => None,
        };
        let decided = decided.or_else(|| (self.datagrams >= MAX_UDP_DATAGRAMS).then(|| Decoded::failed(Some(Kind::Quic), "cap")));
        if decided.is_some() {
            self.done = true;
            self.asm = CryptoAssembler::new(); // free the buffer
        }
        decided
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::quic::{VERSION_1, crypto_frame, seal_client_initial};
    use crate::flow::sni::build;
    use proptest::prelude::*;

    #[test]
    fn tls_hello_in_chunks_decides_once_with_the_domain() {
        let stream = build::typical("chunks.example");
        let mut c = TcpClassifier::new();
        let mut decisions = Vec::new();
        for chunk in stream.chunks(400) {
            if let Some(d) = c.push(chunk) {
                decisions.push(d);
            }
        }
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].kind, Some(Kind::Tls));
        assert_eq!(decisions[0].domain.as_deref(), Some("chunks.example"));
        assert_eq!(decisions[0].alpn, vec!["h2", "http/1.1"]);
        assert!(c.is_done());
        assert_eq!(c.push(b"application data"), None);
        assert_eq!(c.held(), &stream[..]);
    }

    #[test]
    fn http_request_gives_host() {
        let mut c = TcpClassifier::new();
        assert_eq!(c.push(b"GET / HTTP/1.1\r\nHo"), None);
        let d = c.push(b"st: plain.example\r\n\r\n").unwrap();
        assert_eq!((d.kind, d.domain.as_deref()), (Some(Kind::Http), Some("plain.example")));
    }

    #[test]
    fn other_protocols_decide_at_once_with_no_domain() {
        let mut c = TcpClassifier::new();
        let d = c.push(b"SSH-2.0-OpenSSH_9.6\r\n").unwrap();
        assert_eq!(d, Decoded::failed(None, "not tls/quic/http"));
    }

    #[test]
    fn ech_and_missing_sni_are_reported() {
        let mut c = TcpClassifier::new();
        let msg = build::handshake(&[build::sni_ext("public.example"), build::ech_ext()]);
        let d = c.push(&build::records(&msg, 16_384)).unwrap();
        assert!(d.ech);
        assert_eq!(d.domain.as_deref(), Some("public.example"));
        let mut c = TcpClassifier::new();
        let d = c.push(&build::records(&build::handshake(&[]), 16_384)).unwrap();
        assert_eq!((d.domain, d.failure), (None, Some("no SNI")));
    }

    #[test]
    fn tcp_caps_end_inspection() {
        // A hello that announces a big record but trickles one byte at a time.
        let mut c = TcpClassifier::new();
        let mut last = None;
        for b in build::typical("slow.example").iter().take(MAX_TCP_CHUNKS as usize) {
            last = c.push(&[*b]);
        }
        assert_eq!(last, Some(Decoded::failed(None, "cap")));
        // One oversized chunk.
        let mut c = TcpClassifier::new();
        let mut big = vec![22u8, 3, 1, 0x40, 0x00, 1, 0, 0x3f, 0xfc];
        big.resize(MAX_STREAM_BYTES + 100, 0);
        assert!(c.push(&big).is_some());
        assert!(c.held().len() <= MAX_STREAM_BYTES);
    }

    #[test]
    fn quic_split_over_two_datagrams_decides_on_the_second() {
        let dcid = [9u8; 8];
        let hello = build::handshake(&[build::sni_ext("h3.example"), build::alpn_ext(&["h3"]), (0x0033, vec![1; 1300])]);
        let (a, b) = hello.split_at(800);
        let mut f1 = crypto_frame(0, a);
        f1.resize(1100, 0);
        let mut f2 = crypto_frame(800, b);
        f2.resize(1100, 0);
        let d1 = seal_client_initial(VERSION_1, &dcid, &[], 0, 1, &f1);
        let d2 = seal_client_initial(VERSION_1, &dcid, &[], 1, 1, &f2);
        let mut c = UdpClassifier::new();
        assert_eq!(c.push(&d1), None);
        let d = c.push(&d2).unwrap();
        assert_eq!((d.kind, d.domain.as_deref()), (Some(Kind::Quic), Some("h3.example")));
        assert_eq!(d.alpn, vec!["h3"]);
        assert_eq!(c.push(&d1), None);
    }

    #[test]
    fn non_quic_udp_decides_on_the_first_datagram() {
        let mut c = UdpClassifier::new();
        assert_eq!(c.push(&[0x40, 1, 2, 3]), Some(Decoded::failed(None, "not tls/quic/http")));
    }

    #[test]
    fn quic_that_never_completes_hits_the_datagram_cap() {
        let dcid = [3u8; 8];
        let hello = build::handshake(&[build::sni_ext("never.example"), (0x0033, vec![1; 2000])]);
        let mut f = crypto_frame(0, &hello[..500]);
        f.resize(1100, 0);
        let d = seal_client_initial(VERSION_1, &dcid, &[], 0, 1, &f);
        let mut c = UdpClassifier::new();
        let mut got = None;
        for _ in 0..MAX_UDP_DATAGRAMS {
            got = c.push(&d);
        }
        assert_eq!(got, Some(Decoded::failed(Some(Kind::Quic), "cap")));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn arbitrary_chunks_decide_at_most_once_and_never_panic(
            chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..600), 0..24)
        ) {
            let mut t = TcpClassifier::new();
            let mut u = UdpClassifier::new();
            let (mut nt, mut nu) = (0, 0);
            for c in &chunks {
                nt += usize::from(t.push(c).is_some());
                nu += usize::from(u.push(c).is_some());
            }
            prop_assert!(nt <= 1 && nu <= 1);
            prop_assert!(t.held().len() <= MAX_STREAM_BYTES);
        }
    }
}
