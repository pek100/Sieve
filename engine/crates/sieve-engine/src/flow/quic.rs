//! QUIC client Initial decoding: the domain of an HTTP/3 connection.
//!
//! The user's decision for QUIC (UDP 443) is "decode it, don't block": read
//! the SNI out of the client's Initial packets and give the flow the same
//! per-domain verdict as TLS over TCP. QUIC is never dropped wholesale.
//!
//! Client Initial packets are encrypted, but with keys anyone can derive
//! (RFC 9001 section 5.2): HKDF-Extract(version salt, client Destination
//! Connection ID), then HKDF-Expand-Label "client in", then "quic key",
//! "quic iv", "quic hp" (v1) or "quicv2 key", "quicv2 iv", "quicv2 hp"
//! (v2, RFC 9369 section 3.3). Steps per packet:
//! 1. parse the long header up to the Length field (RFC 9000 section 17.2);
//! 2. remove header protection: AES-128-ECB(hp, 16-byte sample starting 4
//!    bytes after the packet number offset) masks the low 4 bits of the
//!    first byte and the packet number bytes (RFC 9001 section 5.4);
//! 3. AES-128-GCM open the payload with nonce = iv XOR packet number and
//!    the unprotected header as associated data (RFC 9001 section 5.3);
//! 4. read frames: only PADDING, PING, ACK, CRYPTO and CONNECTION_CLOSE are
//!    allowed in Initial packets; CRYPTO frames carry (offset, bytes) of the
//!    TLS handshake stream, in any order (Chrome shuffles them on purpose)
//!    and possibly across several Initial packets and datagrams.
//!
//! A datagram may coalesce several packets (Initial then 0-RTT, or
//! Handshake): each long-header packet's Length says where the next one
//! starts; non-Initial packets are skipped, a short-header packet ends the
//! datagram. [`CryptoAssembler`] puts the CRYPTO stream back together and
//! hands the first handshake message to [`crate::flow::sni::parse_handshake`].
//!
//! The packet number used for the nonce is the truncated one as sent. That
//! is exact for a client's first Initials (numbers start at 0 and stay far
//! below the 1-byte window); full reconstruction (RFC 9000 appendix A.3)
//! needs the largest acknowledged number, which only the endpoint knows.
//!
//! Keys come from each packet's own DCID. The ClientHello is complete
//! before the server can answer, so every Initial carrying it uses the
//! client's original DCID (or, after a Retry, the new one, which also keys
//! its Initials).

use std::collections::BTreeMap;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, Payload};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::flow::sni::{self, Hello, MAX_HELLO_LEN};
use crate::flow::{Progress, Reader};

pub const VERSION_1: u32 = 0x0000_0001;
pub const VERSION_2: u32 = 0x6b33_43cf;

/// Per-version constants.
struct Version {
    salt: [u8; 20],
    key_label: &'static [u8],
    iv_label: &'static [u8],
    hp_label: &'static [u8],
    /// The long-header packet type bits (first byte bits 5..4) of Initial.
    initial_type: u8,
    /// Retry has no Length field, so a coalesced walk must stop at it.
    retry_type: u8,
}

const V1: Version = Version {
    salt: [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb,
        0x7f, 0x0a,
    ],
    key_label: b"quic key",
    iv_label: b"quic iv",
    hp_label: b"quic hp",
    initial_type: 0b00,
    retry_type: 0b11,
};

const V2: Version = Version {
    salt: [
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd,
        0x2e, 0xd9,
    ],
    key_label: b"quicv2 key",
    iv_label: b"quicv2 iv",
    hp_label: b"quicv2 hp",
    initial_type: 0b01,
    retry_type: 0b00,
};

fn version(v: u32) -> Option<&'static Version> {
    match v {
        VERSION_1 => Some(&V1),
        VERSION_2 => Some(&V2),
        _ => None,
    }
}

/// True for the versions this module can open.
pub fn is_supported_version(v: u32) -> bool {
    version(v).is_some()
}

/// Client Initial packet protection keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

/// HKDF-Expand-Label (RFC 8446 section 7.1) with an empty context.
fn expand_label(prk: &Hkdf<Sha256>, label: &[u8], out: &mut [u8]) {
    let mut info = Vec::with_capacity(4 + 6 + label.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    // Output lengths here are 12 to 32 bytes, far below 255 * 32.
    prk.expand(&info, out).expect("HKDF output length within limit");
}

/// The client's Initial keys for `version` and the client-chosen DCID.
pub fn client_initial_keys(ver: u32, dcid: &[u8]) -> Option<Keys> {
    let v = version(ver)?;
    let initial = Hkdf::<Sha256>::new(Some(&v.salt), dcid);
    let mut client_secret = [0u8; 32];
    expand_label(&initial, b"client in", &mut client_secret);
    let client = Hkdf::<Sha256>::from_prk(&client_secret).ok()?;
    let mut keys = Keys { key: [0; 16], iv: [0; 12], hp: [0; 16] };
    expand_label(&client, v.key_label, &mut keys.key);
    expand_label(&client, v.iv_label, &mut keys.iv);
    expand_label(&client, v.hp_label, &mut keys.hp);
    Some(keys)
}

fn hp_mask(hp: &[u8; 16], sample: &[u8]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(hp));
    let mut block = GenericArray::clone_from_slice(sample);
    cipher.encrypt_block(&mut block);
    block.into()
}

fn nonce(iv: &[u8; 12], pn: u64) -> [u8; 12] {
    let mut n = *iv;
    for (i, b) in pn.to_be_bytes().iter().enumerate() {
        n[4 + i] ^= b;
    }
    n
}

/// One opened client Initial packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Initial {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub packet_number: u64,
    /// CRYPTO frames as (stream offset, bytes), in packet order.
    pub crypto: Vec<(u64, Vec<u8>)>,
}

/// Opens every client Initial in a UDP datagram.
///
/// `NotThis`: not a QUIC long-header packet of a supported version (short
/// header, version negotiation, unknown version, too short to be QUIC).
/// `Invalid`: looks like a supported Initial but does not open (bad length,
/// failed authentication, forbidden frame). `Done`: at least one Initial
/// opened (other coalesced packets are skipped).
pub fn open_datagram(datagram: &[u8]) -> Progress<Vec<Initial>> {
    let mut out = Vec::new();
    let mut rest = datagram;
    while let Some(&first) = rest.first() {
        if first & 0x80 == 0 {
            break; // short header: always last in a datagram
        }
        let ver = match rest.get(1..5) {
            Some(b) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            None => break,
        };
        let Some(v) = version(ver) else {
            if out.is_empty() {
                return Progress::NotThis;
            }
            break;
        };
        let packet_type = (first >> 4) & 0b11;
        if packet_type == v.retry_type {
            break;
        }
        let consumed = match open_one(rest, ver, packet_type == v.initial_type) {
            Ok((len, Some(initial))) => {
                out.push(initial);
                len
            }
            Ok((len, None)) => len,
            Err(why) => {
                if out.is_empty() {
                    return Progress::Invalid(why);
                }
                break;
            }
        };
        rest = &rest[consumed..];
    }
    if out.is_empty() { Progress::NotThis } else { Progress::Done(out) }
}

/// Opens one long-header packet at the start of `pkt`. Returns the bytes it
/// spans and, for an Initial, its contents.
fn open_one(pkt: &[u8], ver: u32, is_initial: bool) -> Result<(usize, Option<Initial>), &'static str> {
    let mut r = Reader::new(pkt);
    r.bytes(5).ok_or("short header")?;
    let dcid = r.vec(1).ok_or("short dcid")?;
    if dcid.len() > 20 {
        return Err("dcid longer than 20");
    }
    let scid = r.vec(1).ok_or("short scid")?;
    if scid.len() > 20 {
        return Err("scid longer than 20");
    }
    if is_initial {
        let token_len = r.varint().ok_or("short token length")?;
        r.bytes(usize::try_from(token_len).map_err(|_| "token length")?).ok_or("token past end")?;
    }
    let length = usize::try_from(r.varint().ok_or("short length")?).map_err(|_| "length")?;
    let pn_offset = r.pos();
    let end = pn_offset.checked_add(length).ok_or("length overflow")?;
    if end > pkt.len() {
        return Err("length past end of datagram");
    }
    if !is_initial {
        return Ok((end, None));
    }
    // Header protection sample: 16 bytes starting 4 after pn_offset.
    if length < 4 + 16 {
        return Err("packet too short to sample");
    }
    let keys = client_initial_keys(ver, dcid).ok_or("no keys")?;
    let mask = hp_mask(&keys.hp, &pkt[pn_offset + 4..pn_offset + 20]);
    let first = pkt[0] ^ (mask[0] & 0x0f);
    let pn_len = usize::from(first & 0x03) + 1;
    let mut header = pkt[..pn_offset + pn_len].to_vec();
    header[0] = first;
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | u64::from(header[pn_offset + i]);
    }
    let sealed = &pkt[pn_offset + pn_len..end];
    if sealed.len() < 16 {
        return Err("no room for the tag");
    }
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
    let n = nonce(&keys.iv, pn);
    let plain = cipher
        .decrypt(GenericArray::from_slice(&n), Payload { msg: sealed, aad: &header })
        .map_err(|_| "authentication failed")?;
    let crypto = crypto_frames(&plain)?;
    Ok((end, Some(Initial { version: ver, dcid: dcid.to_vec(), packet_number: pn, crypto })))
}

/// The CRYPTO frames of a decrypted Initial payload.
fn crypto_frames(payload: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, &'static str> {
    let mut r = Reader::new(payload);
    let mut out = Vec::new();
    while !r.is_empty() {
        let kind = r.varint().ok_or("short frame type")?;
        match kind {
            0x00 | 0x01 => {} // PADDING, PING
            0x02 | 0x03 => {
                // ACK: largest, delay, range count, first range, ranges, [ECN].
                r.varint().ok_or("short ack")?;
                r.varint().ok_or("short ack")?;
                let ranges = r.varint().ok_or("short ack")?;
                r.varint().ok_or("short ack")?;
                for _ in 0..ranges {
                    r.varint().ok_or("short ack range")?;
                    r.varint().ok_or("short ack range")?;
                }
                if kind == 0x03 {
                    for _ in 0..3 {
                        r.varint().ok_or("short ack ecn")?;
                    }
                }
            }
            0x06 => {
                let offset = r.varint().ok_or("short crypto offset")?;
                let len = usize::try_from(r.varint().ok_or("short crypto length")?).map_err(|_| "crypto length")?;
                let data = r.bytes(len).ok_or("crypto past end")?;
                out.push((offset, data.to_vec()));
            }
            0x1c => {
                r.varint().ok_or("short close")?;
                r.varint().ok_or("short close")?;
                let reason = usize::try_from(r.varint().ok_or("short close")?).map_err(|_| "close reason")?;
                r.bytes(reason).ok_or("close reason past end")?;
            }
            _ => return Err("frame type not allowed in Initial"),
        }
    }
    Ok(out)
}

/// Rebuilds the CRYPTO stream from fragments in any order and parses the
/// ClientHello once its bytes from offset 0 are all present.
#[derive(Debug, Default, Clone)]
pub struct CryptoAssembler {
    fragments: BTreeMap<u64, Vec<u8>>,
    buffered: usize,
}

/// Bytes of CRYPTO stream we will hold per flow: the ClientHello cap plus
/// its 4-byte handshake header.
pub const MAX_CRYPTO_BYTES: usize = MAX_HELLO_LEN + 4;

impl CryptoAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one fragment. Duplicates and overlaps are fine (retransmits).
    pub fn push(&mut self, offset: u64, data: &[u8]) -> Result<(), &'static str> {
        let end = offset.checked_add(data.len() as u64).ok_or("offset overflow")?;
        if end > MAX_CRYPTO_BYTES as u64 {
            return Err("crypto stream beyond the cap");
        }
        if data.is_empty() {
            return Ok(());
        }
        let keep = self.fragments.get(&offset).is_none_or(|old| old.len() < data.len());
        if keep {
            let old = self.fragments.insert(offset, data.to_vec()).map_or(0, |o| o.len());
            self.buffered = self.buffered - old + data.len();
        }
        if self.buffered > 2 * MAX_CRYPTO_BYTES {
            return Err("too many overlapping crypto fragments");
        }
        Ok(())
    }

    /// The stream bytes contiguous from offset 0.
    pub fn contiguous(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for (&offset, data) in &self.fragments {
            let have = out.len() as u64;
            if offset > have {
                break;
            }
            let skip = (have - offset) as usize;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
            }
        }
        out
    }

    /// The ClientHello if the stream so far holds all of it.
    pub fn hello(&self) -> Progress<Hello> {
        sni::parse_handshake(&self.contiguous())
    }
}

/// Feeds one client datagram of a flow into `asm`; the flow's verdict comes
/// from the ClientHello once complete.
pub fn push_datagram(asm: &mut CryptoAssembler, datagram: &[u8]) -> Progress<Hello> {
    match open_datagram(datagram) {
        Progress::Done(initials) => {
            for initial in initials {
                for (offset, data) in initial.crypto {
                    if let Err(why) = asm.push(offset, &data) {
                        return Progress::Invalid(why);
                    }
                }
            }
            asm.hello()
        }
        Progress::NeedMore => Progress::NeedMore,
        Progress::NotThis => Progress::NotThis,
        Progress::Invalid(why) => Progress::Invalid(why),
    }
}

/// Builds and protects a client Initial (the inverse of [`open_datagram`])
/// for tests and the benchmark. `payload` is the frames; the Length field is
/// always encoded in 2 bytes, as in the RFC samples.
pub fn seal_client_initial(ver: u32, dcid: &[u8], scid: &[u8], pn: u32, pn_len: usize, payload: &[u8]) -> Vec<u8> {
    let v = version(ver).expect("supported version");
    let keys = client_initial_keys(ver, dcid).expect("keys");
    let pn_len = pn_len.clamp(1, 4);
    let mut header = vec![0xc0 | (v.initial_type << 4) | (pn_len as u8 - 1)];
    header.extend_from_slice(&ver.to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(scid.len() as u8);
    header.extend_from_slice(scid);
    header.push(0); // token length
    let length = (pn_len + payload.len() + 16) as u16;
    header.extend_from_slice(&(0x4000 | length).to_be_bytes());
    let pn_offset = header.len();
    header.extend_from_slice(&pn.to_be_bytes()[4 - pn_len..]);

    let cipher = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
    let n = nonce(&keys.iv, u64::from(pn));
    let sealed = cipher
        .encrypt(GenericArray::from_slice(&n), Payload { msg: payload, aad: &header })
        .expect("seal");
    let mut pkt = header;
    pkt.extend_from_slice(&sealed);
    let mask = hp_mask(&keys.hp, &pkt[pn_offset + 4..pn_offset + 20]);
    pkt[0] ^= mask[0] & 0x0f;
    for i in 0..pn_len {
        pkt[pn_offset + i] ^= mask[1 + i];
    }
    pkt
}

/// A CRYPTO frame (type 0x06) with 4-byte varint offset and length.
pub fn crypto_frame(offset: u32, data: &[u8]) -> Vec<u8> {
    let mut f = vec![0x06];
    f.extend_from_slice(&(0x8000_0000 | offset).to_be_bytes());
    f.extend_from_slice(&(0x8000_0000 | data.len() as u32).to_be_bytes());
    f.extend_from_slice(data);
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::hex_decode;
    use crate::flow::sni::build;
    use proptest::prelude::*;

    const DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    fn vector(text: &str) -> Vec<u8> {
        hex_decode(text).expect("test vector hex")
    }

    fn rfc9001_packet() -> Vec<u8> {
        vector(include_str!("../../testdata/rfc9001-a2-client-initial.hex"))
    }
    fn rfc9369_packet() -> Vec<u8> {
        vector(include_str!("../../testdata/rfc9369-a2-client-initial.hex"))
    }
    /// The CRYPTO frame both RFC samples carry (06 00 40f1 then the hello).
    fn rfc_crypto_frame() -> Vec<u8> {
        let a = vector(include_str!("../../testdata/rfc9001-a2-crypto-frame.hex"));
        let b = vector(include_str!("../../testdata/rfc9369-a2-crypto-frame.hex"));
        assert_eq!(a, b, "both RFCs use the same ClientHello");
        a
    }
    /// The RFC payload: the CRYPTO frame padded to 1162 bytes.
    fn rfc_payload() -> Vec<u8> {
        let mut p = rfc_crypto_frame();
        p.resize(1162, 0);
        p
    }

    #[test]
    fn rfc9001_a1_client_keys() {
        let k = client_initial_keys(VERSION_1, &DCID).unwrap();
        assert_eq!(k.key.to_vec(), vector("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(k.iv.to_vec(), vector("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(k.hp.to_vec(), vector("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn rfc9369_a1_client_keys() {
        let k = client_initial_keys(VERSION_2, &DCID).unwrap();
        assert_eq!(k.key.to_vec(), vector("8b1a0bc121284290a29e0971b5cd045d"));
        assert_eq!(k.iv.to_vec(), vector("91f73e2351d8fa91660e909f"));
        assert_eq!(k.hp.to_vec(), vector("45b95e15235d6f45a6b19cbcb0294ba9"));
    }

    #[test]
    fn rfc9001_a2_hp_mask() {
        let k = client_initial_keys(VERSION_1, &DCID).unwrap();
        let mask = hp_mask(&k.hp, &vector("d1b1c98dd7689fb8ec11d242b123dc9b"));
        assert_eq!(mask[..5].to_vec(), vector("437b9aec36"));
    }

    fn check_rfc_sample(packet: &[u8], ver: u32) {
        assert_eq!(packet.len(), 1200);
        let Progress::Done(initials) = open_datagram(packet) else { panic!("did not open") };
        assert_eq!(initials.len(), 1);
        let i = &initials[0];
        assert_eq!(i.version, ver);
        assert_eq!(i.dcid, DCID);
        assert_eq!(i.packet_number, 2);
        let frame = rfc_crypto_frame();
        assert_eq!(i.crypto, vec![(0, frame[4..].to_vec())]);
        let mut asm = CryptoAssembler::new();
        let Progress::Done(hello) = push_datagram(&mut asm, packet) else { panic!("no hello") };
        assert_eq!(hello.sni.as_deref(), Some("example.com"));
        assert_eq!(hello.alpn, vec!["alpn"]);
        assert!(!hello.ech);
    }

    #[test]
    fn rfc9001_a2_client_initial_decrypts_to_the_client_hello() {
        check_rfc_sample(&rfc9001_packet(), VERSION_1);
    }

    #[test]
    fn rfc9369_a2_client_initial_decrypts_to_the_client_hello() {
        check_rfc_sample(&rfc9369_packet(), VERSION_2);
    }

    #[test]
    fn sealing_the_rfc_payload_reproduces_the_rfc_packets_byte_for_byte() {
        let p = rfc_payload();
        assert_eq!(seal_client_initial(VERSION_1, &DCID, &[], 2, 4, &p), rfc9001_packet());
        assert_eq!(seal_client_initial(VERSION_2, &DCID, &[], 2, 4, &p), rfc9369_packet());
    }

    fn padded(mut frames: Vec<u8>, to: usize) -> Vec<u8> {
        if frames.len() < to {
            frames.resize(to, 0);
        }
        frames
    }

    /// A big (post-quantum sized) hello split over two Initials in two
    /// datagrams, CRYPTO frames shuffled and interleaved with PING/PADDING
    /// as Chrome does.
    fn split_hello(ver: u32) -> (Vec<u8>, Vec<u8>) {
        let hello = build::handshake(&[
            build::grease_ext(4),
            build::sni_ext("h3.split.example"),
            build::alpn_ext(&["h3"]),
            (0x0033, vec![0x42; 1300]),
        ]);
        assert!(hello.len() > 1400);
        let (a, b) = hello.split_at(700);
        let (a1, a2) = a.split_at(300);
        let mut first = crypto_frame(300, a2);
        first.push(0x01);
        first.extend(crypto_frame(0, a1));
        let second = crypto_frame(700, b);
        let d1 = seal_client_initial(ver, &DCID, &[1, 2, 3], 0, 1, &padded(first, 1100));
        let d2 = seal_client_initial(ver, &DCID, &[1, 2, 3], 1, 2, &padded(second, 1100));
        (d1, d2)
    }

    #[test]
    fn crypto_stream_split_over_two_initials_is_reassembled_v1_and_v2() {
        for ver in [VERSION_1, VERSION_2] {
            let (d1, d2) = split_hello(ver);
            let mut asm = CryptoAssembler::new();
            assert_eq!(push_datagram(&mut asm, &d1), Progress::NeedMore);
            let Progress::Done(h) = push_datagram(&mut asm, &d2) else { panic!("v{ver:x}") };
            assert_eq!(h.sni.as_deref(), Some("h3.split.example"));
            assert_eq!(h.alpn, vec!["h3"]);
            // Arrival order does not matter.
            let mut asm = CryptoAssembler::new();
            assert_eq!(push_datagram(&mut asm, &d2), Progress::NeedMore);
            assert!(matches!(push_datagram(&mut asm, &d1), Progress::Done(_)));
            // A retransmitted datagram is harmless.
            assert!(matches!(push_datagram(&mut asm, &d1), Progress::Done(_)));
        }
    }

    #[test]
    fn coalesced_initial_then_zero_rtt_opens_the_initial_and_skips_the_rest() {
        let initial = seal_client_initial(VERSION_1, &DCID, &[], 0, 1, &padded(rfc_crypto_frame(), 600));
        // A 0-RTT packet (type 01): header, Length 30, 30 opaque bytes.
        let mut zero_rtt = vec![0xd0, 0, 0, 0, 1, 8];
        zero_rtt.extend_from_slice(&DCID);
        zero_rtt.push(0);
        zero_rtt.push(30);
        zero_rtt.extend_from_slice(&[0x77; 30]);
        let mut dg = initial.clone();
        dg.extend_from_slice(&zero_rtt);
        dg.extend_from_slice(&[0x40, 1, 2, 3]); // short header tail
        let Progress::Done(list) = open_datagram(&dg) else { panic!() };
        assert_eq!(list.len(), 1);
        // 0-RTT first, Initial second also works.
        let mut dg = zero_rtt;
        dg.extend_from_slice(&initial);
        let Progress::Done(list) = open_datagram(&dg) else { panic!() };
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn not_quic_and_broken_packets_are_classified_not_panicked() {
        assert_eq!(open_datagram(&[]), Progress::NotThis);
        assert_eq!(open_datagram(&[0x40, 1, 2, 3]), Progress::NotThis);
        // Version negotiation (version 0) and an unknown version.
        assert_eq!(open_datagram(&[0xc0, 0, 0, 0, 0, 0, 0]), Progress::NotThis);
        assert_eq!(open_datagram(&[0xc0, 0xff, 0, 0, 0x1d, 0, 0]), Progress::NotThis);
        // A truncated RFC packet: Length runs past the end.
        let pkt = rfc9001_packet();
        assert_eq!(open_datagram(&pkt[..600]), Progress::Invalid("length past end of datagram"));
        // A flipped ciphertext byte fails authentication.
        let mut bad = pkt.clone();
        bad[500] ^= 1;
        assert_eq!(open_datagram(&bad), Progress::Invalid("authentication failed"));
        // A wrong DCID gives wrong keys.
        let mut bad = pkt;
        bad[6] ^= 1;
        assert!(matches!(open_datagram(&bad), Progress::Invalid(_)));
        // Every prefix of a valid packet is handled.
        let pkt = rfc9369_packet();
        for cut in 0..pkt.len() {
            let _ = open_datagram(&pkt[..cut]);
        }
    }

    #[test]
    fn forbidden_frames_in_initial_are_invalid() {
        // STREAM frame (0x08) is not allowed in an Initial.
        let pkt = seal_client_initial(VERSION_1, &DCID, &[], 0, 1, &padded(vec![0x08, 0, 1, 0x61], 100));
        assert_eq!(open_datagram(&pkt), Progress::Invalid("frame type not allowed in Initial"));
    }

    #[test]
    fn ack_and_close_frames_are_parsed_around_crypto() {
        let mut frames = vec![0x03, 5, 0, 1, 0, 1, 1, 0, 0, 0]; // ACK with ECN, 1 range
        frames.extend(crypto_frame(0, &build::handshake(&[build::sni_ext("ack.example")])));
        frames.extend_from_slice(&[0x1c, 0, 0, 2, b'h', b'i']);
        let pkt = seal_client_initial(VERSION_1, &DCID, &[], 3, 2, &padded(frames, 300));
        let mut asm = CryptoAssembler::new();
        let Progress::Done(h) = push_datagram(&mut asm, &pkt) else { panic!() };
        assert_eq!(h.sni.as_deref(), Some("ack.example"));
    }

    #[test]
    fn assembler_caps_the_stream_and_handles_overlap() {
        let mut asm = CryptoAssembler::new();
        assert!(asm.push(MAX_CRYPTO_BYTES as u64, &[1]).is_err());
        assert!(asm.push(u64::MAX, &[1]).is_err());
        asm.push(0, b"abcdef").unwrap();
        asm.push(3, b"defghi").unwrap();
        asm.push(2, b"cd").unwrap();
        assert_eq!(asm.contiguous(), b"abcdefghi");
        asm.push(20, b"zz").unwrap();
        assert_eq!(asm.contiguous(), b"abcdefghi");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        #[test]
        fn arbitrary_datagrams_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1400)) {
            let _ = open_datagram(&bytes);
            let mut asm = CryptoAssembler::new();
            let _ = push_datagram(&mut asm, &bytes);
        }

        #[test]
        fn long_header_shaped_garbage_never_panics(
            first in 0xc0u8..=0xff,
            v2 in any::<bool>(),
            tail in proptest::collection::vec(any::<u8>(), 0..1300),
        ) {
            let ver = if v2 { VERSION_2 } else { VERSION_1 };
            let mut dg = vec![first];
            dg.extend_from_slice(&ver.to_be_bytes());
            dg.extend(tail);
            let _ = open_datagram(&dg);
        }

        #[test]
        fn mutated_rfc_packet_never_panics(flips in proptest::collection::vec((0usize..1200, any::<u8>()), 1..6)) {
            let mut pkt = rfc9001_packet();
            for (at, v) in flips {
                pkt[at] = v;
            }
            let _ = open_datagram(&pkt);
        }

        #[test]
        fn assembler_order_does_not_matter(cuts in proptest::collection::vec(1usize..400, 1..6), seed in any::<u64>()) {
            let hello = build::handshake(&[build::sni_ext("order.example"), (0x0033, vec![9; 900])]);
            let mut pieces = Vec::new();
            let mut at = 0usize;
            for c in cuts {
                if at >= hello.len() { break; }
                let end = (at + c).min(hello.len());
                pieces.push((at, hello[at..end].to_vec()));
                at = end;
            }
            if at < hello.len() { pieces.push((at, hello[at..].to_vec())); }
            // Deterministic shuffle from the seed.
            let mut s = seed | 1;
            for i in (1..pieces.len()).rev() {
                s ^= s << 13; s ^= s >> 7; s ^= s << 17;
                pieces.swap(i, (s % (i as u64 + 1)) as usize);
            }
            let mut asm = CryptoAssembler::new();
            for (off, data) in &pieces {
                asm.push(*off as u64, data).unwrap();
            }
            let Progress::Done(h) = asm.hello() else { panic!("not done") };
            prop_assert_eq!(h.sni.as_deref(), Some("order.example"));
        }
    }
}
