//! TLS ClientHello parsing: SNI, ALPN and whether ECH is offered.
//!
//! Two entry points:
//! - [`parse_tls_stream`]: the first bytes a client sent on a TCP
//!   connection (one or more TLS records, possibly cut anywhere). The
//!   ClientHello may span several records and several TCP segments; the
//!   caller keeps the stream bytes (see [`crate::flow::stream`]) and calls again.
//! - [`parse_handshake`]: a bare handshake message (type, u24 length,
//!   body), as carried in QUIC CRYPTO frames (no record layer).
//!
//! Rules (RFC 8446 section 4.1.2, RFC 6066 section 3, RFC 7301, ECH draft):
//! - the first handshake message must be a ClientHello (type 1);
//! - SNI is the first `host_name` entry of `server_name` (0x0000), lower
//!   cased, trailing dot dropped; a malformed name is `Invalid`, never guessed;
//! - a second `server_name` extension is `Invalid` (a filter must not pick
//!   one of two names; the server would reject the hello anyway);
//! - unknown extension types, GREASE (0x?a?a) included, are skipped;
//! - `encrypted_client_hello` (0xfe0d) sets `ech`: the SNI then is the
//!   outer (public) name, which is all an on-path observer can see.
//!
//! Size cap: a ClientHello body above [`MAX_HELLO_LEN`] is `Invalid`. Real
//! hellos are 0.5 to 2 KB (post-quantum key shares included); the cap
//! bounds what a flow may make us buffer.

use crate::flow::{Progress, Reader};

/// Largest ClientHello (handshake body) we will wait for.
pub const MAX_HELLO_LEN: usize = 16 * 1024;

/// Largest TLS plaintext record fragment (RFC 8446 section 5.1).
const MAX_RECORD_LEN: usize = 1 << 14;

const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;
const EXT_ECH: u16 = 0xfe0d;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// What a ClientHello says about where it is going.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hello {
    /// The server name, lower case, or None when the client sent none.
    pub sni: Option<String>,
    /// ALPN protocol names in client order (e.g. "h2", "http/1.1", "h3").
    pub alpn: Vec<String>,
    /// The client offered Encrypted Client Hello; `sni` is the outer name.
    pub ech: bool,
    /// What it can speak, so a client rustls cannot serve is known before it
    /// is answered (task D10).
    pub offer: TlsOffer,
}

/// A ClientHello's versions, cipher suites and key exchange groups, as their
/// wire numbers (GREASE values included: they simply match nothing).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsOffer {
    /// `supported_versions`, else the legacy version alone.
    pub versions: Vec<u16>,
    pub suites: Vec<u16>,
    pub groups: Vec<u16>,
}

/// Parses the start of a client's TCP byte stream as TLS records carrying a
/// ClientHello.
pub fn parse_tls_stream(stream: &[u8]) -> Progress<Hello> {
    let Some(&first) = stream.first() else {
        return Progress::NeedMore;
    };
    if first != CONTENT_HANDSHAKE {
        return Progress::NotThis;
    }
    if let Some(&major) = stream.get(1)
        && major != 3
    {
        return Progress::NotThis;
    }
    if let Some(&minor) = stream.get(2)
        && minor > 4
    {
        return Progress::NotThis;
    }

    // Gather handshake bytes from consecutive records until the first
    // handshake message is complete.
    let mut handshake: Vec<u8> = Vec::new();
    let mut r = Reader::new(stream);
    loop {
        if r.remaining() < 5 {
            break;
        }
        let Some(header) = r.bytes(5) else { break };
        if header[0] != CONTENT_HANDSHAKE {
            return Progress::Invalid("non-handshake record before the ClientHello ended");
        }
        if header[1] != 3 {
            return Progress::Invalid("record version");
        }
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if len == 0 || len > MAX_RECORD_LEN {
            return Progress::Invalid("record length");
        }
        let take = len.min(r.remaining());
        let Some(fragment) = r.bytes(take) else { break };
        handshake.extend_from_slice(fragment);
        if handshake_complete(&handshake) || take < len {
            break;
        }
    }
    parse_handshake(&handshake)
}

/// True once `buf` holds at least one whole handshake message.
fn handshake_complete(buf: &[u8]) -> bool {
    let mut r = Reader::new(buf);
    match (r.u8(), r.u24()) {
        (Some(_), Some(len)) => r.remaining() >= len as usize,
        _ => false,
    }
}

/// Parses a handshake message that must be a ClientHello. `msg` may hold
/// more bytes after the message; they are ignored.
pub fn parse_handshake(msg: &[u8]) -> Progress<Hello> {
    let mut r = Reader::new(msg);
    let Some(kind) = r.u8() else {
        return Progress::NeedMore;
    };
    if kind != HANDSHAKE_CLIENT_HELLO {
        return Progress::Invalid("first handshake message is not a ClientHello");
    }
    let Some(len) = r.u24() else {
        return Progress::NeedMore;
    };
    let len = len as usize;
    if len > MAX_HELLO_LEN {
        return Progress::Invalid("ClientHello larger than the cap");
    }
    match r.bytes(len) {
        Some(body) => parse_client_hello_body(body),
        None => Progress::NeedMore,
    }
}

/// Parses a complete ClientHello body (after the 4-byte handshake header).
pub fn parse_client_hello_body(body: &[u8]) -> Progress<Hello> {
    match client_hello_body(body) {
        Ok(hello) => Progress::Done(hello),
        Err(why) => Progress::Invalid(why),
    }
}

fn client_hello_body(body: &[u8]) -> Result<Hello, &'static str> {
    let mut r = Reader::new(body);
    let legacy_version = r.u16().ok_or("short version")?;
    if legacy_version >> 8 != 3 {
        return Err("legacy_version");
    }
    r.bytes(32).ok_or("short random")?;
    let session_id = r.vec(1).ok_or("short session id")?;
    if session_id.len() > 32 {
        return Err("session id longer than 32");
    }
    let suites = r.vec(2).ok_or("short cipher suites")?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Err("cipher suites length");
    }
    let compression = r.vec(1).ok_or("short compression methods")?;
    if compression.is_empty() {
        return Err("no compression methods");
    }
    let mut hello = Hello::default();
    hello.offer.versions = vec![legacy_version];
    hello.offer.suites = wire_numbers(suites);
    if r.is_empty() {
        // Extensions are optional in the grammar (pre TLS 1.3 clients).
        return Ok(hello);
    }
    let extensions = r.vec(2).ok_or("short extensions")?;
    if !r.is_empty() {
        return Err("bytes after extensions");
    }
    let mut seen_sni = false;
    let mut ext = Reader::new(extensions);
    while !ext.is_empty() {
        let kind = ext.u16().ok_or("short extension header")?;
        let data = ext.vec(2).ok_or("extension longer than the block")?;
        match kind {
            EXT_SERVER_NAME => {
                if seen_sni {
                    return Err("two server_name extensions");
                }
                seen_sni = true;
                hello.sni = server_name(data)?;
            }
            EXT_ALPN => hello.alpn = alpn(data)?,
            EXT_ECH => hello.ech = true,
            EXT_SUPPORTED_VERSIONS => hello.offer.versions = Reader::new(data).vec(1).map(wire_numbers).unwrap_or_default(),
            EXT_SUPPORTED_GROUPS => hello.offer.groups = Reader::new(data).vec(2).map(wire_numbers).unwrap_or_default(),
            _ => {}
        }
    }
    Ok(hello)
}

/// A list of big-endian u16 values. A trailing odd byte is ignored: this only
/// ever asks "is a value rustls speaks here", and no match is a pass-through.
fn wire_numbers(list: &[u8]) -> Vec<u16> {
    list.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()
}

/// The first host_name in a server_name extension, validated.
fn server_name(data: &[u8]) -> Result<Option<String>, &'static str> {
    let mut r = Reader::new(data);
    let list = r.vec(2).ok_or("short server_name list")?;
    if !r.is_empty() {
        return Err("bytes after server_name list");
    }
    let mut list = Reader::new(list);
    while !list.is_empty() {
        let name_type = list.u8().ok_or("short server_name entry")?;
        let name = list.vec(2).ok_or("server_name entry longer than list")?;
        if name_type == 0 {
            return host_name(name).map(Some).ok_or("server_name is not a host name");
        }
    }
    Ok(None)
}

/// A DNS host name as raw bytes to a lower-case String, or None when it is
/// not one (empty, too long, non-ASCII, bad label).
pub fn host_name(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    let text = text.strip_suffix('.').unwrap_or(text);
    if text.is_empty() || text.len() > 253 {
        return None;
    }
    let ok = text.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    ok.then(|| text.to_ascii_lowercase())
}

fn alpn(data: &[u8]) -> Result<Vec<String>, &'static str> {
    let mut r = Reader::new(data);
    let list = r.vec(2).ok_or("short ALPN list")?;
    if !r.is_empty() {
        return Err("bytes after ALPN list");
    }
    let mut list = Reader::new(list);
    let mut out = Vec::new();
    while !list.is_empty() {
        let name = list.vec(1).ok_or("ALPN entry longer than list")?;
        if name.is_empty() {
            return Err("empty ALPN entry");
        }
        out.push(String::from_utf8_lossy(name).into_owned());
    }
    Ok(out)
}

/// Builders for well-formed (and deliberately broken) ClientHellos, shared
/// by the unit tests, the QUIC tests and the benchmark.
pub mod build {
    /// One extension: (type, data).
    pub type Ext = (u16, Vec<u8>);

    fn len16(v: &[u8]) -> Vec<u8> {
        let mut out = (v.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(v);
        out
    }

    pub fn sni_ext(name: &str) -> Ext {
        let mut entry = vec![0u8];
        entry.extend(len16(name.as_bytes()));
        (0x0000, len16(&entry))
    }

    pub fn alpn_ext(protocols: &[&str]) -> Ext {
        let mut list = Vec::new();
        for p in protocols {
            list.push(p.len() as u8);
            list.extend_from_slice(p.as_bytes());
        }
        (0x0010, len16(&list))
    }

    /// An ECH outer extension with an opaque payload (the shape does not
    /// matter to the parser, only the type).
    pub fn ech_ext() -> Ext {
        (0xfe0d, vec![0x00, 0x00, 0x01, 0x00, 0x01, 0x07, 0x00, 0x20, 0xaa, 0xbb])
    }

    /// A GREASE extension (RFC 8701): type 0x?a?a with junk data.
    pub fn grease_ext(n: u8) -> Ext {
        let v = 0x0a | (n & 0x0f) << 4;
        (u16::from_be_bytes([v, v]), vec![0x00])
    }

    /// The ClientHello body (no handshake header).
    pub fn hello_body(exts: &[Ext]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x11; 32]);
        body.push(32);
        body.extend_from_slice(&[0x22; 32]);
        body.extend(len16(&[0x13, 0x01, 0x13, 0x02, 0x0a, 0x0a]));
        body.extend_from_slice(&[1, 0]);
        let mut ext_block = Vec::new();
        for (kind, data) in exts {
            ext_block.extend_from_slice(&kind.to_be_bytes());
            ext_block.extend(len16(data));
        }
        body.extend(len16(&ext_block));
        body
    }

    /// The handshake message: type 1, u24 length, body.
    pub fn handshake(exts: &[Ext]) -> Vec<u8> {
        let body = hello_body(exts);
        let len = body.len() as u32;
        let mut msg = vec![1u8];
        msg.extend_from_slice(&len.to_be_bytes()[1..]);
        msg.extend(body);
        msg
    }

    /// The handshake message split into TLS records of at most `chunk`
    /// bytes each.
    pub fn records(msg: &[u8], chunk: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for part in msg.chunks(chunk.max(1)) {
            out.extend_from_slice(&[22, 3, 1]);
            out.extend(len16(part));
        }
        out
    }

    /// A typical modern hello: GREASE, SNI, ALPN h2 + http/1.1, padding.
    pub fn typical(name: &str) -> Vec<u8> {
        records(
            &handshake(&[
                grease_ext(2),
                sni_ext(name),
                (0x0017, vec![]),
                alpn_ext(&["h2", "http/1.1"]),
                (0x0033, vec![0x5a; 1250]),
                (0x0015, vec![0; 200]),
                grease_ext(9),
            ]),
            16_384,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;
    use proptest::prelude::*;

    fn done(p: Progress<Hello>) -> Hello {
        match p {
            Progress::Done(h) => h,
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn typical_hello_gives_sni_and_alpn() {
        let h = done(parse_tls_stream(&typical("WWW.Example.COM")));
        assert_eq!(h.sni.as_deref(), Some("www.example.com"));
        assert_eq!(h.alpn, vec!["h2", "http/1.1"]);
        assert!(!h.ech);
    }

    #[test]
    fn every_prefix_needs_more_and_the_whole_is_done() {
        let stream = typical("cut.example.org");
        for cut in 0..stream.len() {
            assert_eq!(parse_tls_stream(&stream[..cut]), Progress::NeedMore, "cut at {cut}");
        }
        assert_eq!(done(parse_tls_stream(&stream)).sni.as_deref(), Some("cut.example.org"));
    }

    #[test]
    fn hello_spanning_many_small_records_is_reassembled() {
        let msg = handshake(&[grease_ext(1), sni_ext("split.example.net"), (0x0033, vec![7; 900])]);
        for chunk in [1, 2, 5, 64, 333] {
            let stream = records(&msg, chunk);
            let h = done(parse_tls_stream(&stream));
            assert_eq!(h.sni.as_deref(), Some("split.example.net"), "chunk {chunk}");
            // Every strict prefix of the stream is incomplete, never invalid.
            for cut in (0..stream.len()).step_by(37) {
                assert_eq!(parse_tls_stream(&stream[..cut]), Progress::NeedMore, "chunk {chunk} cut {cut}");
            }
        }
    }

    #[test]
    fn trailing_bytes_after_the_hello_are_ignored() {
        let mut stream = typical("a.example");
        stream.extend_from_slice(&[0x14, 3, 3, 0, 1, 1]);
        assert_eq!(done(parse_tls_stream(&stream)).sni.as_deref(), Some("a.example"));
    }

    #[test]
    fn missing_sni_is_done_with_none() {
        let h = done(parse_tls_stream(&records(&handshake(&[alpn_ext(&["h2"])]), 16_384)));
        assert_eq!(h.sni, None);
        assert_eq!(h.alpn, vec!["h2"]);
    }

    #[test]
    fn hello_without_any_extensions_is_done_with_none() {
        let mut body = hello_body(&[]);
        body.truncate(body.len() - 2); // drop the empty extensions block
        let mut msg = vec![1, 0, 0, body.len() as u8];
        msg.extend(body);
        let hello = done(parse_handshake(&msg));
        assert_eq!((hello.sni, hello.alpn, hello.ech), (None, vec![], false));
        assert_eq!(hello.offer.versions, [0x0303], "no supported_versions: the legacy version alone");
        assert!(hello.offer.groups.is_empty());
    }

    #[test]
    fn a_hello_says_what_it_offers() {
        let groups = (0x000a_u16, vec![0, 4, 0x11, 0xec, 0, 0x1d]);
        let versions = (0x002b_u16, vec![4, 3, 4, 3, 3]);
        let hello = done(parse_handshake(&handshake(&[groups, versions])));
        assert_eq!(hello.offer.groups, [0x11ec, 0x001d]);
        assert_eq!(hello.offer.versions, [0x0304, 0x0303], "supported_versions replaces the legacy version");
        assert_eq!(hello.offer.suites, [0x1301, 0x1302, 0x0a0a], "in order, GREASE included");
    }

    #[test]
    fn grease_extensions_and_unknown_types_are_skipped() {
        let mut exts: Vec<Ext> = (0..16).map(grease_ext).collect();
        exts.push((0x4469, vec![1, 2, 3]));
        exts.push(sni_ext("grease.example"));
        exts.push(grease_ext(3));
        let h = done(parse_handshake(&handshake(&exts)));
        assert_eq!(h.sni.as_deref(), Some("grease.example"));
    }

    #[test]
    fn ech_is_reported_with_the_outer_name_only() {
        let h = done(parse_handshake(&handshake(&[sni_ext("public.ech.example"), ech_ext()])));
        assert!(h.ech);
        assert_eq!(h.sni.as_deref(), Some("public.ech.example"));
    }

    #[test]
    fn trailing_dot_is_dropped() {
        let h = done(parse_handshake(&handshake(&[sni_ext("dot.example.")])));
        assert_eq!(h.sni.as_deref(), Some("dot.example"));
    }

    #[test]
    fn non_host_names_are_invalid_never_guessed() {
        for bad in ["", "a..b", "spa ce.example", "caf\u{e9}.fr", ".lead", "under\0nul.example"] {
            let p = parse_handshake(&handshake(&[sni_ext(bad)]));
            assert!(matches!(p, Progress::Invalid(_)), "{bad:?} gave {p:?}");
        }
        let long = format!("{}.com", "a".repeat(64));
        assert!(matches!(parse_handshake(&handshake(&[sni_ext(&long)])), Progress::Invalid(_)));
    }

    #[test]
    fn two_server_name_extensions_are_invalid() {
        let p = parse_handshake(&handshake(&[sni_ext("one.example"), sni_ext("two.example")]));
        assert_eq!(p, Progress::Invalid("two server_name extensions"));
    }

    #[test]
    fn non_hostname_name_types_before_the_host_name_are_skipped() {
        // name_type 7 (unknown) then host_name.
        let mut list = vec![7u8, 0, 2, 0xde, 0xad, 0];
        list.extend_from_slice(&(9u16).to_be_bytes());
        list.extend_from_slice(b"x.example");
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend(list);
        let h = done(parse_handshake(&handshake(&[(0, data)])));
        assert_eq!(h.sni.as_deref(), Some("x.example"));
    }

    #[test]
    fn not_tls_streams_are_not_this() {
        assert_eq!(parse_tls_stream(b"GET / HTTP/1.1\r\n"), Progress::NotThis);
        assert_eq!(parse_tls_stream(&[22, 9, 9]), Progress::NotThis);
        assert_eq!(parse_tls_stream(&[22, 3, 7]), Progress::NotThis);
        assert_eq!(parse_tls_stream(&[]), Progress::NeedMore);
        assert_eq!(parse_tls_stream(&[22]), Progress::NeedMore);
    }

    #[test]
    fn server_hello_or_wrong_record_is_invalid() {
        let mut msg = handshake(&[sni_ext("a.example")]);
        msg[0] = 2;
        assert!(matches!(parse_tls_stream(&records(&msg, 16_384)), Progress::Invalid(_)));
        // A change_cipher_spec record in the middle of a split hello.
        let msg = handshake(&[sni_ext("a.example")]);
        let mut stream = records(&msg[..10], 16_384);
        stream.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        assert!(matches!(parse_tls_stream(&stream), Progress::Invalid(_)));
        // Zero-length and oversized records.
        assert!(matches!(parse_tls_stream(&[22, 3, 1, 0, 0, 0]), Progress::Invalid(_)));
        assert!(matches!(parse_tls_stream(&[22, 3, 1, 0x40, 0x01, 1]), Progress::Invalid(_)));
    }

    #[test]
    fn hello_longer_than_the_cap_is_invalid_without_waiting() {
        let len = (MAX_HELLO_LEN + 1) as u32;
        let msg = [1, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        assert_eq!(parse_handshake(&msg), Progress::Invalid("ClientHello larger than the cap"));
    }

    #[test]
    fn extension_block_overrun_is_invalid() {
        // Fixed part of build::hello_body: version 2, random 32, session id
        // 1 + 32, suites 2 + 6, compression 2: the extensions length is at 77.
        const EXT_LEN_AT: usize = 77;
        let body = hello_body(&[sni_ext("a.example")]);
        let real = u16::from_be_bytes([body[EXT_LEN_AT], body[EXT_LEN_AT + 1]]);
        assert_eq!(usize::from(real), body.len() - EXT_LEN_AT - 2);
        for claimed in [real + 1, real - 1] {
            let mut bad = body.clone();
            bad[EXT_LEN_AT..EXT_LEN_AT + 2].copy_from_slice(&claimed.to_be_bytes());
            assert!(matches!(parse_client_hello_body(&bad), Progress::Invalid(_)), "claimed {claimed}");
        }
    }

    #[test]
    fn alpn_with_empty_entry_is_invalid() {
        let p = parse_handshake(&handshake(&[(0x0010, vec![0, 1, 0])]));
        assert_eq!(p, Progress::Invalid("empty ALPN entry"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..3000)) {
            let _ = parse_tls_stream(&bytes);
            let _ = parse_handshake(&bytes);
            let _ = parse_client_hello_body(&bytes);
        }

        #[test]
        fn handshake_prefixed_garbage_never_panics(tail in proptest::collection::vec(any::<u8>(), 0..2000)) {
            let mut stream = vec![22u8, 3, 1, 0x07, 0xd0, 1, 0, 0x07, 0xcc];
            stream.extend(tail);
            let _ = parse_tls_stream(&stream);
        }

        #[test]
        fn mutated_valid_hello_never_panics(flips in proptest::collection::vec((0usize..2000, any::<u8>()), 1..8)) {
            let mut stream = typical("mutate.example.com");
            for (at, v) in flips {
                let n = stream.len();
                stream[at % n] = v;
            }
            let _ = parse_tls_stream(&stream);
        }

        #[test]
        fn any_valid_name_round_trips(name in "[a-z0-9]{1,20}(\\.[a-z0-9-]{1,20}){1,4}", chunk in 1usize..400) {
            let stream = records(&handshake(&[grease_ext(5), sni_ext(&name)]), chunk);
            let hello = done(parse_tls_stream(&stream));
            prop_assert_eq!((hello.sni, hello.alpn, hello.ech), (Some(name), vec![], false));
        }
    }
}
