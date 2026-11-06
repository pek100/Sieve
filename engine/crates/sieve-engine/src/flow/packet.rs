//! Raw IP packet parsing (what a TUN read hands us):
//! IPv4 or IPv6, then TCP or UDP, down to the transport payload.
//!
//! Fragments are not reassembled (None): a ClientHello or QUIC Initial in
//! an IP fragment is rare (QUIC forbids it, TCP uses MSS), and the probe
//! counts what it skipped. IPv6 extension headers hop-by-hop, routing and
//! destination options are walked; anything else ends the parse.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn number(self) -> u8 {
        match self {
            Proto::Tcp => 6,
            Proto::Udp => 17,
        }
    }

    pub fn from_number(n: u8) -> Option<Self> {
        match n {
            6 => Some(Proto::Tcp),
            17 => Some(Proto::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    pub proto: Proto,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// TCP sequence number (0 for UDP).
    pub seq: u32,
    /// TCP flags byte (0 for UDP).
    pub tcp_flags: u8,
    /// The transport header, options included.
    pub header: &'a [u8],
    pub payload: &'a [u8],
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

pub fn parse(ip: &[u8]) -> Option<Packet<'_>> {
    match ip.first()? >> 4 {
        4 => parse_v4(ip),
        6 => parse_v6(ip),
        _ => None,
    }
}

/// The destination address of any IPv4 or IPv6 packet (any protocol,
/// fragments included). The TUN reader uses it to keep only packets for
/// the routed test addresses.
pub fn dst_ip(ip: &[u8]) -> Option<IpAddr> {
    match ip.first()? >> 4 {
        4 => {
            let b = ip.get(16..20)?;
            Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
        }
        6 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(ip.get(24..40)?).ok()?))),
        _ => None,
    }
}

fn parse_v4(ip: &[u8]) -> Option<Packet<'_>> {
    let ihl = usize::from(ip.first()? & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]));
    if ihl < 20 || total < ihl || total > ip.len() {
        return None;
    }
    let frag = u16::from_be_bytes([ip[6], ip[7]]);
    if frag & 0x3fff != 0 {
        return None; // MF set or nonzero offset: a fragment
    }
    let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
    transport(Proto::from_number(ip[9])?, src, dst, &ip[ihl..total])
}

fn parse_v6(ip: &[u8]) -> Option<Packet<'_>> {
    if ip.len() < 40 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([ip[4], ip[5]]));
    let end = 40usize.checked_add(payload_len)?;
    if end > ip.len() {
        return None;
    }
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?));
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?));
    let mut next = ip[6];
    let mut at = 40usize;
    loop {
        match next {
            0 | 43 | 60 => {
                let hdr = ip.get(at..at + 2)?;
                next = hdr[0];
                at = at.checked_add((usize::from(hdr[1]) + 1) * 8)?;
                if at > end {
                    return None;
                }
            }
            n => return transport(Proto::from_number(n)?, src, dst, &ip[at..end]),
        }
    }
}

fn transport(proto: Proto, src: IpAddr, dst: IpAddr, seg: &[u8]) -> Option<Packet<'_>> {
    let src_port = u16::from_be_bytes([*seg.first()?, *seg.get(1)?]);
    let dst_port = u16::from_be_bytes([*seg.get(2)?, *seg.get(3)?]);
    match proto {
        Proto::Tcp => {
            let offset = usize::from(seg.get(12)? >> 4) * 4;
            if offset < 20 || offset > seg.len() {
                return None;
            }
            let seq = u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]);
            Some(Packet { proto, src, dst, src_port, dst_port, seq, tcp_flags: seg[13], header: &seg[..offset], payload: &seg[offset..] })
        }
        Proto::Udp => {
            let len = usize::from(u16::from_be_bytes([*seg.get(4)?, *seg.get(5)?]));
            if len < 8 || len > seg.len() {
                return None;
            }
            Some(Packet { proto, src, dst, src_port, dst_port, seq: 0, tcp_flags: 0, header: &seg[..8], payload: &seg[8..len] })
        }
    }
}

/// What a SYN's headers said, raw (A1, diagnostic builds). Recorded and never
/// read by any decision: any host program can set its own TTL.
#[cfg(feature = "attribution-diagnostics")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SynFingerprint {
    /// IPv4 TTL or IPv6 hop limit.
    pub ttl: u8,
    pub window: u16,
    /// The TCP option kinds, in order.
    pub option_kinds: Vec<u8>,
}

/// The fingerprint of a TCP SYN without ACK; None for anything else.
#[cfg(feature = "attribution-diagnostics")]
pub fn syn_fingerprint(ip: &[u8]) -> Option<SynFingerprint> {
    let parsed = parse(ip)?;
    if parsed.proto != Proto::Tcp || parsed.tcp_flags & (TCP_SYN | TCP_ACK) != TCP_SYN {
        return None;
    }
    let ttl = *ip.get(if ip.first()? >> 4 == 4 { 8 } else { 7 })?;
    let window = u16::from_be_bytes([*parsed.header.get(14)?, *parsed.header.get(15)?]);
    let mut option_kinds = Vec::new();
    let mut options = parsed.header.get(20..)?;
    while let Some(&kind) = options.first() {
        option_kinds.push(kind);
        match kind {
            0 => break,
            1 => options = &options[1..],
            _ => {
                let len = usize::from(*options.get(1)?);
                if len < 2 || len > options.len() {
                    break;
                }
                options = &options[len..];
            }
        }
    }
    Some(SynFingerprint { ttl, window, option_kinds })
}

/// Packet builders for tests and the benchmark (checksums left zero: the
/// parser does not check them).
pub mod build {
    use super::Proto;
    use std::net::IpAddr;

    fn transport(proto: Proto, sport: u16, dport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&sport.to_be_bytes());
        t.extend_from_slice(&dport.to_be_bytes());
        match proto {
            Proto::Tcp => {
                t.extend_from_slice(&seq.to_be_bytes());
                t.extend_from_slice(&[0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
            }
            Proto::Udp => {
                t.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
                t.extend_from_slice(&[0, 0]);
            }
        }
        t.extend_from_slice(payload);
        t
    }

    pub fn ip(proto: Proto, src: IpAddr, dst: IpAddr, sport: u16, dport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let t = transport(proto, sport, dport, seq, payload);
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let total = (20 + t.len()) as u16;
                let mut p = vec![0x45, 0];
                p.extend_from_slice(&total.to_be_bytes());
                p.extend_from_slice(&[0, 0, 0x40, 0, 64, proto.number(), 0, 0]);
                p.extend_from_slice(&s.octets());
                p.extend_from_slice(&d.octets());
                p.extend(t);
                p
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let mut p = vec![0x60, 0, 0, 0];
                p.extend_from_slice(&(t.len() as u16).to_be_bytes());
                p.extend_from_slice(&[proto.number(), 64]);
                p.extend_from_slice(&s.octets());
                p.extend_from_slice(&d.octets());
                p.extend(t);
                p
            }
            _ => panic!("mixed address families"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ipv4_tcp_payload_ports_and_seq() {
        let p = build::ip(Proto::Tcp, v4("10.0.0.2"), v4("93.184.216.34"), 50000, 443, 77, b"hello");
        let pkt = parse(&p).unwrap();
        assert_eq!(pkt.proto, Proto::Tcp);
        assert_eq!((pkt.src_port, pkt.dst_port, pkt.seq), (50000, 443, 77));
        assert_eq!(pkt.dst, v4("93.184.216.34"));
        assert_eq!(pkt.payload, b"hello");
    }

    #[test]
    fn ipv6_udp_with_extension_header() {
        let mut p = build::ip(Proto::Udp, v4("::1"), v4("2001:db8::1"), 1234, 443, 0, b"quic");
        // Insert an 8-byte destination options header (type 60) before UDP.
        p[6] = 60;
        let ext = [17u8, 0, 1, 4, 0, 0, 0, 0];
        let plen = u16::from_be_bytes([p[4], p[5]]) + 8;
        p[4..6].copy_from_slice(&plen.to_be_bytes());
        p.splice(40..40, ext);
        let pkt = parse(&p).unwrap();
        assert_eq!(pkt.proto, Proto::Udp);
        assert_eq!(pkt.dst_port, 443);
        assert_eq!(pkt.payload, b"quic");
    }

    #[test]
    fn fragments_and_other_protocols_are_skipped() {
        let mut p = build::ip(Proto::Tcp, v4("1.1.1.1"), v4("2.2.2.2"), 1, 2, 0, b"x");
        p[6] = 0x20; // MF
        assert!(parse(&p).is_none());
        let mut p = build::ip(Proto::Tcp, v4("1.1.1.1"), v4("2.2.2.2"), 1, 2, 0, b"x");
        p[9] = 1; // ICMP
        assert!(parse(&p).is_none());
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45]).is_none());
    }

    #[test]
    fn dst_ip_reads_both_families_and_any_protocol() {
        let p = build::ip(Proto::Udp, v4("198.18.211.1"), v4("239.255.255.250"), 1900, 1900, 0, b"M-SEARCH");
        assert_eq!(dst_ip(&p), Some(v4("239.255.255.250")));
        let p = build::ip(Proto::Tcp, v4("fd53::1"), v4("2606:4700::1"), 1, 443, 0, b"");
        assert_eq!(dst_ip(&p), Some(v4("2606:4700::1")));
        let mut icmp = build::ip(Proto::Tcp, v4("1.1.1.1"), v4("2.2.2.2"), 1, 2, 0, b"x");
        icmp[9] = 1;
        assert_eq!(dst_ip(&icmp), Some(v4("2.2.2.2")));
        assert_eq!(dst_ip(&[0x45, 0, 0]), None);
        assert_eq!(dst_ip(&[]), None);
    }

    /// A SYN with options: MSS, SACK permitted, timestamps, NOP, window scale.
    #[cfg(feature = "attribution-diagnostics")]
    fn with_syn_options(mut p: Vec<u8>, tcp_at: usize, window: u16) -> Vec<u8> {
        let options: [u8; 20] = [2, 4, 5, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 8];
        p[tcp_at + 12] = 0xa0; // 40 byte header
        p[tcp_at + 13] = TCP_SYN;
        p[tcp_at + 14..tcp_at + 16].copy_from_slice(&window.to_be_bytes());
        p.splice(tcp_at + 20..tcp_at + 20, options);
        p
    }

    #[cfg(feature = "attribution-diagnostics")]
    #[test]
    fn syn_fingerprint_reads_ttl_hop_window_and_option_order() {
        let kinds = vec![2, 4, 8, 1, 3];
        let mut ipv4 = build::ip(Proto::Tcp, v4("198.18.0.1"), v4("1.1.1.1"), 5000, 443, 0, b"");
        ipv4[8] = 127;
        let mut ipv4 = with_syn_options(ipv4, 20, 64240);
        ipv4[2..4].copy_from_slice(&60u16.to_be_bytes());
        assert_eq!(syn_fingerprint(&ipv4), Some(SynFingerprint { ttl: 127, window: 64240, option_kinds: kinds.clone() }));

        let mut ipv6 = build::ip(Proto::Tcp, v4("fd53::1"), v4("2606:4700::1"), 5000, 443, 0, b"");
        ipv6[7] = 63;
        let mut ipv6 = with_syn_options(ipv6, 40, 65535);
        ipv6[4..6].copy_from_slice(&40u16.to_be_bytes());
        assert_eq!(syn_fingerprint(&ipv6), Some(SynFingerprint { ttl: 63, window: 65535, option_kinds: kinds }));
    }

    #[cfg(feature = "attribution-diagnostics")]
    #[test]
    fn a_non_syn_has_no_fingerprint() {
        let data = build::ip(Proto::Tcp, v4("198.18.0.1"), v4("1.1.1.1"), 5000, 443, 0, b"x");
        assert_eq!(syn_fingerprint(&data), None, "ACK+PSH");
        let mut syn_ack = data.clone();
        syn_ack[33] = TCP_SYN | TCP_ACK;
        assert_eq!(syn_fingerprint(&syn_ack), None);
        let udp = build::ip(Proto::Udp, v4("198.18.0.1"), v4("1.1.1.1"), 5000, 443, 0, b"x");
        assert_eq!(syn_fingerprint(&udp), None);
        let mut bare = data;
        bare[33] = TCP_SYN;
        assert_eq!(syn_fingerprint(&bare).unwrap().option_kinds, Vec::<u8>::new());
    }

    #[cfg(feature = "attribution-diagnostics")]
    proptest! {
        #[test]
        fn syn_fingerprint_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..120), v in prop_oneof![Just(4u8), Just(6u8)]) {
            let mut b = bytes;
            if let Some(f) = b.first_mut() { *f = (v << 4) | (*f & 0x0f); }
            let _ = syn_fingerprint(&b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..200), v in 0u8..16) {
            let mut b = bytes;
            if let Some(f) = b.first_mut() { *f = (v << 4) | (*f & 0x0f); }
            let _ = parse(&b);
            let _ = dst_ip(&b);
        }
    }
}
