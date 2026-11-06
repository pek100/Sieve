//! The port-unreachable a refused flow is answered with, written into the TUN.
//!
//! ipstack hands the relay the payload and the two addresses, so the app's IP
//! and UDP headers are gone and the quote is rebuilt from them (task F1): its
//! checksums and lengths are right, its IP id and TTL cannot match the original
//! (live check U1). The outer packet comes from `remote` to `local`: the
//! destination itself says the port is closed.

use std::net::SocketAddr;

use etherparse::err::packet::BuildWriteError;
use etherparse::{Icmpv4Type, Icmpv6Type, PacketBuilder, icmpv4, icmpv6};

/// RFC 1812 4.3.2.3: an ICMP error quotes as much as fits in this total.
pub const ICMP4_MAX: usize = 576;
/// RFC 4443 2.4: an ICMPv6 error quotes as much as fits in this total.
pub const ICMP6_MAX: usize = 1280;
const IP4_HEADER: usize = 20;
const IP6_HEADER: usize = 40;
const ICMP_HEADER: usize = 8;
/// What a host would start with. Nothing reads it past the adapter.
const TTL: u8 = 64;

fn written(size: usize, write: impl FnOnce(&mut Vec<u8>) -> Result<(), BuildWriteError>) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(size);
    write(&mut out).ok()?;
    Some(out)
}

/// The answer to one datagram the app sent from `local` to `remote`. None for
/// mixed families or a datagram too large to rebuild: the flow then behaves as a
/// silent drop, so the browser's own timer takes it to TCP.
pub fn port_unreachable(local: SocketAddr, remote: SocketAddr, datagram: &[u8]) -> Option<Vec<u8>> {
    match (local, remote) {
        (SocketAddr::V4(l), SocketAddr::V4(r)) => {
            let (app, far) = (l.ip().octets(), r.ip().octets());
            let quote = PacketBuilder::ipv4(app, far, TTL).udp(l.port(), r.port());
            let quote = written(quote.size(datagram.len()), |out| quote.write(out, datagram))?;
            let cut = &quote[..quote.len().min(ICMP4_MAX - IP4_HEADER - ICMP_HEADER)];
            let error = PacketBuilder::ipv4(far, app, TTL).icmpv4(Icmpv4Type::DestinationUnreachable(icmpv4::DestUnreachableHeader::Port));
            written(error.size(cut.len()), |out| error.write(out, cut))
        }
        (SocketAddr::V6(l), SocketAddr::V6(r)) => {
            let (app, far) = (l.ip().octets(), r.ip().octets());
            let quote = PacketBuilder::ipv6(app, far, TTL).udp(l.port(), r.port());
            let quote = written(quote.size(datagram.len()), |out| quote.write(out, datagram))?;
            let cut = &quote[..quote.len().min(ICMP6_MAX - IP6_HEADER - ICMP_HEADER)];
            let error = PacketBuilder::ipv6(far, app, TTL).icmpv6(Icmpv6Type::DestinationUnreachable(icmpv6::DestUnreachableCode::Port));
            written(error.size(cut.len()), |out| error.write(out, cut))
        }
        _ => None,
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::flow::packet::{self, Proto};
    use proptest::prelude::*;
    use std::net::IpAddr;

    const LOCAL4: &str = "198.18.0.2:50000";
    const REMOTE4: &str = "192.0.2.1:443";
    const LOCAL6: &str = "[fd00::2]:50000";
    const REMOTE6: &str = "[2001:db8::1]:443";
    const ICMP6_NEXT_HEADER: u8 = 58;
    const UDP_NUMBER: u8 = 17;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    /// The tests' own one's-complement sum (RFC 1071), not etherparse's.
    fn sum(parts: &[&[u8]]) -> u16 {
        let bytes: Vec<u8> = parts.concat();
        let mut total: u32 = bytes.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))).sum();
        while total > 0xffff {
            total = (total & 0xffff) + (total >> 16);
        }
        total as u16
    }

    /// Data that carries its own checksum sums to all ones.
    fn holds(parts: &[&[u8]]) -> bool {
        sum(parts) == 0xffff
    }

    fn pseudo(src: &[u8], dst: &[u8], number: u8, len: usize) -> Vec<u8> {
        let mut p = [src, dst].concat();
        if src.len() == 4 {
            p.extend_from_slice(&[0, number]);
            p.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            p.extend_from_slice(&(len as u32).to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, number]);
        }
        p
    }

    /// The whole answer by the witness: its checksums, its kind, who sent it to
    /// whom, and the flow its quote names. Returns the quote.
    pub(in crate::quic) fn assert_answers(packet: &[u8], local: SocketAddr, remote: SocketAddr) -> Vec<u8> {
        let (quote, kind_code) = match (local.ip(), remote.ip()) {
            (IpAddr::V4(l), IpAddr::V4(r)) => {
                assert_eq!(packet[0], 0x45);
                assert!(packet.len() <= ICMP4_MAX, "{}", packet.len());
                assert_eq!(usize::from(u16::from_be_bytes([packet[2], packet[3]])), packet.len());
                assert_eq!(packet[9], 1, "protocol ICMP");
                assert!(holds(&[&packet[..IP4_HEADER]]), "the IP header checksum");
                assert_eq!((&packet[12..16], &packet[16..20]), (&r.octets()[..], &l.octets()[..]), "from the destination to the app");
                let icmp = &packet[IP4_HEADER..];
                assert!(holds(&[icmp]), "the ICMP checksum");
                (icmp[ICMP_HEADER..].to_vec(), (icmp[0], icmp[1]))
            }
            (IpAddr::V6(l), IpAddr::V6(r)) => {
                assert_eq!(packet[0] >> 4, 6);
                assert!(packet.len() <= ICMP6_MAX, "{}", packet.len());
                assert_eq!(usize::from(u16::from_be_bytes([packet[4], packet[5]])), packet.len() - IP6_HEADER);
                assert_eq!(packet[6], ICMP6_NEXT_HEADER);
                assert_eq!((&packet[8..24], &packet[24..40]), (&r.octets()[..], &l.octets()[..]), "from the destination to the app");
                let icmp = &packet[IP6_HEADER..];
                assert!(holds(&[&pseudo(&packet[8..24], &packet[24..40], ICMP6_NEXT_HEADER, icmp.len()), icmp]), "the ICMPv6 checksum over the pseudo-header");
                (icmp[ICMP_HEADER..].to_vec(), (icmp[0], icmp[1]))
            }
            _ => panic!("mixed families have no answer"),
        };
        assert_eq!(kind_code, if local.is_ipv4() { (3, 3) } else { (1, 4) }, "port unreachable");
        let (src, dst, udp) = match local {
            SocketAddr::V4(_) => (&quote[12..16], &quote[16..20], &quote[IP4_HEADER..]),
            SocketAddr::V6(_) => (&quote[8..24], &quote[24..40], &quote[IP6_HEADER..]),
        };
        let octets = |a: IpAddr| match a {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        assert_eq!((src, dst), (&octets(local.ip())[..], &octets(remote.ip())[..]), "the quote is the app's flow");
        assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), local.port());
        assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), remote.port());
        quote
    }

    #[test]
    fn the_witness_is_sound() {
        // The sample of RFC 1071 section 3: the sum is ddf2.
        let sample = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(sum(&[&sample]), 0xddf2);
        let mut with_checksum = sample.to_vec();
        with_checksum.extend_from_slice(&(!0xddf2_u16).to_be_bytes());
        assert!(holds(&[&with_checksum]));
        with_checksum[3] ^= 0x10;
        assert!(!holds(&[&with_checksum]), "a flipped byte is caught");
    }

    #[test]
    fn v4_port_unreachable_is_checksum_correct() {
        let (local, remote) = (addr(LOCAL4), addr(REMOTE4));
        let packet = port_unreachable(local, remote, &[7; 100]).unwrap();
        assert_answers(&packet, local, remote);
        let mut broken = packet.clone();
        *broken.last_mut().unwrap() ^= 1;
        assert!(!holds(&[&broken[IP4_HEADER..]]), "the witness sees the payload");
    }

    #[test]
    fn v6_port_unreachable_is_checksum_correct() {
        let (local, remote) = (addr(LOCAL6), addr(REMOTE6));
        let packet = port_unreachable(local, remote, &[7; 100]).unwrap();
        assert_answers(&packet, local, remote);
        assert_eq!(packet[6], ICMP6_NEXT_HEADER);
    }

    #[test]
    fn the_quote_names_the_app_flow() {
        for (local, remote) in [(addr(LOCAL4), addr(REMOTE4)), (addr(LOCAL6), addr(REMOTE6))] {
            let datagram = [9u8; 300];
            let quote = assert_answers(&port_unreachable(local, remote, &datagram).unwrap(), local, remote);
            let parsed = packet::parse(&quote).expect("a whole quote parses as the app's packet");
            assert_eq!((parsed.proto, parsed.src, parsed.dst), (Proto::Udp, local.ip(), remote.ip()));
            assert_eq!((parsed.src_port, parsed.dst_port), (local.port(), remote.port()));
            assert_eq!(parsed.payload, datagram);
            let segment = [parsed.header, parsed.payload].concat();
            let (src, dst) = if local.is_ipv4() { (&quote[12..16], &quote[16..20]) } else { (&quote[8..24], &quote[24..40]) };
            assert!(holds(&[&pseudo(src, dst, UDP_NUMBER, segment.len()), &segment]), "the quote's UDP checksum");
        }
    }

    #[test]
    fn the_quote_is_cut_at_the_rfc_limit() {
        for size in [0usize, 1200, 65_000] {
            let datagram = vec![3u8; size];
            let (local, remote) = (addr(LOCAL4), addr(REMOTE4));
            let v4 = port_unreachable(local, remote, &datagram).unwrap();
            let quote = assert_answers(&v4, local, remote);
            assert_eq!(v4.len(), (IP4_HEADER + ICMP_HEADER + IP4_HEADER + 8 + size).min(ICMP4_MAX));
            assert_eq!(usize::from(u16::from_be_bytes([quote[2], quote[3]])), IP4_HEADER + 8 + size, "the IP length is the original's");
            assert_eq!(usize::from(u16::from_be_bytes([quote[24], quote[25]])), 8 + size, "the UDP length is the original's");

            let (local, remote) = (addr(LOCAL6), addr(REMOTE6));
            let v6 = port_unreachable(local, remote, &datagram).unwrap();
            let quote = assert_answers(&v6, local, remote);
            assert_eq!(v6.len(), (IP6_HEADER + ICMP_HEADER + IP6_HEADER + 8 + size).min(ICMP6_MAX));
            assert_eq!(usize::from(u16::from_be_bytes([quote[4], quote[5]])), 8 + size, "the IPv6 length is the original's");
            assert_eq!(usize::from(u16::from_be_bytes([quote[44], quote[45]])), 8 + size, "the UDP length is the original's");
        }
    }

    #[test]
    fn mixed_families_and_an_oversized_datagram_give_none() {
        assert_eq!(port_unreachable(addr(LOCAL4), addr(REMOTE6), b"x"), None);
        assert_eq!(port_unreachable(addr(LOCAL6), addr(REMOTE4), b"x"), None);
        let oversized = vec![0u8; 70_000];
        assert_eq!(port_unreachable(addr(LOCAL4), addr(REMOTE4), &oversized), None);
        assert_eq!(port_unreachable(addr(LOCAL6), addr(REMOTE6), &oversized), None);
    }

    fn any_addr() -> impl Strategy<Value = SocketAddr> {
        prop_oneof![
            (any::<[u8; 4]>(), any::<u16>()).prop_map(|(ip, port)| SocketAddr::from((ip, port))),
            (any::<[u8; 16]>(), any::<u16>()).prop_map(|(ip, port)| SocketAddr::from((ip, port))),
        ]
    }

    proptest! {
        #[test]
        fn port_unreachable_never_panics(local in any_addr(), remote in any_addr(), size in prop_oneof![0usize..2_000, 65_400usize..65_600], byte in any::<u8>()) {
            let datagram = vec![byte; size];
            if let Some(packet) = port_unreachable(local, remote, &datagram) {
                assert_answers(&packet, local, remote);
            }
        }
    }
}
