//! Windows: a relayed UDP datagram larger than the real path is answered the way a
//! router on that path answers it, with ICMP packet too big (`quic::icmp`).
//!
//! The adapter's MTU is [`crate::tun::MTU`] (9000), so apps may send datagrams of
//! up to 8972 bytes; the real path is smaller (1460 on the test VM, at most 1500 on
//! Ethernet, less under PPPoE or a VPN). TCP never meets this: ipstack terminates
//! it and the upstream connection runs Windows' own MSS and path-MTU discovery.
//!
//! The relay's upstream UDP socket runs path-MTU discovery with fragmentation off
//! (`IP_MTU_DISCOVER` / `IPV6_MTU_DISCOVER` = `IP_PMTUDISC_DO`): a datagram larger
//! than the path MTU Windows knows for the destination (the interface MTU, lowered
//! by any ICMP the path sent back) is not sent and fails with `WSAEMSGSIZE`. The
//! relay then drops it, as the router would, and answers the app with packet too
//! big carrying Windows' path MTU (`IP_MTU` / `IPV6_MTU`), so the app's own
//! discovery (RFC 1191, RFC 8201, QUIC's RFC 8899) settles on what fits.
//!
//! Not letting Windows fragment, which it does for a plain socket: QUIC sets DF
//! (RFC 9000 section 14) and a stack that probes up to the link MTU would see its
//! 8 KiB probes arrive, reassembled, and then send every packet as six fragments,
//! a whole packet lost with any one of them and many paths dropping fragments. The
//! cost: ipstack does not hand on the IPv4 DF bit, so an IPv4 datagram that allowed
//! fragmentation is answered too, and its sender learns the smaller path instead
//! of being fragmented. Such senders lost those datagrams before as well: at the
//! old 1500-byte adapter their own OS fragmented them and ipstack, which does not
//! reassemble, could not read the fragments.
//!
//! When Windows cannot say the path MTU, no number is guessed: the datagram is
//! dropped without an answer, a lost probe to the app, and counted.

use std::io;
use std::net::SocketAddr;
use std::os::windows::io::AsRawSocket;

use windows::Win32::Networking::WinSock::{
    IP_MTU, IP_MTU_DISCOVER, IP_PMTUDISC_DO, IPPROTO_IP, IPPROTO_IPV6, IPV6_MTU, IPV6_MTU_DISCOVER, SOCKET, WSAEMSGSIZE, getsockopt, setsockopt,
};

use crate::quic::{PacketSink, icmp};
use crate::stack::Meters;

/// Where one flow's too-big datagrams are answered.
pub struct TooBig<'a> {
    /// (local, remote): the app's end first.
    pub ends: (SocketAddr, SocketAddr),
    pub sink: &'a dyn PacketSink,
    pub meters: &'a Meters,
}

impl TooBig<'_> {
    /// The bytes one upstream send of `datagram` put on the path. A datagram too big
    /// for the path is dropped and answered (with `path_mtu`, when Windows knows it),
    /// and the flow goes on with 0 sent; any other failure ends it.
    pub fn after_send(&self, sent: io::Result<usize>, datagram: &[u8], path_mtu: impl FnOnce() -> Option<u16>) -> io::Result<usize> {
        match sent {
            Err(e) if is_too_big(&e) => {
                Meters::bump(&self.meters.udp_too_big);
                let answer = path_mtu().and_then(|mtu| icmp::packet_too_big(self.ends.0, self.ends.1, datagram, mtu));
                if answer.is_none_or(|packet| self.sink.send(&packet).is_err()) {
                    Meters::bump(&self.meters.udp_too_big_unanswered);
                }
                Ok(0)
            }
            other => other,
        }
    }
}

fn level(ipv4: bool) -> i32 {
    if ipv4 { IPPROTO_IP.0 } else { IPPROTO_IPV6.0 }
}

/// Turns on path-MTU discovery with fragmentation off for `socket`.
pub fn discover(socket: &impl AsRawSocket, ipv4: bool) -> Result<(), String> {
    let s = SOCKET(socket.as_raw_socket() as usize);
    let name = if ipv4 { IP_MTU_DISCOVER } else { IPV6_MTU_DISCOVER };
    let value = IP_PMTUDISC_DO.0.to_ne_bytes();
    // SAFETY: `s` is a live socket; the option value is a 4-byte DWORD.
    let r = unsafe { setsockopt(s, level(ipv4), name, Some(&value)) };
    if r == 0 { Ok(()) } else { Err(format!("setsockopt MTU_DISCOVER: {}", io::Error::last_os_error())) }
}

/// Windows' path MTU for a connected `socket`, or None when it cannot say.
pub fn of(socket: &impl AsRawSocket, ipv4: bool) -> Option<u16> {
    let s = SOCKET(socket.as_raw_socket() as usize);
    let name = if ipv4 { IP_MTU } else { IPV6_MTU };
    let mut value = [0u8; 4];
    let mut len = value.len() as i32;
    // SAFETY: `s` is a live socket; `value` is a writable 4-byte DWORD and `len` says so.
    let r = unsafe { getsockopt(s, level(ipv4), name, windows::core::PSTR(value.as_mut_ptr()), &mut len) };
    if r != 0 || len != value.len() as i32 {
        return None;
    }
    u16::try_from(u32::from_ne_bytes(value)).ok()
}

/// The send failed because the datagram is larger than the path.
pub fn is_too_big(e: &io::Error) -> bool {
    e.raw_os_error() == Some(WSAEMSGSIZE.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

    fn reads_back_discovery(socket: &UdpSocket, ipv4: bool) -> i32 {
        let s = SOCKET(socket.as_raw_socket() as usize);
        let name = if ipv4 { IP_MTU_DISCOVER } else { IPV6_MTU_DISCOVER };
        let mut value = [0u8; 4];
        let mut len = value.len() as i32;
        // SAFETY: as in `of`.
        assert_eq!(unsafe { getsockopt(s, level(ipv4), name, windows::core::PSTR(value.as_mut_ptr()), &mut len) }, 0, "{}", io::Error::last_os_error());
        i32::from_ne_bytes(value)
    }

    /// Loopback only, and connecting a UDP socket sends nothing.
    #[test]
    fn discovery_is_on_and_a_connected_socket_has_a_path_mtu() {
        for (any, peer, ipv4) in [
            (SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), SocketAddr::from((Ipv4Addr::LOCALHOST, 9)), true),
            (SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), SocketAddr::from((Ipv6Addr::LOCALHOST, 9)), false),
        ] {
            let socket = UdpSocket::bind(any).unwrap();
            assert_ne!(reads_back_discovery(&socket, ipv4), IP_PMTUDISC_DO.0, "the control: off by default");
            discover(&socket, ipv4).unwrap();
            assert_eq!(reads_back_discovery(&socket, ipv4), IP_PMTUDISC_DO.0, "ipv4 {ipv4}");
            socket.connect(peer).unwrap();
            // Loopback's MTU does not fit 16 bits on Windows, so either answer is right;
            // a value that fits is a real MTU.
            if let Some(mtu) = of(&socket, ipv4) {
                assert!(mtu >= IPV6_MIN_MTU, "{mtu}");
            }
        }
    }

    /// RFC 8200 section 5: no link Windows runs IP on is smaller.
    const IPV6_MIN_MTU: u16 = 1280;
    const PATH_MTU: u16 = 1460;

    #[derive(Default)]
    struct Sink {
        sent: std::sync::Mutex<Vec<Vec<u8>>>,
        fails: bool,
    }

    impl PacketSink for Sink {
        fn send(&self, ip_packet: &[u8]) -> io::Result<()> {
            if self.fails {
                return Err(io::Error::other("the session is gone"));
            }
            self.sent.lock().unwrap().push(ip_packet.to_vec());
            Ok(())
        }
    }

    fn ends() -> (SocketAddr, SocketAddr) {
        ("198.18.0.2:50000".parse().unwrap(), "192.0.2.1:443".parse().unwrap())
    }

    fn too_big() -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(WSAEMSGSIZE.0))
    }

    fn counts(meters: &Meters) -> (u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (meters.udp_too_big.load(Relaxed), meters.udp_too_big_unanswered.load(Relaxed))
    }

    #[test]
    fn a_too_big_datagram_is_answered_with_the_path_mtu_and_the_flow_goes_on() {
        let (sink, meters) = (Sink::default(), Meters::default());
        let reply = TooBig { ends: ends(), sink: &sink, meters: &meters };
        let datagram = [7u8; 8_000];
        assert_eq!(reply.after_send(too_big(), &datagram, || Some(PATH_MTU)).unwrap(), 0, "nothing went up");
        let sent = sink.sent.lock().unwrap().clone();
        assert_eq!(sent, [icmp::packet_too_big(ends().0, ends().1, &datagram, PATH_MTU).unwrap()]);
        assert_eq!(counts(&meters), (1, 0));
    }

    #[test]
    fn a_sent_datagram_is_not_answered_and_another_failure_ends_the_flow() {
        let (sink, meters) = (Sink::default(), Meters::default());
        let reply = TooBig { ends: ends(), sink: &sink, meters: &meters };
        let unasked = || -> Option<u16> { panic!("the path MTU is read only for a too-big datagram") };
        assert_eq!(reply.after_send(Ok(1_200), &[1; 1_200], unasked).unwrap(), 1_200);
        let reset = io::Error::from_raw_os_error(10054);
        assert_eq!(reply.after_send(Err(reset), &[1; 1_200], unasked).unwrap_err().raw_os_error(), Some(10054));
        assert!(sink.sent.lock().unwrap().is_empty());
        assert_eq!(counts(&meters), (0, 0));
    }

    /// No guessed MTU: unknown to Windows, or no way back to the app, is a silent drop.
    #[test]
    fn an_unknown_path_mtu_or_a_gone_adapter_drops_without_an_answer() {
        let meters = Meters::default();
        let sink = Sink::default();
        TooBig { ends: ends(), sink: &sink, meters: &meters }.after_send(too_big(), &[7; 8_000], || None).unwrap();
        assert!(sink.sent.lock().unwrap().is_empty());
        let gone = Sink { fails: true, ..Sink::default() };
        TooBig { ends: ends(), sink: &gone, meters: &meters }.after_send(too_big(), &[7; 8_000], || Some(PATH_MTU)).unwrap();
        assert_eq!(counts(&meters), (2, 2));
    }

    #[test]
    fn only_wsaemsgsize_is_too_big() {
        assert!(is_too_big(&io::Error::from_raw_os_error(WSAEMSGSIZE.0)));
        for other in [io::Error::from_raw_os_error(10054), io::Error::other("closed"), io::ErrorKind::WouldBlock.into()] {
            assert!(!is_too_big(&other), "{other}");
        }
    }
}
