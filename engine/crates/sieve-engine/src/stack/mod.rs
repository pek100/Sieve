//! The relay of every flow (plan 1.1, slice 3): ipstack terminates each flow
//! that enters the adapter, the flow is attributed to its process, its first
//! bytes are decoded (SNI, Host, QUIC Initial), and it is relayed to its
//! destination through a socket pinned to the interface Windows would use
//! without Sieve. A flow to port 53 is answered by `dns::service` instead. Slice
//! 3 filters nothing: every flow is relayed (or fails to connect, and is closed
//! at once).
//!
//! - [`book`]: the flows as the app sees them, batched for the pipe;
//! - [`Meters`]: the engine's own counters (attribution is read from them);
//! - `relay` (Windows): the per-flow tasks; `dns_flow` (Windows): port 53;
//! - `egress` (Windows): the pinned sockets both of them leave through.

pub mod book;
#[cfg(feature = "attribution-diagnostics")]
pub mod diagnostics;
#[cfg(windows)]
pub mod dns_flow;
#[cfg(windows)]
pub mod egress;
#[cfg(windows)]
pub mod relay;

use std::sync::atomic::{AtomicU64, Ordering};

use sieve_ipc::{Counters, FlowKind};

use crate::flow::classify::{Decoded, Kind};

/// Counters since the engine started.
#[derive(Debug, Default)]
pub struct Meters {
    #[cfg(feature = "attribution-diagnostics")]
    pub attribution: std::sync::Mutex<diagnostics::Report>,
    pub flows: AtomicU64,
    pub attributed: AtomicU64,
    pub own_refused: AtomicU64,
    pub dns_answers: AtomicU64,
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub not_unicast: AtomicU64,
}

impl Meters {
    pub fn bump(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn counters(&self) -> Counters {
        let l = |c: &AtomicU64| c.load(Ordering::Relaxed);
        Counters {
            flows: l(&self.flows),
            attributed: l(&self.attributed),
            own_refused: l(&self.own_refused),
            dns_answers: l(&self.dns_answers),
            packets_in: l(&self.packets_in),
            packets_out: l(&self.packets_out),
            not_unicast: l(&self.not_unicast),
        }
    }
}

/// The wire kind of a decoded flow.
pub fn kind_of(d: &Decoded) -> FlowKind {
    match d.kind {
        Some(Kind::Tls) => FlowKind::Tls,
        Some(Kind::Http) => FlowKind::Http,
        Some(Kind::Quic) => FlowKind::Quic,
        None => FlowKind::Other,
    }
}

/// The port DNS is caught on (UDP and TCP), whatever the server address.
pub const DNS_PORT: u16 = 53;

/// A bound, non-blocking socket from a connector, handed to the runtime.
pub fn datagram_socket(socket: socket2::Socket) -> std::io::Result<tokio::net::UdpSocket> {
    tokio::net::UdpSocket::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_read_what_was_counted() {
        let m = Meters::default();
        Meters::bump(&m.flows);
        Meters::bump(&m.flows);
        Meters::bump(&m.attributed);
        let c = m.counters();
        assert_eq!((c.flows, c.attributed, c.own_refused), (2, 1, 0));
    }

    #[test]
    fn decoded_kinds_map_to_wire_kinds() {
        let d = |kind| Decoded { kind, ..Decoded::default() };
        assert_eq!(kind_of(&d(Some(Kind::Tls))), FlowKind::Tls);
        assert_eq!(kind_of(&d(Some(Kind::Http))), FlowKind::Http);
        assert_eq!(kind_of(&d(Some(Kind::Quic))), FlowKind::Quic);
        assert_eq!(kind_of(&d(None)), FlowKind::Other);
    }
}
