//! QUIC under `filtering.https` (plan section 3, slice 8). QUIC is not
//! terminated. A flow the same policy would decrypt over TCP is refused, so the
//! browser falls back to TCP where interception filters it. Every other flow is
//! decoded and relayed: refusal follows from the filtering decision, not from
//! QUIC, and nothing is sent upstream for a refused flow.
//!
//! - [`path`]: the one gate, after the host-level decision;
//! - [`refuse`]: a refused flow, to its idle end, and a blocked one the same way;
//! - [`icmp`]: the packet; [`fallback`]: the fallback-time measurement.
//!
//! Refused exactly when `sieve_filter::exclusions::decrypt` says `Intercept`:
//! there is no second condition, and every "relayed for" case is a `PassReason`.
//! A blocked flow needs none of this: it is answered with the slot empty too.

pub mod fallback;
pub mod icmp;
#[cfg(test)]
pub(crate) mod tests;

use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use sieve_filter::exclusions::{Decrypt, Transport};
use sieve_ipc::FlowAction;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::flow::classify::{Decoded, Kind};
use crate::flow::flows::Action;
use crate::stack::Meters;
use crate::stack::book::FlowBook;
use crate::tls::intercept::{Dial, HttpsSlot, Who};
use fallback::QuicMeters;

/// How a refused flow is told. Both arms are built and tested; which one stands
/// is decided by the live numbers, `docs/live/engine-slice-8.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    PortUnreachable,
    SilentDrop,
}

impl Refusal {
    fn word(self) -> &'static str {
        match self {
            Self::PortUnreachable => "port_unreachable",
            Self::SilentDrop => "silent_drop",
        }
    }
}

/// Plan section 3: if ICMP proves no faster than a drop, this word changes.
pub const REFUSAL: Refusal = Refusal::PortUnreachable;

/// How a blocked UDP flow is told. Apart from [`REFUSAL`]: that word is flipped to
/// measure TCP fallback, and a blocked flow has nothing to fall back to, so silence
/// only makes the browser wait out QUIC's idle timeout.
pub const BLOCKED_ANSWER: Refusal = Refusal::PortUnreachable;

/// The log's word for a refused flow. The app shows a slug it does not know
/// with spaces (`reasonWords` in `src/core/log.ts`), so no protocol bump.
pub const QUIC_REFUSED: &str = "quic_refused";

/// Where an IP packet goes back to the apps: `tun::device::TunSink` in
/// production, a fake in tests, so no test sends a real packet.
pub trait PacketSink: Send + Sync {
    fn send(&self, ip_packet: &[u8]) -> std::io::Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpPath {
    /// A blocked name: nothing goes upstream and each datagram is answered with
    /// [`BLOCKED_ANSWER`] until idle.
    Drop,
    Refuse(Refusal),
    Relay,
}

/// The way one decided UDP flow goes on. No slot relays with nothing asked, so
/// off is provably today's path. A flow that is not QUIC, including a live
/// connection coming back with a short header after idling, is never refused.
pub fn path<C: Dial>(action: Action, slot: &HttpsSlot<C>, decoded: &Decoded, who: &Who<'_>, id: u64) -> UdpPath {
    if action == Action::Drop {
        return UdpPath::Drop;
    }
    let Some(https) = slot.get() else { return UdpPath::Relay };
    if decoded.kind != Some(Kind::Quic) {
        return UdpPath::Relay;
    }
    match https.before_upstream(https.facts_for(Transport::Quic, decoded, who)) {
        Decrypt::Intercept => {
            https.not_decrypted_row(id, QUIC_REFUSED);
            UdpPath::Refuse(REFUSAL)
        }
        Decrypt::PassThrough(reason) => {
            https.not_decrypted(id, &reason);
            UdpPath::Relay
        }
    }
}

/// A refused flow's book entry. `Relayed` with 0 bytes is a false word on the
/// wire, kept on purpose (task Q2): `FlowAction` has nothing true for this, the
/// app does not read the action, `Blocked` would count against the block figures
/// when nothing was blocked, and a new variant is a protocol bump.
pub fn close_refused(book: &Mutex<FlowBook>, id: u64) {
    book.lock().unwrap_or_else(|p| p.into_inner()).close(id, FlowAction::Relayed, 0, 0);
}

/// What answers one refused or blocked flow.
pub struct Reply<'a> {
    /// (local, remote): the app's end first.
    pub ends: (SocketAddr, SocketAddr),
    pub refusal: Refusal,
    pub sink: &'a dyn PacketSink,
    pub meters: &'a QuicMeters,
    /// Which figure a sent answer moves: refused and blocked flows are read apart.
    pub replies: &'a AtomicU64,
}

impl Reply<'_> {
    /// At most one small packet per datagram the local app itself sent, so
    /// there is no amplification and no rate limit to invent. A failed send
    /// leaves a silent drop, the fail-open direction.
    fn answer(&self, datagram: &[u8]) {
        if self.refusal == Refusal::SilentDrop {
            return;
        }
        let Some(packet) = icmp::port_unreachable(self.ends.0, self.ends.1, datagram) else { return };
        match self.sink.send(&packet) {
            Ok(()) => Meters::bump(self.replies),
            Err(_) => Meters::bump(&self.meters.send_failed),
        }
    }
}

/// Answers the held datagrams and each later one until the flow has been idle
/// for `idle`, so a retransmit costs no new attribution. `still_on` is asked per
/// datagram: with the switch off or the app Off the refusal ends, and the datagrams
/// not answered are returned, to be judged as a new flow. None is lost. Empty when
/// the flow simply ended. An idle flow costs nothing and needs no wake.
pub async fn refuse<A: AsyncRead + Unpin>(app: &mut A, reply: &Reply<'_>, held: Vec<Vec<u8>>, buf: &mut [u8], idle: Duration, still_on: impl Fn() -> bool) -> Vec<Vec<u8>> {
    for (at, datagram) in held.iter().enumerate() {
        if !still_on() {
            return held[at..].to_vec();
        }
        reply.answer(datagram);
    }
    while let Ok(Ok(n)) = tokio::time::timeout(idle, app.read(buf)).await {
        if n == 0 {
            break;
        }
        if !still_on() {
            return vec![buf[..n].to_vec()];
        }
        reply.answer(&buf[..n]);
    }
    Vec::new()
}
