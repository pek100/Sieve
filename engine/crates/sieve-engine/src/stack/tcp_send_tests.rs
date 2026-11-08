//! ipstack's TCP send path (server bytes to the app) at the MTUs the engine runs,
//! through a real `IpStack` in memory. The test plays the app's stack: it ACKs every
//! data segment it gets, and can lose a segment or an ACK. After that it sends
//! nothing more on its own, as a browser waiting on a response does until its
//! 45 s keep-alive.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use etherparse::{PacketHeaders, TcpHeader, TransportHeader};
use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, TcpConfig};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::relay_tests::{Flags, segment};
use crate::quic::tests::{FLOWS, MemDevice};

const CLIENT_ISN: u32 = 1_000;
/// What the relay hands the stack per write: `tokio::io::copy`'s buffer.
const RELAY_WRITE: usize = 8 * 1024;
/// More than ipstack's 16 KiB unacknowledged-byte cap, so the cap fills.
const TRANSFER: usize = 4 * RELAY_WRITE;
const ENGINE_MTU: u16 = 1500;
const JUMBO_MTU: u16 = 9000;
/// ipstack's 1 s RTO and its first doubling, with room: a resend must come by then.
const RECOVERY: Duration = Duration::from_secs(5);
/// A short RTO for the laws about running out of retransmissions: ipstack gives up
/// after three, at 20 + 40 + 80 + 160 ms.
const SHORT_RTO: Duration = Duration::from_millis(20);
/// Well past those four timeouts.
const PAST_GIVING_UP: Duration = Duration::from_secs(1);

/// One accepted flow, the app-side end of it, and what reached the app so far.
struct Bed {
    to_stack: mpsc::UnboundedSender<Vec<u8>>,
    from_stack: mpsc::UnboundedReceiver<Vec<u8>>,
    _stack: IpStack,
    local: SocketAddr,
    remote: SocketAddr,
    window: u16,
    /// The next server byte in order, and the server's first data byte.
    rcv_nxt: u32,
    first: u32,
    /// Server bytes in order, and those that came early, by offset.
    data: Vec<u8>,
    early: BTreeMap<u32, Vec<u8>>,
    /// Data segments seen, lost ones included.
    arrivals: usize,
    writer: JoinHandle<()>,
}

impl Bed {
    async fn new(flow: (&str, &str), mtu: u16, window: u16) -> Self {
        Self::with_tcp(flow, mtu, window, TcpConfig::default()).await
    }

    async fn with_tcp(flow: (&str, &str), mtu: u16, window: u16, tcp_config: TcpConfig) -> Self {
        let (local, remote): (SocketAddr, SocketAddr) = (flow.0.parse().unwrap(), flow.1.parse().unwrap());
        let (to_stack, rx) = mpsc::unbounded_channel();
        let (tx, mut from_stack) = mpsc::unbounded_channel();
        let mut config = IpStackConfig::default();
        config.mtu(mtu).unwrap().with_tcp_config(tcp_config);
        let mut stack = IpStack::new(config, MemDevice { rx, tx });
        let flags = Flags { syn: true, window: Some(window), ..Flags::default() };
        to_stack.send(segment(local, remote, CLIENT_ISN, flags, &[])).unwrap();
        let Ok(IpStackStream::Tcp(app)) = stack.accept().await else { panic!("no TCP stream") };
        let syn_ack = tokio::time::timeout(RECOVERY, from_stack.recv()).await.expect("a SYN-ACK").unwrap();
        let (header, _) = tcp(&syn_ack);
        assert!(header.syn && header.ack, "{header:?}");
        let rcv_nxt = header.sequence_number.wrapping_add(1);
        let mut bed = Self {
            to_stack, from_stack, _stack: stack, local, remote, window,
            rcv_nxt, first: rcv_nxt,
            data: Vec::new(), early: BTreeMap::new(), arrivals: 0,
            writer: tokio::spawn(write_all(app)),
        };
        bed.ack();
        bed
    }

    fn ack(&mut self) {
        let flags = Flags { ack: Some(self.rcv_nxt), window: Some(self.window), ..Flags::default() };
        self.to_stack.send(segment(self.local, self.remote, CLIENT_ISN + 1, flags, &[])).unwrap();
    }

    async fn next(&mut self, deadline: Instant) -> Option<(TcpHeader, Vec<u8>)> {
        let left = deadline.saturating_duration_since(Instant::now());
        let packet = tokio::time::timeout(left, self.from_stack.recv()).await.ok()??;
        Some(tcp(&packet))
    }

    /// Takes data segments until all of [`TRANSFER`] is in order, or until `budget`
    /// passes. `lose_segment` and `lose_ack` see each data segment's arrival index.
    async fn receive(&mut self, budget: Duration, lose_segment: impl Fn(usize) -> bool, lose_ack: impl Fn(usize) -> bool) {
        let deadline = Instant::now() + budget;
        while self.data.len() < TRANSFER {
            let Some((header, payload)) = self.next(deadline).await else { break };
            if !payload.is_empty() {
                let index = self.arrivals;
                self.arrivals += 1;
                if !lose_segment(index) {
                    self.take(&header, payload);
                    if !lose_ack(index) {
                        self.ack();
                    }
                }
            }
        }
    }

    fn take(&mut self, header: &TcpHeader, payload: Vec<u8>) {
        self.early.entry(header.sequence_number.wrapping_sub(self.first)).or_insert(payload);
        while let Some(bytes) = self.early.remove(&u32::try_from(self.data.len()).unwrap()) {
            self.data.extend_from_slice(&bytes);
        }
        // A retransmission that overlaps what is already in order.
        let in_order = u32::try_from(self.data.len()).unwrap();
        self.early.retain(|&at, bytes| at + u32::try_from(bytes.len()).unwrap() > in_order);
        self.rcv_nxt = self.first.wrapping_add(in_order);
    }

    /// Every segment the stack sends within `wait`, the app sending nothing.
    async fn listen(&mut self, wait: Duration) -> Vec<(TcpHeader, Vec<u8>)> {
        let deadline = Instant::now() + wait;
        let mut got = Vec::new();
        while let Some(segment) = self.next(deadline).await {
            got.push(segment);
        }
        got
    }
}

impl Drop for Bed {
    fn drop(&mut self) {
        self.writer.abort();
    }
}

fn tcp(packet: &[u8]) -> (TcpHeader, Vec<u8>) {
    let headers = PacketHeaders::from_ip_slice(packet).unwrap();
    let Some(TransportHeader::Tcp(header)) = headers.transport else { panic!("not TCP") };
    (header, headers.payload.slice().to_vec())
}

fn transfer() -> Vec<u8> {
    (0..TRANSFER).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

fn short_rto() -> TcpConfig {
    let mut config = TcpConfig::default();
    config.rto = SHORT_RTO;
    config
}

/// The relay's side: the server's bytes, a relay write at a time. It keeps the
/// stream open afterwards, as a flow waiting on more does.
async fn write_all(mut app: IpStackTcpStream) {
    for chunk in transfer().chunks(RELAY_WRITE) {
        app.write_all(chunk).await.unwrap();
    }
    std::future::pending::<()>().await;
}

/// The control: at the engine's MTU a lost segment is followed by enough duplicate
/// ACKs for ipstack's fast retransmit, so the flow recovers with the app silent.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_segment_at_the_engine_mtu_is_resent() {
    for flow in FLOWS {
        let mut bed = Bed::new(flow, ENGINE_MTU, u16::MAX).await;
        bed.receive(RECOVERY, |i| i == 1, |_| false).await;
        assert_eq!(bed.data, transfer(), "{flow:?}");
    }
}

/// At MTU 9000 the cap holds two segments, so a loss brings one duplicate ACK, not
/// three. The resend must come from ipstack's own timer: nothing else arrives.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_segment_at_mtu_9000_is_resent_with_the_app_silent() {
    for flow in FLOWS {
        let mut bed = Bed::new(flow, JUMBO_MTU, u16::MAX).await;
        bed.receive(RECOVERY, |i| i == 1, |_| false).await;
        assert_eq!(bed.data.len(), TRANSFER, "{flow:?}: the lost segment was never resent");
        assert_eq!(bed.data, transfer());
    }
}

/// The ACKs of one full flight are lost: the cap is full and the app has all it
/// was sent. Only a retransmission draws a new ACK.
#[tokio::test(flavor = "multi_thread")]
async fn lost_acks_for_a_full_flight_at_mtu_9000_are_recovered() {
    for flow in FLOWS {
        let mut bed = Bed::new(flow, JUMBO_MTU, u16::MAX).await;
        bed.receive(RECOVERY, |_| false, |i| i < 2).await;
        assert_eq!(bed.data.len(), TRANSFER, "{flow:?}: nothing was resent after the lost ACKs");
        assert_eq!(bed.data, transfer());
    }
}

/// A segment that never gets through ends the flow with a reset once its
/// retransmissions run out, not with a gap the app's stack waits on for ever.
#[tokio::test(flavor = "multi_thread")]
async fn a_segment_out_of_retransmissions_resets_the_flow() {
    for flow in FLOWS {
        let mut bed = Bed::with_tcp(flow, JUMBO_MTU, u16::MAX, short_rto()).await;
        let sent = bed.listen(PAST_GIVING_UP).await;
        let resends = sent.iter().filter(|(h, payload)| !payload.is_empty() && h.sequence_number == bed.first).count();
        assert_eq!(resends, 4, "{flow:?}: the first send and three retransmissions");
        assert!(sent.last().is_some_and(|(h, _)| h.rst), "{flow:?}: no reset after the retransmissions ran out");
    }
}

/// While the app's window is zero no bytes fit, so the timer counts nothing toward
/// giving up: the flow waits, and resumes when the window opens.
#[tokio::test(flavor = "multi_thread")]
async fn a_closed_window_is_waited_out_not_reset() {
    for flow in FLOWS {
        let mut bed = Bed::with_tcp(flow, JUMBO_MTU, u16::MAX, short_rto()).await;
        bed.window = 0;
        // The first segment's ACK closes the window; the second stays unacknowledged.
        bed.receive(PAST_GIVING_UP / 4, |_| false, |i| i > 0).await;
        assert_eq!(bed.data.len(), 2 * RELAY_WRITE, "{flow:?}: both segments were out before the window closed");
        let sent = bed.listen(PAST_GIVING_UP).await;
        assert!(sent.iter().all(|(h, payload)| !h.rst && payload.is_empty()), "{flow:?}: data or a reset into a closed window");
        bed.window = u16::MAX;
        bed.ack();
        bed.receive(RECOVERY, |_| false, |_| false).await;
        assert_eq!(bed.data, transfer(), "{flow:?}");
    }
}
