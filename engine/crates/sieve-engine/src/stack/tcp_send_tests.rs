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
/// What a zero-window probe carries (RFC 9293 3.8.6.1).
const PROBE: usize = 1;

/// One accepted flow, the app-side end of it, and what reached the app so far.
struct Bed {
    to_stack: mpsc::UnboundedSender<Vec<u8>>,
    from_stack: mpsc::UnboundedReceiver<Vec<u8>>,
    _stack: IpStack,
    local: SocketAddr,
    remote: SocketAddr,
    /// The app's receive window now, and the one its latest ACK advertised: a window
    /// can open without the stack hearing of it (a lost update).
    window: u16,
    advertised: u16,
    /// The next server byte in order, the latest ACK sent, and the server's first data byte.
    rcv_nxt: u32,
    acked: u32,
    first: u32,
    /// Server bytes in order, and those that came early, by offset.
    data: Vec<u8>,
    early: BTreeMap<u32, Vec<u8>>,
    /// Data segments seen, lost ones included.
    arrivals: usize,
    /// Bytes sent past the window the app had advertised in its latest ACK.
    beyond_window: usize,
    writer: JoinHandle<()>,
}

impl Bed {
    async fn new(flow: (&str, &str), mtu: u16, window: u16) -> Self {
        Self::with_tcp(flow, mtu, window, TcpConfig::default()).await
    }

    async fn with_tcp(flow: (&str, &str), mtu: u16, window: u16, tcp_config: TcpConfig) -> Self {
        let mut bed = Self::before_handshake_ack(flow, mtu, window, tcp_config).await;
        bed.ack();
        bed
    }

    /// The SYN sent and the SYN-ACK taken; the handshake's last ACK not yet sent.
    async fn before_handshake_ack(flow: (&str, &str), mtu: u16, window: u16, tcp_config: TcpConfig) -> Self {
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
        Self {
            to_stack, from_stack, _stack: stack, local, remote, window, advertised: window,
            rcv_nxt, acked: rcv_nxt, first: rcv_nxt,
            data: Vec::new(), early: BTreeMap::new(), arrivals: 0, beyond_window: 0,
            writer: tokio::spawn(write_all(app)),
        }
    }

    fn ack(&mut self) {
        self.acked = self.rcv_nxt;
        self.advertised = self.window;
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

    /// A one-byte segment at the last ACK of a closed window: RFC 9293 3.8.6.1.
    fn is_probe(&self, header: &TcpHeader, payload: &[u8]) -> bool {
        self.advertised == 0 && payload.len() == PROBE && header.sequence_number == self.acked
    }

    fn take(&mut self, header: &TcpHeader, payload: Vec<u8>) {
        let end = header.sequence_number.wrapping_add(u32::try_from(payload.len()).unwrap());
        let edge = self.acked.wrapping_add(u32::from(self.advertised));
        if self.is_probe(header, &payload) {
            // The probe's byte is kept only once the window is open again.
            if self.window == 0 {
                return;
            }
        } else if is_after(end, edge) {
            self.beyond_window += usize::try_from(end.wrapping_sub(edge)).unwrap();
        }
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

/// `a` is after `b` in sequence space.
fn is_after(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < u32::MAX / 2
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
/// giving up: the flow waits, probing, and resumes when the window opens.
#[tokio::test(flavor = "multi_thread")]
async fn a_closed_window_is_waited_out_not_reset() {
    for flow in FLOWS {
        let mut bed = Bed::with_tcp(flow, JUMBO_MTU, u16::MAX, short_rto()).await;
        bed.window = 0;
        // The first segment's ACK closes the window; the second stays unacknowledged.
        bed.receive(PAST_GIVING_UP / 4, |_| false, |i| i > 0).await;
        assert_eq!(bed.data.len(), 2 * RELAY_WRITE, "{flow:?}: both segments were out before the window closed");
        let sent = bed.listen(PAST_GIVING_UP).await;
        assert!(sent.iter().any(|(h, payload)| bed.is_probe(h, payload)), "{flow:?}: no zero-window probe");
        let into_window = |(h, payload): &&(TcpHeader, Vec<u8>)| h.rst || !(payload.is_empty() || bed.is_probe(h, payload));
        assert_eq!(sent.iter().find(into_window), None, "{flow:?}: data or a reset into a closed window");
        bed.window = u16::MAX;
        bed.ack();
        bed.receive(RECOVERY, |_| false, |_| false).await;
        assert_eq!(bed.data, transfer(), "{flow:?}");
    }
}

/// A segment held while the window was closed goes out as soon as an ACK opens it,
/// not when its timer, doubled meanwhile, runs out. The app answers each probe.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_segment_is_resent_once_the_window_opens() {
    /// Past ipstack's 1 s RTO and the 2 s it doubled to before the fix: its resend was
    /// then due 7 s in, and with the fix but no catch-up at the next 1 s probe tick.
    const CLOSED: Duration = Duration::from_millis(3_300);
    const PROMPT: Duration = Duration::from_millis(400);
    for flow in FLOWS {
        let mut bed = Bed::new(flow, JUMBO_MTU, u16::MAX).await;
        bed.window = 0;
        // The first segment's ACK closes the window; the second is lost.
        bed.receive(CLOSED, |i| i == 1, |_| false).await;
        assert_eq!(bed.data.len(), RELAY_WRITE, "{flow:?}");
        bed.window = u16::MAX;
        bed.ack();
        bed.receive(PROMPT, |_| false, |_| false).await;
        assert_eq!(bed.data.len(), TRANSFER, "{flow:?}: the held segment waited on its timer");
        assert_eq!(bed.data, transfer());
    }
}

/// The app's window opens but its update is lost: everything was acknowledged, so
/// only the stack's zero-window probe can learn of it.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_window_update_is_found_by_the_probe() {
    for flow in FLOWS {
        let mut bed = Bed::new(flow, JUMBO_MTU, u16::MAX).await;
        bed.window = 0;
        bed.receive(PAST_GIVING_UP / 4, |_| false, |_| false).await;
        assert_eq!(bed.data.len(), 2 * RELAY_WRITE, "{flow:?}: both segments acknowledged, the window closed");
        bed.window = u16::MAX;
        bed.receive(RECOVERY, |_| false, |_| false).await;
        assert_eq!(bed.data.len(), TRANSFER, "{flow:?}: no probe found the open window");
        assert_eq!(bed.data, transfer());
    }
}

/// The relay's bytes wait for the handshake's last ACK: none go out in SYN-RECEIVED.
#[tokio::test(flavor = "multi_thread")]
async fn no_data_goes_out_before_the_handshake_completes() {
    const WAIT: Duration = Duration::from_millis(300);
    for flow in FLOWS {
        let mut bed = Bed::before_handshake_ack(flow, JUMBO_MTU, u16::MAX, TcpConfig::default()).await;
        let early = bed.listen(WAIT).await;
        assert!(early.iter().all(|(_, payload)| payload.is_empty()), "{flow:?}: data before the ACK");
        bed.ack();
        bed.receive(RECOVERY, |_| false, |_| false).await;
        assert_eq!(bed.data, transfer(), "{flow:?}");
    }
}

/// An app window smaller than the cap: the first flight, sent before any data ACK,
/// fills that window and goes no byte past it, at either MTU.
#[tokio::test(flavor = "multi_thread")]
async fn the_first_flight_fills_the_apps_window_and_no_more() {
    const SMALL_WINDOW: u16 = 10_000;
    /// Under ipstack's 1 s RTO, so no retransmission is in the flight.
    const FLIGHT: Duration = Duration::from_millis(300);
    for mtu in [ENGINE_MTU, JUMBO_MTU] {
        for flow in FLOWS {
            let mut bed = Bed::new(flow, mtu, SMALL_WINDOW).await;
            bed.receive(FLIGHT, |_| false, |_| true).await;
            assert_eq!(bed.beyond_window, 0, "MTU {mtu} {flow:?}: bytes past the window");
            assert_eq!(bed.data, transfer()[..usize::from(SMALL_WINDOW)], "MTU {mtu} {flow:?}");
        }
    }
}

// ---- The app's end (2026-11-09, run 7): the FIN reaches the reader as the end, at once.

/// How soon the reader must hear of the app's end: at once, by the packet that ends it,
/// not by a timer. Far under the 30 s and 60 s timeouts it waited for before, with room
/// for a loaded test machine; the live check holds it to self-healing's 2 s.
const END_HEARD: Duration = Duration::from_secs(5);

/// One accepted flow whose app-side stream the test reads: the handshake done, and
/// the stack's next sequence number.
async fn reading_bed(flow: (&str, &str)) -> (mpsc::UnboundedSender<Vec<u8>>, mpsc::UnboundedReceiver<Vec<u8>>, IpStack, IpStackTcpStream, SocketAddr, SocketAddr, u32) {
    reading_bed_with(flow, super::relay::tcp_config()).await
}

#[allow(clippy::type_complexity)]
async fn reading_bed_with(flow: (&str, &str), tcp_config: TcpConfig) -> (mpsc::UnboundedSender<Vec<u8>>, mpsc::UnboundedReceiver<Vec<u8>>, IpStack, IpStackTcpStream, SocketAddr, SocketAddr, u32) {
    let (local, remote): (SocketAddr, SocketAddr) = (flow.0.parse().unwrap(), flow.1.parse().unwrap());
    let (to_stack, rx) = mpsc::unbounded_channel();
    let (tx, mut from_stack) = mpsc::unbounded_channel();
    let mut config = IpStackConfig::default();
    config.mtu(ENGINE_MTU).unwrap().with_tcp_config(tcp_config);
    let mut stack = IpStack::new(config, MemDevice { rx, tx });
    to_stack.send(segment(local, remote, CLIENT_ISN, Flags { syn: true, ..Flags::default() }, &[])).unwrap();
    let Ok(IpStackStream::Tcp(app)) = stack.accept().await else { panic!("no TCP stream") };
    let syn_ack = tokio::time::timeout(RECOVERY, from_stack.recv()).await.expect("a SYN-ACK").unwrap();
    let server_next = tcp(&syn_ack).0.sequence_number.wrapping_add(1);
    to_stack.send(segment(local, remote, CLIENT_ISN + 1, Flags { ack: Some(server_next), ..Flags::default() }, &[])).unwrap();
    (to_stack, from_stack, stack, app, local, remote, server_next)
}

/// The reader, already waiting when the app's bytes and FIN arrive, as the TLS side of
/// an intercepted flow waits for a request: it ends with what the app sent.
fn read_to_end(mut app: IpStackTcpStream) -> JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut got = Vec::new();
        app.read_to_end(&mut got).await.unwrap();
        got
    })
}

/// Run 7, slice 7 U1: curl over Schannel completed the handshake and closed with a
/// bare FIN; the reader slept until hyper's 30 s timeout, so self-healing never heard
/// a quiet close. The same holds for a FIN that carries the app's last bytes, which
/// upstream dropped (FIN|PSH|ACK matched no branch).
#[tokio::test(flavor = "multi_thread")]
async fn the_apps_fin_ends_the_read_at_once_after_its_bytes() {
    const LAST: &[u8] = b"the app's last bytes";
    for flow in FLOWS {
        for carried in [false, true] {
            let (to_stack, mut from_stack, _stack, app, local, remote, server_next) = reading_bed(flow).await;
            let reader = read_to_end(app);
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!reader.is_finished(), "{flow:?}: the control, nothing said yet");
            let ack = Some(server_next);
            let len = u32::try_from(LAST.len()).unwrap();
            if carried {
                to_stack.send(segment(local, remote, CLIENT_ISN + 1, Flags { psh: true, fin: true, ack, ..Flags::default() }, LAST)).unwrap();
            } else {
                to_stack.send(segment(local, remote, CLIENT_ISN + 1, Flags { psh: true, ack, ..Flags::default() }, LAST)).unwrap();
                to_stack.send(segment(local, remote, CLIENT_ISN + 1 + len, Flags { fin: true, ack, ..Flags::default() }, &[])).unwrap();
            }
            let got = tokio::time::timeout(END_HEARD, reader).await.unwrap_or_else(|_| panic!("{flow:?} carried {carried}: the end was not read")).unwrap();
            assert_eq!(got, LAST, "{flow:?} carried {carried}");
            // The stack acknowledged the bytes and the FIN.
            let deadline = Instant::now() + RECOVERY;
            let mut acked = 0;
            while let Ok(Some(packet)) = tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), from_stack.recv()).await {
                let (header, _) = tcp(&packet);
                acked = acked.max(header.acknowledgment_number.wrapping_sub(CLIENT_ISN + 1));
                if header.fin {
                    break;
                }
            }
            assert_eq!(acked, len + 1, "{flow:?} carried {carried}: every byte and the FIN acknowledged");
        }
    }
}

/// The control of the rule: a FIN ahead of a lost segment is not yet the end; the
/// read waits for the missing bytes, then ends with all of them in order.
#[tokio::test(flavor = "multi_thread")]
async fn a_fin_ahead_of_a_gap_is_not_the_end() {
    for flow in FLOWS {
        let (to_stack, _from_stack, _stack, app, local, remote, server_next) = reading_bed(flow).await;
        let reader = read_to_end(app);
        let ack = Some(server_next);
        to_stack.send(segment(local, remote, CLIENT_ISN + 1 + 5, Flags { psh: true, fin: true, ack, ..Flags::default() }, b"world")).unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!reader.is_finished(), "{flow:?}: the first five bytes never came");
        to_stack.send(segment(local, remote, CLIENT_ISN + 1, Flags { psh: true, ack, ..Flags::default() }, b"hello")).unwrap();
        // What the app's stack does when the FIN goes unacknowledged: it sends it again.
        to_stack.send(segment(local, remote, CLIENT_ISN + 1 + 5, Flags { psh: true, fin: true, ack, ..Flags::default() }, b"world")).unwrap();
        let got = tokio::time::timeout(END_HEARD, reader).await.unwrap_or_else(|_| panic!("{flow:?}: the end was not read")).unwrap();
        assert_eq!(got, b"helloworld", "{flow:?}");
    }
}

/// A reset ends the read at once too, where the reader slept until its timeout.
#[tokio::test(flavor = "multi_thread")]
async fn the_apps_reset_ends_the_read_at_once() {
    for flow in FLOWS {
        let (to_stack, _from_stack, _stack, mut app, local, remote, server_next) = reading_bed(flow).await;
        let reader = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            app.read_to_end(&mut Vec::new()).await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        to_stack.send(segment(local, remote, CLIENT_ISN + 1, Flags { rst: true, ack: Some(server_next), ..Flags::default() }, &[])).unwrap();
        assert!(tokio::time::timeout(END_HEARD, reader).await.is_ok(), "{flow:?}: the reset was not heard");
    }
}


/// Run 7: a client that half-closes after its request (HTTP/1.0 style, `nc -N`) got
/// the stack's FIN with the ACK of its own, and its answer never arrived. Now the
/// stream is half-closed: the app's end is read, the engine's answer still goes, and
/// the stack's FIN follows only once the engine shuts its side.
#[tokio::test(flavor = "multi_thread")]
async fn a_half_closed_app_still_gets_the_answer_then_the_fin() {
    const REQUEST: &[u8] = b"GET / HTTP/1.0\r\n\r\n";
    const ANSWER: &[u8] = b"HTTP/1.0 200 OK\r\n\r\nhello";
    for flow in FLOWS {
        let (to_stack, mut from_stack, _stack, mut app, local, remote, server_next) = reading_bed(flow).await;
        let len = u32::try_from(REQUEST.len()).unwrap();
        let ack = Some(server_next);
        to_stack.send(segment(local, remote, CLIENT_ISN + 1, Flags { psh: true, fin: true, ack, ..Flags::default() }, REQUEST)).unwrap();
        let engine = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut got = Vec::new();
            app.read_to_end(&mut got).await.unwrap();
            // The engine's answer comes later than the app's FIN, as a server's does.
            tokio::time::sleep(Duration::from_millis(200)).await;
            app.write_all(ANSWER).await.unwrap();
            let _ = tokio::time::timeout(RECOVERY, app.shutdown()).await;
            got
        });
        let deadline = Instant::now() + RECOVERY;
        let (mut answer, mut fin_before_answer, mut fin) = (Vec::new(), false, false);
        while let Ok(Some(packet)) = tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), from_stack.recv()).await {
            let (header, payload) = tcp(&packet);
            if !payload.is_empty() {
                answer.extend_from_slice(&payload);
                let next = header.sequence_number.wrapping_add(u32::try_from(payload.len()).unwrap());
                to_stack.send(segment(local, remote, CLIENT_ISN + 2 + len, Flags { ack: Some(next), ..Flags::default() }, &[])).unwrap();
            }
            if header.fin {
                fin_before_answer |= answer.is_empty();
                fin = true;
                let next = header.sequence_number.wrapping_add(u32::try_from(payload.len()).unwrap()).wrapping_add(1);
                to_stack.send(segment(local, remote, CLIENT_ISN + 2 + len, Flags { ack: Some(next), ..Flags::default() }, &[])).unwrap();
                break;
            }
        }
        assert!(!fin_before_answer, "{flow:?}: the stack closed before the answer");
        assert_eq!(answer, ANSWER, "{flow:?}: the answer reached the half-closed app");
        assert!(fin, "{flow:?}: and the FIN followed the engine's shutdown");
        assert_eq!(tokio::time::timeout(RECOVERY, engine).await.expect("the engine side ended").unwrap(), REQUEST, "{flow:?}");
    }
}
// ---- An idle connection (2026-11-09, run 7): TCP has no idle limit, the stack's is hours.

/// The engine's stack keeps an idle connection for Windows' keep-alive time, not
/// ipstack's minute, and the stack it builds is given that setting.
#[test]
fn the_engines_idle_limit_is_hours_not_a_minute() {
    assert_eq!(super::relay::tcp_config().timeout, super::relay::TCP_IDLE);
    assert!(super::relay::TCP_IDLE >= Duration::from_secs(2 * 60 * 60));
    assert!(TcpConfig::default().timeout <= Duration::from_secs(60), "the control: ipstack's own is a minute");
    let routing = include_str!("../control/routing.rs");
    assert!(routing.contains("config.with_tcp_config(crate::stack::relay::tcp_config());"), "the routed stack is built with it");
}

/// What the limit does: a connection neither side used for that long is reset, the
/// reader told so. With ipstack's minute an idle WebSocket died 60 s in (run 7).
#[tokio::test(flavor = "multi_thread")]
async fn an_idle_connection_lives_until_the_limit_then_is_reset() {
    const SHORT_IDLE: Duration = Duration::from_millis(400);
    for flow in FLOWS {
        let mut short = super::relay::tcp_config();
        short.timeout = SHORT_IDLE;
        let (_to_stack, mut from_stack, _stack, app, _local, _remote, _) = reading_bed_with(flow, short).await;
        let reader = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut app = app;
            let mut byte = [0u8; 1];
            app.read(&mut byte).await
        });
        tokio::time::sleep(SHORT_IDLE / 2).await;
        assert!(!reader.is_finished(), "{flow:?}: alive inside the limit");
        let got = tokio::time::timeout(RECOVERY, reader).await.expect("reset at the limit").unwrap();
        assert_eq!(got.unwrap_err().kind(), std::io::ErrorKind::TimedOut, "{flow:?}");
        let deadline = Instant::now() + RECOVERY;
        let mut rst = false;
        while let Ok(Some(packet)) = tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), from_stack.recv()).await {
            if tcp(&packet).0.rst {
                rst = true;
                break;
            }
        }
        assert!(rst, "{flow:?}: and the app's side reset");
    }
}

// ---- Closing (2026-11-09, second review of run 7): every FIN goes, once, and is resent.

/// The app's end of one accepted flow: it sends what a test tells it and keeps what
/// the stack sent, with the sequence numbers both sides are at.
struct Peer {
    to_stack: mpsc::UnboundedSender<Vec<u8>>,
    from_stack: mpsc::UnboundedReceiver<Vec<u8>>,
    _stack: IpStack,
    local: SocketAddr,
    remote: SocketAddr,
    /// The app's next sequence number, and the stack's next one the app expects.
    client_next: u32,
    server_next: u32,
}

/// What the stack sent, as the test reads it.
#[derive(Debug, Clone)]
struct Sent {
    seq: u32,
    ack: u32,
    len: usize,
    fin: bool,
    rst: bool,
}

async fn peer(flow: (&str, &str), tcp_config: TcpConfig) -> (Peer, IpStackTcpStream) {
    let (to_stack, from_stack, stack, app, local, remote, server_next) = reading_bed_with(flow, tcp_config).await;
    (Peer { to_stack, from_stack, _stack: stack, local, remote, client_next: CLIENT_ISN + 1, server_next }, app)
}

impl Peer {
    /// A segment from the app at its next sequence number, acknowledging `ack`.
    fn send_at(&mut self, seq: u32, ack: u32, fin: bool, payload: &[u8]) {
        let flags = Flags { psh: !payload.is_empty(), fin, ack: Some(ack), ..Flags::default() };
        self.to_stack.send(segment(self.local, self.remote, seq, flags, payload)).unwrap();
    }

    fn send(&mut self, fin: bool, payload: &[u8]) {
        let (seq, ack) = (self.client_next, self.server_next);
        self.send_at(seq, ack, fin, payload);
        self.client_next = seq.wrapping_add(u32::try_from(payload.len()).unwrap()).wrapping_add(u32::from(fin));
    }

    /// A keep-alive probe: one sequence number back, no data (RFC 9293 3.8.4).
    fn keep_alive(&mut self) {
        let (seq, ack) = (self.client_next.wrapping_sub(1), self.server_next);
        self.send_at(seq, ack, false, &[]);
    }

    /// Every segment within `wait`, acknowledging none of them.
    async fn listen(&mut self, wait: Duration) -> Vec<Sent> {
        let deadline = Instant::now() + wait;
        let mut got = Vec::new();
        while let Ok(Some(packet)) = tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), self.from_stack.recv()).await {
            let (h, payload) = tcp(&packet);
            got.push(Sent { seq: h.sequence_number, ack: h.acknowledgment_number, len: payload.len(), fin: h.fin, rst: h.rst });
        }
        got
    }

    /// Segments until one with a FIN or a RST, or `wait`; data is acknowledged as it
    /// comes, the FIN is not.
    async fn until_end(&mut self, wait: Duration) -> Option<Sent> {
        let deadline = Instant::now() + wait;
        while let Ok(Some(packet)) = tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), self.from_stack.recv()).await {
            let (h, payload) = tcp(&packet);
            let sent = Sent { seq: h.sequence_number, ack: h.acknowledgment_number, len: payload.len(), fin: h.fin, rst: h.rst };
            if sent.len > 0 {
                self.server_next = sent.seq.wrapping_add(u32::try_from(sent.len).unwrap());
                self.send(false, &[]);
            }
            if sent.fin || sent.rst {
                return Some(sent);
            }
        }
        None
    }
}

/// P1-1: the server closes right after its last bytes, so the relay shuts down while
/// they are unacknowledged. The FIN must follow their ACK; it waited for a second
/// shutdown poll that nothing made, and the app hung until the idle limit (2 h).
#[tokio::test(flavor = "multi_thread")]
async fn the_fin_follows_the_last_bytes_once_they_are_acknowledged() {
    const BODY: &[u8] = b"HTTP/1.0 200 OK\r\n\r\nclose-delimited body";
    for flow in FLOWS {
        let (mut peer, mut app) = peer(flow, super::relay::tcp_config()).await;
        let engine = tokio::spawn(async move {
            app.write_all(BODY).await.unwrap();
            let shut = tokio::time::timeout(RECOVERY, app.shutdown()).await;
            (shut.is_ok(), app)
        });
        // The ACK comes after the shutdown was asked, as an app's does.
        let data = loop {
            let packet = tokio::time::timeout(RECOVERY, peer.from_stack.recv()).await.expect("the body").unwrap();
            let (h, payload) = tcp(&packet);
            if !payload.is_empty() {
                break Sent { seq: h.sequence_number, ack: h.acknowledgment_number, len: payload.len(), fin: h.fin, rst: h.rst };
            }
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        peer.server_next = data.seq.wrapping_add(u32::try_from(data.len).unwrap());
        peer.send(false, &[]);
        let end = peer.until_end(RECOVERY).await;
        assert!(end.as_ref().is_some_and(|e| e.fin && !e.rst && e.seq == peer.server_next), "{flow:?}: no FIN after the ACK of the last bytes: {end:?}");
        let (shut, _app) = engine.await.unwrap();
        assert!(shut, "{flow:?}: and the engine's shutdown returned");
    }
}

/// P1-2: a shutdown asked as the app's FIN arrives. Upstream woke the TCP task before
/// it recorded the ask, so a task that looked in between slept on with no FIN sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_shutdown_racing_the_apps_fin_still_sends_ours() {
    const ROUNDS: usize = 150;
    let mut missing = 0;
    for round in 0..ROUNDS {
        let flow = FLOWS[round % FLOWS.len()];
        let (mut peer, mut app) = peer(flow, super::relay::tcp_config()).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        peer.send(true, &[]);
        let engine = tokio::spawn(async move {
            let _ = tokio::time::timeout(RECOVERY, app.shutdown()).await;
            app
        });
        if !peer.until_end(Duration::from_secs(1)).await.is_some_and(|e| e.fin) {
            missing += 1;
        }
        engine.abort();
    }
    assert_eq!(missing, 0, "rounds of {ROUNDS} with no FIN from the stack");
}

/// P1-2: a server that never answers a half-closed app cannot hold the flow for
/// ever: past the idle limit with nothing from the app, the stack resets it.
#[tokio::test(flavor = "multi_thread")]
async fn a_half_closed_flow_no_one_ends_is_reset_at_the_idle_limit() {
    const SHORT_IDLE: Duration = Duration::from_millis(400);
    for flow in FLOWS {
        let mut short = super::relay::tcp_config();
        short.timeout = SHORT_IDLE;
        let (mut peer, app) = peer(flow, short).await;
        peer.send(true, &[]);
        let early = peer.listen(SHORT_IDLE / 2).await;
        assert!(early.iter().all(|s| !s.rst && !s.fin), "{flow:?}: inside the limit only the ACK: {early:?}");
        let end = peer.until_end(RECOVERY).await;
        assert!(end.as_ref().is_some_and(|e| e.rst), "{flow:?}: the half-closed flow was never ended: {end:?}");
        drop(app);
    }
}

/// P2-3: the app's keep-alives are the connection in use. Windows sends its first
/// after 2 h, the same as the idle limit, so an app that relies on them was reset at
/// exactly the limit.
#[tokio::test(flavor = "multi_thread")]
async fn keep_alives_keep_an_idle_connection_alive() {
    const SHORT_IDLE: Duration = Duration::from_millis(600);
    for flow in FLOWS {
        let mut short = super::relay::tcp_config();
        short.timeout = SHORT_IDLE;
        let (mut peer, mut app) = peer(flow, short).await;
        let reader = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut byte = [0u8; 1];
            app.read(&mut byte).await.map_err(|e| e.kind())
        });
        let mut sent = Vec::new();
        for _ in 0..8 {
            sent.extend(peer.listen(SHORT_IDLE / 3).await);
            peer.keep_alive();
        }
        assert!(!reader.is_finished(), "{flow:?}: reset with the app's keep-alives coming");
        assert!(sent.iter().all(|s| !s.rst), "{flow:?}: {sent:?}");
        assert!(sent.iter().any(|s| s.ack == peer.client_next), "{flow:?}: the probes were answered");
        // The control: once they stop, the limit holds.
        let end = peer.until_end(RECOVERY).await;
        assert!(end.as_ref().is_some_and(|e| e.rst), "{flow:?}: {end:?}");
        assert_eq!(tokio::time::timeout(RECOVERY, reader).await.unwrap().unwrap(), Err(std::io::ErrorKind::TimedOut));
    }
}

/// P2-4: the app's FIN again in CLOSE-WAIT, because our ACK of it was lost: it is
/// acknowledged again, or the app's stack resends it until it gives up.
#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_fin_in_close_wait_is_acknowledged() {
    for flow in FLOWS {
        let (mut peer, app) = peer(flow, super::relay::tcp_config()).await;
        let fin_at = peer.client_next;
        peer.send(true, &[]);
        let first = peer.listen(Duration::from_millis(200)).await;
        assert!(first.iter().any(|s| s.ack == fin_at.wrapping_add(1)), "{flow:?}: the control, the FIN acknowledged: {first:?}");
        let server_next = peer.server_next;
        peer.send_at(fin_at, server_next, true, &[]);
        let again = peer.listen(Duration::from_millis(300)).await;
        assert!(again.iter().any(|s| s.ack == fin_at.wrapping_add(1) && !s.fin && !s.rst), "{flow:?}: the resent FIN went unanswered: {again:?}");
        drop(app);
    }
}

/// P2-5: our FIN, unacknowledged in LAST-ACK, is resent at its own sequence number,
/// not one past it; an ACK that does not cover it closes nothing; its own ACK does.
#[tokio::test(flavor = "multi_thread")]
async fn our_fin_is_resent_at_its_sequence_and_only_its_ack_closes() {
    for flow in FLOWS {
        let (mut peer, mut app) = peer(flow, super::relay::tcp_config()).await;
        peer.send(true, &[]);
        let _ = peer.listen(Duration::from_millis(100)).await;
        let fin_seq = peer.server_next;
        let engine = tokio::spawn(async move {
            let _ = tokio::time::timeout(RECOVERY, app.shutdown()).await;
            app
        });
        // An ACK of nothing new, after the first FIN: not the end.
        let first = peer.until_end(RECOVERY).await.expect("a FIN");
        assert!(first.fin && first.seq == fin_seq, "{flow:?}: {first:?}");
        peer.send(false, &[]);
        let resent = peer.listen(Duration::from_millis(1_200)).await;
        let fins: Vec<u32> = resent.iter().filter(|s| s.fin).map(|s| s.seq).collect();
        assert!(!fins.is_empty(), "{flow:?}: an ACK below the FIN closed the flow: {resent:?}");
        assert!(fins.iter().all(|&s| s == fin_seq), "{flow:?}: resent FINs at {fins:?}, ours is at {fin_seq}");
        // Its own ACK ends it: nothing more is sent.
        peer.server_next = fin_seq.wrapping_add(1);
        peer.send(false, &[]);
        let after = peer.listen(Duration::from_millis(1_200)).await;
        assert!(after.iter().all(|s| !s.fin && !s.rst), "{flow:?}: still closing after its ACK: {after:?}");
        let _ = engine.await;
    }
}

/// P3: a half-closed stream the engine lets go of without a shutdown still closes
/// the app's side: one FIN, resent while unacknowledged, then a reset once its
/// retransmissions run out, where it was sent once and the task torn down with it.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_half_closed_stream_resends_its_one_fin_then_resets() {
    for flow in FLOWS {
        let (mut peer, app) = peer(flow, super::relay::tcp_config()).await;
        peer.send(true, &[]);
        let _ = peer.listen(Duration::from_millis(100)).await;
        let fin_seq = peer.server_next;
        drop(app);
        let sent = peer.listen(Duration::from_secs(3)).await;
        let fins: Vec<u32> = sent.iter().filter(|s| s.fin).map(|s| s.seq).collect();
        assert!(fins.len() >= 2, "{flow:?}: the dropped stream's FIN was never resent: {sent:?}");
        assert!(fins.iter().all(|&s| s == fin_seq), "{flow:?}: two FINs, at {fins:?}");
        assert!(sent.last().is_some_and(|s| s.rst), "{flow:?}: no reset once the FIN went unanswered: {sent:?}");
    }
}

/// P3: the control of the rule above: a dropped stream whose FIN is acknowledged ends
/// there, with no reset.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_half_closed_stream_whose_fin_is_acknowledged_just_ends() {
    for flow in FLOWS {
        let (mut peer, app) = peer(flow, super::relay::tcp_config()).await;
        peer.send(true, &[]);
        let _ = peer.listen(Duration::from_millis(100)).await;
        drop(app);
        let fin = peer.until_end(RECOVERY).await.expect("a FIN");
        assert!(fin.fin, "{flow:?}: {fin:?}");
        peer.server_next = fin.seq.wrapping_add(1);
        peer.send(false, &[]);
        let after = peer.listen(Duration::from_secs(2)).await;
        assert!(after.iter().all(|s| !s.fin && !s.rst), "{flow:?}: {after:?}");
    }
}

/// P3: in FIN-WAIT-2 a FIN that carries bytes ahead of a gap is not the end yet, as in
/// ESTABLISHED: the read waits for the missing bytes and the FIN is taken after them.
#[tokio::test(flavor = "multi_thread")]
async fn a_fin_ahead_of_a_gap_in_fin_wait_2_is_not_the_end() {
    for flow in FLOWS {
        let (mut peer, mut app) = peer(flow, super::relay::tcp_config()).await;
        // Bounded: before the fix a shutdown returned only once the connection closed.
        let _ = tokio::time::timeout(Duration::from_millis(300), app.shutdown()).await;
        let fin = peer.until_end(RECOVERY).await.expect("our FIN");
        assert!(fin.fin, "{flow:?}: {fin:?}");
        peer.server_next = fin.seq.wrapping_add(1);
        peer.send(false, &[]);
        let reader = read_to_end(app);
        let start = peer.client_next;
        let server_next = peer.server_next;
        peer.send_at(start.wrapping_add(5), server_next, true, b"world");
        let early = peer.listen(Duration::from_millis(300)).await;
        assert!(early.iter().all(|s| s.ack == start), "{flow:?}: a FIN past a gap was acknowledged: {early:?}");
        assert!(!reader.is_finished(), "{flow:?}: the first five bytes never came");
        peer.send_at(start, server_next, false, b"hello");
        peer.send_at(start.wrapping_add(5), server_next, true, b"world");
        let got = tokio::time::timeout(END_HEARD, reader).await.unwrap_or_else(|_| panic!("{flow:?}: the end was not read")).unwrap();
        assert_eq!(got, b"helloworld", "{flow:?}");
    }
}

/// P3: the app's reset reads as a reset, not as the end of what it sent: a relay that
/// took it for the end would close the upload upstream as if it were complete.
#[tokio::test(flavor = "multi_thread")]
async fn the_apps_reset_reads_as_a_reset_not_an_end() {
    for flow in FLOWS {
        let (mut peer, mut app) = peer(flow, super::relay::tcp_config()).await;
        let reader = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut got = Vec::new();
            app.read_to_end(&mut got).await.map(|_| got).map_err(|e| e.kind())
        });
        peer.send(false, b"half an upload");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (seq, ack) = (peer.client_next, peer.server_next);
        peer.to_stack.send(segment(peer.local, peer.remote, seq, Flags { rst: true, ack: Some(ack), ..Flags::default() }, &[])).unwrap();
        let read = tokio::time::timeout(END_HEARD, reader).await.expect("the reset was heard").unwrap();
        assert_eq!(read, Err(std::io::ErrorKind::ConnectionReset), "{flow:?}");
    }
}

/// The book's eviction (P3): a stream's handle tells how long the app has been
/// silent, keep-alives counting, and ends the flow with a reset when told to.
#[tokio::test(flavor = "multi_thread")]
async fn a_streams_handle_tells_its_idle_time_and_resets_it() {
    for flow in FLOWS {
        let (mut peer, mut app) = peer(flow, super::relay::tcp_config()).await;
        let handle = app.handle();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(handle.idle() >= Duration::from_millis(250), "{flow:?}: {:?}", handle.idle());
        peer.keep_alive();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(handle.idle() < Duration::from_millis(250), "{flow:?}: a keep-alive is use: {:?}", handle.idle());
        handle.abort();
        let end = peer.until_end(RECOVERY).await;
        assert!(end.as_ref().is_some_and(|e| e.rst), "{flow:?}: {end:?}");
        use tokio::io::AsyncReadExt;
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(END_HEARD, app.read(&mut byte)).await.unwrap_or_else(|_| panic!("{flow:?}: the reader never heard of it"));
        // P2-a: an aborted flow reads as cut short, not as the app's end: the relay
        // passes it upstream as a reset and stops, where it sent a FIN and waited on.
        assert_eq!(read.map_err(|e| e.kind()), Err(std::io::ErrorKind::ConnectionAborted), "{flow:?}");
    }
}

/// An upstream in memory that records whether the relay reset it.
struct Recorded {
    inner: tokio::io::DuplexStream,
    reset: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl crate::flow::relay::Reset for Recorded {
    fn reset(&self) {
        self.reset.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl tokio::io::AsyncRead for Recorded {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Recorded {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, data: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// P2-b: the app sends its request and half-closes; the server never answers; the
/// stack resets the app's side at its idle limit. The relay, reading only the server
/// by then, ends at once and resets upstream, where its task, socket and book entry
/// lived until the server acted. Through the relay and the stream the engine runs.
#[tokio::test(flavor = "multi_thread")]
async fn a_half_closed_flow_the_stack_resets_ends_its_relay_and_resets_upstream() {
    const SHORT_IDLE: Duration = Duration::from_millis(400);
    const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: slow.example\r\n\r\n";
    for flow in FLOWS {
        let mut short = super::relay::tcp_config();
        short.timeout = SHORT_IDLE;
        let (mut peer, mut app) = peer(flow, short).await;
        let (near, mut server) = tokio::io::duplex(64 * 1024);
        let reset = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let up = Recorded { inner: near, reset: reset.clone() };
        let relay = tokio::spawn(async move {
            let closed = app.closed();
            crate::flow::relay::relay_tcp_until(&mut app, up, super::relay::FIRST_BYTES_WAIT, |_| crate::flow::flows::Action::Pass, closed).await
        });
        peer.send(true, REQUEST);
        use tokio::io::AsyncReadExt;
        let mut got = Vec::new();
        tokio::time::timeout(RECOVERY, server.read_to_end(&mut got)).await.expect("the request and the half-close upstream").unwrap();
        assert_eq!(got, REQUEST, "{flow:?}");
        let end = peer.until_end(RECOVERY).await;
        assert!(end.as_ref().is_some_and(|e| e.rst), "{flow:?}: the control, the stack reset the app's side: {end:?}");
        let out = tokio::time::timeout(END_HEARD, relay).await.unwrap_or_else(|_| panic!("{flow:?}: the relay waited on the server")).unwrap();
        assert!(out.reset_upstream && reset.load(std::sync::atomic::Ordering::SeqCst), "{flow:?}: upstream was not reset: {out:?}");
        assert_eq!(out.bytes_up, REQUEST.len() as u64, "{flow:?}");
        drop(server);
    }
}

/// P3-2: a server that resets right after its answer: the app gets every byte of it
/// before the reset, here a lost segment's resend, where the reset went at once.
#[tokio::test(flavor = "multi_thread")]
async fn a_reset_after_the_answer_lets_its_bytes_reach_the_app_first() {
    const ANSWER: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    for flow in FLOWS {
        let mut fast = super::relay::tcp_config();
        fast.rto = Duration::from_millis(100);
        let (mut peer, mut app) = peer(flow, fast).await;
        app.write_all(ANSWER).await.unwrap();
        let ender = tokio::spawn(async move {
            crate::tls::splice::drain_then_abort(&app).await;
            app
        });
        let (mut sends, mut lost, mut delivered, mut rst_after) = (0, false, false, None);
        let deadline = Instant::now() + RECOVERY;
        while let Ok(Some(packet)) = tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), peer.from_stack.recv()).await {
            let (h, payload) = tcp(&packet);
            if h.rst {
                rst_after = Some(delivered);
                break;
            }
            if !payload.is_empty() {
                sends += 1;
                // The first send is lost; the resend is taken and acknowledged.
                if !lost {
                    lost = true;
                    continue;
                }
                assert_eq!(payload, ANSWER, "{flow:?}");
                delivered = true;
                peer.server_next = h.sequence_number.wrapping_add(u32::try_from(payload.len()).unwrap());
                peer.send(false, &[]);
            }
        }
        assert_eq!(rst_after, Some(true), "{flow:?}: the reset came before the answer reached the app ({sends} sends)");
        let _ = tokio::time::timeout(RECOVERY, ender).await.expect("bounded");
    }
}

/// P3-3: the server's bytes on their way to the app are use too, so a paused download
/// or a long poll whose server just answered is not the idlest flow at the cap.
#[tokio::test(flavor = "multi_thread")]
async fn a_streams_handle_counts_the_engines_writes_as_use() {
    for flow in FLOWS {
        let (_peer, mut app) = peer(flow, super::relay::tcp_config()).await;
        let handle = app.handle();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(handle.idle() >= Duration::from_millis(250), "{flow:?}: the control: {:?}", handle.idle());
        app.write_all(b"the server's next bytes").await.unwrap();
        assert!(handle.idle() < Duration::from_millis(250), "{flow:?}: a write is use: {:?}", handle.idle());
    }
}

/// P3-6: nothing is written after our FIN, queued or sent: bytes past it would reach
/// the app after its end, or never.
#[tokio::test(flavor = "multi_thread")]
async fn nothing_is_written_after_our_fin() {
    for flow in FLOWS {
        let (mut peer, mut app) = peer(flow, super::relay::tcp_config()).await;
        app.write_all(b"the last bytes").await.unwrap();
        // Bytes in flight: the FIN is queued behind them.
        assert!(tokio::time::timeout(Duration::from_millis(100), app.shutdown()).await.is_err(), "{flow:?}: the control, the FIN waits");
        let queued = app.write(b"more").await.map_err(|e| e.kind());
        assert_eq!(queued, Err(std::io::ErrorKind::BrokenPipe), "{flow:?}: a write after the FIN was queued");
        let fin = peer.until_end(RECOVERY).await.expect("our FIN");
        assert!(fin.fin, "{flow:?}: {fin:?}");
        let sent = app.write(b"more").await.map_err(|e| e.kind());
        assert_eq!(sent, Err(std::io::ErrorKind::BrokenPipe), "{flow:?}: a write after the FIN was sent");
    }
}

/// P3-1: the app's FIN crosses ours (a simultaneous close): ours is still unacknowledged,
/// so it is resent until the app acknowledges it, and only its ACK ends the close.
#[tokio::test(flavor = "multi_thread")]
async fn a_simultaneous_close_resends_our_fin_until_it_is_acknowledged() {
    // Resends at 1 s, 2 s and 3 s after our FIN: each look below ends well clear of one.
    let mut config = super::relay::tcp_config();
    config.last_ack_timeout = Duration::from_secs(1);
    for flow in FLOWS {
        let (mut peer, mut app) = peer(flow, config.clone()).await;
        let engine = tokio::spawn(async move {
            let _ = tokio::time::timeout(RECOVERY, app.shutdown()).await;
            app
        });
        let fin = peer.until_end(RECOVERY).await.expect("our FIN");
        assert!(fin.fin, "{flow:?}: {fin:?}");
        let fin_seq = fin.seq;
        // The app's FIN, sent before ours arrived: it acknowledges nothing of ours.
        let their_fin = peer.client_next;
        peer.send(true, &[]);
        let sent = peer.listen(Duration::from_millis(1_300)).await;
        assert!(sent.iter().any(|s| s.ack == their_fin.wrapping_add(1)), "{flow:?}: the app's FIN was not acknowledged: {sent:?}");
        let fins: Vec<u32> = sent.iter().filter(|s| s.fin).map(|s| s.seq).collect();
        assert!(!fins.is_empty(), "{flow:?}: our unacknowledged FIN was never resent: {sent:?}");
        assert!(fins.iter().all(|&s| s == fin_seq), "{flow:?}: resent FINs at {fins:?}, ours is at {fin_seq}");
        assert!(sent.iter().all(|s| !s.rst), "{flow:?}: {sent:?}");
        // The app's FIN again (our ACK of it lost): our FIN answers it, at its sequence.
        peer.send_at(their_fin, fin_seq, true, &[]);
        let again = peer.listen(Duration::from_millis(200)).await;
        assert!(again.iter().any(|s| s.fin && s.seq == fin_seq && s.ack == their_fin.wrapping_add(1)), "{flow:?}: {again:?}");
        // Its ACK ends the close: nothing more is sent.
        peer.server_next = fin_seq.wrapping_add(1);
        peer.send(false, &[]);
        let after = peer.listen(Duration::from_millis(1_200)).await;
        assert!(after.iter().all(|s| !s.fin && !s.rst), "{flow:?}: still closing after its ACK: {after:?}");
        let _ = engine.await;
    }
}
