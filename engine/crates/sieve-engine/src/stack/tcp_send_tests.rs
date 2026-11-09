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
        let (to_stack, _from_stack, _stack, app, local, remote, server_next) = reading_bed(flow).await;
        let reader = read_to_end(app);
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