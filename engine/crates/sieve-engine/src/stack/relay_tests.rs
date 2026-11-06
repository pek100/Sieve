//! How a blocked flow ends, through the real relay and a real `IpStack` in memory,
//! with `filtering.https` off (its slot empty). Nothing leaves this machine: answers
//! end at the in-memory device, the empty route table refuses every upstream socket, a TCP
//! flow's upstream is on loopback, and the attributor only reads the owner tables.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use etherparse::{PacketBuilder, PacketHeaders, TcpHeader, TransportHeader};
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use sieve_filter::rules::{ListText, RuleEngine, RuleSet};
use sieve_ipc::{FlowAction, FlowKind, FlowProto, LogOutcome, Policy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::Meters;
use super::egress::Egress;
use super::relay::{Relay, RelayParts, handle_udp, serve_admitted};
use crate::dns::NameMap;
use crate::dns::service::Service;
use crate::domain::{DomainFilter, FilterSlot};
use crate::flow::etw::Unwitnessed;
use crate::flow::flows::FiveTuple;
use crate::flow::nat::{NatTable, NoDirectory, VmDirectory};
use crate::flow::packet::{self, Proto};
use crate::flow::quic::{VERSION_1, VERSION_2};
use crate::quic::tests::{FLOWS, FakeSink, MemDevice, sealed_initials, sealed_initials_of, udp_packet};
use crate::route::table::NetTables;
use crate::watchdog::monotonic_ms;

const BLOCKED: &str = "ads.example";
const ALLOWED: &str = "news.example";
const RULES: &str = "||ads.example^\n";
const MTU: u16 = 1500;
const NAME_TTL_S: u32 = 300;
/// Far above the owner lookup's give-up time; only a failure waits this long.
const WAIT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(5);
/// Long enough for a packet that should not come to have come.
const SETTLE: Duration = Duration::from_millis(100);

fn relay(sink: Arc<FakeSink>) -> Arc<Relay> {
    let tables: Arc<RwLock<NetTables>> = Arc::default();
    let names: Arc<Mutex<NameMap>> = Arc::default();
    let meters: Arc<Meters> = Arc::default();
    let lists = RuleEngine::compile(&[ListText { id: "test", text: RULES, trusted: false }]);
    let rules = RuleSet { user: Arc::new(RuleEngine::empty()), lists: Arc::new(lists) };
    let filter = Arc::new(FilterSlot::new(DomainFilter::new(&Policy { sieving: true, ..Policy::default() }, rules)));
    let context = crate::dns::testing::Ca::new().context(Arc::default(), Vec::new());
    let dns = Arc::new(Service::new(Vec::new(), context, tables.clone(), names.clone(), meters.clone(), usize::from(MTU), Box::new(|_| false)));
    let nat = Arc::new(NatTable::spawn(|| (Vec::new(), Box::new(NoDirectory) as Box<dyn VmDirectory>)));
    let egress = Arc::new(Egress::new(0, tables.clone()));
    Arc::new(Relay::new(RelayParts { tables, egress, dns, book: Arc::default(), names, meters, filter, witness: Box::new(Unwitnessed), nat, https: Arc::default(), sink }))
}

struct Wire {
    to_stack: mpsc::UnboundedSender<Vec<u8>>,
    from_stack: mpsc::UnboundedReceiver<Vec<u8>>,
    stack: IpStack,
}

fn wire() -> Wire {
    let (to_stack, rx) = mpsc::unbounded_channel();
    let (tx, from_stack) = mpsc::unbounded_channel();
    let mut config = IpStackConfig::default();
    config.mtu(MTU).unwrap();
    Wire { to_stack, from_stack, stack: IpStack::new(config, MemDevice { rx, tx }) }
}

fn ends(flow: (&str, &str)) -> (SocketAddr, SocketAddr) {
    (flow.0.parse().unwrap(), flow.1.parse().unwrap())
}

async fn until(what: &str, done: impl Fn() -> bool) {
    let polled = async {
        while !done() {
            tokio::time::sleep(POLL).await;
        }
    };
    tokio::time::timeout(WAIT, polled).await.unwrap_or_else(|_| panic!("{what}"));
}

/// The one thing the flow must have left in the book: one closed `Blocked`
/// event and one `Blocked` log row, counted once.
fn assert_blocked_once(ctx: &Relay, host: &str) {
    let mut book = ctx.book.lock().unwrap();
    let batch = book.take_batch();
    assert_eq!(batch.iter().map(|e| (e.action, e.open)).collect::<Vec<_>>(), [(FlowAction::Blocked, false)]);
    assert_eq!(batch[0].host.as_deref(), Some(host));
    let rows = book.take_log();
    assert_eq!(rows.iter().map(|r| &r.outcome).collect::<Vec<_>>(), [&LogOutcome::Blocked]);
    let counters = ctx.meters.counters();
    assert_eq!((counters.flows, counters.blocked), (1, 1), "one owner lookup, one block");
}

async fn accept_udp(wire: &mut Wire) -> ipstack::IpStackUdpStream {
    let Ok(IpStackStream::Udp(app)) = wire.stack.accept().await else { panic!("no UDP stream") };
    app
}

async fn ended<T>(task: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, task).await.expect("the flow ended")
}

/// The next packet the stack wrote: a datagram from the blocked server to the app,
/// which is what reaches the browser's socket. Returns its payload.
async fn next_datagram(wire: &mut Wire, local: SocketAddr, remote: SocketAddr) -> Vec<u8> {
    let packet = tokio::time::timeout(WAIT, wire.from_stack.recv()).await.expect("a datagram").unwrap();
    let parsed = packet::parse(&packet).expect("an IP packet");
    assert_eq!((parsed.proto, parsed.src, parsed.dst), (Proto::Udp, remote.ip(), local.ip()));
    assert_eq!((parsed.src_port, parsed.dst_port), (remote.port(), local.port()));
    parsed.payload.to_vec()
}

/// Neither of the refused path's effects happened.
fn assert_no_icmp_and_no_refusal(ctx: &Relay, sink: &FakeSink) {
    let quic = &ctx.meters.quic;
    assert_eq!(sink.tried.load(Ordering::Relaxed), 0, "no ICMP for a blocked flow");
    assert_eq!((quic.replies.load(Ordering::Relaxed), quic.refused.load(Ordering::Relaxed)), (0, 0), "a block is not a refusal");
}

/// The exact bytes for both versions over both families, each retransmit answered on
/// the one flow, with `filtering.https` off.
#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_quic_flow_gets_version_negotiation_and_a_retransmit_is_no_new_flow() {
    const DCID: [u8; 8] = [0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7];
    const SCID: [u8; 5] = [0x50, 0x51, 0x52, 0x53, 0x54];
    #[rustfmt::skip]
    const EXPECTED: [u8; 24] = [
        0xc0,
        0, 0, 0, 0,
        5, 0x50, 0x51, 0x52, 0x53, 0x54,
        8, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
        0x1a, 0x2a, 0x3a, 0x4a,
    ];
    for version in [VERSION_1, VERSION_2] {
        for flow in FLOWS {
            let (local, remote) = ends(flow);
            let sink = Arc::new(FakeSink::default());
            let ctx = relay(sink.clone());
            assert!(ctx.https.get().is_none(), "filtering.https is off");
            let mut wire = wire();
            let initials = sealed_initials_of(version, &DCID, &SCID, BLOCKED);
            for initial in &initials {
                wire.to_stack.send(udp_packet(local, remote, initial)).unwrap();
            }
            let task = tokio::spawn(handle_udp(ctx.clone(), accept_udp(&mut wire).await));

            for _ in &initials {
                assert_eq!(next_datagram(&mut wire, local, remote).await, EXPECTED, "each held Initial");
            }
            wire.to_stack.send(udp_packet(local, remote, &initials[0])).unwrap();
            assert_eq!(next_datagram(&mut wire, local, remote).await, EXPECTED, "a retransmit");

            // Answered in order, so the answer after this one proves it got none.
            wire.to_stack.send(udp_packet(local, remote, &[0x40; 1_250])).unwrap();
            wire.to_stack.send(udp_packet(local, remote, &initials[1])).unwrap();
            assert_eq!(next_datagram(&mut wire, local, remote).await, EXPECTED);
            assert!(wire.from_stack.try_recv().is_err(), "the short header got nothing");

            assert!(!task.is_finished(), "the flow stays until idle");
            assert_blocked_once(&ctx, BLOCKED);
            assert_eq!(ctx.meters.quic.blocked_replies.load(Ordering::Relaxed), 4, "the figure counts these packets");
            assert_no_icmp_and_no_refusal(&ctx, &sink);
            task.abort();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn zero_length_connection_ids_are_answered() {
    const EXPECTED: [u8; 11] = [0xc0, 0, 0, 0, 0, 0, 0, 0x1a, 0x2a, 0x3a, 0x4a];
    for flow in FLOWS {
        let (local, remote) = ends(flow);
        let ctx = relay(Arc::default());
        let mut wire = wire();
        for initial in sealed_initials_of(VERSION_1, &[], &[], BLOCKED) {
            wire.to_stack.send(udp_packet(local, remote, &initial)).unwrap();
        }
        let task = tokio::spawn(handle_udp(ctx.clone(), accept_udp(&mut wire).await));
        assert_eq!(next_datagram(&mut wire, local, remote).await, EXPECTED);
        task.abort();
    }
}

/// Blocked by the names its address was resolved for, not QUIC: swallowed, as
/// before, with neither packet sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_datagram_that_is_not_quic_is_drained_silently() {
    for flow in FLOWS {
        let (local, remote) = ends(flow);
        let sink = Arc::new(FakeSink::default());
        let ctx = relay(sink.clone());
        ctx.names.lock().unwrap().record(BLOCKED, remote.ip(), NAME_TTL_S, monotonic_ms());
        let mut wire = wire();
        wire.to_stack.send(udp_packet(local, remote, b"\x00\x01 not quic")).unwrap();
        let task = tokio::spawn(handle_udp(ctx.clone(), accept_udp(&mut wire).await));
        until("the flow is blocked", || ctx.meters.counters().blocked == 1).await;
        wire.to_stack.send(udp_packet(local, remote, b"\x00\x02 not quic")).unwrap();
        tokio::time::sleep(SETTLE).await;
        assert!(wire.from_stack.try_recv().is_err(), "nothing back");
        assert_eq!(ctx.meters.quic.blocked_replies.load(Ordering::Relaxed), 0);
        assert_no_icmp_and_no_refusal(&ctx, &sink);
        assert!(!task.is_finished(), "the flow stays until idle");
        task.abort();
    }
}

/// The control: the same flow to a host no rule blocks is not answered. It goes
/// on to its upstream socket, which the empty route table refuses.
#[tokio::test(flavor = "multi_thread")]
async fn an_allowed_flow_gets_no_answer() {
    for flow in FLOWS {
        let (local, remote) = ends(flow);
        let sink = Arc::new(FakeSink::default());
        let ctx = relay(sink.clone());
        let mut wire = wire();
        for initial in sealed_initials(ALLOWED) {
            wire.to_stack.send(udp_packet(local, remote, &initial)).unwrap();
        }
        let app = accept_udp(&mut wire).await;
        ended(handle_udp(ctx.clone(), app)).await;
        tokio::time::sleep(SETTLE).await;
        assert!(wire.from_stack.try_recv().is_err(), "no Version Negotiation");
        assert_eq!(ctx.meters.quic.blocked_replies.load(Ordering::Relaxed), 0);
        assert_no_icmp_and_no_refusal(&ctx, &sink);
        assert_eq!(ctx.meters.counters().blocked, 0);
        let batch = ctx.book.lock().unwrap().take_batch();
        assert_eq!(batch.iter().map(|e| e.action).collect::<Vec<_>>(), [FlowAction::Failed], "no route, so nothing left");
    }
}

// ---- TCP: a segment at a time, as the app's own stack would send them.

const CLIENT_ISN: u32 = 1_000;
const WINDOW: u16 = 64_000;
const BANNER: &[u8] = b"220 ready\r\n";

#[derive(Clone, Copy, Default)]
struct Flags {
    syn: bool,
    psh: bool,
    ack: Option<u32>,
}

fn segment(local: SocketAddr, remote: SocketAddr, seq: u32, flags: Flags, payload: &[u8]) -> Vec<u8> {
    let ip = match (local, remote) {
        (SocketAddr::V4(l), SocketAddr::V4(r)) => PacketBuilder::ipv4(l.ip().octets(), r.ip().octets(), 64),
        (SocketAddr::V6(l), SocketAddr::V6(r)) => PacketBuilder::ipv6(l.ip().octets(), r.ip().octets(), 64),
        _ => panic!("one family"),
    };
    let mut tcp = ip.tcp(local.port(), remote.port(), seq, WINDOW);
    if flags.syn {
        tcp = tcp.syn();
    }
    if flags.psh {
        tcp = tcp.psh();
    }
    if let Some(ack) = flags.ack {
        tcp = tcp.ack(ack);
    }
    let mut out = Vec::new();
    tcp.write(&mut out, payload).unwrap();
    out
}

/// One TCP flow in an `IpStack`, its handshake done, and its SYN-time upstream:
/// a loopback socket whose far end the test holds.
struct TcpBed {
    ctx: Arc<Relay>,
    wire: Wire,
    local: SocketAddr,
    remote: SocketAddr,
    /// The next sequence number the app expects, and the next it sends.
    server_next: u32,
    client_next: u32,
    server: TcpStream,
    task: JoinHandle<()>,
}

impl TcpBed {
    async fn new(flow: (&str, &str)) -> Self {
        let (local, remote) = ends(flow);
        let ctx = relay(Arc::default());
        let mut wire = wire();
        wire.to_stack.send(segment(local, remote, CLIENT_ISN, Flags { syn: true, ..Flags::default() }, &[])).unwrap();
        let Ok(IpStackStream::Tcp(app)) = wire.stack.accept().await else { panic!("no TCP stream") };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let (upstream, server) = tokio::join!(TcpStream::connect(listener.local_addr().unwrap()), listener.accept());
        let tuple = FiveTuple { proto: Proto::Tcp, local, remote };
        let admitted = ctx.admit(&tuple, &ctx.attribute(tuple).await, FlowProto::Tcp, FlowKind::Other).expect("admitted");
        let task = tokio::spawn(serve_admitted(ctx.clone(), app, tuple, admitted, upstream.unwrap(), monotonic_ms()));
        let mut bed = Self { ctx, wire, local, remote, server_next: 0, client_next: CLIENT_ISN + 1, server: server.unwrap().0, task };
        let syn_ack = bed.next_segment().await;
        assert!(syn_ack.syn && syn_ack.ack, "{syn_ack:?}");
        bed.send(&[]);
        bed
    }

    fn send(&mut self, payload: &[u8]) {
        let flags = Flags { psh: !payload.is_empty(), ack: Some(self.server_next), ..Flags::default() };
        self.wire.to_stack.send(segment(self.local, self.remote, self.client_next, flags, payload)).unwrap();
        self.client_next += u32::try_from(payload.len()).unwrap();
    }

    async fn next_segment(&mut self) -> TcpHeader {
        let packet = tokio::time::timeout(WAIT, self.wire.from_stack.recv()).await.expect("a segment").unwrap();
        let headers = PacketHeaders::from_ip_slice(&packet).unwrap();
        let Some(TransportHeader::Tcp(header)) = headers.transport else { panic!("not TCP") };
        let used = u32::try_from(headers.payload.slice().len()).unwrap() + u32::from(header.syn);
        self.server_next = header.sequence_number.wrapping_add(used);
        header
    }

    /// Segments up to the one that ends the flow from the stack's side.
    async fn until_the_end(&mut self) -> TcpHeader {
        loop {
            let header = self.next_segment().await;
            if header.rst || header.fin {
                return header;
            }
        }
    }
}

/// First bytes that name the host in one segment.
fn hello(host: &str) -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_tcp_flow_ends_with_a_reset_at_the_next_sequence() {
    for flow in FLOWS {
        let mut bed = TcpBed::new(flow).await;
        let expected_seq = bed.server_next;
        bed.send(&hello(BLOCKED));
        let end = bed.until_the_end().await;
        assert!(end.rst && !end.fin, "{end:?}");
        assert_eq!((end.sequence_number, end.acknowledgment_number), (expected_seq, bed.client_next), "a reset the app's stack accepts");
        ended(&mut bed.task).await.unwrap();
        assert_blocked_once(&bed.ctx, BLOCKED);
        assert!(bed.wire.from_stack.try_recv().is_err(), "nothing follows the reset");
        let mut upstream_got = Vec::new();
        ended(bed.server.read_to_end(&mut upstream_got)).await.unwrap();
        assert_eq!(upstream_got, b"", "nothing went upstream");
    }
}

/// The relay forwards server bytes before the decision: the reset's sequence
/// number comes after them, or the app's stack would not accept it.
#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_flow_after_server_bytes_resets_after_them() {
    for flow in FLOWS {
        let mut bed = TcpBed::new(flow).await;
        bed.server.write_all(BANNER).await.unwrap();
        let banner = bed.next_segment().await;
        assert!(!banner.rst && !banner.fin, "{banner:?}");
        bed.send(&hello(BLOCKED));
        let end = bed.until_the_end().await;
        assert!(end.rst && !end.fin, "{end:?}");
        assert_eq!(end.sequence_number, banner.sequence_number.wrapping_add(u32::try_from(BANNER.len()).unwrap()));
        ended(&mut bed.task).await.unwrap();
        assert_blocked_once(&bed.ctx, BLOCKED);
    }
}

/// A client that never saw the server's bytes expects the older sequence, and under
/// RFC 5961 only challenges a reset at any other: it gets one at each.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_missed_server_bytes_still_gets_a_reset_it_accepts() {
    for flow in FLOWS {
        let mut bed = TcpBed::new(flow).await;
        let expected = bed.server_next;
        bed.server.write_all(BANNER).await.unwrap();
        let banner = bed.next_segment().await;
        assert_eq!(banner.sequence_number, expected);
        bed.server_next = expected;
        bed.send(&hello(BLOCKED));
        let first = bed.until_the_end().await;
        let second = bed.until_the_end().await;
        assert!(first.rst && second.rst, "{first:?} {second:?}");
        assert_eq!(first.sequence_number, expected.wrapping_add(u32::try_from(BANNER.len()).unwrap()));
        assert_eq!(second.sequence_number, expected);
        ended(&mut bed.task).await.unwrap();
    }
}

/// The control: a flow no rule blocks still ends with a FIN when its server does.
#[tokio::test(flavor = "multi_thread")]
async fn a_passed_flow_still_closes_with_a_fin() {
    for flow in FLOWS {
        let mut bed = TcpBed::new(flow).await;
        let hello = hello(ALLOWED);
        bed.send(&hello);
        let mut got = vec![0u8; hello.len()];
        ended(bed.server.read_exact(&mut got)).await.unwrap();
        assert_eq!(got, hello, "the flow was relayed");
        bed.server.shutdown().await.unwrap();
        let end = bed.until_the_end().await;
        assert!(end.fin && !end.rst, "{end:?}");
        assert_eq!(bed.ctx.meters.counters().blocked, 0);
        bed.task.abort();
    }
}
