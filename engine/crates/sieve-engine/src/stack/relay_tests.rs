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
    relay_with(sink, no_link(), None)
}

/// The relay with `link`, whose UDP upstreams all go to `server` on loopback,
/// whatever their target; `opened` counts them.
fn relay_udp_to(sink: Arc<FakeSink>, link: Arc<crate::link::LinkManager>, server: SocketAddr, opened: Arc<std::sync::atomic::AtomicUsize>) -> Arc<Relay> {
    let ctx = relay_with(sink, link, None);
    let mut relay = Arc::into_inner(ctx).expect("not shared yet");
    relay.udp = Arc::new(move |_target| {
        opened.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let up = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.map_err(|e| e.to_string())?;
            no_udp_resets(&up);
            up.connect(server).await.map_err(|e| e.to_string())?;
            Ok(up)
        })
    });
    Arc::new(relay)
}

/// Where loopback UDP is filtered (see [`loopback_udp_works`]), an ICMP error for
/// a datagram the filter refused would end the test's relay with a reset on its
/// next receive (Windows reports it on a connected UDP socket): turned off for the
/// test's own upstream sockets (`SIO_UDP_CONNRESET`), so only the relay's own
/// decisions end a flow under test.
fn no_udp_resets(socket: &tokio::net::UdpSocket) {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawSocket;
    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAIoctl(s: usize, code: u32, input: *const c_void, input_len: u32, output: *mut c_void, output_len: u32, returned: *mut u32, overlapped: *mut c_void, routine: *const c_void) -> i32;
    }
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    let off: u32 = 0;
    let mut returned = 0u32;
    // SAFETY: a live socket; the input is a 4-byte BOOL, nothing is written back,
    // and the call is synchronous (no overlapped, no routine).
    let r = unsafe { WSAIoctl(socket.as_raw_socket() as usize, SIO_UDP_CONNRESET, std::ptr::from_ref(&off).cast(), 4, std::ptr::null_mut(), 0, &mut returned, std::ptr::null_mut(), std::ptr::null()) };
    assert_eq!(r, 0, "SIO_UDP_CONNRESET");
}

/// Whether a datagram between two loopback sockets of this process arrives. Not
/// on the PC this was written on: its filtering proxy (AdGuard) drops the
/// loopback UDP of new executables, so a test then proves what it can without
/// an answer from the server, and says so.
async fn loopback_udp_works() -> bool {
    let (Ok(server), Ok(probe)) = (tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await, tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await) else { return false };
    let Ok(to) = server.local_addr() else { return false };
    if probe.send_to(b"probe", to).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 8];
    let works = matches!(tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut buf)).await, Ok(Ok((5, _))));
    if !works {
        eprintln!("loopback UDP is filtered on this machine (e.g. AdGuard): the server's answers are not checked; run on the VM for them");
    }
    works
}

/// A UDP server on loopback that sends each datagram back, and counts them.
async fn udp_echo() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let at = socket.local_addr().unwrap();
    let got = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = got.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            counted.fetch_add(1, Ordering::SeqCst);
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    (at, got)
}

/// A link manager with no pairing and no network: nothing exits.
fn no_link() -> Arc<crate::link::LinkManager> {
    Arc::new(crate::link::LinkManager::new(None, Box::new(|| Err("no network in this test".into())), crate::policy::wall_ms))
}

/// The relay with `link`, and its TCP connects made by `tcp` when given.
fn relay_with(sink: Arc<FakeSink>, link: Arc<crate::link::LinkManager>, tcp: Option<Arc<super::relay::TcpDial>>) -> Arc<Relay> {
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
    let mut relay = Relay::new(RelayParts { tables, egress, dns, book: Arc::default(), names, meters, filter, witness: Box::new(Unwitnessed), nat, https: Arc::default(), sink, link });
    if let Some(tcp) = tcp {
        relay.tcp = tcp;
    }
    Arc::new(relay)
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
pub(super) struct Flags {
    pub(super) syn: bool,
    pub(super) psh: bool,
    pub(super) fin: bool,
    pub(super) rst: bool,
    pub(super) ack: Option<u32>,
    /// The receive window the app's stack advertises; [`WINDOW`] when unset.
    pub(super) window: Option<u16>,
}

pub(super) fn segment(local: SocketAddr, remote: SocketAddr, seq: u32, flags: Flags, payload: &[u8]) -> Vec<u8> {
    let ip = match (local, remote) {
        (SocketAddr::V4(l), SocketAddr::V4(r)) => PacketBuilder::ipv4(l.ip().octets(), r.ip().octets(), 64),
        (SocketAddr::V6(l), SocketAddr::V6(r)) => PacketBuilder::ipv6(l.ip().octets(), r.ip().octets(), 64),
        _ => panic!("one family"),
    };
    let mut tcp = ip.tcp(local.port(), remote.port(), seq, flags.window.unwrap_or(WINDOW));
    if flags.syn {
        tcp = tcp.syn();
    }
    if flags.psh {
        tcp = tcp.psh();
    }
    if flags.fin {
        tcp = tcp.fin();
    }
    if flags.rst {
        tcp = tcp.rst();
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
    /// The upstream's own address and the one the server saw it from: they differ
    /// when a filtering proxy on this machine sits in loopback ([`Self::needs_plain_loopback`]).
    upstream_ends: (SocketAddr, SocketAddr),
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
        let (upstream, (server, seen_from)) = (upstream.unwrap(), server.unwrap());
        let upstream_ends = (upstream.local_addr().unwrap(), seen_from);
        let tuple = FiveTuple { proto: Proto::Tcp, local, remote };
        let admitted = ctx.admit(&tuple, &ctx.attribute(tuple).await, FlowProto::Tcp, FlowKind::Other).expect("admitted");
        let task = tokio::spawn(serve_admitted(ctx.clone(), app, tuple, admitted, crate::link::exit::Upstream::Tcp(upstream), monotonic_ms(), None));
        let mut bed = Self { ctx, wire, local, remote, server_next: 0, client_next: CLIENT_ISN + 1, server, upstream_ends, task };
        let syn_ack = bed.next_segment().await;
        assert!(syn_ack.syn && syn_ack.ack, "{syn_ack:?}");
        bed.send(&[]);
        bed
    }

    /// For a test whose server must see the relay's own TCP segments (a reset, a
    /// half-close, a FIN): a filtering proxy that sits in this machine's loopback
    /// (AdGuard proxies the loopback TCP of new executables: a client's reset
    /// reaches the server as a FIN) would fail it with a confusing assertion, so it
    /// fails here, saying so. Not ignored: on the VM it runs and must pass.
    fn needs_plain_loopback(&self) {
        let (ours, seen) = self.upstream_ends;
        assert_eq!(ours, seen, "loopback is proxied on this machine (e.g. AdGuard); run on the VM (the server saw {seen}, the relay's socket is {ours})");
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

impl TcpBed {
    /// A flow that exits through a hub (`relay::handle_exiting`'s path): no
    /// SYN-time socket, an upstream the decision opens. `server` is an unused
    /// loopback pair, as no server is dialled from here.
    async fn through(flow: (&str, &str), plan: crate::link::Plan) -> Self {
        let (local, remote) = ends(flow);
        let ctx = relay(Arc::default());
        let mut wire = wire();
        wire.to_stack.send(segment(local, remote, CLIENT_ISN, Flags { syn: true, ..Flags::default() }, &[])).unwrap();
        let Ok(IpStackStream::Tcp(app)) = wire.stack.accept().await else { panic!("no TCP stream") };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let (_unused, server) = tokio::join!(TcpStream::connect(listener.local_addr().unwrap()), listener.accept());
        let tuple = FiveTuple { proto: Proto::Tcp, local, remote };
        let admitted = ctx.admit(&tuple, &ctx.attribute(tuple).await, FlowProto::Tcp, FlowKind::Other).expect("admitted");
        let (upstream, starter) = crate::link::exit::lazy();
        let exit = super::relay::FlowExit::for_test(&ctx, starter, plan, admitted.id, remote);
        let task = tokio::spawn(serve_admitted(ctx.clone(), app, tuple, admitted, crate::link::exit::Upstream::Lazy(upstream), monotonic_ms(), Some(exit)));
        let (server, seen_from) = server.unwrap();
        let mut bed = Self { ctx, wire, local, remote, server_next: 0, client_next: CLIENT_ISN + 1, server, upstream_ends: (seen_from, seen_from), task };
        let syn_ack = bed.next_segment().await;
        assert!(syn_ack.syn && syn_ack.ack, "{syn_ack:?}");
        bed.send(&[]);
        bed
    }

    /// The app's received bytes, until `len` of them came.
    async fn received(&mut self, len: usize) -> Vec<u8> {
        let mut got = Vec::new();
        while got.len() < len {
            let packet = tokio::time::timeout(WAIT, self.wire.from_stack.recv()).await.expect("a segment").unwrap();
            let headers = PacketHeaders::from_ip_slice(&packet).unwrap();
            let Some(TransportHeader::Tcp(header)) = headers.transport else { continue };
            let payload = headers.payload.slice();
            self.server_next = header.sequence_number.wrapping_add(u32::try_from(payload.len()).unwrap());
            got.extend_from_slice(payload);
            self.send(&[]);
        }
        got
    }
}

/// Exiting through a hub, through the real relay and a real `IpStack`: a blocked
/// flow never reaches the hub and is reset as before; a passed one opens through
/// the hub by the name it carries, its bytes go both ways, and its row says so.
#[tokio::test(flavor = "multi_thread")]
async fn an_exiting_flow_opens_through_the_hub_only_once_passed_and_by_the_name_it_carries() {
    use crate::link::tests as lt;
    let h = lt::hub(true).await;
    let port = lt::http_echo().await;
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(lt::LoopNet::default());
    let m = lt::manager(dir.path(), net.clone());
    lt::paired(&m, &h).await;
    m.set(lt::exiting(sieve_ipc::LinkRoute::Dial { address: h.addr.to_string() }, sieve_ipc::LinkHubDown::Stop)).unwrap();
    m.routes_up(net.clone(), lt::noop_reset());
    lt::until("up", || m.status().state == sieve_ipc::LinkState::Up).await;
    let plan = m.plan(lt::SITE.parse().unwrap()).unwrap();
    let remote = format!("{}:{port}", lt::SITE);

    let mut bed = TcpBed::through(("10.9.0.2:50001", &remote), plan.clone()).await;
    let expected_seq = bed.server_next;
    bed.send(&hello(BLOCKED));
    let end = bed.until_the_end().await;
    assert!(end.rst && !end.fin && end.sequence_number == expected_seq, "{end:?}");
    ended(&mut bed.task).await.unwrap();
    assert_blocked_once(&bed.ctx, BLOCKED);

    let mut bed = TcpBed::through(("10.9.0.2:50002", &remote), plan).await;
    let request = hello("echo.test");
    bed.send(&request);
    // The server's whole answer, byte for byte, through the hub (an HTTP answer, so
    // a filtering proxy in this machine's loopback passes it as it is).
    let expected = lt::http_wrapped(&request);
    assert_eq!(bed.received(expected.len()).await, expected, "the answer came back through the hub");
    let rows = bed.ctx.book.lock().unwrap().take_log();
    assert!(
        rows.iter().any(|r| r.outcome == LogOutcome::Exit { via: sieve_ipc::ExitVia::Hub, target: Some(format!("echo.test:{port}")), reason: None }),
        "{rows:?}"
    );
    let audit = std::fs::read_to_string(h.hub.audit_path()).unwrap_or_default();
    assert!(audit.contains(&format!("echo.test:{port}")), "the hub was asked by name");
    assert!(!audit.contains(BLOCKED), "the blocked flow never reached the hub");
    bed.task.abort();
    m.routes_down();
}

/// A connect that records its target and fails at once as unreachable, so the
/// relay's retry goes on to the next address.
#[derive(Default)]
struct Scripted {
    tried: Mutex<Vec<SocketAddr>>,
}

impl super::retry::Attempt for Scripted {
    type Stream = TcpStream;
    fn attempt(&self, target: SocketAddr) -> super::retry::AttemptFuture<'_, TcpStream> {
        self.tried.lock().unwrap().push(target);
        Box::pin(async { Err(super::retry::Failure::Unreachable) })
    }
}

/// A paired manager with exiting on, its link dialling the test hub.
async fn exiting_manager(h: &crate::link::tests::TestHub, dir: &std::path::Path, net: Arc<crate::link::tests::LoopNet>) -> Arc<crate::link::LinkManager> {
    use crate::link::tests as lt;
    let m = lt::manager(dir, net.clone());
    lt::paired(&m, h).await;
    m.set(lt::exiting(sieve_ipc::LinkRoute::Dial { address: h.addr.to_string() }, sieve_ipc::LinkHubDown::Stop)).unwrap();
    m.routes_up(net, lt::noop_reset());
    lt::until("up", || m.status().state == sieve_ipc::LinkState::Up).await;
    m
}

/// The app's SYN, through `handle_tcp`, to its end.
async fn through_handle_tcp(ctx: &Arc<Relay>, local: SocketAddr, remote: SocketAddr, first: Option<Vec<u8>>) -> Wire {
    let mut wire = wire();
    wire.to_stack.send(segment(local, remote, CLIENT_ISN, Flags { syn: true, ..Flags::default() }, &[])).unwrap();
    let Ok(IpStackStream::Tcp(app)) = wire.stack.accept().await else { panic!("no TCP stream") };
    let task = tokio::spawn(super::relay::handle_tcp(ctx.clone(), app));
    if let Some(first) = first {
        let packet = tokio::time::timeout(WAIT, wire.from_stack.recv()).await.expect("the SYN-ACK").unwrap();
        let headers = PacketHeaders::from_ip_slice(&packet).unwrap();
        let Some(TransportHeader::Tcp(syn_ack)) = headers.transport else { panic!("not TCP") };
        let server_next = syn_ack.sequence_number.wrapping_add(1);
        wire.to_stack.send(segment(local, remote, CLIENT_ISN + 1, Flags { ack: Some(server_next), ..Flags::default() }, &[])).unwrap();
        wire.to_stack.send(segment(local, remote, CLIENT_ISN + 1, Flags { psh: true, ack: Some(server_next), ..Flags::default() }, &first)).unwrap();
        // The server's whole answer through the hub ([`lt::http_echo`]).
        let expected = crate::link::tests::http_wrapped(&first);
        let mut got = Vec::new();
        while got.len() < expected.len() {
            let packet = tokio::time::timeout(WAIT, wire.from_stack.recv()).await.expect("the echo").unwrap();
            let headers = PacketHeaders::from_ip_slice(&packet).unwrap();
            got.extend_from_slice(headers.payload.slice());
        }
        assert_eq!(got, expected, "the answer came back through the hub");
        task.abort();
        return wire;
    }
    ended(task).await.unwrap();
    wire
}

/// P1-1 (2026-11-20 review): a destination exiting does not concern (a private
/// address) whose name also resolved to a public one is never retried at the
/// public one from this computer while exiting is on; the control, without
/// exiting, retries it there as before.
#[tokio::test(flavor = "multi_thread")]
async fn while_exiting_a_public_alternate_of_a_local_destination_is_never_dialled_directly() {
    use crate::link::tests as lt;
    let h = lt::hub(true).await;
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(lt::LoopNet::default());
    let m = exiting_manager(&h, dir.path(), net.clone()).await;
    let public: std::net::IpAddr = lt::SITE.parse().unwrap();
    let (local, remote) = ends(("10.9.0.2:50010", "10.255.255.1:8080"));
    for (link, exiting) in [(m.clone(), true), (no_link(), false)] {
        let dial = Arc::new(Scripted::default());
        let ctx = relay_with(Arc::default(), link, Some(dial.clone()));
        {
            // A hostile name that answers a private address and its own public one.
            let mut names = ctx.names.lock().unwrap();
            names.record("planted.example", remote.ip(), NAME_TTL_S, monotonic_ms());
            names.record("planted.example", public, NAME_TTL_S, monotonic_ms());
        }
        through_handle_tcp(&ctx, local, remote, None).await;
        let tried = dial.tried.lock().unwrap().clone();
        assert_eq!(tried.first(), Some(&remote), "the app's own address first");
        if exiting {
            assert!(!tried.iter().any(|t| t.ip() == public), "the public alternate was dialled from this computer: {tried:?}");
            assert!(!net.asked(public), "nor through the link's network");
        } else {
            assert!(tried.contains(&SocketAddr::new(public, remote.port())), "the control: retried at the alternate without exiting: {tried:?}");
        }
    }
    m.routes_down();
}

/// The review's missing case: `handle_tcp` with exiting on, to a public address
/// that has retry alternates. It takes the exit path: nothing at all is dialled
/// from this computer (not the address, not an alternate), and the flow opens
/// through the hub by the name it carries.
#[tokio::test(flavor = "multi_thread")]
async fn handle_tcp_takes_the_exit_path_and_dials_no_alternate() {
    use crate::link::tests as lt;
    let h = lt::hub(true).await;
    let port = lt::http_echo().await;
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(lt::LoopNet::default());
    let m = exiting_manager(&h, dir.path(), net.clone()).await;
    let dial = Arc::new(Scripted::default());
    let ctx = relay_with(Arc::default(), m.clone(), Some(dial.clone()));
    let remote: SocketAddr = format!("{}:{port}", lt::SITE).parse().unwrap();
    {
        let mut names = ctx.names.lock().unwrap();
        names.record("echo.test", remote.ip(), NAME_TTL_S, monotonic_ms());
        names.record("echo.test", "81.2.69.171".parse().unwrap(), NAME_TTL_S, monotonic_ms());
    }
    through_handle_tcp(&ctx, "10.9.0.2:50011".parse().unwrap(), remote, Some(hello("echo.test"))).await;
    assert!(dial.tried.lock().unwrap().is_empty(), "nothing dialled from this computer: {:?}", dial.tried.lock().unwrap());
    let rows = ctx.book.lock().unwrap().take_log();
    assert!(rows.iter().any(|r| r.outcome == LogOutcome::Exit { via: sieve_ipc::ExitVia::Hub, target: Some(format!("echo.test:{port}")), reason: None }), "{rows:?}");
    m.routes_down();
}

/// P2-1: the engine's own plain HTTP (certificate status fetches) goes through
/// the hub by its Host while exiting applies, never from this computer; with the
/// hub down and Stop, it fails like any flow, with nothing sent directly.
#[tokio::test(flavor = "multi_thread")]
async fn the_engines_own_plain_http_goes_through_the_hub_by_its_host() {
    use crate::link::tests as lt;
    let h = lt::hub(true).await;
    let port = lt::http_echo().await;
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(lt::LoopNet::default());
    let m = exiting_manager(&h, dir.path(), net.clone()).await;
    let ctx = relay_with(Arc::default(), m.clone(), Some(Arc::new(Scripted::default())));
    let remote: SocketAddr = format!("{}:{port}", lt::SITE).parse().unwrap();
    let local: SocketAddr = "10.9.0.2:50012".parse().unwrap();
    let request = b"GET /ocsp HTTP/1.1\r\nHost: echo.test\r\n\r\n".to_vec();

    let mut wire = wire();
    wire.to_stack.send(segment(local, remote, CLIENT_ISN, Flags { syn: true, ..Flags::default() }, &[])).unwrap();
    let Ok(IpStackStream::Tcp(app)) = wire.stack.accept().await else { panic!("no TCP stream") };
    let plan = m.plan(remote.ip()).expect("exiting applies");
    let tuple = FiveTuple { proto: Proto::Tcp, local, remote };
    let task = tokio::spawn(super::relay::relay_own_through(ctx.clone(), app, tuple, plan));
    let packet = tokio::time::timeout(WAIT, wire.from_stack.recv()).await.expect("the SYN-ACK").unwrap();
    let Some(TransportHeader::Tcp(syn_ack)) = PacketHeaders::from_ip_slice(&packet).unwrap().transport else { panic!("not TCP") };
    let server_next = syn_ack.sequence_number.wrapping_add(1);
    wire.to_stack.send(segment(local, remote, CLIENT_ISN + 1, Flags { psh: true, ack: Some(server_next), ..Flags::default() }, &request)).unwrap();
    let expected = lt::http_wrapped(&request);
    let mut got = Vec::new();
    while got.len() < expected.len() {
        let packet = tokio::time::timeout(WAIT, wire.from_stack.recv()).await.expect("the echo").unwrap();
        got.extend_from_slice(PacketHeaders::from_ip_slice(&packet).unwrap().payload.slice());
    }
    assert_eq!(got, expected, "the answer came back through the hub");
    let audit = std::fs::read_to_string(h.hub.audit_path()).unwrap_or_default();
    assert!(audit.contains(&format!("echo.test:{port}")), "the hub was asked by the Host");
    assert!(ctx.book.lock().unwrap().take_log().is_empty(), "the engine's own flow has no row");
    task.abort();

    // The hub gone, Stop: the fetch fails, and nothing leaves this computer.
    drop(h);
    lt::until("down", || m.status().state == sieve_ipc::LinkState::Down).await;
    let mut wire = self::wire();
    let local: SocketAddr = "10.9.0.2:50013".parse().unwrap();
    wire.to_stack.send(segment(local, remote, CLIENT_ISN, Flags { syn: true, ..Flags::default() }, &[])).unwrap();
    let Ok(IpStackStream::Tcp(app)) = wire.stack.accept().await else { panic!("no TCP stream") };
    let tuple = FiveTuple { proto: Proto::Tcp, local, remote };
    let task = tokio::spawn(super::relay::relay_own_through(ctx.clone(), app, tuple, m.plan(remote.ip()).unwrap()));
    let packet = tokio::time::timeout(WAIT, wire.from_stack.recv()).await.expect("the SYN-ACK").unwrap();
    let Some(TransportHeader::Tcp(syn_ack)) = PacketHeaders::from_ip_slice(&packet).unwrap().transport else { panic!("not TCP") };
    wire.to_stack.send(segment(local, remote, CLIENT_ISN + 1, Flags { psh: true, ack: Some(syn_ack.sequence_number.wrapping_add(1)), ..Flags::default() }, &request)).unwrap();
    ended(task).await.unwrap();
    assert!(!net.asked(remote.ip()), "nothing went to the site from this computer");
    m.routes_down();
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

/// P3 (second review of run 7): the app resets its connection halfway through an
/// upload. The server must see a reset, not the end of the stream: a FIN there ends
/// the upload as if it were complete.
#[tokio::test(flavor = "multi_thread")]
async fn an_apps_reset_reaches_the_server_as_a_reset() {
    for flow in FLOWS {
        for reset in [true, false] {
            let mut bed = TcpBed::new(flow).await;
            bed.needs_plain_loopback();
            let head = format!("POST /upload HTTP/1.1\r\nHost: {ALLOWED}\r\nContent-Length: 100000\r\n\r\n").into_bytes();
            bed.send(&head);
            let mut got = vec![0u8; head.len()];
            ended(bed.server.read_exact(&mut got)).await.unwrap();
            let (seq, ack) = (bed.client_next, bed.server_next);
            let flags = if reset { Flags { rst: true, ack: Some(ack), ..Flags::default() } } else { Flags { fin: true, ack: Some(ack), ..Flags::default() } };
            bed.wire.to_stack.send(segment(bed.local, bed.remote, seq, flags, &[])).unwrap();
            let mut rest = Vec::new();
            let read = ended(bed.server.read_to_end(&mut rest)).await;
            if reset {
                assert_eq!(read.map_err(|e| e.kind()), Err(std::io::ErrorKind::ConnectionReset), "{flow:?}: the server took the cut-short upload as complete");
            } else {
                assert_eq!(read.map_err(|e| e.kind()), Ok(0), "{flow:?}: the control, the app's FIN is the server's end");
            }
            bed.task.abort();
        }
    }
}

/// Run 8: a client that half-closes after its request (HTTP/1.0 style) gets the
/// answer through the relay, whose server answers once it saw the end of the request.
#[tokio::test(flavor = "multi_thread")]
async fn a_half_closed_app_gets_the_servers_answer_through_the_relay() {
    const ANSWER: &[u8] = b"HTTP/1.0 200 OK\r\n\r\nthe answer, close-delimited";
    for flow in FLOWS {
        let mut bed = TcpBed::new(flow).await;
        bed.needs_plain_loopback();
        let request = format!("GET / HTTP/1.0\r\nHost: {ALLOWED}\r\n\r\n").into_bytes();
        bed.send(&request);
        let (seq, ack) = (bed.client_next, bed.server_next);
        bed.wire.to_stack.send(segment(bed.local, bed.remote, seq, Flags { fin: true, ack: Some(ack), ..Flags::default() }, &[])).unwrap();
        bed.client_next += 1;
        let mut got = Vec::new();
        ended(bed.server.read_to_end(&mut got)).await.unwrap();
        assert_eq!(got, request, "{flow:?}: the request, then the end");
        bed.server.write_all(ANSWER).await.unwrap();
        bed.server.shutdown().await.unwrap();
        let mut answer = Vec::new();
        let mut fin = false;
        while !fin {
            let packet = tokio::time::timeout(WAIT, bed.wire.from_stack.recv()).await.expect("a segment").unwrap();
            let headers = PacketHeaders::from_ip_slice(&packet).unwrap();
            let Some(TransportHeader::Tcp(header)) = headers.transport else { panic!("not TCP") };
            let payload = headers.payload.slice();
            assert!(!header.rst, "{flow:?}: reset after {} bytes", answer.len());
            if !payload.is_empty() {
                answer.extend_from_slice(payload);
                bed.server_next = header.sequence_number.wrapping_add(u32::try_from(payload.len()).unwrap());
                bed.send(&[]);
            }
            fin = header.fin;
        }
        assert_eq!(answer, ANSWER, "{flow:?}: the answer reached the half-closed app before the FIN");
        bed.task.abort();
    }
}

/// A connect that turns exiting on while it runs (after the guard let it through,
/// so it races the change), then connects to `server` on loopback whatever its
/// target.
struct TurnsExitingOn {
    link: Arc<crate::link::LinkManager>,
    settings: sieve_ipc::LinkSettings,
    server: SocketAddr,
    turn: bool,
}

impl super::retry::Attempt for TurnsExitingOn {
    type Stream = TcpStream;
    fn attempt(&self, _target: SocketAddr) -> super::retry::AttemptFuture<'_, TcpStream> {
        if self.turn {
            self.link.set(self.settings.clone()).unwrap();
        }
        let server = self.server;
        Box::pin(async move { TcpStream::connect(server).await.map_err(|e| super::retry::Failure::from_io(&e)) })
    }
}

/// Round 2's P3: a direct connect that started just before exiting turned on is
/// in the book only after the change ended the open connections: it ends too (a
/// reset, one row), never stays on this computer's address. The control, with no
/// change, is served.
#[tokio::test(flavor = "multi_thread")]
async fn a_direct_connect_that_raced_exiting_turning_on_is_ended() {
    use crate::link::tests as lt;
    let h = lt::hub(true).await;
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(lt::LoopNet::default());
    let m = lt::manager(dir.path(), net.clone());
    lt::paired(&m, &h).await;
    m.routes_up(net.clone(), lt::noop_reset());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut kept = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            kept.push(s);
        }
    });
    let on = lt::exiting(sieve_ipc::LinkRoute::Dial { address: h.addr.to_string() }, sieve_ipc::LinkHubDown::Stop);
    let remote: SocketAddr = format!("{}:443", lt::SITE).parse().unwrap();
    for turn in [true, false] {
        let dial = Arc::new(TurnsExitingOn { link: m.clone(), settings: on.clone(), server, turn });
        let ctx = relay_with(Arc::default(), m.clone(), Some(dial));
        // The engine's own registration: the change ends what it finds in the book.
        let (book, filter) = (ctx.book.clone(), ctx.filter.clone());
        m.on_exit_change(Arc::new(move |concerns: &dyn Fn(std::net::IpAddr) -> bool, change: crate::link::Change| {
            super::relay::reconnect_the_new_way(&book, &filter, concerns, change);
        }));
        let local: SocketAddr = if turn { "10.9.0.2:50020" } else { "10.9.0.2:50021" }.parse().unwrap();
        let mut wire = wire();
        wire.to_stack.send(segment(local, remote, CLIENT_ISN, Flags { syn: true, ..Flags::default() }, &[])).unwrap();
        let Ok(IpStackStream::Tcp(app)) = wire.stack.accept().await else { panic!("no TCP stream") };
        let task = tokio::spawn(super::relay::handle_tcp(ctx.clone(), app));
        let ended_row = |rows: &[sieve_ipc::LogRow]| rows.iter().any(|r| matches!(&r.outcome, LogOutcome::Exit { via: sieve_ipc::ExitVia::Hub, target: None, reason: Some(r) } if r.contains("1 open connection ended")));
        if turn {
            ended(task).await.unwrap();
            // The app hears a reset, so it reconnects the new way.
            loop {
                let packet = tokio::time::timeout(WAIT, wire.from_stack.recv()).await.expect("a reset").unwrap();
                if let Some(TransportHeader::Tcp(t)) = PacketHeaders::from_ip_slice(&packet).unwrap().transport {
                    assert!(!t.fin, "a FIN would end the connection as complete: {t:?}");
                    if t.rst {
                        break;
                    }
                }
            }
            let mut book = ctx.book.lock().unwrap();
            assert_eq!(book.live(), 0, "nothing left open");
            let rows = book.take_log();
            assert!(ended_row(&rows), "a row says it ended");
            let said = rows.iter().filter(|r| matches!(&r.outcome, LogOutcome::Exit { reason: Some(r), .. } if r.contains("ended"))).count();
            assert_eq!(said, 1, "said once: {rows:?}");
        } else {
            // Its owner lookup gives up first (no owner in a test), then it is served.
            until("the control admitted", || ctx.book.lock().unwrap().live() == 1).await;
            tokio::time::sleep(SETTLE).await;
            let mut book = ctx.book.lock().unwrap();
            let (rows, batch) = (book.take_log(), book.take_batch());
            assert!(!task.is_finished() && book.live() == 1, "the control is served: {rows:?} {batch:?}");
            assert!(!ended_row(&rows));
            drop(book);
            task.abort();
        }
        // Off again for the control.
        m.set(sieve_ipc::LinkSettings { exit: false, ..on.clone() }).unwrap();
    }
    m.routes_down();
}

/// Rows of the book read so far, kept across polls.
fn rows_so_far(ctx: &Relay, seen: &Mutex<Vec<sieve_ipc::LogRow>>) -> Vec<sieve_ipc::LogRow> {
    let mut seen = seen.lock().unwrap();
    seen.extend(ctx.book.lock().unwrap().take_log());
    seen.clone()
}

/// Round 2's P1: an open UDP flow that was relayed from this computer stops
/// leaving directly once exiting applies to it: when exiting turns on (the
/// change ends it in the book, and the way out moves), when sieving resumes after
/// a pause, and when UDP is set from Direct to Drop (the way out moves only). It
/// is decided again: dropped, as set, or, QUIC, refused. A LAN flow is untouched.
#[tokio::test(flavor = "multi_thread")]
async fn an_open_udp_flow_stops_leaving_directly_once_exiting_applies() {
    use crate::link::tests as lt;
    use sieve_ipc::{ExitVia, LinkHubDown, LinkRoute, LinkSettings, LinkUdp};
    let h = lt::hub(true).await;
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(lt::LoopNet::default());
    let m = lt::manager(dir.path(), net.clone());
    lt::paired(&m, &h).await;
    m.routes_up(net.clone(), lt::noop_reset());
    let (echo, echoed) = udp_echo().await;
    let answers = loopback_udp_works().await;
    let on =lt::exiting(LinkRoute::Dial { address: h.addr.to_string() }, LinkHubDown::Stop);
    let off = LinkSettings { exit: false, ..on.clone() };
    const GAME: &[u8] = b"\x00\x01 a game's datagram";
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Case {
        ExitTurnsOn,
        Resumes,
        UdpToDrop,
        QuicExitTurnsOn,
        LanExitTurnsOn,
    }
    for (n, case) in [Case::ExitTurnsOn, Case::Resumes, Case::UdpToDrop, Case::QuicExitTurnsOn, Case::LanExitTurnsOn].into_iter().enumerate() {
        // Before: the flow relays from this computer.
        match case {
            Case::Resumes => {
                m.set(on.clone()).unwrap();
                m.set_sieving(false);
            }
            Case::UdpToDrop => m.set(LinkSettings { udp: LinkUdp::Direct, ..on.clone() }).unwrap(),
            _ => m.set(off.clone()).unwrap(),
        }
        let sink = Arc::new(FakeSink::default());
        let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ctx = relay_udp_to(sink.clone(), m.clone(), echo, opened.clone());
        if case == Case::ExitTurnsOn {
            // The engine's own registration: a change of the way out ends what it concerns.
            let (book, filter) = (ctx.book.clone(), ctx.filter.clone());
            m.on_exit_change(Arc::new(move |concerns: &dyn Fn(std::net::IpAddr) -> bool, change: crate::link::Change| {
                super::relay::reconnect_the_new_way(&book, &filter, concerns, change);
            }));
        } else {
            m.on_exit_change(Arc::new(|_: &dyn Fn(std::net::IpAddr) -> bool, _: crate::link::Change| {}));
        }
        let remote = if case == Case::LanExitTurnsOn { "10.0.0.9:4000" } else { "81.2.69.170:4000" };
        let (local, remote) = ends((&format!("10.9.0.2:{}", 40_000 + n), remote));
        let mut wire = wire();
        let first: Vec<Vec<u8>> = if case == Case::QuicExitTurnsOn { sealed_initials(ALLOWED).to_vec() } else { vec![GAME.to_vec()] };
        for d in &first {
            wire.to_stack.send(udp_packet(local, remote, d)).unwrap();
        }
        let task = tokio::spawn(handle_udp(ctx.clone(), accept_udp(&mut wire).await));
        until(&format!("{case:?}: relayed from this computer"), || opened.load(Ordering::SeqCst) == 1).await;
        if answers {
            for d in &first {
                assert_eq!(&next_datagram(&mut wire, local, remote).await, d, "{case:?}: relayed, and answered");
            }
        } else {
            tokio::time::sleep(SETTLE).await;
        }
        let before = echoed.load(Ordering::SeqCst);
        let seen = Mutex::new(Vec::new());
        assert!(!rows_so_far(&ctx, &seen).iter().any(|r| matches!(r.outcome, LogOutcome::Exit { via: ExitVia::Dropped, .. })), "{case:?}: not dropped before the change");
        {
            let mut book = ctx.book.lock().unwrap();
            assert_eq!(book.live(), 1, "{case:?}: open: {:?}", book.take_batch());
        }

        // The change.
        match case {
            Case::Resumes => m.set_sieving(true),
            _ => m.set(on.clone()).unwrap(),
        }
        if case == Case::LanExitTurnsOn {
            tokio::time::sleep(SETTLE).await;
            wire.to_stack.send(udp_packet(local, remote, GAME)).unwrap();
            if answers {
                assert_eq!(next_datagram(&mut wire, local, remote).await, GAME, "a LAN flow keeps going");
            } else {
                tokio::time::sleep(SETTLE).await;
            }
            assert!(!rows_so_far(&ctx, &seen).iter().any(|r| matches!(r.outcome, LogOutcome::Exit { .. })), "a LAN flow is not touched");
            assert_eq!((ctx.book.lock().unwrap().live(), opened.load(Ordering::SeqCst)), (1, 1), "the same flow, on the same socket");
            assert!(!task.is_finished());
        } else {
            let why = if case == Case::QuicExitTurnsOn { "QUIC is refused" } else { "UDP is not carried" };
            until(&format!("{case:?}: decided again"), || {
                rows_so_far(&ctx, &seen).iter().any(|r| matches!(&r.outcome, LogOutcome::Exit { via: ExitVia::Dropped, reason: Some(r), .. } if r.starts_with(why)))
            })
            .await;
            // Whatever came back while it was still relayed (late, where loopback UDP is filtered).
            while wire.from_stack.try_recv().is_ok() {}
            wire.to_stack.send(udp_packet(local, remote, &first[0])).unwrap();
            tokio::time::sleep(SETTLE).await;
            assert_eq!(opened.load(Ordering::SeqCst), 1, "{case:?}: no new socket from this computer");
            if answers {
                // Where loopback UDP is filtered it may also arrive late: counted only where it does not.
                assert_eq!(echoed.load(Ordering::SeqCst), before, "{case:?}: nothing more left from this computer");
            }
            assert_eq!(ctx.book.lock().unwrap().live(), 0, "{case:?}: the relayed row closed, the dropped one too");
            if case == Case::QuicExitTurnsOn {
                assert!(ctx.meters.quic.replies.load(Ordering::Relaxed) >= 1, "refused, so the browser falls back to TCP");
            } else {
                assert!(wire.from_stack.try_recv().is_err(), "{case:?}: nothing back");
            }
            let batch = ctx.book.lock().unwrap().take_batch();
            assert!(batch.iter().all(|e| !e.open), "{case:?}: the relayed row closed, the new one too: {batch:?}");
            assert!(batch.iter().any(|e| e.bytes_up > 0 && e.action == FlowAction::Relayed), "{case:?}: the relayed row kept its bytes");
        }
        task.abort();
    }
    m.routes_down();
}

/// A paired manager with routes up and exiting as `settings` (the link need not be
/// up: what a UDP flow decides reads only the choices), and a relay on it whose
/// UDP upstreams go to `server`, with the engine's own registration: a change of
/// the way out ends what it concerns.
async fn udp_bed(h: &crate::link::tests::TestHub, dir: &std::path::Path, server: SocketAddr, opened: Arc<std::sync::atomic::AtomicUsize>) -> (Arc<crate::link::LinkManager>, Arc<Relay>) {
    use crate::link::tests as lt;
    let net = Arc::new(lt::LoopNet::default());
    let m = lt::manager(dir, net.clone());
    lt::paired(&m, h).await;
    m.routes_up(net, lt::noop_reset());
    let ctx = relay_udp_to(Arc::default(), m.clone(), server, opened);
    let (book, filter) = (ctx.book.clone(), ctx.filter.clone());
    m.on_exit_change(Arc::new(move |concerns: &dyn Fn(std::net::IpAddr) -> bool, change: crate::link::Change| {
        super::relay::reconnect_the_new_way(&book, &filter, concerns, change);
    }));
    (m, ctx)
}

/// Round 3's P3-c: a change of the way out that leaves a UDP flow going from this
/// computer does not end it: a game or a call sent directly as set keeps its
/// socket when the link restarts, when exiting turns off, and when it turns on
/// again with UDP still Direct.
#[tokio::test(flavor = "multi_thread")]
async fn a_udp_flow_whose_way_does_not_change_keeps_its_socket() {
    use crate::link::tests as lt;
    use sieve_ipc::{ExitVia, LinkHubDown, LinkRoute, LinkSettings, LinkUdp};
    let h = lt::hub(true).await;
    let dir = tempfile::tempdir().unwrap();
    let (echo, _) = udp_echo().await;
    let answers = loopback_udp_works().await;
    let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (m, ctx) = udp_bed(&h, dir.path(), echo, opened.clone()).await;
    let direct = LinkSettings { udp: LinkUdp::Direct, ..lt::exiting(LinkRoute::Dial { address: h.addr.to_string() }, LinkHubDown::Stop) };
    m.set(direct.clone()).unwrap();
    const GAME: &[u8] = b"\x00\x02 a call's datagram";
    let (local, remote) = ends(("10.9.0.2:42000", "81.2.69.170:4000"));
    let mut wire = wire();
    wire.to_stack.send(udp_packet(local, remote, GAME)).unwrap();
    let task = tokio::spawn(handle_udp(ctx.clone(), accept_udp(&mut wire).await));
    until("relayed from this computer, as set", || opened.load(Ordering::SeqCst) == 1).await;
    let seen = Mutex::new(Vec::new());
    until("its row says direct", || rows_so_far(&ctx, &seen).iter().any(|r| matches!(r.outcome, LogOutcome::Exit { via: ExitVia::Direct, .. }))).await;
    for what in ["the link restarts", "exiting turns off", "exiting turns on, UDP Direct"] {
        match what {
            "the link restarts" => m.network_changed(),
            "exiting turns off" => m.set(LinkSettings { exit: false, ..direct.clone() }).unwrap(),
            _ => m.set(direct.clone()).unwrap(),
        }
        tokio::time::sleep(SETTLE).await;
        wire.to_stack.send(udp_packet(local, remote, GAME)).unwrap();
        if answers {
            assert_eq!(next_datagram(&mut wire, local, remote).await, GAME, "{what}: still answered");
        } else {
            tokio::time::sleep(SETTLE).await;
        }
        assert_eq!(opened.load(Ordering::SeqCst), 1, "{what}: the same socket");
        assert_eq!(ctx.book.lock().unwrap().live(), 1, "{what}: the same flow");
        assert!(!task.is_finished(), "{what}");
        let rows = rows_so_far(&ctx, &seen);
        assert!(!rows.iter().any(|r| matches!(&r.outcome, LogOutcome::Exit { reason: Some(r), .. } if r.contains("ended"))), "{what}: nothing ended: {rows:?}");
    }
    task.abort();
    m.routes_down();
}

/// Round 3's P3-d: a UDP flow dropped while exiting is on is decided again once
/// the way out no longer drops it: when the way out moves (exiting turned off),
/// at once, and on its next datagram when only the filter changed (the switch
/// paused there first): relayed from this computer, never black-holed until idle.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_udp_flow_is_decided_again_once_it_is_no_longer_dropped() {
    use crate::link::tests as lt;
    use sieve_ipc::{ExitVia, LinkHubDown, LinkRoute, LinkSettings};
    let h = lt::hub(true).await;
    let (echo, _) = udp_echo().await;
    const GAME: &[u8] = b"\x00\x03 a game's datagram";
    for (n, by_datagram) in [false, true].into_iter().enumerate() {
        let dir = tempfile::tempdir().unwrap();
        let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (m, ctx) = udp_bed(&h, dir.path(), echo, opened.clone()).await;
        let on = lt::exiting(LinkRoute::Dial { address: h.addr.to_string() }, LinkHubDown::Stop);
        m.set(on.clone()).unwrap();
        let (local, remote) = ends((&format!("10.9.0.2:{}", 43_000 + n), "81.2.69.170:4000"));
        let mut wire = wire();
        wire.to_stack.send(udp_packet(local, remote, GAME)).unwrap();
        let task = tokio::spawn(handle_udp(ctx.clone(), accept_udp(&mut wire).await));
        let seen = Mutex::new(Vec::new());
        until("dropped, as set", || rows_so_far(&ctx, &seen).iter().any(|r| matches!(r.outcome, LogOutcome::Exit { via: ExitVia::Dropped, .. }))).await;
        assert_eq!(opened.load(Ordering::SeqCst), 0, "nothing from this computer while dropped");
        if by_datagram {
            // Paused in the filter only: the way out did not move; the next datagram finds it.
            ctx.filter.update(|f| DomainFilter::new(&Policy { sieving: false, ..Policy::default() }, f.rules.clone()));
            tokio::time::sleep(SETTLE).await;
            assert_eq!(opened.load(Ordering::SeqCst), 0, "nothing sent until a datagram comes");
            wire.to_stack.send(udp_packet(local, remote, GAME)).unwrap();
        } else {
            m.set(LinkSettings { exit: false, ..on.clone() }).unwrap();
        }
        until(&format!("by datagram {by_datagram}: decided again and relayed"), || opened.load(Ordering::SeqCst) == 1).await;
        assert!(!task.is_finished());
        assert_eq!(ctx.book.lock().unwrap().live(), 1, "a new flow, relayed");
        task.abort();
        m.routes_down();
    }
}

/// Round 3's P3-a: a change that only moves the way out (UDP set from Direct to
/// Drop, which ends nothing in the book) made after a flow decided its way, here
/// while its socket opens, is seen before anything is sent: its held datagram
/// never leaves, and it is decided again (dropped).
#[tokio::test(flavor = "multi_thread")]
async fn a_set_only_change_after_the_decision_is_seen_before_anything_is_sent() {
    use crate::link::tests as lt;
    use sieve_ipc::{ExitVia, LinkHubDown, LinkRoute, LinkSettings, LinkUdp};
    let h = lt::hub(true).await;
    let dir = tempfile::tempdir().unwrap();
    let (echo, echoed) = udp_echo().await;
    let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (m, ctx) = udp_bed(&h, dir.path(), echo, opened.clone()).await;
    let on = lt::exiting(LinkRoute::Dial { address: h.addr.to_string() }, LinkHubDown::Stop);
    m.set(LinkSettings { udp: LinkUdp::Direct, ..on.clone() }).unwrap();
    // The upstream's open sets UDP to Drop on its way.
    let mut relay = Arc::into_inner(ctx).expect("not shared yet");
    let (link, drop_now) = (m.clone(), on.clone());
    let inner = relay.udp.clone();
    relay.udp = Arc::new(move |target| {
        link.set(drop_now.clone()).unwrap();
        inner(target)
    });
    let ctx = Arc::new(relay);
    let (local, remote) = ends(("10.9.0.2:44000", "81.2.69.170:4000"));
    let mut wire = wire();
    wire.to_stack.send(udp_packet(local, remote, b"\x00\x04 held")).unwrap();
    let task = tokio::spawn(handle_udp(ctx.clone(), accept_udp(&mut wire).await));
    let seen = Mutex::new(Vec::new());
    until("decided again: dropped", || rows_so_far(&ctx, &seen).iter().any(|r| matches!(r.outcome, LogOutcome::Exit { via: ExitVia::Dropped, .. }))).await;
    assert_eq!(opened.load(Ordering::SeqCst), 1);
    let batch = ctx.book.lock().unwrap().take_batch();
    assert!(batch.iter().filter(|e| !e.open).all(|e| e.bytes_up == 0), "nothing was sent from this computer: {batch:?}");
    tokio::time::sleep(SETTLE).await;
    assert_eq!(echoed.load(Ordering::SeqCst), 0, "the server got nothing");
    task.abort();
    m.routes_down();
}

/// The control: a flow no rule blocks still ends with a FIN when its server does.
#[tokio::test(flavor = "multi_thread")]
async fn a_passed_flow_still_closes_with_a_fin() {
    for flow in FLOWS {
        let mut bed = TcpBed::new(flow).await;
        bed.needs_plain_loopback();
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

/// Half-open flows cancelled at once, many more than the runtime has threads.
const HALF_OPEN: u16 = 64;

/// The engine's dump of 2026-11-22: a routes take-down cancelled its flows, and every
/// thread of the runtime (all 540: 28 workers and the 512 blocking threads) sat in
/// ipstack's stream drop, waiting in `block_in_place` + `block_on` for a session task
/// that no thread was left to run. The stop hung with them. Here the runtime has 4
/// threads in all and 64 half-open streams are cancelled: the take-down must end.
#[test]
fn cancelling_more_half_open_flows_than_the_runtime_has_threads_ends() {
    use crate::flow::tasks::{FlowTasks, ShutdownReport};
    let (done, heard) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).max_blocking_threads(2).enable_all().build().unwrap();
        let report = rt.block_on(async {
            let mut wire = wire();
            let remote: SocketAddr = "198.51.100.7:443".parse().unwrap();
            let mut tasks = FlowTasks::new();
            for i in 0..HALF_OPEN {
                let local = SocketAddr::from(([10, 9, 0, 2], 40_000 + i));
                wire.to_stack.send(segment(local, remote, CLIENT_ISN, Flags { syn: true, ..Flags::default() }, &[])).unwrap();
                let Ok(IpStackStream::Tcp(app)) = wire.stack.accept().await else { panic!("no TCP stream") };
                // A flow that holds its app side and never finishes its handshake.
                tasks.spawn(async move {
                    let _app = app;
                    std::future::pending::<()>().await;
                });
            }
            let report = tasks.shutdown(Duration::from_secs(3)).await;
            drop(wire);
            report
        });
        rt.shutdown_timeout(Duration::from_secs(1));
        let _ = done.send(report);
    });
    let report = heard.recv_timeout(Duration::from_secs(20)).expect("the cancelled flows held every thread of the runtime");
    assert_eq!(report, ShutdownReport { live: usize::from(HALF_OPEN), drained: true });
}
