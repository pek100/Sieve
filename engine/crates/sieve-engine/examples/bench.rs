//! CPU-only benchmark of the per-flow decode path and of ipstack's
//! per-packet ingress cost (no adapter, no network: packets go through an
//! in-memory packet device).
//!
//!     cargo run --release --example bench
//!
//! Decode numbers are per call. A flow pays the decode once (classify stops
//! after its first ClientHello / Initial / request); every later packet only
//! pays the stack and the relay, which the ipstack numbers estimate.

use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Instant;

use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use sieve_engine::flow::classify::{TcpClassifier, UdpClassifier};
use sieve_engine::domain::{DomainFilter, Flow, Owner};
use sieve_engine::flow::flows::{FiveTuple, OwnerRow, match_owner};
use sieve_engine::flow::packet::{self, Proto};
use sieve_engine::flow::quic::{self, VERSION_1};
use sieve_filter::rules::{ListText, RuleEngine, RuleSet};
use sieve_ipc::Policy;
use sieve_engine::flow::sni::build;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

fn time<T>(name: &str, iters: u32, mut f: impl FnMut() -> T) -> f64 {
    for _ in 0..iters / 10 {
        black_box(f());
    }
    let t = Instant::now();
    for _ in 0..iters {
        black_box(f());
    }
    let ns = t.elapsed().as_nanos() as f64 / f64::from(iters);
    println!("{name:<58} {:>10.0} ns/op", ns);
    ns
}

/// One IP packet per read and per write, like a TUN.
struct MemDevice {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl AsyncRead for MemDevice {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if let Some(p) = ready!(self.rx.poll_recv(cx)) {
            buf.put_slice(&p);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MemDevice {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let _ = self.tx.send(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

const APP: [u8; 4] = [198, 18, 211, 1];
const SRV: [u8; 4] = [93, 184, 215, 14];

fn udp_packet(payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv4(APP, SRV, 64).udp(50_000, 443);
    let mut out = Vec::with_capacity(b.size(payload.len()));
    b.write(&mut out, payload).unwrap();
    out
}

fn tcp_packet(seq: u32, ack: Option<u32>, syn: bool, payload: &[u8]) -> Vec<u8> {
    let mut b = PacketBuilder::ipv4(APP, SRV, 64).tcp(50_001, 443, seq, 65_535);
    if syn {
        b = b.syn();
    }
    if let Some(a) = ack {
        b = b.ack(a).psh();
    }
    let mut out = Vec::with_capacity(b.size(payload.len()));
    b.write(&mut out, payload).unwrap();
    out
}

async fn stack_bench(n: u32) -> (f64, f64) {
    let (to_stack, rx) = mpsc::unbounded_channel();
    let (tx, mut from_stack) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut config = IpStackConfig::default();
    config.mtu(1500).unwrap();
    let mut stack = IpStack::new(config, MemDevice { rx, tx });

    // UDP: n datagrams of 1200 bytes into one flow, read back from the stream.
    let payload = vec![0x5a; 1200];
    to_stack.send(udp_packet(&payload)).unwrap();
    let Ok(IpStackStream::Udp(mut udp)) = stack.accept().await else { panic!("no udp stream") };
    let mut buf = vec![0u8; 2048];
    assert_eq!(udp.read(&mut buf).await.unwrap(), 1200);
    let t = Instant::now();
    for _ in 0..n {
        to_stack.send(udp_packet(&payload)).unwrap();
        let got = udp.read(&mut buf).await.unwrap();
        assert_eq!(got, 1200);
    }
    let udp_ns = t.elapsed().as_nanos() as f64 / f64::from(n);

    // TCP: handshake, then n segments of 1400 bytes, each read back.
    to_stack.send(tcp_packet(1000, None, true, &[])).unwrap();
    let synack = from_stack.recv().await.unwrap();
    let Ok(sliced) = SlicedPacket::from_ip(&synack) else { panic!("bad syn-ack") };
    let Some(TransportSlice::Tcp(t)) = sliced.transport else { panic!("not tcp") };
    let server_seq = t.sequence_number();
    let ack = server_seq.wrapping_add(1);
    to_stack.send(tcp_packet(1001, Some(ack), false, &[])).unwrap();
    let Ok(IpStackStream::Tcp(mut tcp)) = stack.accept().await else { panic!("no tcp stream") };
    // Drain the stack's ACKs in the background.
    tokio::spawn(async move { while from_stack.recv().await.is_some() {} });
    let seg = vec![0x42; 1400];
    let mut seq = 1001u32;
    let mut big = vec![0u8; 4096];
    let t = Instant::now();
    for _ in 0..n {
        to_stack.send(tcp_packet(seq, Some(ack), false, &seg)).unwrap();
        seq = seq.wrapping_add(1400);
        let mut got = 0;
        while got < 1400 {
            got += tcp.read(&mut big).await.unwrap();
        }
    }
    let tcp_ns = t.elapsed().as_nanos() as f64 / f64::from(n);
    (udp_ns, tcp_ns)
}

fn main() {
    println!("== decode path (once per flow) ==");
    let tls = build::typical("www.example.com");
    time("TLS ClientHello (1.5 KB, one chunk) -> SNI+ALPN", 200_000, || {
        let mut c = TcpClassifier::new();
        c.push(&tls)
    });
    let http_req = b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: curl/8\r\nAccept: */*\r\n\r\n";
    time("HTTP/1 request head -> Host", 500_000, || {
        let mut c = TcpClassifier::new();
        c.push(http_req)
    });
    let rfc = sieve_engine::flow::hex_decode(include_str!("../testdata/rfc9001-a2-client-initial.hex")).unwrap();
    time("QUIC v1 Initial (1200 B): keys + HP + AES-GCM + SNI", 50_000, || {
        let mut c = UdpClassifier::new();
        c.push(&rfc)
    });
    time("  of which: Initial key derivation (HKDF x4)", 200_000, || quic::client_initial_keys(VERSION_1, &[1, 2, 3, 4, 5, 6, 7, 8]));
    let pkt = packet::build::ip(Proto::Tcp, "198.18.211.1".parse().unwrap(), "93.184.215.14".parse().unwrap(), 50000, 443, 7, &tls);
    time("IPv4+TCP header parse", 2_000_000, || packet::parse(&pkt).map(|p| p.payload.len()));

    let rows: Vec<OwnerRow> = (0..500u16)
        .map(|i| OwnerRow {
            local: SocketAddr::new(Ipv4Addr::new(192, 168, 1, 10).into(), 40_000 + i),
            remote: Some(SocketAddr::new(Ipv4Addr::new(1, 1, 1, 1).into(), 443)),
            pid: u32::from(i),
        })
        .collect();
    let flow = FiveTuple {
        proto: Proto::Tcp,
        local: SocketAddr::new(Ipv4Addr::new(192, 168, 1, 10).into(), 40_499),
        remote: SocketAddr::new(Ipv4Addr::new(1, 1, 1, 1).into(), 443),
    };
    time("owner match, 500-row table, last row", 200_000, || match_owner(&flow, &rows));

    let text: String = (0..100_000).map(|i| format!("||ads{i}.tracker{}.example^\n", i % 997)).collect();
    let lists = RuleEngine::compile(&[ListText { id: "bench", text: &text, trusted: false }]);
    let rules = RuleSet { user: std::sync::Arc::new(RuleEngine::empty()), lists: std::sync::Arc::new(lists) };
    let filter = DomainFilter::new(&Policy { sieving: true, ..Policy::default() }, rules);
    let names = std::sync::Mutex::default();
    let decide = |name| {
        let flow = Flow { dns: false, name: Some(name), remote: flow.remote.ip(), owner: Owner::App { key: "chrome" } };
        filter.decide(flow, &names, 0)
    };
    time("decision, 100k rules, 5-label miss", 1_000_000, || decide("a.b.cdn.example.org"));
    time("decision, 100k rules, hit", 1_000_000, || decide("x.ads77.tracker77.example"));

    println!("\n== ipstack ingress (every packet; one flow, one task hop each) ==");
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (udp_ns, tcp_ns) = rt.block_on(stack_bench(20_000));
    println!("{:<58} {:>10.0} ns/packet", "UDP 1200 B datagram: TUN packet -> stream read", udp_ns);
    println!("{:<58} {:>10.0} ns/packet", "TCP 1400 B segment: TUN packet -> stream read", tcp_ns);
    println!(
        "{:<58} {:>10.0} Mbit/s",
        "single-flow TCP ceiling at that cost (1400 B / packet)",
        1400.0 * 8.0 / tcp_ns * 1000.0
    );
}
