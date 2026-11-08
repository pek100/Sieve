//! Real ipstack, in-memory packets, fake watchdog time. No sockets or routes.

use super::*;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use crate::stack::Meters;
use crate::tun::{Input, PacketSource, read_packets};

struct Device<W> {
    rx: mpsc::Receiver<Vec<u8>>,
    writer: W,
}

impl<W: Unpin> AsyncRead for Device<W> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if let Some(packet) = ready!(self.rx.poll_recv(cx)) { buf.put_slice(&packet); }
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Device<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

struct FailedWrite;
impl AsyncWrite for FailedWrite {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Err(std::io::Error::other("injected adapter write failure")))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> { Poll::Ready(Ok(())) }
}

struct FailedRead;
impl AsyncRead for FailedRead {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(std::io::Error::other("injected adapter read failure")))
    }
}
impl AsyncWrite for FailedRead {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> { Poll::Ready(Ok(buf.len())) }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> { Poll::Ready(Ok(())) }
}

async fn assert_read_ended(mut stack: IpStack, reason: &str) {
    let progress = stack.progress();
    // Advance explicitly: an EOF busy loop must not prevent the fake clock
    // reaching the assertion. Sample for the existing watchdog budget.
    for _ in 0..STALL_MS / CHECK_EVERY_MS {
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(CHECK_EVERY_MS)).await;
    }
    let p = progress.snapshot();
    assert!(p.exited, "device ended but packet worker stayed alive: {p:?}");
    assert!(stack.accept().await.is_err(), "EOF is not an UnknownNetwork packet");
    assert_eq!((p.received, p.dispatched), (0, 0));
    let recorded = progress.exit_reason().expect("the worker's error is kept");
    assert!(recorded.contains(reason), "{recorded}");
}

#[tokio::test(start_paused = true)]
async fn adapter_eof_ends_worker_instead_of_spinning_on_empty_packets() {
    let (stack, tx) = wire(tokio::io::sink());
    drop(tx);
    assert_read_ended(stack, "packet device closed").await;
}

#[tokio::test(start_paused = true)]
async fn adapter_read_error_ends_worker_instead_of_silently_disabling_input() {
    assert_read_ended(IpStack::new(IpStackConfig::default(), FailedRead), "injected adapter read failure").await;
}

#[tokio::test]
async fn an_aborted_worker_records_no_error() {
    let (stack, _tx) = wire(tokio::io::sink());
    let progress = stack.progress();
    drop(stack);
    until(|| progress.snapshot().exited).await;
    assert_eq!(progress.exit_reason(), None, "a routing run's own take-down is not a failure");
}

fn wire<W: AsyncWrite + Unpin + Send + 'static>(writer: W) -> (IpStack, mpsc::Sender<Vec<u8>>) {
    // Minimum nonzero bounded queue: the tests cannot rely on filling the
    // production queue before detection.
    let (tx, rx) = mpsc::channel(1);
    (IpStack::new(IpStackConfig::default(), Device { rx, writer }), tx)
}

fn query() -> Vec<u8> {
    crate::quic::tests::udp_packet("192.0.2.1:1234".parse().unwrap(), "198.51.100.1:443".parse().unwrap(), b"query")
}

async fn offer(tx: &mpsc::Sender<Vec<u8>>, input: &Input, beats: &Beats) {
    let packet = query();
    beats.tun.begin(0);
    assert!(input.arrive(&packet));
    tx.send(packet).await.unwrap();
    beats.tun.end();
}

async fn until(done: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_millis(STALL_MS), async {
        while !done() { tokio::time::sleep(Duration::from_millis(CHECK_EVERY_MS)).await; }
    }).await.expect("ipstack reached the injected fault");
}

fn armed() -> Arm {
    let arm = Arm::default();
    arm.set(true);
    arm
}

#[tokio::test(start_paused = true)]
async fn a_pending_device_write_stalls_the_real_packet_loop_but_not_the_old_beats() {
    // Duplex capacity is one byte, while the packet necessarily includes IP
    // and UDP headers. Keeping its peer unread makes write_all stay pending.
    let (writer, _unread) = tokio::io::duplex(1);
    let (mut stack, tx) = wire(writer);
    let progress = stack.progress();
    let input = run_input();
    let beats = Beats::default();
    let arm = armed();
    offer(&tx, &input, &beats).await;
    let IpStackStream::Udp(mut flow) = stack.accept().await.unwrap() else { panic!("UDP") };
    flow.write_all(b"answer").await.unwrap();
    until(|| progress.snapshot().writes_started > 0).await;
    offer(&tx, &input, &beats).await;
    let p = progress.snapshot();
    assert_eq!((p.received, p.dispatched, p.writes_started, p.writes_finished), (1, 1, 1, 0));
    assert_eq!(check(&arm, &beats, STALL_MS, &|| beats.relay.end()), None, "legacy watchdog misses the stall");
    *beats.path.lock().unwrap() = Some(PathWatch::new(input.offered, progress.clone()));
    assert_eq!(check(&arm, &beats, 0, &|| beats.relay.end()), None);
    let stall = check(&arm, &beats, STALL_MS, &|| beats.relay.end()).unwrap();
    assert_eq!(stall.what, "ipstack to TUN write");
    assert_eq!(beats.path.lock().unwrap().as_ref().unwrap().report()["waiting_stage"], stall.what);
    drop(flow);
    drop(stack);
    until(|| progress.snapshot().exited).await;
}

#[tokio::test(start_paused = true)]
async fn a_device_write_error_exits_ipstack_and_now_trips_routes_first() {
    let (mut stack, tx) = wire(FailedWrite);
    let progress = stack.progress();
    let input = run_input();
    let beats = Beats::default();
    let arm = armed();
    offer(&tx, &input, &beats).await;
    let IpStackStream::Udp(mut flow) = stack.accept().await.unwrap() else { panic!("UDP") };
    flow.write_all(b"answer").await.unwrap();
    until(|| progress.snapshot().exited).await;
    assert!(stack.accept().await.is_err());
    assert_eq!(check(&arm, &beats, STALL_MS, &|| beats.relay.end()), None, "legacy watchdog misses worker exit");
    *beats.path.lock().unwrap() = Some(PathWatch::new(input.offered, progress));
    assert_eq!(check(&arm, &beats, 0, &|| beats.relay.end()), None);
    assert_eq!(check(&arm, &beats, STALL_MS - 1, &|| beats.relay.end()), None);
    let stall = check(&arm, &beats, STALL_MS, &|| beats.relay.end()).unwrap();
    assert_eq!(stall.what, "ipstack worker exited");
    // The cause reaches both records: status.json's packet_path and the trip's last-error.
    let report = beats.path.lock().unwrap().as_ref().unwrap().report();
    assert!(report["exit_reason"].as_str().unwrap().contains("injected adapter write failure"), "{report}");
    assert!(stall.reason().ends_with("(IO error: injected adapter write failure)"), "{}", stall.reason());
    struct Record(std::cell::RefCell<Vec<&'static str>>);
    impl Trip for Record {
        fn delete_routes(&self) -> String { self.0.borrow_mut().push("routes"); String::new() }
        fn exit(&self, stall: &Stall, _: &str) {
            assert_eq!(stall.what, "ipstack worker exited");
            assert!(stall.reason().contains("injected adapter write failure"));
            self.0.borrow_mut().push("exit");
        }
    }
    let record = Record(Default::default());
    run(&arm, &beats, &|| STALL_MS, &|| beats.relay.end(), &record);
    assert_eq!(*record.0.borrow(), ["routes", "exit"]);
}

fn run_input() -> Input { Input::new(Arc::new(Meters::default())) }

/// A queue standing in for one routing run's Wintun ring.
struct Ring(std::collections::VecDeque<Vec<u8>>);
impl PacketSource for Ring {
    type Packet = Vec<u8>;
    fn receive_blocking(&mut self) -> std::io::Result<Option<Self::Packet>> { Ok(self.0.pop_front()) }
    fn try_receive(&mut self) -> std::io::Result<Option<Self::Packet>> { Ok(self.0.pop_front()) }
    fn bytes(packet: &Self::Packet) -> &[u8] { packet }
}

#[tokio::test(start_paused = true)]
async fn a_previous_runs_reader_draining_after_the_next_bring_up_cannot_trip_an_idle_run() {
    // Both runs share the process-wide meters, as in the engine.
    let meters = Arc::new(Meters::default());
    let (old, new) = (Input::new(meters.clone()), Input::new(meters.clone()));
    let (stack, _tx) = wire(tokio::io::sink());
    let beats = Beats::default();
    let arm = armed();
    *beats.path.lock().unwrap() = Some(PathWatch::new(new.offered.clone(), stack.progress()));
    // The old run's never-joined reader drains one more packet into its stack, already gone.
    let (old_tx, old_rx) = mpsc::channel(1);
    drop(old_rx);
    let ring = std::thread::spawn(move || read_packets(&mut Ring([query()].into()), &old_tx, &old, &Beats::default(), || 0));
    ring.join().unwrap().unwrap();
    assert_eq!(meters.packets_in.load(std::sync::atomic::Ordering::Relaxed), 1, "the status counters still count it");
    assert_eq!(new.offered.get(), 0);
    assert_eq!(check(&arm, &beats, 0, &|| beats.relay.end()), None);
    assert_eq!(check(&arm, &beats, STALL_MS, &|| beats.relay.end()), None, "an idle run tripped on the old run's packet");
    drop(stack);
}

#[test]
fn the_default_reader_returns_a_receive_error_and_ends_quietly_on_shutdown() {
    struct Failing(Option<Vec<u8>>);
    impl PacketSource for Failing {
        type Packet = Vec<u8>;
        fn receive_blocking(&mut self) -> std::io::Result<Option<Self::Packet>> {
            self.0.take().map(Some).ok_or_else(|| std::io::Error::other("injected receive failure"))
        }
        fn try_receive(&mut self) -> std::io::Result<Option<Self::Packet>> { unreachable!() }
        fn bytes(packet: &Self::Packet) -> &[u8] { packet }
    }
    let input = run_input();
    let beats = Beats::default();
    let (tx, mut rx) = mpsc::channel(1);
    let e = read_packets(&mut Failing(Some(query())), &tx, &input, &beats, || 0).unwrap_err();
    assert_eq!(e.to_string(), "injected receive failure");
    assert_eq!((rx.try_recv().unwrap(), input.offered.get()), (query(), 1), "the packet before it still went");
    assert_eq!(beats.tun.pending_since(), None);
    assert!(read_packets(&mut Ring(Default::default()), &tx, &input, &beats, || 0).is_ok(), "shutdown is no error");
}

#[tokio::test(start_paused = true)]
async fn quiet_link_multicast_and_oversized_drops_do_not_trip_and_rearming_resets() {
    let (stack, _tx) = wire(tokio::io::sink());
    let input = run_input();
    let beats = Beats::default();
    let arm = armed();
    let mut multicast = query();
    multicast[16..20].copy_from_slice(&[224, 0, 0, 251]);
    *beats.path.lock().unwrap() = Some(PathWatch::new(input.offered.clone(), stack.progress()));
    for now in [0, STALL_MS, STALL_MS * 2] {
        assert!(!input.arrive(&multicast));
        assert!(input.arrive(&query()));
        input.oversized();
        assert_eq!(check(&arm, &beats, now, &|| beats.relay.end()), None);
    }
    arm.set(false);
    *beats.path.lock().unwrap() = None;
    assert_eq!(check(&arm, &beats, STALL_MS * 4, &|| beats.relay.end()), None);
    *beats.path.lock().unwrap() = Some(PathWatch::new(run_input().offered, stack.progress()));
    arm.set(true);
    assert_eq!(check(&arm, &beats, STALL_MS * 5, &|| beats.relay.end()), None);
    drop(stack);
}
