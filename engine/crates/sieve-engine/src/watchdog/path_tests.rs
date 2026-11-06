//! Real ipstack, in-memory packets, fake watchdog time. No sockets or routes.

use super::*;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use crate::stack::Meters;

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

async fn assert_read_ended(mut stack: IpStack) {
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
}

#[tokio::test(start_paused = true)]
async fn adapter_eof_ends_worker_instead_of_spinning_on_empty_packets() {
    let (stack, tx) = wire(tokio::io::sink());
    drop(tx);
    assert_read_ended(stack).await;
}

#[tokio::test(start_paused = true)]
async fn adapter_read_error_ends_worker_instead_of_silently_disabling_input() {
    assert_read_ended(IpStack::new(IpStackConfig::default(), FailedRead)).await;
}

fn wire<W: AsyncWrite + Unpin + Send + 'static>(writer: W) -> (IpStack, mpsc::Sender<Vec<u8>>) {
    // Minimum nonzero bounded queue: the tests cannot rely on filling the
    // production queue before detection.
    let (tx, rx) = mpsc::channel(1);
    (IpStack::new(IpStackConfig::default(), Device { rx, writer }), tx)
}

async fn offer(tx: &mpsc::Sender<Vec<u8>>, meters: &Meters, beats: &Beats) {
    let packet = crate::quic::tests::udp_packet("192.0.2.1:1234".parse().unwrap(), "198.51.100.1:443".parse().unwrap(), b"query");
    Meters::bump(&meters.packets_in);
    beats.tun.begin(0);
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
    let meters = Arc::new(Meters::default());
    let beats = Beats::default();
    let arm = armed();
    offer(&tx, &meters, &beats).await;
    let IpStackStream::Udp(mut flow) = stack.accept().await.unwrap() else { panic!("UDP") };
    flow.write_all(b"answer").await.unwrap();
    until(|| progress.snapshot().writes_started > 0).await;
    offer(&tx, &meters, &beats).await;
    let p = progress.snapshot();
    assert_eq!((p.received, p.dispatched, p.writes_started, p.writes_finished), (1, 1, 1, 0));
    assert_eq!(check(&arm, &beats, STALL_MS, &|| beats.relay.end()), None, "legacy watchdog misses the stall");
    *beats.path.lock().unwrap() = Some(PathWatch::new(meters, progress.clone(), 0));
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
    let meters = Arc::new(Meters::default());
    let beats = Beats::default();
    let arm = armed();
    offer(&tx, &meters, &beats).await;
    let IpStackStream::Udp(mut flow) = stack.accept().await.unwrap() else { panic!("UDP") };
    flow.write_all(b"answer").await.unwrap();
    until(|| progress.snapshot().exited).await;
    assert!(stack.accept().await.is_err());
    assert_eq!(check(&arm, &beats, STALL_MS, &|| beats.relay.end()), None, "legacy watchdog misses worker exit");
    *beats.path.lock().unwrap() = Some(PathWatch::new(meters, progress, 0));
    assert_eq!(check(&arm, &beats, 0, &|| beats.relay.end()), None);
    assert_eq!(check(&arm, &beats, STALL_MS - 1, &|| beats.relay.end()), None);
    assert_eq!(check(&arm, &beats, STALL_MS, &|| beats.relay.end()).unwrap().what, "ipstack worker exited");
    struct Record(std::cell::RefCell<Vec<&'static str>>);
    impl Trip for Record {
        fn delete_routes(&self) -> String { self.0.borrow_mut().push("routes"); String::new() }
        fn exit(&self, stall: &Stall, _: &str) {
            assert_eq!(stall.what, "ipstack worker exited");
            self.0.borrow_mut().push("exit");
        }
    }
    let record = Record(Default::default());
    run(&arm, &beats, &|| STALL_MS, &|| beats.relay.end(), &record);
    assert_eq!(*record.0.borrow(), ["routes", "exit"]);
}

#[tokio::test(start_paused = true)]
async fn quiet_link_multicast_and_oversized_drops_do_not_trip_and_rearming_resets() {
    let (stack, _tx) = wire(tokio::io::sink());
    let meters = Arc::new(Meters::default());
    let beats = Beats::default();
    let arm = armed();
    // Process-wide counters from the previous routing run are not this stack's work.
    Meters::bump(&meters.packets_in);
    let baseline = meters.stack_offered();
    *beats.path.lock().unwrap() = Some(PathWatch::new(meters.clone(), stack.progress(), baseline));
    for now in [0, STALL_MS, STALL_MS * 2] {
        Meters::bump(&meters.packets_in);
        Meters::bump(&meters.not_unicast);
        Meters::bump(&meters.packets_in);
        Meters::bump(&meters.oversized);
        assert_eq!(check(&arm, &beats, now, &|| beats.relay.end()), None);
    }
    Meters::bump(&meters.packets_in);
    assert_eq!(check(&arm, &beats, STALL_MS * 3, &|| beats.relay.end()), None);
    arm.set(false);
    *beats.path.lock().unwrap() = None;
    assert_eq!(check(&arm, &beats, STALL_MS * 4, &|| beats.relay.end()), None);
    let baseline = meters.stack_offered();
    *beats.path.lock().unwrap() = Some(PathWatch::new(meters, stack.progress(), baseline));
    arm.set(true);
    assert_eq!(check(&arm, &beats, STALL_MS * 5, &|| beats.relay.end()), None);
    drop(stack);
}
