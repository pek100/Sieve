//! Diagnostic TUN batching. Slabs are recycled after the stack reads them.
//! The packet budget is inherited from the original channel, not multiplied
//! by the batch limit. Storage is allocated lazily up to that bounded budget.

use std::io;
use std::sync::mpsc as sync;
#[cfg(any(windows, test))]
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use tokio::io::ReadBuf;
use tokio::sync::mpsc;
use crate::flow::packet;
use crate::stack::Meters;
use crate::watchdog::Beats;

pub trait PacketSource {
    type Packet;
    fn receive_blocking(&mut self) -> io::Result<Option<Self::Packet>>;
    fn try_receive(&mut self) -> io::Result<Option<Self::Packet>>;
    fn bytes(packet: &Self::Packet) -> &[u8];
}

struct Batch {
    bytes: Vec<u8>,
    lengths: Vec<usize>,
    count: usize,
    cursor: usize,
    mtu: usize,
}

impl Batch {
    fn new(mtu: usize, limit: usize) -> Self {
        Self { bytes: vec![0; mtu * limit], lengths: vec![0; limit], count: 0, cursor: 0, mtu }
    }

    fn push(&mut self, bytes: &[u8], meters: &Meters) {
        Meters::bump(&meters.packets_in);
        if !packet::dst_ip(bytes).is_some_and(super::admit) {
            Meters::bump(&meters.not_unicast);
            return;
        }
        if bytes.len() > self.mtu {
            // The legacy device also discards packets that cannot fit the
            // stack's MTU-sized ReadBuf. Never truncate a packet into the slab.
            return;
        }
        let offset = self.count * self.mtu;
        self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        self.lengths[self.count] = bytes.len();
        self.count += 1;
    }
}

pub struct Sender {
    tx: mpsc::Sender<Batch>,
    recycled: sync::Receiver<Batch>,
    allocated: usize,
    max_slabs: usize,
    mtu: usize,
    limit: usize,
}

pub struct Receiver {
    rx: mpsc::Receiver<Batch>,
    recycle: sync::SyncSender<Batch>,
    current: Option<Batch>,
}

pub fn channel(packet_budget: usize, mtu: u16, limit: usize) -> (Sender, Receiver) {
    let queued = packet_budget.div_ceil(limit);
    // One slab may be in the reader, one in poll_read, besides queued slabs.
    let max_slabs = queued + 2;
    let (tx, rx) = mpsc::channel(queued);
    let (recycle, recycled) = sync::sync_channel(max_slabs);
    (Sender { tx, recycled, allocated: 0, max_slabs, mtu: usize::from(mtu), limit }, Receiver { rx, recycle, current: None })
}

impl Sender {
    fn take(&mut self) -> io::Result<Batch> {
        match self.recycled.try_recv() {
            Ok(batch) => Ok(batch),
            Err(sync::TryRecvError::Empty) if self.allocated < self.max_slabs => {
                self.allocated += 1;
                Ok(Batch::new(self.mtu, self.limit))
            }
            Err(sync::TryRecvError::Empty) => self.recycled.recv().map_err(io::Error::other),
            Err(e) => Err(io::Error::other(e)),
        }
    }

    /// Idle waits have no pending beat. Pool waits, draining and channel
    /// backpressure all occur inside the beat, so a stalled stack is visible.
    pub fn run<S: PacketSource>(mut self, source: &mut S, meters: &Meters, beats: &Beats, now: impl Fn() -> u64) -> io::Result<()> {
        while let Some(first) = source.receive_blocking()? {
            beats.tun.begin(now());
            let result = self.send_batch(source, first, meters);
            beats.tun.end();
            result?;
        }
        Ok(())
    }

    fn send_batch<S: PacketSource>(&mut self, source: &mut S, first: S::Packet, meters: &Meters) -> io::Result<()> {
        let mut batch = self.take()?;
        batch.count = 0;
        batch.cursor = 0;
        batch.push(S::bytes(&first), meters);
        let mut result = Ok(());
        drop(first); // Release the Wintun ring slot before waiting on the stack.
        // Count every received packet, including multicast, toward the wake
        // limit. An error after a valid prefix still delivers that prefix.
        for _ in 1..self.limit {
            match source.try_receive() {
                Ok(Some(packet)) => batch.push(S::bytes(&packet), meters),
                Ok(None) => break,
                Err(e) => { result = Err(e); break; }
            }
        }
        self.tx.blocking_send(batch).map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TUN stack closed"))?;
        result
    }
}

impl Receiver {
    pub fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(batch) = self.current.as_mut() {
                if batch.cursor < batch.count {
                    let i = batch.cursor;
                    batch.cursor += 1;
                    let len = batch.lengths[i];
                    // Same whole-packet rule as the original TunDevice.
                    if len > buf.remaining() { continue; }
                    buf.put_slice(&batch.bytes[i * batch.mtu..i * batch.mtu + len]);
                    return Poll::Ready(Ok(()));
                }
                if let Some(batch) = self.current.take() {
                    // Disconnection means the reader has already ended. The
                    // pool cannot be full: this slab is still owned here.
                    match self.recycle.try_send(batch) {
                        Ok(()) | Err(sync::TrySendError::Disconnected(_)) => {}
                        Err(sync::TrySendError::Full(_)) => return Poll::Ready(Err(io::Error::other("TUN pool ownership invariant"))),
                    }
                }
            }
            match ready!(self.rx.poll_recv(cx)) {
                Some(batch) => self.current = Some(batch),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

#[cfg(windows)]
impl PacketSource for Arc<wintun_bindings::Session> {
    type Packet = wintun_bindings::Packet;

    fn receive_blocking(&mut self) -> io::Result<Option<Self::Packet>> {
        match wintun_bindings::Session::receive_blocking(self) {
            Ok(packet) => Ok(Some(packet)),
            Err(wintun_bindings::Error::ShuttingDown) => Ok(None),
            Err(e) => Err(io::Error::other(e)),
        }
    }

    fn try_receive(&mut self) -> io::Result<Option<Self::Packet>> {
        wintun_bindings::Session::try_receive(self).map_err(io::Error::other)
    }

    fn bytes(packet: &Self::Packet) -> &[u8] { packet.bytes() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::experiments::{BATCH_MAX, BATCH_MIN, MTU_MAX};
    use crate::watchdog::{Arm, STALL_MS, check};
    use std::collections::{BTreeSet, VecDeque};
    use std::pin::Pin;
    use tokio::io::{AsyncRead, AsyncReadExt};

    struct Fake(VecDeque<Vec<u8>>);
    impl PacketSource for Fake {
        type Packet = Vec<u8>;
        fn receive_blocking(&mut self) -> io::Result<Option<Self::Packet>> { Ok(self.0.pop_front()) }
        fn try_receive(&mut self) -> io::Result<Option<Self::Packet>> { Ok(self.0.pop_front()) }
        fn bytes(packet: &Self::Packet) -> &[u8] { packet }
    }

    impl AsyncRead for Receiver {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Receiver::poll_read(&mut self, cx, buf)
        }
    }

    fn packet(id: usize, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        bytes[0] = 0x45;
        bytes[16..20].copy_from_slice(&[192, 0, 2, 1]);
        let end = bytes.len();
        bytes[end - size_of::<usize>()..].copy_from_slice(&id.to_le_bytes());
        bytes
    }

    #[tokio::test]
    async fn packets_cross_every_batch_edge_in_order_and_reuse_slabs() {
        for limit in [BATCH_MIN, BATCH_MIN + 1, BATCH_MAX] {
            for n in [limit - 1, limit, limit + 1, limit * 3 + 1] {
                let expected: Vec<_> = (0..n).map(|id| packet(id, MTU_MAX - id % 2)).collect();
                let mut source = Fake(expected.clone().into());
                // One queued batch forces recycling and backpressure.
                let (tx, mut rx) = channel(limit, MTU_MAX as u16, limit);
                let beats = Arc::new(Beats::default());
                let reader_beats = beats.clone();
                let reader = std::thread::spawn(move || tx.run(&mut source, &Meters::default(), &reader_beats, || 0));
                let mut buf = vec![0; MTU_MAX];
                let mut actual = Vec::new();
                let mut slabs = BTreeSet::new();
                loop {
                    let len = rx.read(&mut buf).await.unwrap();
                    if len == 0 { break; }
                    slabs.insert(rx.current.as_ref().unwrap().bytes.as_ptr() as usize);
                    actual.push(buf[..len].to_vec());
                }
                reader.join().unwrap().unwrap();
                assert_eq!(actual, expected);
                assert_eq!(beats.tun.done(), n.div_ceil(limit) as u64);
                assert_eq!(beats.tun.pending_since(), None);
                // channel(limit, ...) holds one queued slab, plus its producer
                // and consumer. More batches must reuse those same allocations.
                assert!(slabs.len() <= limit.div_ceil(limit) + 2);
            }
        }
    }

    #[tokio::test]
    async fn short_drains_and_filtered_packets_preserve_admitted_order() {
        struct Bursty(Fake);
        impl PacketSource for Bursty {
            type Packet = Vec<u8>;
            fn receive_blocking(&mut self) -> io::Result<Option<Self::Packet>> { self.0.receive_blocking() }
            fn try_receive(&mut self) -> io::Result<Option<Self::Packet>> { Ok(None) }
            fn bytes(packet: &Self::Packet) -> &[u8] { packet }
        }
        let good = packet(0, usize::from(crate::tun::MTU));
        let mut filtered = good.clone();
        filtered[16..20].copy_from_slice(&[224, 0, 0, 1]);
        let mut source = Bursty(Fake([good.clone(), filtered, good.clone()].into()));
        let (tx, mut rx) = channel(BATCH_MAX, crate::tun::MTU, BATCH_MAX);
        let meters = Arc::new(Meters::default());
        let m = meters.clone();
        let reader = std::thread::spawn(move || tx.run(&mut source, &m, &Beats::default(), || 0));
        let mut got = Vec::new();
        let mut buf = vec![0; usize::from(crate::tun::MTU)];
        loop {
            let n = rx.read(&mut buf).await.unwrap();
            if n == 0 { break; }
            got.extend_from_slice(&buf[..n]);
        }
        reader.join().unwrap().unwrap();
        assert_eq!(got, [good.as_slice(), good.as_slice()].concat());
        assert_eq!(meters.not_unicast.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn heartbeat_brackets_draining_and_blocked_send_and_clears_on_disconnect() {
        struct Observe {
            source: Fake,
            beats: Arc<Beats>,
            observed: sync::SyncSender<()>,
        }
        impl PacketSource for Observe {
            type Packet = Vec<u8>;
            fn receive_blocking(&mut self) -> io::Result<Option<Self::Packet>> {
                assert_eq!(self.beats.tun.pending_since(), None, "idle wait outside beat");
                self.source.receive_blocking()
            }
            fn try_receive(&mut self) -> io::Result<Option<Self::Packet>> {
                assert_eq!(self.beats.tun.pending_since(), Some(0));
                self.observed.send(()).unwrap();
                self.source.try_receive()
            }
            fn bytes(packet: &Self::Packet) -> &[u8] { packet }
        }
        let limit = BATCH_MIN + 1;
        let beats = Arc::new(Beats::default());
        let (observed, events) = sync::sync_channel(limit);
        let mut source = Observe { source: Fake((0..limit * 2).map(|id| packet(id, usize::from(crate::tun::MTU))).collect()), beats: beats.clone(), observed };
        let (tx, rx) = channel(limit, crate::tun::MTU, limit);
        let reader_beats = beats.clone();
        let reader = std::thread::spawn(move || tx.run(&mut source, &Meters::default(), &reader_beats, || 0));
        events.recv().unwrap();
        events.recv().unwrap(); // First batch queued, second cannot be sent.
        let arm = Arm::default();
        arm.set(true);
        assert_eq!(beats.tun.done(), 1);
        assert_eq!(check(&arm, &beats, STALL_MS - 1, &|| beats.relay.end()), None);
        assert_eq!(check(&arm, &beats, STALL_MS, &|| beats.relay.end()).unwrap().what, "TUN reader");
        drop(rx);
        assert!(reader.join().unwrap().is_err());
        assert_eq!(beats.tun.pending_since(), None);
        assert_eq!(beats.tun.done(), 2);
    }
}
