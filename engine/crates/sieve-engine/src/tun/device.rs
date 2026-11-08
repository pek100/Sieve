//! Windows: the Wintun adapter and its session as a packet device for
//! ipstack (one IP packet per read and per write).
//!
//! A plain thread blocks in `receive_blocking` (no CPU while idle) and runs
//! [`super::read_packets`]: each packet it admits goes to the stack through a
//! bounded channel. The watchdog separately compares this run's admitted
//! arrivals ([`super::Input`]) with ipstack's consumed packets, without
//! waiting for the channel to fill. `Session::shutdown` ends the thread.

use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use wintun_bindings::{Adapter, Session, Wintun};

#[cfg(not(feature = "relay-experiments"))]
use super::MTU;
use super::{ADAPTER_GUID, Input, PacketSource, RING_BYTES, TUNNEL_TYPE, dll_beside, read_packets, verify_dll};
use crate::quic::PacketSink;
use crate::route::ADAPTER_NAME;
use crate::route::apply::SieveLuid;
use crate::stack::Meters;
use crate::watchdog::{Beats, monotonic_ms};

/// Packets waiting for the stack at most; a full channel makes the reader wait.
const QUEUE: usize = 4096;

/// The adapter, its session, and the DLL that serves both (kept loaded).
pub struct Tun {
    pub session: Arc<Session>,
    pub luid: SieveLuid,
    pub index: u32,
    // Dropped after the session: closing the adapter removes it.
    _adapter: Arc<Adapter>,
    _wintun: Wintun,
}

/// Loads the pinned `wintun.dll` beside `exe` and creates the adapter.
pub fn open(exe: &Path, #[cfg(feature = "relay-experiments")] mtu: u16) -> Result<Tun, String> {
    let dll = dll_beside(exe);
    verify_dll(&dll)?;
    // SAFETY: the DLL's hash is the pinned build and wintun-bindings checks
    // its Authenticode signer (WireGuard LLC) before any of its code runs; it
    // sits in the admin-only install folder.
    let wintun = unsafe { wintun_bindings::load_from_path(&dll) }.map_err(|e| format!("{}: {e}", dll.display()))?;
    let adapter = Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, Some(ADAPTER_GUID)).map_err(|e| format!("creating the adapter: {e}"))?;
    // SAFETY: NET_LUID_LH is a union over one u64.
    let luid = SieveLuid::of_created_adapter(unsafe { adapter.get_luid().Value });
    let index = adapter.get_adapter_index().map_err(|e| format!("adapter index: {e}"))?;
    #[cfg(not(feature = "relay-experiments"))]
    adapter.set_mtu(usize::from(MTU)).map_err(|e| format!("MTU: {e}"))?;
    #[cfg(feature = "relay-experiments")]
    adapter.set_mtu(usize::from(mtu)).map_err(|e| format!("MTU: {e}"))?;
    let session = adapter.start_session(RING_BYTES).map_err(|e| format!("session: {e}"))?;
    Ok(Tun { session, luid, index, _adapter: adapter, _wintun: wintun })
}

pub struct TunDevice {
    session: Arc<Session>,
    rx: mpsc::Receiver<Vec<u8>>,
    input: Input,
    #[cfg(feature = "relay-experiments")]
    batch: Option<super::batch::Receiver>,
    #[cfg(feature = "relay-experiments")]
    reader: Option<std::thread::JoinHandle<()>>,
}

impl TunDevice {
    pub fn new(session: Arc<Session>, meters: Arc<Meters>, beats: Arc<Beats>) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE);
        let mut source = session.clone();
        let input = Input::new(meters);
        let counted = input.clone();
        let spawned = std::thread::Builder::new().name("sieve-tun".into()).spawn(move || {
            if let Err(e) = read_packets(&mut source, &tx, &counted, &beats, monotonic_ms) {
                eprintln!("sieve-engine: TUN reader: {e}");
            }
        });
        if let Err(e) = spawned {
            eprintln!("sieve-engine: TUN reader thread: {e}");
        }
        Self {
            session, rx, input,
            #[cfg(feature = "relay-experiments")]
            batch: None,
            #[cfg(feature = "relay-experiments")]
            reader: None,
        }
    }

    #[cfg(feature = "relay-experiments")]
    pub fn experimental(session: Arc<Session>, meters: Arc<Meters>, beats: Arc<Beats>, settings: &crate::experiments::Settings) -> Self {
        if settings.tun_batch == crate::experiments::BATCH_MIN {
            return Self::new(session, meters, beats);
        }
        let input = Input::new(meters);
        let (tx, batch) = super::batch::channel(QUEUE, settings.tun_mtu, settings.tun_batch, input.clone());
        let mut source = session.clone();
        let reader = match std::thread::Builder::new().name("sieve-tun".into()).spawn(move || {
            if let Err(e) = tx.run(&mut source, &beats, monotonic_ms) {
                eprintln!("sieve-engine: batched TUN reader: {e}");
            }
        }) {
            Ok(reader) => Some(reader),
            Err(e) => {
                eprintln!("sieve-engine: TUN reader thread: {e}");
                None
            }
        };
        let (_, rx) = mpsc::channel(QUEUE);
        Self { session, rx, input, batch: Some(batch), reader }
    }

    /// This run's admitted arrivals, for its packet-path watchdog.
    pub fn offered(&self) -> Arc<crate::watchdog::Offered> {
        self.input.offered.clone()
    }
}

impl PacketSource for Arc<Session> {
    type Packet = wintun_bindings::Packet;

    fn receive_blocking(&mut self) -> io::Result<Option<Self::Packet>> {
        match Session::receive_blocking(self) {
            Ok(packet) => Ok(Some(packet)),
            Err(wintun_bindings::Error::ShuttingDown) => Ok(None),
            Err(e) => Err(io::Error::other(e)),
        }
    }

    fn try_receive(&mut self) -> io::Result<Option<Self::Packet>> {
        Session::try_receive(self).map_err(io::Error::other)
    }

    fn bytes(packet: &Self::Packet) -> &[u8] { packet.bytes() }
}

#[cfg(feature = "relay-experiments")]
impl Drop for TunDevice {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.take() {
            // Unblock every possible wait before joining: channel, pool and
            // Wintun receive. None of these needs the async runtime to run.
            drop(self.batch.take());
            if let Err(e) = self.session.shutdown() {
                eprintln!("sieve-engine: batched TUN shutdown: {e}");
            }
            if reader.join().is_err() {
                eprintln!("sieve-engine: batched TUN reader panicked");
            }
        }
    }
}

impl AsyncRead for TunDevice {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        #[cfg(feature = "relay-experiments")]
        if let Some(batch) = &mut self.batch {
            return batch.poll_read(cx, buf);
        }
        loop {
            match ready!(self.rx.poll_recv(cx)) {
                // Larger than ipstack's buffer: dropped rather than truncated.
                Some(packet) if packet.len() > buf.remaining() => {
                    self.input.oversized();
                    continue;
                }
                Some(packet) => {
                    buf.put_slice(&packet);
                    return Poll::Ready(Ok(()));
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

/// One IP packet onto the adapter. Wintun documents allocate and send as safe to
/// call from several threads, so the stack and [`TunSink`] can both write.
/// Both TUN readers (default and batched) write through here.
fn write_packet(session: &Arc<Session>, meters: &Meters, bytes: &[u8]) -> io::Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| io::Error::other("packet larger than 65535"))?;
    let mut packet = match session.allocate_send_packet(len) {
        Ok(packet) => packet,
        Err(e) => return allocation_failed(e, meters),
    };
    packet.bytes_mut().copy_from_slice(bytes);
    session.send_packet(packet);
    Meters::bump(&meters.packets_out);
    Ok(())
}

/// `WintunAllocateSendPacket` fails with ERROR_BUFFER_OVERFLOW while the send
/// ring is full: Windows has not yet taken earlier packets. That drops this
/// one packet, as a full NIC queue would, and the writer carries on. Any
/// other failure ends the writer (and with it ipstack's worker).
fn allocation_failed(e: wintun_bindings::Error, meters: &Meters) -> io::Result<()> {
    let ring_full = matches!(&e, wintun_bindings::Error::Io(io) if io.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW.0 as i32));
    if !ring_full {
        return Err(io::Error::other(e));
    }
    Meters::bump(&meters.tun_write_dropped);
    Ok(())
}

/// What a refused QUIC flow answers through. It does not keep the session alive:
/// `control::routing::take_down` closes the adapter with the flows' relay still
/// held, and the order there is what keeps the network.
pub struct TunSink {
    session: Weak<Session>,
    meters: Arc<Meters>,
}

impl TunSink {
    pub fn new(session: &Arc<Session>, meters: Arc<Meters>) -> Self {
        Self { session: Arc::downgrade(session), meters }
    }
}

impl PacketSink for TunSink {
    fn send(&self, ip_packet: &[u8]) -> std::io::Result<()> {
        let session = self.session.upgrade().ok_or_else(|| std::io::Error::other("the session is gone"))?;
        write_packet(&session, &self.meters, ip_packet)
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        write_packet(&self.session, &self.input.meters, buf)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use windows::Win32::Foundation::ERROR_NOT_ENOUGH_MEMORY;

    /// The error `WintunAllocateSendPacket` leaves, as wintun-bindings wraps it.
    fn allocate_error(code: u32) -> wintun_bindings::Error {
        wintun_bindings::Error::Io(io::Error::from_raw_os_error(code as i32))
    }

    #[test]
    fn a_full_send_ring_drops_one_packet_and_every_other_failure_stays_terminal() {
        let meters = Meters::default();
        assert!(allocation_failed(allocate_error(ERROR_BUFFER_OVERFLOW.0), &meters).is_ok(), "the writer carries on");
        assert_eq!(meters.tun_write_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(meters.packets_out.load(Ordering::Relaxed), 0, "nothing reached the adapter");
        for e in [allocate_error(ERROR_NOT_ENOUGH_MEMORY.0), wintun_bindings::Error::ShuttingDown, "closed".into()] {
            assert!(allocation_failed(e, &meters).is_err());
        }
        assert_eq!(meters.tun_write_dropped.load(Ordering::Relaxed), 1);
    }
}
