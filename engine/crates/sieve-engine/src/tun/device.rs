//! Windows: the Wintun adapter and its session as a packet device for
//! ipstack (one IP packet per read and per write).
//!
//! A plain thread blocks in `receive_blocking` (no CPU while idle). Each
//! packet it admits ([`super::admit`]) goes to the stack through a bounded
//! channel; the TUN heartbeat is pending from the packet's arrival until the
//! stack took it, so a runtime that stops taking packets stalls the reader
//! and the watchdog sees it. `Session::shutdown` ends the thread.

use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use wintun_bindings::{Adapter, Session, Wintun};

#[cfg(not(feature = "relay-experiments"))]
use super::MTU;
use super::{ADAPTER_GUID, RING_BYTES, TUNNEL_TYPE, admit, dll_beside, verify_dll};
use crate::flow::packet;
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
    meters: Arc<Meters>,
    #[cfg(feature = "relay-experiments")]
    batch: Option<super::batch::Receiver>,
    #[cfg(feature = "relay-experiments")]
    reader: Option<std::thread::JoinHandle<()>>,
}

impl TunDevice {
    pub fn new(session: Arc<Session>, meters: Arc<Meters>, beats: Arc<Beats>) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE);
        let reader = session.clone();
        let m = meters.clone();
        let spawned = std::thread::Builder::new().name("sieve-tun".into()).spawn(move || {
            while let Ok(p) = reader.receive_blocking() {
                beats.tun.begin(monotonic_ms());
                let bytes = p.bytes();
                Meters::bump(&m.packets_in);
                #[cfg(feature = "attribution-diagnostics")]
                super::record_fingerprint(bytes, &m);
                let admitted = packet::dst_ip(bytes).is_some_and(admit);
                let sent = if admitted { tx.blocking_send(bytes.to_vec()).is_ok() } else { true };
                if !admitted {
                    Meters::bump(&m.not_unicast);
                }
                beats.tun.end();
                if !sent {
                    break;
                }
            }
        });
        if let Err(e) = spawned {
            eprintln!("sieve-engine: TUN reader thread: {e}");
        }
        Self {
            session, rx, meters,
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
        let (tx, batch) = super::batch::channel(QUEUE, settings.tun_mtu, settings.tun_batch);
        let mut source = session.clone();
        let m = meters.clone();
        let reader = match std::thread::Builder::new().name("sieve-tun".into()).spawn(move || {
            if let Err(e) = tx.run(&mut source, &m, &beats, monotonic_ms) {
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
        Self { session, rx, meters, batch: Some(batch), reader }
    }
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
                Some(packet) if packet.len() > buf.remaining() => continue,
                Some(packet) => {
                    buf.put_slice(&packet);
                    return Poll::Ready(Ok(()));
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let len = u16::try_from(buf.len()).map_err(|_| std::io::Error::other("packet larger than 65535"))?;
        let mut packet = self.session.allocate_send_packet(len).map_err(std::io::Error::other)?;
        packet.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(packet);
        Meters::bump(&self.meters.packets_out);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
