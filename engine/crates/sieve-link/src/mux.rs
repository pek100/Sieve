//! One yamux session over the TLS connection, driven by its own task.
//!
//! yamux makes progress only while `poll_next_inbound` is polled, so a single
//! task owns the `Connection`, keeps polling it, opens outbound streams on
//! request and hands inbound streams to a callback.
//!
//! The device is always yamux `Client` and the hub always `Server`, whichever
//! of them dialled the TCP connection.
//!
//! ## Memory the hub spends on one device
//!
//! yamux grants the sender credit (a receive window) and treats data beyond
//! it as a protocol violation, so the bytes yamux holds unread for one link
//! never exceed that link's connection-wide receive window. The hub sizes it
//! from the device's own limit (`hub_config`): `hub_streams(c)` streams, where
//! `c` is the device's `max_concurrent`, plus one control stream and one
//! spare stream that carries a `Busy` answer instead of being reset; and the
//! window is that many times 256 KiB (the yamux floor per stream). Each relay
//! adds two fixed 16 KiB copy buffers. A device holds at most
//! `MAX_LINKS_PER_DEVICE` links (a newer one closes the oldest), so:
//!
//! `device_buffer_bound(c) = MAX_LINKS_PER_DEVICE * hub_streams(c) * (256 KiB + 32 KiB)`
//!
//! e.g. 2 * 66 * 288 KiB = 37.1 MiB for the default 64, and 145.1 MiB at the
//! largest accepted `max_concurrent` (256). A link keeps the size it came up
//! with: a lowered limit takes effect on the device's next link, and a raised
//! one makes the hub close the device's links so it relinks at the new size.

use std::future::poll_fn;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::Duration;

use futures::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;

use crate::error::{LinkError, Result};

pub use yamux::Mode;

/// A stream inside the link, with tokio's I/O traits.
pub type LinkIo = Compat<yamux::Stream>;

/// Most streams one link carries at once on the device's side (the hub, its
/// peer there, is trusted).
pub const MAX_STREAMS: usize = 128;

/// Links one device may hold at once at the hub; a newer one closes the oldest.
pub const MAX_LINKS_PER_DEVICE: usize = 2;

/// yamux's window per stream (its initial credit, and the floor it requires).
pub const STREAM_WINDOW: usize = yamux::DEFAULT_CREDIT as usize;

/// Bytes of relay copy buffers per stream (two directions of 16 KiB).
pub const RELAY_BUFFERS: usize = 2 * 16 * 1024;

type Opener = oneshot::Sender<std::result::Result<yamux::Stream, yamux::ConnectionError>>;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn sized(streams: usize) -> yamux::Config {
    let mut c = yamux::Config::default();
    // Order matters: yamux asserts window >= 256 KiB * streams on each call,
    // and the default window (1 GiB) is larger than any count set here.
    c.set_max_num_streams(streams);
    c.set_max_connection_receive_window(Some(streams * STREAM_WINDOW));
    c
}

/// The device side's session config.
pub fn config() -> yamux::Config {
    sized(MAX_STREAMS)
}

/// Streams the hub lets one link of a device carry: its concurrency limit,
/// one control stream, and one spare that is answered `Busy`.
pub fn hub_streams(max_concurrent: u32) -> usize {
    max_concurrent.clamp(1, crate::rules::MAX_CONCURRENT) as usize + 2
}

/// The hub's session config for a link of a device with this limit.
pub fn hub_config(max_concurrent: u32) -> yamux::Config {
    sized(hub_streams(max_concurrent))
}

/// The most bytes the hub holds for one device at once (see the module docs).
pub fn device_buffer_bound(max_concurrent: u32) -> usize {
    MAX_LINKS_PER_DEVICE * hub_streams(max_concurrent) * (STREAM_WINDOW + RELAY_BUFFERS)
}

/// Opens streams on a running session. Cheap to clone.
#[derive(Clone, Debug)]
pub struct MuxHandle {
    id: u64,
    tx: mpsc::Sender<Opener>,
    cancel: CancellationToken,
}

impl MuxHandle {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub async fn open(&self) -> Result<LinkIo> {
        let (otx, orx) = oneshot::channel();
        self.tx.send(otx).await.map_err(|_| LinkError::HubDown)?;
        match orx.await {
            Ok(Ok(s)) => Ok(s.compat()),
            _ => Err(LinkError::HubDown),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Ends the session (and with it every stream).
    pub fn close(&self) {
        self.cancel.cancel();
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }
}

/// Starts the session task. `on_inbound` runs inside the driver for every
/// stream the peer opens and must only hand it off (spawn). The session ends
/// when the peer closes, on an error, or when `cancel` fires; it then cancels
/// `cancel` itself so everyone watching it learns the link is gone.
pub fn spawn<T, F>(io: T, mode: Mode, on_inbound: F, cancel: CancellationToken) -> (MuxHandle, tokio::task::JoinHandle<()>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnMut(yamux::Stream) + Send + 'static,
{
    spawn_with(io, mode, config(), on_inbound, cancel)
}

/// `spawn` with a given session config.
pub fn spawn_with<T, F>(io: T, mode: Mode, cfg: yamux::Config, mut on_inbound: F, cancel: CancellationToken) -> (MuxHandle, tokio::task::JoinHandle<()>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnMut(yamux::Stream) + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<Opener>(16);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let handle = MuxHandle { id, tx, cancel: cancel.clone() };
    let task = tokio::spawn(async move {
        let mut conn = yamux::Connection::new(io, cfg, mode);
        {
            let mut pending: Option<Opener> = None;
            let drive = poll_fn(|cx| {
                loop {
                    if let Some(op) = pending.take() {
                        match conn.poll_new_outbound(cx) {
                            Poll::Ready(r) => {
                                let failed = r.is_err();
                                let _ = op.send(r);
                                if failed {
                                    return Poll::Ready(());
                                }
                                continue;
                            }
                            Poll::Pending => pending = Some(op),
                        }
                    } else if let Poll::Ready(Some(op)) = rx.poll_recv(cx) {
                        pending = Some(op);
                        continue;
                    }
                    match conn.poll_next_inbound(cx) {
                        Poll::Ready(Some(Ok(s))) => {
                            on_inbound(s);
                            continue;
                        }
                        Poll::Ready(Some(Err(_))) | Poll::Ready(None) => return Poll::Ready(()),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            });
            tokio::select! {
                _ = drive => {}
                _ = cancel.cancelled() => {}
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), poll_fn(|cx| conn.poll_close(cx))).await;
        cancel.cancel();
    });
    (handle, task)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Limits, MAX_CONCURRENT};

    const MIB: usize = 1024 * 1024;

    #[test]
    fn the_hub_bounds_each_device_by_its_own_limit() {
        // The window is exactly the yamux floor for the stream count, and the
        // stream count follows the device's limit.
        assert_eq!(hub_streams(1), 3);
        assert_eq!(hub_streams(64), 66);
        assert_eq!(hub_streams(0), 3, "a zero limit is clamped, never a zero-stream session");
        assert_eq!(hub_streams(u32::MAX), MAX_CONCURRENT as usize + 2);
        // Building the configs passes yamux's own window >= streams * 256 KiB assertion.
        for c in [1, 2, 64, MAX_CONCURRENT, u32::MAX] {
            let _ = hub_config(c);
        }
        let d = Limits::default().max_concurrent;
        assert_eq!(device_buffer_bound(d), MAX_LINKS_PER_DEVICE * 66 * (256 * 1024 + 32 * 1024));
        assert!(device_buffer_bound(d) < 38 * MIB, "{}", device_buffer_bound(d));
        assert!(device_buffer_bound(MAX_CONCURRENT) < 146 * MIB);
        assert!(device_buffer_bound(1) < 2 * MIB);
        // Monotonic in the limit.
        assert!(device_buffer_bound(8) < device_buffer_bound(9));
    }
}
