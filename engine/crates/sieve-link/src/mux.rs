//! One yamux session over the TLS connection, driven by its own task.
//!
//! yamux makes progress only while `poll_next_inbound` is polled, so a single
//! task owns the `Connection`, keeps polling it, opens outbound streams on
//! request and hands inbound streams to a callback.
//!
//! The device is always yamux `Client` and the hub always `Server`, whichever
//! of them dialled the TCP connection.
//!
//! ## Streams over the limit
//!
//! yamux ends the WHOLE connection when the peer opens a stream beyond
//! `max_num_streams`, so the limit a device is held to is enforced above
//! yamux, with room to spare below it:
//!
//! - the hub tells the device its limit on the control stream (`Limit`, at
//!   once and on every change) and the device opens at most that many streams
//!   (it queues an open briefly, then answers `Busy` itself);
//! - the hub admits streams against the limit and answers the extra ones
//!   `Busy`; its yamux session holds `hub_streams(c)` = `c` + 1 control +
//!   `spare(c)` streams (at least `MIN_SPARE`, a quarter of `c` above 32), so
//!   a device that opens too many, or races a lowered limit, or opens a new
//!   stream before the hub has seen an old one close, gets `Busy` answers on
//!   the spare streams and its open streams carry on. Only a device that
//!   blows through all the spare streams at once loses its link;
//! - on the device, an open that yamux itself refuses (`TooManyStreams`) is
//!   a `Busy` answer, not the end of the session.
//!
//! ## Memory the hub spends on one device
//!
//! yamux grants the sender credit (a receive window) and treats data beyond
//! it as a protocol violation, so the bytes yamux holds unread for one link
//! never exceed that link's connection-wide receive window: `hub_streams(c)`
//! times 256 KiB (the yamux floor per stream). Each relay adds two fixed
//! 16 KiB copy buffers. A device holds at most `MAX_LINKS_PER_DEVICE` links
//! (a newer one closes the oldest), so:
//!
//! `device_buffer_bound(c) = MAX_LINKS_PER_DEVICE * hub_streams(c) * (256 KiB + 32 KiB)`
//!
//! e.g. 2 * 81 * 288 KiB = 45.6 MiB for the default 64, 5.6 MiB for a limit
//! of 1, and 180.6 MiB at the largest accepted `max_concurrent` (256).
//!
//! A link keeps the size it came up with. A lowered limit leaves it (the old,
//! larger bound holds until the device's next link); a raised one that still
//! leaves `MIN_SPARE` spare streams (`link_carries`) applies at once on the
//! same link; only a raise beyond that makes the hub close the device's links
//! so it relinks at the new size (its open streams end, and `sieve-hub limit`
//! says so when it happens).

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use futures::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::error::{LinkError, Result};

pub use yamux::Mode;

/// A stream inside the link, with tokio's I/O traits. A read or write that
/// would wait on a session that has ended fails at once instead: yamux does
/// not wake the streams of a session closed from this side, so each stream
/// also watches the session's cancel token.
pub struct LinkIo {
    inner: Compat<yamux::Stream>,
    gone: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl std::fmt::Debug for LinkIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkIo").finish_non_exhaustive()
    }
}

impl LinkIo {
    /// A stream of the session that `session` cancels when it ends.
    pub fn new(s: yamux::Stream, session: CancellationToken) -> Self {
        LinkIo { inner: s.compat(), gone: Box::pin(session.cancelled_owned()) }
    }

    /// For a poll that came back pending: the error to give instead when the
    /// session has ended (polling registers the waker either way).
    fn ended<T>(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<T>> {
        match self.gone.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "the link is closed"))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl tokio::io::AsyncRead for LinkIo {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Pending => this.ended(cx),
            r => r,
        }
    }
}

impl tokio::io::AsyncWrite for LinkIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Pending => this.ended(cx),
            r => r,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => this.ended(cx),
            r => r,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Pending => this.ended(cx),
            r => r,
        }
    }
}

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

/// The fewest spare streams a hub link keeps beyond the limit and the
/// control stream (each answered `Busy` rather than ending the link).
pub const MIN_SPARE: usize = 8;

/// Spare streams for a device with this limit.
pub fn spare(max_concurrent: u32) -> usize {
    (max_concurrent.clamp(1, crate::rules::MAX_CONCURRENT) as usize / 4).max(MIN_SPARE)
}

/// Streams the hub lets one link of a device carry: its concurrency limit,
/// one control stream, and the spare ones that are answered `Busy`.
pub fn hub_streams(max_concurrent: u32) -> usize {
    max_concurrent.clamp(1, crate::rules::MAX_CONCURRENT) as usize + 1 + spare(max_concurrent)
}

/// Whether a link that came up with room for `streams` streams can carry a
/// device limit of `max_concurrent` and still keep `MIN_SPARE` spare.
pub fn link_carries(streams: usize, max_concurrent: u32) -> bool {
    max_concurrent.clamp(1, crate::rules::MAX_CONCURRENT) as usize + 1 + MIN_SPARE <= streams
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

    /// Opens a stream. A session that already has as many streams as it
    /// allows answers `Busy` and carries on; any other failure means the
    /// session is gone (`HubDown`).
    pub async fn open(&self) -> Result<LinkIo> {
        let (otx, orx) = oneshot::channel();
        self.tx.send(otx).await.map_err(|_| LinkError::HubDown)?;
        match orx.await {
            Ok(Ok(s)) => Ok(LinkIo::new(s, self.cancel.clone())),
            Ok(Err(yamux::ConnectionError::TooManyStreams)) => {
                Err(LinkError::Refused { status: crate::wire::Status::Busy, message: "too many streams open on this link".into() })
            }
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
                                // Too many streams is one refused open; any
                                // other error is the session's end.
                                let fatal = matches!(&r, Err(e) if !matches!(e, yamux::ConnectionError::TooManyStreams));
                                let _ = op.send(r);
                                if fatal {
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
        // Everyone watching learns the session is gone, and every `LinkIo`
        // of it fails its waiting reads and writes: yamux's closing state
        // (below) never wakes streams that are still open. The graceful
        // close then flushes what was written last (a pairing refusal, a
        // Busy answer).
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), poll_fn(|cx| conn.poll_close(cx))).await;
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
        assert_eq!(hub_streams(1), 1 + 1 + MIN_SPARE);
        assert_eq!(hub_streams(2), 11);
        assert_eq!(hub_streams(64), 64 + 1 + 16);
        assert_eq!(hub_streams(0), hub_streams(1), "a zero limit is clamped, never a zero-stream session");
        assert_eq!(hub_streams(u32::MAX), MAX_CONCURRENT as usize + 1 + 64);
        // Every limit keeps at least MIN_SPARE spare streams.
        for c in 1..=MAX_CONCURRENT {
            assert!(link_carries(hub_streams(c), c), "{c}");
        }
        // Building the configs passes yamux's own window >= streams * 256 KiB assertion.
        for c in [1, 2, 64, MAX_CONCURRENT, u32::MAX] {
            let _ = hub_config(c);
        }
        // The bound, stated in the module docs.
        let d = Limits::default().max_concurrent;
        assert_eq!(device_buffer_bound(d), MAX_LINKS_PER_DEVICE * 81 * (256 * 1024 + 32 * 1024));
        assert!(device_buffer_bound(d) < 46 * MIB, "{}", device_buffer_bound(d));
        assert!(device_buffer_bound(MAX_CONCURRENT) < 181 * MIB, "{}", device_buffer_bound(MAX_CONCURRENT));
        assert!(device_buffer_bound(1) < 6 * MIB);
        // Monotonic in the limit.
        for c in 1..MAX_CONCURRENT {
            assert!(device_buffer_bound(c) <= device_buffer_bound(c + 1));
        }
    }

    /// A stream read on a session this side ends returns at once (it used to
    /// hang until something else polled it: yamux's graceful close does not
    /// wake open streams).
    #[tokio::test]
    async fn closing_a_session_wakes_its_open_streams() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_util::compat::TokioAsyncReadCompatExt;
        for close_side in ["client", "server"] {
            let (a, b) = tokio::io::duplex(64 * 1024);
            let (in_tx, mut in_rx) = mpsc::unbounded_channel();
            let server_cancel = CancellationToken::new();
            let (server, _st) = spawn(b.compat(), Mode::Server, move |s| drop(in_tx.send(s)), server_cancel.clone());
            let (client, _ct) = spawn(a.compat(), Mode::Client, |_| {}, CancellationToken::new());
            let mut c = client.open().await.unwrap();
            c.write_all(b"x").await.unwrap();
            let mut s = LinkIo::new(in_rx.recv().await.unwrap(), server_cancel.clone());
            let mut one = [0u8; 1];
            s.read_exact(&mut one).await.unwrap();
            // Both sides wait for data that never comes; one side ends.
            let reader_c = tokio::spawn(async move { c.read(&mut [0u8; 8]).await });
            let reader_s = tokio::spawn(async move { s.read(&mut [0u8; 8]).await });
            tokio::time::sleep(Duration::from_millis(50)).await;
            if close_side == "client" { client.close() } else { server.close() }
            for (who, r) in [("client", reader_c), ("server", reader_s)] {
                let r = tokio::time::timeout(Duration::from_secs(2), r).await;
                assert!(r.is_ok(), "{close_side} closed: the {who} side's read hung");
                assert!(!matches!(r.unwrap().unwrap(), Ok(n) if n > 0));
            }
        }
    }

    #[test]
    fn a_raise_within_the_spare_room_needs_no_new_link() {
        // A link made for 64 carries up to 64 + 16 - 8 = 72 with MIN_SPARE left.
        assert!(link_carries(hub_streams(64), 72));
        assert!(!link_carries(hub_streams(64), 73));
        // Lowering always fits.
        assert!(link_carries(hub_streams(64), 1));
        assert!(link_carries(hub_streams(2), 2) && !link_carries(hub_streams(2), 3));
    }
}
