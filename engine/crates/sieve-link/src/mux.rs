//! One yamux session over the TLS connection, driven by its own task.
//!
//! yamux makes progress only while `poll_next_inbound` is polled, so a single
//! task owns the `Connection`, keeps polling it, opens outbound streams on
//! request and hands inbound streams to a callback. Memory is bounded by
//! yamux's per-stream windows (256 KiB, auto-tuned within the connection-wide
//! cap below) and by the stream cap.
//!
//! The device is always yamux `Client` and the hub always `Server`, whichever
//! of them dialled the TCP connection.

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

/// Most streams one link carries at once (per connection).
pub const MAX_STREAMS: usize = 128;

type Opener = oneshot::Sender<std::result::Result<yamux::Stream, yamux::ConnectionError>>;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub fn config() -> yamux::Config {
    let mut c = yamux::Config::default();
    // Order matters: yamux asserts window >= 256 KiB * streams on each call.
    c.set_max_num_streams(MAX_STREAMS);
    c.set_max_connection_receive_window(Some(MAX_STREAMS * 256 * 1024));
    c
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
pub fn spawn<T, F>(io: T, mode: Mode, mut on_inbound: F, cancel: CancellationToken) -> (MuxHandle, tokio::task::JoinHandle<()>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnMut(yamux::Stream) + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<Opener>(16);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let handle = MuxHandle { id, tx, cancel: cancel.clone() };
    let task = tokio::spawn(async move {
        let mut conn = yamux::Connection::new(io, config(), mode);
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
