//! A Wintun session as a tokio AsyncRead + AsyncWrite device, one IP
//! packet per read and per write, which is what ipstack expects.
//!
//! A plain thread blocks in `receive_blocking` and hands packets to the
//! async side through a channel; `Session::shutdown` makes it return an
//! error and the thread ends. Writes go straight into the send ring.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use wintun_bindings::Session;

pub struct TunDevice {
    session: Arc<Session>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    packets_out: Arc<AtomicU64>,
}

impl TunDevice {
    pub fn new(session: Arc<Session>, packets_in: Arc<AtomicU64>, packets_out: Arc<AtomicU64>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let reader = session.clone();
        std::thread::spawn(move || {
            while let Ok(packet) = reader.receive_blocking() {
                packets_in.fetch_add(1, Ordering::Relaxed);
                if tx.send(packet.bytes().to_vec()).is_err() {
                    break;
                }
            }
        });
        Self { session, rx, packets_out }
    }
}

impl AsyncRead for TunDevice {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match ready!(self.rx.poll_recv(cx)) {
            Some(packet) => {
                if packet.len() > buf.remaining() {
                    // Larger than ipstack's MTU buffer: drop it rather than
                    // hand over a truncated IP packet.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                buf.put_slice(&packet);
                Poll::Ready(Ok(()))
            }
            None => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let len = u16::try_from(buf.len()).map_err(|_| std::io::Error::other("packet larger than 65535"))?;
        let mut packet = self.session.allocate_send_packet(len).map_err(std::io::Error::other)?;
        packet.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(packet);
        self.packets_out.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
