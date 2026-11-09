//! The byte streams of a flow: [`AppSide`] is the app's end, shared so the flow
//! can close it after any path gave it away, and counted in one place;
//! [`Prefixed`] replays what the classifier held; [`splice`] is the pass-through.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::flow::relay::{APP_SHUTDOWN_BOUND, Reset};

/// How long a FIN to the app may take (`stack::relay::close_app`'s bound).
const CLOSE_BOUND: Duration = Duration::from_secs(1);

#[derive(Debug, Default)]
struct Meter {
    up: AtomicU64,
    down: AtomicU64,
}

/// An app end that can be torn down at once. A reset does not stop a page's own
/// retries (live, 2026-11-06: about 730 in 15 s with a FIN or an RST alike).
pub trait Abort {
    fn abort(&self);
}

/// The app's end. Clones share one stream: a dropped ipstack stream leaves the
/// app waiting (live run 1), so whoever holds it last must not be the only way
/// to close it, and `rustls`, hyper and an upgrade each want to own it.
pub struct AppSide<A> {
    inner: Arc<Mutex<A>>,
    meter: Arc<Meter>,
    /// When this clone's shutdown stops being waited for ([`APP_SHUTDOWN_BOUND`]): a
    /// copy or a TLS session shuts the app side when the server's ended, and the flow
    /// must not wait on it for ever (P1-2 of the second review of run 7).
    shutdown_by: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<A> Clone for AppSide<A> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), meter: self.meter.clone(), shutdown_by: None }
    }
}

impl<A: AsyncRead + AsyncWrite + Unpin> AppSide<A> {
    pub fn new(app: A) -> Self {
        Self { inner: Arc::new(Mutex::new(app)), meter: Arc::default(), shutdown_by: None }
    }

    fn app(&self) -> std::sync::MutexGuard<'_, A> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Bytes the app sent, and bytes written to it.
    pub fn counted(&self) -> (u64, u64) {
        (self.meter.up.load(Ordering::Relaxed), self.meter.down.load(Ordering::Relaxed))
    }

    /// A FIN, bounded: the flow is over.
    pub async fn close(&self) {
        let mut side = self.clone();
        let _ = tokio::time::timeout(CLOSE_BOUND, side.shutdown()).await;
    }
}

impl<A: Abort> AppSide<A> {
    /// A blocked flow's end. After it, [`Self::close`] sends nothing.
    pub fn abort(&self) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).abort();
    }
}

impl<A: AsyncRead + AsyncWrite + Unpin> AsyncRead for AppSide<A> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut *self.app()).poll_read(cx, buf);
        self.meter.up.fetch_add((buf.filled().len() - before) as u64, Ordering::Relaxed);
        polled
    }
}

impl<A: AsyncRead + AsyncWrite + Unpin> AsyncWrite for AppSide<A> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut *self.app()).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = polled {
            self.meter.down.fetch_add(n as u64, Ordering::Relaxed);
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.app()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if Pin::new(&mut *self.app()).poll_shutdown(cx).is_ready() {
            self.shutdown_by = None;
            return Poll::Ready(Ok(()));
        }
        // Past the bound the stack still sends the FIN, or resets, by itself.
        let by = self.shutdown_by.get_or_insert_with(|| Box::pin(tokio::time::sleep(APP_SHUTDOWN_BOUND)));
        if by.as_mut().poll(cx).is_ready() {
            self.shutdown_by = None;
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
}

impl<A: Abort> Abort for AppSide<A> {
    fn abort(&self) {
        AppSide::abort(self);
    }
}

/// A stream whose first reads come from `prefix`.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    at: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, at: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.at < this.prefix.len() {
            let n = buf.remaining().min(this.prefix.len() - this.at);
            buf.put_slice(&this.prefix[this.at..this.at + n]);
            this.at += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The pass-through: the held bytes, in order and once, then both directions
/// to the end, half-closes passed on. True when the held bytes reached it. A copy
/// that ends with an error (the app's reset among them) resets upstream rather than
/// closing it, so a cut-short upload does not look complete (`flow::relay`).
pub async fn splice<A, U>(app: &mut A, mut upstream: U, held: &[u8]) -> bool
where
    A: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Reset + Unpin,
{
    if upstream.write_all(held).await.is_err() {
        return false;
    }
    if tokio::io::copy_bidirectional(app, &mut upstream).await.is_err() {
        upstream.reset();
    }
    true
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test]
    async fn prefixed_replays_then_reads_on() {
        let (mut far, near) = tokio::io::duplex(64);
        far.write_all(b"rest").await.unwrap();
        far.shutdown().await.unwrap();
        let mut stream = Prefixed::new(b"held-".to_vec(), near);
        let mut small = [0u8; 2];
        stream.read_exact(&mut small).await.unwrap();
        assert_eq!(&small, b"he", "a short read keeps its place");
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ld-rest");
    }

    #[tokio::test]
    async fn the_app_side_counts_both_ways_and_its_clone_closes_it() {
        let (mut far, near) = tokio::io::duplex(64);
        let side = AppSide::new(near);
        far.write_all(b"abc").await.unwrap();
        let mut reader = side.clone();
        let mut got = [0u8; 3];
        reader.read_exact(&mut got).await.unwrap();
        let mut writer = side.clone();
        writer.write_all(b"xy").await.unwrap();
        assert_eq!(side.counted(), (3, 2));
        side.close().await;
        let mut rest = Vec::new();
        far.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"xy", "then a FIN");
    }

    #[tokio::test]
    async fn splice_replays_and_passes_half_closes() {
        let (mut client, mut app) = tokio::io::duplex(1024);
        let (up, mut server) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move { splice(&mut app, up, b"HELD").await });
        client.write_all(b"more").await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"HELDmore");
        server.write_all(b"reply").await.unwrap();
        server.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply", "the server's reply still arrives");
        assert!(task.await.unwrap());
    }
}
