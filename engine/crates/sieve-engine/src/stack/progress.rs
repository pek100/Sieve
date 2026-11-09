//! A relayed flow's progress, for the stall signal: when bytes last went up to
//! the server and last came down from it. A flow that ends with its newest bytes
//! up unanswered for [`STALL_AFTER`] stalled: the app sent something and waited
//! that long with nothing back. Read once, when the flow ends, so a flow costs a
//! clock read per read or write and no timer.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Longer than an ordinary page, API or update answer takes, so what reads as a
/// stall is an app that waited well past when it would have had its answer.
/// A long poll the app gives up on this late reads as one too, which is true:
/// it got nothing back.
pub const STALL_AFTER: Duration = Duration::from_secs(15);

/// The flow's two times, ms on `clock` plus one (0 is never).
pub struct Progress {
    up: AtomicU64,
    down: AtomicU64,
    clock: fn() -> u64,
}

impl Progress {
    pub fn new(clock: fn() -> u64) -> Arc<Self> {
        Arc::new(Self { up: AtomicU64::new(0), down: AtomicU64::new(0), clock })
    }

    fn mark(&self, at: &AtomicU64) {
        at.store((self.clock)().saturating_add(1), Ordering::Relaxed);
    }

    /// True when the newest bytes went up and nothing came down for
    /// [`STALL_AFTER`] since, up to now.
    pub fn stalled(&self) -> bool {
        let (up, down) = (self.up.load(Ordering::Relaxed), self.down.load(Ordering::Relaxed));
        let waited = (self.clock)().saturating_add(1).saturating_sub(up);
        up > 0 && up > down && waited >= STALL_AFTER.as_millis() as u64
    }
}

/// The upstream side of a relay, watched.
pub struct Watched<S> {
    inner: S,
    progress: Arc<Progress>,
}

impl<S> Watched<S> {
    pub fn new(inner: S, progress: Arc<Progress>) -> Self {
        Self { inner, progress }
    }
}

impl<S: crate::flow::relay::Reset> crate::flow::relay::Reset for Watched<S> {
    fn reset(&self) {
        self.inner.reset();
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.progress.mark(&self.progress.down);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, data);
        if matches!(polled, Poll::Ready(Ok(n)) if n > 0) {
            self.progress.mark(&self.progress.up);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    static NOW: AtomicU64 = AtomicU64::new(1_000);

    fn clock() -> u64 {
        NOW.load(Ordering::Relaxed)
    }

    fn at(ms: u64) {
        NOW.store(ms, Ordering::Relaxed);
    }

    /// One test, since the fake clock is shared.
    #[tokio::test]
    async fn only_bytes_up_left_unanswered_past_the_bound_are_a_stall() {
        let stall = STALL_AFTER.as_millis() as u64;
        let (near, mut far) = tokio::io::duplex(64);
        let progress = Progress::new(clock);
        let mut up = Watched::new(near, progress.clone());
        at(1_000);
        assert!(!progress.stalled(), "nothing sent is no stall");
        up.write_all(b"GET").await.unwrap();
        at(1_000 + stall - 1);
        assert!(!progress.stalled(), "not yet");
        at(1_000 + stall);
        assert!(progress.stalled(), "waited the bound with no answer");
        far.write_all(b"200").await.unwrap();
        let mut buf = [0u8; 3];
        up.read_exact(&mut buf).await.unwrap();
        assert!(!progress.stalled(), "answered");
        at(1_000 + 10 * stall);
        assert!(!progress.stalled(), "an idle flow after its answer is no stall");
    }
}
