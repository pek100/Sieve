//! The TCP relay between an app-side stream (ipstack in the probe) and an
//! upstream connection, generic over the stream types so it is tested
//! offline with in-memory streams on both sides.
//!
//! One code path for every TCP flow (TLS, HTTP, anything else):
//! 1. server -> app is relayed from the start (server-first protocols);
//! 2. client bytes are held by [`TcpClassifier`] until it decides, or until
//!    `first_bytes_wait` passes with nothing to decide on;
//! 3. `decide` is called exactly once with the decoded result;
//! 4. pass: the held bytes are written upstream once, in order, then the
//!    rest of the client stream is copied; both directions run to the end
//!    (a client half-close is passed on, the server's reply still arrives);
//!    drop, or a client EOF before any decision: the flow ends at once and
//!    nothing is sent upstream.
//!
//! The caller closes the app side when [`Outcome::stop`] is true, and resets it
//! first when [`Outcome::dropped`] or [`Outcome::reset_app`] is.
//!
//! A side that ends with an error (a reset, the stack's idle limit) is passed on as
//! a reset, never as a FIN: an upload or a close-delimited download cut short must
//! not look complete to the other end.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::flow::classify::{Decoded, TcpClassifier};
use crate::flow::flows::Action;

/// The longest the app side's shutdown is waited for once the server's side ended.
/// The stack sends the FIN once every byte before it is acknowledged, which takes at
/// most until its retransmissions give up (1 + 2 + 4 + 8 s at ipstack's 1 s RTO), or
/// for ever into a window the app keeps closed; past this the flow ends without
/// waiting, and the stack still sends the FIN or resets the connection by itself.
pub const APP_SHUTDOWN_BOUND: Duration = Duration::from_secs(30);

/// An upstream connection that can be ended with a reset rather than a FIN.
pub trait Reset {
    /// Makes the connection's close a reset: dropping it then sends a RST.
    fn reset(&self);
}

impl Reset for tokio::net::TcpStream {
    fn reset(&self) {
        // A zero linger makes the close abortive (a RST), on Windows as elsewhere. If
        // the socket refuses it, the close is the FIN it was before.
        let _ = socket2::SockRef::from(self).set_linger(Some(Duration::ZERO));
    }
}

impl<S: Reset> Reset for tokio_rustls::client::TlsStream<S> {
    fn reset(&self) {
        self.get_ref().0.reset();
    }
}

/// An in-memory pipe has no reset: its far end sees the end of the stream.
#[cfg(test)]
impl Reset for tokio::io::DuplexStream {
    fn reset(&self) {}
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// The classifier's answer, None if the client closed before any.
    pub decided: Option<Decoded>,
    /// What `decide` returned (Pass when never called).
    pub dropped: bool,
    /// The flow must be ended now (dropped, or broken before a decision);
    /// the caller closes the app side.
    pub stop: bool,
    /// Client bytes written upstream (held bytes included).
    pub bytes_up: u64,
    /// Server bytes written to the app.
    pub bytes_down: u64,
    /// The upstream write of the held bytes failed.
    pub upstream_write_failed: bool,
    /// The app's side ended with an error, or the upload into upstream failed: the
    /// upstream connection was reset, not closed.
    pub reset_upstream: bool,
    /// The server's side ended with an error: the app gets no FIN, and the caller
    /// resets its side.
    pub reset_app: bool,
}

/// A writer that counts the bytes it took, so an outcome keeps them however the flow
/// ended (P3-5: a flow cut short reported none).
struct Counting<'a, W: ?Sized> {
    inner: &'a mut W,
    n: &'a AtomicU64,
}

impl<W: AsyncWrite + Unpin + ?Sized> AsyncWrite for Counting<'_, W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut *this.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = polled {
            this.n.fetch_add(n as u64, Ordering::Relaxed);
        }
        polled
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The server's bytes to the app; an upstream that ended with an error is not passed
/// on as the end. True when it ended so, or when the app's connection ended under
/// the copy (`app_closed`).
///
/// Sieve (2026-11-09, P2-b): once the app half-closed, only the server is read here,
/// so an app connection the stack reset (its idle limit, an eviction) went unseen:
/// the task, the upstream socket and the book entry lived until the server acted.
async fn server_to_app<R, W>(up_read: &mut R, app_write: &mut W, app_closed: impl Future<Output = ()>) -> bool
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let copied = tokio::select! {
        biased;
        copied = tokio::io::copy(up_read, app_write) => copied.is_ok(),
        () = app_closed => false,
    };
    if copied {
        let _ = tokio::time::timeout(APP_SHUTDOWN_BOUND, app_write.shutdown()).await;
    }
    !copied
}

/// The app's bytes into upstream after the held ones; an app side that ended with an
/// error is not passed on as the end. True when it ended so.
async fn app_to_server<R, W>(app_read: &mut R, up_write: &mut W) -> bool
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    match tokio::io::copy(app_read, up_write).await {
        Ok(_) => {
            let _ = up_write.shutdown().await;
            false
        }
        Err(_) => true,
    }
}

/// The read buffer the classifier phase uses. It only has to cover the
/// classifier's cap (MAX_STREAM_BYTES) in about one read; both relays share it
/// so the diagnostic one differs from production only in its copy phase.
pub const CLASSIFIER_READ: usize = 16 * 1024;

/// [`relay_tcp_until`] for an app end that cannot tell when its connection is gone.
pub async fn relay_tcp<A, U>(
    app: &mut A,
    upstream: U,
    first_bytes_wait: Duration,
    decide: impl FnOnce(&Decoded) -> Action,
) -> Outcome
where
    A: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Reset + Unpin,
{
    relay_tcp_until(app, upstream, first_bytes_wait, decide, std::future::pending()).await
}

/// The relay; `app_closed` completes once the app's connection is gone, which ends
/// the flow, upstream reset, even while only the server is read.
pub async fn relay_tcp_until<A, U>(
    app: &mut A,
    upstream: U,
    first_bytes_wait: Duration,
    decide: impl FnOnce(&Decoded) -> Action,
    app_closed: impl Future<Output = ()>,
) -> Outcome
where
    A: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Reset + Unpin,
{
    let (mut up_read, mut up_write) = tokio::io::split(upstream);
    let out = relay_halves(app, &mut up_read, &mut up_write, first_bytes_wait, decide, app_closed).await;
    if out.reset_upstream {
        up_read.unsplit(up_write).reset();
    }
    out
}

/// [`relay_tcp`] with the upstream split, so it can be reset once both directions end.
async fn relay_halves<A, R, W>(app: &mut A, up_read: &mut R, up_write: &mut W, first_bytes_wait: Duration, decide: impl FnOnce(&Decoded) -> Action, app_closed: impl Future<Output = ()>) -> Outcome
where
    A: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut app_read, mut app_write) = tokio::io::split(app);
    let (up_bytes, down_bytes) = (AtomicU64::new(0), AtomicU64::new(0));
    let mut up_write = Counting { inner: up_write, n: &up_bytes };
    let mut app_write = Counting { inner: &mut app_write, n: &down_bytes };

    let server_to_app = server_to_app(up_read, &mut app_write, app_closed);
    let client_to_server = async {
        let mut out = Outcome::default();
        let mut classifier = TcpClassifier::new();
        let mut buf = vec![0u8; CLASSIFIER_READ];
        // The classifier holds at most its cap, so the read that decides can
        // carry a tail it did not keep: `spill` is that tail, sent after the
        // held bytes and before the rest of the stream.
        let (decided, spill) = loop {
            match tokio::time::timeout(first_bytes_wait, app_read.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => {
                    out.stop = true;
                    return out;
                }
                Ok(Ok(n)) => {
                    let before = classifier.held().len();
                    if let Some(d) = classifier.push(&buf[..n]) {
                        break (d, classifier.held().len() - before..n);
                    }
                }
                Err(_) => break (Decoded { failure: Some("no client bytes in time"), ..Decoded::default() }, 0..0),
            }
        };
        let action = decide(&decided);
        out.decided = Some(decided);
        if action == Action::Drop {
            out.dropped = true;
            out.stop = true;
            return out;
        }
        let held = classifier.take_held();
        let tail = &buf[spill];
        if up_write.write_all(&held).await.is_err() || up_write.write_all(tail).await.is_err() {
            out.upstream_write_failed = true;
            out.stop = true;
            return out;
        }
        // The classifier's buffers go before the copy phase, which can last the stack's
        // two-hour idle limit: 16 KiB of an idle plain flow's 68 KiB (VM run 8).
        drop((held, buf, classifier));
        out.reset_upstream = app_to_server(&mut app_read, &mut up_write).await;
        out
    };
    tokio::pin!(server_to_app, client_to_server);
    // A side that broke ends the flow at once: the other direction is not waited
    // for, as nothing it carries can reach a connection that is gone.
    let mut out = tokio::select! {
        mut out = &mut client_to_server => {
            if !out.stop && !out.reset_upstream {
                out.reset_app = server_to_app.await;
                out.reset_upstream = out.reset_app;
            }
            out
        }
        broke = &mut server_to_app => {
            if broke {
                Outcome { reset_app: true, reset_upstream: true, stop: true, ..Outcome::default() }
            } else {
                client_to_server.await
            }
        }
    };
    (out.bytes_up, out.bytes_down) = (up_bytes.load(Ordering::Relaxed), down_bytes.load(Ordering::Relaxed));
    out
}

/// Diagnostic counterpart of relay_tcp. Keep classification, half-close and
/// outcomes in sync; only the copy phase's buffers differ (`capacity`).
#[cfg(feature = "relay-experiments")]
pub async fn relay_tcp_buffered<A, U>(
    app: &mut A,
    upstream: U,
    first_bytes_wait: Duration,
    decide: impl FnOnce(&Decoded) -> Action,
    capacity: usize,
    app_closed: impl Future<Output = ()>,
) -> Outcome
where
    A: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Reset + Unpin,
{
    let (up_read, mut up_write) = tokio::io::split(upstream);
    let mut up_read = tokio::io::BufReader::with_capacity(capacity, up_read);
    let out = buffered_halves(app, &mut up_read, &mut up_write, first_bytes_wait, decide, capacity, app_closed).await;
    if out.reset_upstream {
        up_read.into_inner().unsplit(up_write).reset();
    }
    out
}

#[cfg(feature = "relay-experiments")]
async fn buffered_halves<A, R, W>(app: &mut A, up_read: &mut R, up_write: &mut W, first_bytes_wait: Duration, decide: impl FnOnce(&Decoded) -> Action, capacity: usize, app_closed: impl Future<Output = ()>) -> Outcome
where
    A: AsyncRead + AsyncWrite + Unpin,
    R: tokio::io::AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut app_read, mut app_write) = tokio::io::split(app);
    let (up_bytes, down_bytes) = (AtomicU64::new(0), AtomicU64::new(0));
    let mut up_write = Counting { inner: up_write, n: &up_bytes };
    let mut app_write = Counting { inner: &mut app_write, n: &down_bytes };
    let server_to_app = async {
        let copied = tokio::select! {
            biased;
            copied = tokio::io::copy_buf(up_read, &mut app_write) => copied.is_ok(),
            () = app_closed => false,
        };
        if copied {
            let _ = tokio::time::timeout(APP_SHUTDOWN_BOUND, app_write.shutdown()).await;
        }
        !copied
    };
    let client_to_server = async {
        let mut out = Outcome::default();
        let mut classifier = TcpClassifier::new();
        // Same classifier read as production; dropped before the copy phase
        // so a flow holds only its two copy buffers.
        let mut buf = vec![0u8; CLASSIFIER_READ];
        let (decided, spill) = loop {
            match tokio::time::timeout(first_bytes_wait, app_read.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => {
                    out.stop = true;
                    return out;
                }
                Ok(Ok(n)) => {
                    let before = classifier.held().len();
                    if let Some(d) = classifier.push(&buf[..n]) {
                        // A large read can exceed the classifier's held-byte
                        // cap. Replay the unretained tail before copying more.
                        let retained = classifier.held().len() - before;
                        break (d, retained..n);
                    }
                }
                Err(_) => break (Decoded { failure: Some("no client bytes in time"), ..Decoded::default() }, 0..0),
            }
        };
        let action = decide(&decided);
        out.decided = Some(decided);
        if action == Action::Drop {
            out.dropped = true;
            out.stop = true;
            return out;
        }
        let held = classifier.take_held();
        if up_write.write_all(&held).await.is_err() || up_write.write_all(&buf[spill.clone()]).await.is_err() {
            out.upstream_write_failed = true;
            out.stop = true;
            return out;
        }
        drop(buf);
        let mut app_read = tokio::io::BufReader::with_capacity(capacity, &mut app_read);
        match tokio::io::copy_buf(&mut app_read, &mut up_write).await {
            Ok(_) => {
                let _ = up_write.shutdown().await;
            }
            Err(_) => out.reset_upstream = true,
        }
        out
    };
    tokio::pin!(server_to_app, client_to_server);
    // A side that broke ends the flow at once: the other direction is not waited
    // for, as nothing it carries can reach a connection that is gone.
    let mut out = tokio::select! {
        mut out = &mut client_to_server => {
            if !out.stop && !out.reset_upstream {
                out.reset_app = server_to_app.await;
                out.reset_upstream = out.reset_app;
            }
            out
        }
        broke = &mut server_to_app => {
            if broke {
                Outcome { reset_app: true, reset_upstream: true, stop: true, ..Outcome::default() }
            } else {
                client_to_server.await
            }
        }
    };
    (out.bytes_up, out.bytes_down) = (up_bytes.load(Ordering::Relaxed), down_bytes.load(Ordering::Relaxed));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::classify::Kind;
    use crate::flow::sni::build;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncBufReadExt, BufReader, DuplexStream};

    const WAIT: Duration = Duration::from_secs(2);
    const PIPE_BYTES: usize = 64 * 1024;

    #[cfg(feature = "relay-experiments")]
    #[tokio::test]
    async fn experimental_copy_moves_payloads_intact_in_both_directions_at_both_bounds() {
        use crate::experiments::{COPY_MIN, COPY_MAX};
        for capacity in [COPY_MIN, COPY_MAX] {
            // More than two of the largest buffers, with a partial last fill.
            let mut payload = REQUEST.to_vec();
            payload.extend((0..COPY_MAX * 3 + 1).map(|i| i as u8));
            let expected = payload.clone();
            let (mut app, mut relay_side) = tokio::io::duplex(capacity);
            let (up, mut server) = tokio::io::duplex(PIPE_BYTES);
            let relay = tokio::spawn(async move {
                relay_tcp_buffered(&mut relay_side, up, WAIT, |_| Action::Pass, capacity, std::future::pending()).await
            });
            let echo = tokio::spawn(async move {
                let mut got = Vec::new();
                server.read_to_end(&mut got).await.unwrap();
                server.write_all(&got).await.unwrap();
                server.shutdown().await.unwrap();
                got
            });
            tokio::time::timeout(WAIT, async {
                app.write_all(&payload).await.unwrap();
                app.shutdown().await.unwrap();
                let mut got = Vec::new();
                app.read_to_end(&mut got).await.unwrap();
                assert_eq!(got, expected);
                assert_eq!(echo.await.unwrap(), expected);
                let out = relay.await.unwrap();
                assert!(!out.stop && !out.upstream_write_failed);
                assert_eq!((out.bytes_up, out.bytes_down), (expected.len() as u64, expected.len() as u64));
            }).await.expect("buffered relay completed");
        }
    }

    /// An upstream running `serve` on the server end of an in-memory pipe;
    /// returns the relay's end and the server task (yielding what the server
    /// read in total).
    ///
    /// In memory, not a loopback socket: the spike drove these tests over
    /// 127.0.0.1, and on this machine (AdGuard for Windows running, which
    /// filters localhost) plain loopback TCP lost the server's reply under
    /// parallel load. Measured 2026-10-18 with std blocking sockets, no relay
    /// involved: 200 parallel request/reply/close exchanges gave 61 empty
    /// replies, 300 sequential ones none. The relay's logic does not depend
    /// on the transport, so the test must not either.
    async fn upstream<F, Fut>(serve: F) -> (DuplexStream, tokio::task::JoinHandle<Vec<u8>>)
    where
        F: FnOnce(DuplexStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Vec<u8>> + Send + 'static,
    {
        let (relay_end, server_end) = tokio::io::duplex(PIPE_BYTES);
        (relay_end, tokio::spawn(serve(server_end)))
    }

    /// Reads an HTTP request head, answers it, keeps the connection open
    /// (keep-alive) until the client closes.
    async fn http_server(s: DuplexStream, close_after: bool) -> Vec<u8> {
        let (r, mut w) = tokio::io::split(s);
        let mut r = BufReader::new(r);
        let mut seen = Vec::new();
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                return seen;
            }
            seen.extend_from_slice(line.as_bytes());
            if line == "\r\n" {
                break;
            }
        }
        let conn = if close_after { "close" } else { "keep-alive" };
        let reply = format!("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: {conn}\r\n\r\nhello");
        w.write_all(reply.as_bytes()).await.unwrap();
        if close_after {
            w.shutdown().await.unwrap();
            return seen;
        }
        let mut rest = Vec::new();
        let _ = r.read_to_end(&mut rest).await;
        seen.extend(rest);
        seen
    }

    async fn read_response(app: &mut DuplexStream, len: usize) -> Vec<u8> {
        let mut got = vec![0u8; len];
        tokio::time::timeout(WAIT, app.read_exact(&mut got)).await.expect("response in time").expect("response");
        got
    }

    const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: plain.example\r\nUser-Agent: curl/8\r\nAccept: */*\r\n\r\n";
    /// Length of the keep-alive reply `http_server` sends.
    const RESPONSE_LEN: usize =
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello".len();

    #[tokio::test]
    async fn http_request_is_replayed_once_and_the_response_reaches_the_app() {
        let (up, server) = upstream(|s| http_server(s, false)).await;
        let (mut app, mut relay_side) = tokio::io::duplex(PIPE_BYTES);
        let relay = tokio::spawn(async move {
            relay_tcp(&mut relay_side, up, WAIT, |d| {
                assert_eq!(d.kind, Some(Kind::Http));
                assert_eq!(d.domain.as_deref(), Some("plain.example"));
                Action::Pass
            })
            .await
        });
        app.write_all(REQUEST).await.unwrap();
        let reply = read_response(&mut app, RESPONSE_LEN).await;
        assert!(reply.starts_with(b"HTTP/1.1 200 OK"), "{}", String::from_utf8_lossy(&reply));
        assert!(reply.ends_with(b"hello"));
        drop(app); // the client closes, as curl does after the body
        let out = relay.await.unwrap();
        assert!(!out.stop && !out.dropped);
        assert_eq!(out.bytes_up, REQUEST.len() as u64);
        assert_eq!(out.bytes_down, RESPONSE_LEN as u64);
        assert_eq!(server.await.unwrap(), REQUEST, "upstream saw the request exactly once, in order");
    }

    #[tokio::test]
    async fn a_deciding_read_larger_than_the_classifier_cap_loses_no_byte() {
        // First read: an unfinished head (the classifier needs more). Second
        // read: a full 16 KiB buffer, more than the classifier's remaining
        // room, so the read that decides carries a tail it does not keep.
        let mut first = b"POST /upload HTTP/1.1\r\nHost: big.example\r\nX-Pad: ".to_vec();
        first.resize(1460, b'a');
        let mut second = b"\r\nContent-Length: 20000\r\n\r\n".to_vec();
        second.resize(16 * 1024, b'b');
        let mut expected = first.clone();
        expected.extend_from_slice(&second);
        let (up, server) = upstream(|mut s| async move {
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.unwrap();
            got
        })
        .await;
        let (mut app, mut relay_side) = tokio::io::duplex(PIPE_BYTES);
        let relay = tokio::spawn(async move { relay_tcp(&mut relay_side, up, WAIT, |_| Action::Pass).await });
        app.write_all(&first).await.unwrap();
        // Let the relay take the first read on its own before the second arrives.
        tokio::time::sleep(Duration::from_millis(50)).await;
        app.write_all(&second).await.unwrap();
        app.shutdown().await.unwrap();
        let out = tokio::time::timeout(WAIT, relay).await.expect("relay ended").unwrap();
        assert!(!out.upstream_write_failed);
        let got = server.await.unwrap();
        assert_eq!(got.len(), expected.len(), "every client byte reached upstream");
        assert_eq!(got, expected, "in order, none lost or repeated");
        assert_eq!(out.bytes_up, expected.len() as u64);
    }

    #[tokio::test]
    async fn http_request_split_in_tiny_writes_still_arrives_whole() {
        let (up, server) = upstream(|s| http_server(s, false)).await;
        let (mut app, mut relay_side) = tokio::io::duplex(PIPE_BYTES);
        let relay = tokio::spawn(async move { relay_tcp(&mut relay_side, up, WAIT, |_| Action::Pass).await });
        for chunk in REQUEST.chunks(7) {
            app.write_all(chunk).await.unwrap();
            tokio::task::yield_now().await;
        }
        let reply = read_response(&mut app, RESPONSE_LEN).await;
        assert!(reply.ends_with(b"hello"));
        drop(app);
        relay.await.unwrap();
        assert_eq!(server.await.unwrap(), REQUEST);
    }

    #[tokio::test]
    async fn server_that_answers_and_closes_still_delivers_the_whole_reply() {
        let (up, _server) = upstream(|s| http_server(s, true)).await;
        let (mut app, mut relay_side) = tokio::io::duplex(PIPE_BYTES);
        let relay = tokio::spawn(async move { relay_tcp(&mut relay_side, up, WAIT, |_| Action::Pass).await });
        app.write_all(REQUEST).await.unwrap();
        let mut all = Vec::new();
        tokio::time::timeout(WAIT, app.read_to_end(&mut all)).await.expect("eof in time").unwrap();
        assert!(all.starts_with(b"HTTP/1.1 200 OK") && all.ends_with(b"hello"), "{}", String::from_utf8_lossy(&all));
        drop(app);
        let out = relay.await.unwrap();
        assert_eq!(out.bytes_down, all.len() as u64);
    }

    #[tokio::test]
    async fn server_that_closes_without_reply_gives_the_app_eof_not_a_hang() {
        // A real host on port 80, seen 2026-10-17: reads the request, closes.
        let (up, server) = upstream(|s| async move {
            let (mut r, mut w) = tokio::io::split(s);
            let mut buf = vec![0u8; REQUEST.len()];
            r.read_exact(&mut buf).await.unwrap();
            w.shutdown().await.unwrap();
            buf
        })
        .await;
        let (mut app, mut relay_side) = tokio::io::duplex(PIPE_BYTES);
        let relay = tokio::spawn(async move { relay_tcp(&mut relay_side, up, WAIT, |_| Action::Pass).await });
        app.write_all(REQUEST).await.unwrap();
        let mut all = Vec::new();
        tokio::time::timeout(WAIT, app.read_to_end(&mut all)).await.expect("eof in time").unwrap();
        assert!(all.is_empty(), "the app sees the same empty reply as without the TUN");
        drop(app);
        let out = relay.await.unwrap();
        assert_eq!((out.bytes_up, out.bytes_down), (REQUEST.len() as u64, 0));
        assert_eq!(server.await.unwrap(), REQUEST);
    }

    #[tokio::test]
    async fn tls_uses_the_same_path_hello_replayed_then_both_directions_flow() {
        let hello = build::typical("tls.example");
        let hello_len = hello.len();
        let (up, server) = upstream(move |s| async move {
            let (mut r, mut w) = tokio::io::split(s);
            let mut got = vec![0u8; hello_len];
            r.read_exact(&mut got).await.unwrap();
            w.write_all(b"SERVER-FLIGHT").await.unwrap();
            let mut more = Vec::new();
            let _ = r.read_to_end(&mut more).await;
            got.extend(more);
            got
        })
        .await;
        let (mut app, mut relay_side) = tokio::io::duplex(PIPE_BYTES);
        let relay = tokio::spawn(async move {
            relay_tcp(&mut relay_side, up, WAIT, |d| {
                assert_eq!((d.kind, d.domain.as_deref()), (Some(Kind::Tls), Some("tls.example")));
                Action::Pass
            })
            .await
        });
        // Hello in two writes (split across segments), then app data.
        app.write_all(&hello[..100]).await.unwrap();
        app.write_all(&hello[100..]).await.unwrap();
        assert_eq!(read_response(&mut app, 13).await, b"SERVER-FLIGHT");
        app.write_all(b"FINISHED+APPDATA").await.unwrap();
        app.shutdown().await.unwrap();
        let out = relay.await.unwrap();
        let mut expect = hello.clone();
        expect.extend_from_slice(b"FINISHED+APPDATA");
        assert_eq!(server.await.unwrap(), expect);
        assert_eq!(out.bytes_up, expect.len() as u64);
    }

    #[tokio::test]
    async fn drop_sends_nothing_upstream_and_asks_to_close_the_app() {
        let (up, server) = upstream(|s| async move {
            let mut r = s;
            let mut all = Vec::new();
            let _ = r.read_to_end(&mut all).await;
            all
        })
        .await;
        let (mut app, mut relay_side) = tokio::io::duplex(PIPE_BYTES);
        let relay = tokio::spawn(async move { relay_tcp(&mut relay_side, up, WAIT, |_| Action::Drop).await });
        app.write_all(&build::typical("blocked.example")).await.unwrap();
        let out = relay.await.unwrap();
        assert!(out.dropped && out.stop);
        assert_eq!(out.bytes_up, 0);
        assert!(server.await.unwrap().is_empty(), "nothing reached the upstream");
    }

    fn decision_filter() -> (crate::domain::DomainFilter, std::sync::Mutex<crate::dns::NameMap>) {
        use sieve_filter::rules::{ListText, RuleEngine, RuleSet};
        let lists = RuleEngine::compile(&[ListText { id: "test", text: "||blocked.example^\n", trusted: false }]);
        let rules = RuleSet { user: std::sync::Arc::new(RuleEngine::empty()), lists: std::sync::Arc::new(lists) };
        let policy = sieve_ipc::Policy { sieving: true, off_apps: vec!["off app".into()], ..sieve_ipc::Policy::default() };
        (crate::domain::DomainFilter::new(&policy, rules), std::sync::Mutex::default())
    }

    fn decide_as(key: &'static str) -> impl FnOnce(&Decoded) -> Action {
        use crate::domain::{Flow, Owner};
        move |d| {
            let (filter, names) = decision_filter();
            filter.decide(Flow::from_decoded(d, false, "192.0.2.1".parse().unwrap(), Owner::App { key }), &names, 0).action
        }
    }

    /// The real classifier and the real decision: the sieved app's hello never
    /// leaves, and once the caller closes as `stop` asks, the app sees the FIN.
    #[tokio::test]
    async fn blocked_flow_sends_nothing_upstream_and_closes_the_app() {
        let (up, server) = upstream(|mut s| async move {
            let mut all = Vec::new();
            let _ = s.read_to_end(&mut all).await;
            all
        })
        .await;
        let (mut app, mut relay_side) = tokio::io::duplex(PIPE_BYTES);
        app.write_all(&build::typical("x.blocked.example")).await.unwrap();
        let relay = tokio::spawn(async move {
            let out = relay_tcp(&mut relay_side, up, WAIT, decide_as("browser")).await;
            if out.stop {
                relay_side.shutdown().await.unwrap();
            }
            out
        });
        let out = relay.await.unwrap();
        assert!(out.dropped && out.stop);
        assert_eq!((out.bytes_up, out.decided.and_then(|d| d.domain).as_deref()), (0, Some("x.blocked.example")));
        assert!(server.await.unwrap().is_empty(), "nothing reached the upstream");
        let mut closed = Vec::new();
        tokio::time::timeout(WAIT, app.read_to_end(&mut closed)).await.expect("the app sees a close").unwrap();
    }

    /// The same flow from an Off app: its hello, then its data, reach upstream
    /// byte for byte, in order, once.
    #[tokio::test]
    async fn off_app_held_bytes_reach_upstream_intact() {
        let hello = build::typical("x.blocked.example");
        let (up, server) = upstream(|mut s| async move {
            let mut all = Vec::new();
            let _ = s.read_to_end(&mut all).await;
            all
        })
        .await;
        let (mut app, mut relay_side) = tokio::io::duplex(PIPE_BYTES);
        let relay = tokio::spawn(async move { relay_tcp(&mut relay_side, up, WAIT, decide_as("off app")).await });
        app.write_all(&hello[..50]).await.unwrap();
        tokio::task::yield_now().await;
        app.write_all(&hello[50..]).await.unwrap();
        app.write_all(b"APPDATA").await.unwrap();
        app.shutdown().await.unwrap();
        let out = relay.await.unwrap();
        let expected = [hello.as_slice(), b"APPDATA"].concat();
        assert!(!out.dropped && !out.stop);
        assert_eq!(out.bytes_up, expected.len() as u64);
        assert_eq!(server.await.unwrap(), expected);
    }

    #[tokio::test]
    async fn server_first_banner_reaches_the_app_before_any_client_byte() {
        let (up, server) = upstream(|s| async move {
            let (mut r, mut w) = tokio::io::split(s);
            w.write_all(b"220 smtp.example ESMTP\r\n").await.unwrap();
            let mut all = Vec::new();
            let _ = r.read_to_end(&mut all).await;
            all
        })
        .await;
        let (mut app, mut relay_side) = tokio::io::duplex(PIPE_BYTES);
        let relay = tokio::spawn(async move { relay_tcp(&mut relay_side, up, WAIT, |_| Action::Pass).await });
        assert_eq!(read_response(&mut app, 24).await, b"220 smtp.example ESMTP\r\n");
        app.write_all(b"EHLO me\r\n").await.unwrap();
        app.shutdown().await.unwrap();
        let out = relay.await.unwrap();
        assert_eq!(out.decided.and_then(|d| d.failure), Some("not tls/quic/http"));
        assert_eq!(server.await.unwrap(), b"EHLO me\r\n");
    }

    /// An app end whose reads fail with a reset once its bytes are read, and whose
    /// shutdown never completes when `stuck`.
    struct App {
        inner: DuplexStream,
        reset_after: bool,
        stuck: bool,
    }

    impl AsyncRead for App {
        fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
            let before = buf.filled().len();
            let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
            if self.reset_after && matches!(polled, std::task::Poll::Ready(Ok(()))) && buf.filled().len() == before {
                return std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()));
            }
            polled
        }
    }

    impl AsyncWrite for App {
        fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, data: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
        }
        fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            if self.stuck {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// An upstream that records whether it was reset or shut down, and whose reads
    /// fail with a reset once its bytes are read when `reset_at_end`.
    struct Upstream {
        inner: DuplexStream,
        reset: Arc<AtomicBool>,
        shut: Arc<AtomicBool>,
        reset_at_end: bool,
    }

    impl Reset for Upstream {
        fn reset(&self) {
            self.reset.store(true, Ordering::SeqCst);
        }
    }

    impl AsyncRead for Upstream {
        fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
            let before = buf.filled().len();
            let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
            if self.reset_at_end && matches!(polled, std::task::Poll::Ready(Ok(()))) && buf.filled().len() == before {
                return std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()));
            }
            polled
        }
    }

    impl AsyncWrite for Upstream {
        fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, data: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
        }
        fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            self.shut.store(true, Ordering::SeqCst);
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// P3 (second review of run 7): the app resets the connection halfway through an
    /// upload. Upstream must be reset, never sent a FIN: a FIN would end the upload
    /// there as if it were complete.
    #[tokio::test]
    async fn an_app_reset_resets_upstream_and_sends_no_fin() {
        for reset_after in [true, false] {
            let (app_far, app_near) = tokio::io::duplex(PIPE_BYTES);
            let (up_near, mut server) = tokio::io::duplex(PIPE_BYTES);
            let (reset, shut) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
            let up = Upstream { inner: up_near, reset: reset.clone(), shut: shut.clone(), reset_at_end: false };
            let mut app = App { inner: app_near, reset_after, stuck: false };
            let relay = tokio::spawn(async move { relay_tcp(&mut app, up, WAIT, |_| Action::Pass).await });
            let mut app_far = app_far;
            app_far.write_all(b"POST /upload HTTP/1.1\r\nHost: up.example\r\nContent-Length: 100000\r\n\r\nhalf").await.unwrap();
            app_far.shutdown().await.unwrap();
            let mut byte = [0u8; 1];
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                server.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
            }
            drop(server);
            let out = tokio::time::timeout(WAIT, relay).await.expect("the relay ended").unwrap();
            assert_eq!((out.reset_upstream, reset.load(Ordering::SeqCst)), (reset_after, reset_after), "reset after {reset_after}: {out:?}");
            assert_eq!(shut.load(Ordering::SeqCst), !reset_after, "a FIN upstream only for a clean end");
        }
    }

    /// P3-5: a flow cut short by the server still reports the bytes it carried both
    /// ways; it reported none.
    #[tokio::test]
    async fn a_server_reset_keeps_the_byte_counts() {
        const PARTIAL: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial";
        let (mut app_far, app_near) = tokio::io::duplex(PIPE_BYTES);
        let (up_near, mut server) = tokio::io::duplex(PIPE_BYTES);
        let (reset, shut) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let up = Upstream { inner: up_near, reset: reset.clone(), shut, reset_at_end: true };
        let mut app = App { inner: app_near, reset_after: false, stuck: false };
        let relay = tokio::spawn(async move { relay_tcp(&mut app, up, WAIT, |_| Action::Pass).await });
        app_far.write_all(REQUEST).await.unwrap();
        let mut request = vec![0u8; REQUEST.len()];
        server.read_exact(&mut request).await.unwrap();
        server.write_all(PARTIAL).await.unwrap();
        drop(server);
        let out = tokio::time::timeout(WAIT, relay).await.expect("the relay ended").unwrap();
        assert!(out.reset_app && out.reset_upstream, "the control: the server's side broke: {out:?}");
        assert_eq!((out.bytes_up, out.bytes_down), (REQUEST.len() as u64, PARTIAL.len() as u64), "{out:?}");
        let mut got = vec![0u8; PARTIAL.len()];
        app_far.read_exact(&mut got).await.unwrap();
        assert_eq!(got, PARTIAL);
    }

    /// P1-2 (second review of run 7): the app side's shutdown is bounded; a stack that
    /// never completes it cannot hold the flow once both directions ended.
    #[tokio::test(start_paused = true)]
    async fn an_app_shutdown_that_never_completes_is_waited_for_a_bound() {
        let (up, server) = upstream(|s| http_server(s, true)).await;
        let (mut app_far, app_near) = tokio::io::duplex(PIPE_BYTES);
        let mut app = App { inner: app_near, reset_after: false, stuck: true };
        let relay = tokio::spawn(async move { relay_tcp(&mut app, up, WAIT, |_| Action::Pass).await });
        app_far.write_all(REQUEST).await.unwrap();
        app_far.shutdown().await.unwrap();
        let _ = server.await.unwrap();
        let started = tokio::time::Instant::now();
        let out = tokio::time::timeout(APP_SHUTDOWN_BOUND * 2, relay).await.expect("bounded").unwrap();
        assert!(started.elapsed() >= APP_SHUTDOWN_BOUND - Duration::from_secs(1), "the control: it did wait for the shutdown");
        assert!(!out.stop && !out.reset_upstream && !out.reset_app, "{out:?}");
    }

    #[tokio::test]
    async fn client_eof_before_any_byte_stops_without_deciding() {
        let (up, _server) = upstream(|s| async move {
            let mut r = s;
            let mut all = Vec::new();
            let _ = r.read_to_end(&mut all).await;
            all
        })
        .await;
        let (app, mut relay_side) = tokio::io::duplex(1024);
        drop(app);
        let out = relay_tcp(&mut relay_side, up, WAIT, |_| panic!("must not decide")).await;
        assert!(out.stop && out.decided.is_none());
    }
}
