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
//! The caller closes the app side when [`Outcome::stop`] is true.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::flow::classify::{Decoded, TcpClassifier};
use crate::flow::flows::Action;

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
}

pub async fn relay_tcp<A, U>(
    app: &mut A,
    upstream: U,
    first_bytes_wait: Duration,
    decide: impl FnOnce(&Decoded) -> Action,
) -> Outcome
where
    A: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut up_read, mut up_write) = tokio::io::split(upstream);
    let (mut app_read, mut app_write) = tokio::io::split(app);

    let server_to_app = async {
        let n = tokio::io::copy(&mut up_read, &mut app_write).await.unwrap_or(0);
        let _ = app_write.shutdown().await;
        n
    };
    let client_to_server = async {
        let mut out = Outcome::default();
        let mut classifier = TcpClassifier::new();
        let mut buf = vec![0u8; 16 * 1024];
        let decided = loop {
            match tokio::time::timeout(first_bytes_wait, app_read.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => {
                    out.stop = true;
                    return out;
                }
                Ok(Ok(n)) => {
                    if let Some(d) = classifier.push(&buf[..n]) {
                        break d;
                    }
                }
                Err(_) => break Decoded { failure: Some("no client bytes in time"), ..Decoded::default() },
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
        if up_write.write_all(&held).await.is_err() {
            out.upstream_write_failed = true;
            out.stop = true;
            return out;
        }
        out.bytes_up = held.len() as u64 + tokio::io::copy(&mut app_read, &mut up_write).await.unwrap_or(0);
        let _ = up_write.shutdown().await;
        out
    };
    tokio::pin!(server_to_app, client_to_server);
    tokio::select! {
        mut out = &mut client_to_server => {
            if !out.stop {
                out.bytes_down = server_to_app.await;
            }
            out
        }
        down = &mut server_to_app => {
            let mut out = client_to_server.await;
            out.bytes_down = down;
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::classify::Kind;
    use crate::flow::sni::build;
    use tokio::io::{AsyncBufReadExt, BufReader, DuplexStream};

    const WAIT: Duration = Duration::from_secs(2);
    const PIPE_BYTES: usize = 64 * 1024;

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
        // quic.nginx.org on port 80 (2026-10-17): reads the request, closes.
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
