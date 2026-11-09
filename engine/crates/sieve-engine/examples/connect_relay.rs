//! P0: explicit loopback CONNECT proxy, no installation or settings changes.
//! Stdout is the chosen port, then the final JSON record. Diagnostics use stderr.

#[cfg(any(windows, test))]
use std::net::SocketAddr;

#[cfg(any(windows, test))]
fn parse_connect(line: &str, peer: SocketAddr) -> Option<(String, u16)> {
    // Reuse the engine's HTTP head budget, including for the request line.
    if !peer.ip().is_loopback() || line.len() > sieve_engine::flow::http::MAX_HEAD {
        return None;
    }
    let authority = line.strip_prefix("CONNECT ")?.strip_suffix(" HTTP/1.1")?;
    let (host, port) = authority.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    let host = if host.starts_with('[') {
        let ip = host.strip_prefix('[')?.strip_suffix(']')?.parse::<std::net::Ipv6Addr>().ok()?;
        ip.to_string()
    } else {
        // A CONNECT authority has no path, credentials, fragment or whitespace.
        if !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
            return None;
        }
        host.to_owned()
    };
    Some((host, port))
}

#[cfg(any(windows, test))]
#[derive(serde::Serialize)]
struct Summary {
    user_cpu_seconds: f64,
    kernel_cpu_seconds: f64,
    bytes_up: u64,
    bytes_down: u64,
    tunnels: u64,
    cancelled_connections: u64,
    failed_connections: u64,
    /// Connections answered 405. Their CPU is in the process total, so the
    /// runner refuses to score a sample that has any.
    rejected_connections: u64,
}

#[cfg(windows)]
mod proxy {
    use super::{Summary, parse_connect};
    use std::io::{self, Read, Write};
    use std::pin::Pin;
    use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
    use std::task::{Context, Poll};
    use std::time::Duration;
    use sieve_engine::flow::{flows::Action, http::MAX_HEAD, relay::relay_tcp};
    use sieve_engine::stack::relay::FIRST_BYTES_WAIT;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinSet;
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    // Explicit P0 resource bounds from the task, not performance thresholds.
    const MAX_TUNNELS: usize = 16;
    const MAX_SECONDS: u64 = 600;
    // After stdin closes, open tunnels may finish normally: curl has left, and
    // the origin's FIN follows ours within a round trip. Bounded well inside
    // the runner's shutdown allowance (one workload deadline, at least 1 s).
    const DRAIN: Duration = Duration::from_millis(900);

    #[derive(Default)]
    struct Counts {
        up: AtomicU64,
        down: AtomicU64,
        tunnels: AtomicU64,
        rejected: AtomicU64,
    }

    // Count successful payload writes, including a tunnel cancelled at the deadline.
    // The relay itself still owns all copy buffers and classification behaviour.
    struct Counted<'a> {
        stream: TcpStream,
        total: &'a AtomicU64,
        written: u64,
    }
    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            // Publish once per direction, including cancellation, rather than
            // adding an atomic operation to every payload write being measured.
            self.total.fetch_add(self.written, Ordering::Relaxed);
        }
    }
    impl sieve_engine::flow::relay::Reset for Counted<'_> {
        fn reset(&self) {
            self.stream.reset();
        }
    }
    impl AsyncRead for Counted<'_> {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for Counted<'_> {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let result = Pin::new(&mut self.stream).poll_write(cx, buf);
            if let Poll::Ready(Ok(n)) = &result {
                self.written += *n as u64;
            }
            result
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }

    async fn reject(stream: &mut TcpStream, counts: &Counts) -> io::Result<()> {
        counts.rejected.fetch_add(1, Ordering::Relaxed);
        stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await
    }

    async fn tunnel(mut stream: TcpStream, peer: std::net::SocketAddr, counts: Arc<Counts>) -> io::Result<()> {
        if !peer.ip().is_loopback() {
            return reject(&mut stream, &counts).await;
        }
        let mut head = Vec::new();
        // Read only the CONNECT head, never consume a pipelined TLS byte.
        // This is setup work only, the payload uses relay_tcp's existing buffers.
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() >= MAX_HEAD {
                return reject(&mut stream, &counts).await;
            }
            match stream.read_u8().await {
                Ok(byte) => head.push(byte),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return reject(&mut stream, &counts).await,
                Err(error) => return Err(error),
            }
            // Refuse other methods as soon as their complete request line arrives.
            if head.ends_with(b"\r\n") && !head[..head.len() - 2].contains(&b'\n') {
                let line = std::str::from_utf8(&head[..head.len() - 2]).ok();
                if line.and_then(|line| parse_connect(line, peer)).is_none() {
                    return reject(&mut stream, &counts).await;
                }
            }
        }
        let target = std::str::from_utf8(&head).ok()
            .and_then(|head| head.split("\r\n").next())
            .and_then(|line| parse_connect(line, peer));
        let Some((host, port)) = target else { return reject(&mut stream, &counts).await };
        let upstream = match TcpStream::connect((host.as_str(), port)).await {
            Ok(stream) => stream,
            Err(error) => {
                stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                return Err(error);
            }
        };
        stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
        counts.tunnels.fetch_add(1, Ordering::Relaxed);
        let mut app = Counted { stream, total: &counts.down, written: 0 };
        let upstream = Counted { stream: upstream, total: &counts.up, written: 0 };
        let outcome = relay_tcp(&mut app, upstream, FIRST_BYTES_WAIT, |_| Action::Pass).await;
        if outcome.stop {
            return Err(io::Error::other("relay stopped before completing the tunnel"));
        }
        Ok(())
    }

    fn cpu_times() -> Result<(f64, f64), windows::core::Error> {
        let (mut created, mut exited, mut kernel, mut user) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
        // GetCurrentProcess returns a pseudo handle, which must not be closed.
        unsafe { GetProcessTimes(GetCurrentProcess(), &mut created, &mut exited, &mut kernel, &mut user)?; }
        // FILETIME counts 100 ns units. A second contains 10^9 ns.
        let seconds = |t: FILETIME| ((u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)) as f64 * 100.0 / 1e9;
        Ok((seconds(user), seconds(kernel)))
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let mut args = std::env::args().skip(1);
        let (mut port, mut seconds) = (0_u16, None);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--port" => port = args.next().ok_or("--port needs a value")?.parse()?,
                "--seconds" => seconds = Some(args.next().ok_or("--seconds needs a value")?.parse::<u64>()?),
                _ => return Err(format!("unknown argument: {arg}").into()),
            }
        }
        let seconds = seconds.filter(|s| (1..=MAX_SECONDS).contains(s)).ok_or("--seconds is required, in 1..=600")?;
        let counts = Arc::new(Counts::default());
        let (done, closed) = tokio::sync::oneshot::channel();
        // A dedicated std thread avoids Tokio's non-cancellable stdin blocking task,
        // which would otherwise keep runtime shutdown waiting after the deadline.
        std::thread::spawn(move || {
            let mut stdin = io::stdin().lock();
            let mut byte = [0_u8; 1];
            loop {
                match stdin.read(&mut byte) {
                    Ok(0) => break,
                    Ok(_) => (),
                    Err(error) => { eprintln!("stdin: {error}"); break; }
                }
            }
            let _ = done.send(()); // The timer may already have ended the process.
        });
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        let (cancelled_connections, failed_connections) = runtime.block_on(async {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
            println!("{}", listener.local_addr()?.port());
            io::stdout().flush()?;
            let deadline = tokio::time::sleep(Duration::from_secs(seconds));
            tokio::pin!(deadline, closed);
            let mut tasks = JoinSet::new();
            let mut failed = 0;
            loop {
                tokio::select! {
                    biased;
                    _ = &mut deadline => break,
                    _ = &mut closed => break,
                    result = tasks.join_next(), if !tasks.is_empty() => {
                        if let Some(result) = result {
                            match result {
                                Ok(Ok(())) => (),
                                error => { failed += 1; eprintln!("connection: {error:?}"); }
                            }
                        }
                    }
                    // Backpressure caps all accepted connections, including handshakes.
                    accepted = listener.accept(), if tasks.len() < MAX_TUNNELS => {
                        let (stream, peer) = accepted?;
                        tasks.spawn(tunnel(stream, peer, Arc::clone(&counts)));
                    }
                }
            }
            // The listener is no longer polled, so no new connection starts.
            // Let open tunnels close normally first, then cancel what is left.
            let _ = tokio::time::timeout(DRAIN, async {
                while let Some(result) = tasks.join_next().await {
                    if !matches!(result, Ok(Ok(()))) {
                        failed += 1;
                        eprintln!("connection: {result:?}");
                    }
                }
            })
            .await;
            tasks.abort_all();
            let mut cancelled = 0;
            while let Some(result) = tasks.join_next().await {
                match result {
                    Ok(Ok(())) => (),
                    Err(error) if error.is_cancelled() => cancelled += 1,
                    error => { failed += 1; eprintln!("connection: {error:?}"); }
                }
            }
            Ok::<_, io::Error>((cancelled, failed))
        })?;
        // A cancelled DNS lookup may still occupy a blocking worker. Do not let
        // that worker extend the process lifetime past stdin EOF or the timer.
        runtime.shutdown_background();
        let (user_cpu_seconds, kernel_cpu_seconds) = cpu_times()?;
        let summary = Summary {
            user_cpu_seconds, kernel_cpu_seconds,
            bytes_up: counts.up.load(Ordering::Relaxed),
            bytes_down: counts.down.load(Ordering::Relaxed),
            tunnels: counts.tunnels.load(Ordering::Relaxed),
            cancelled_connections, failed_connections,
            rejected_connections: counts.rejected.load(Ordering::Relaxed),
        };
        println!("{}", serde_json::to_string(&summary)?);
        Ok(())
    }
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> { proxy::run() }

#[cfg(not(windows))]
fn main() { eprintln!("Windows only"); }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_parser_requires_loopback_authority_and_http11() {
        let peer = "127.0.0.1:1234".parse().unwrap();
        assert_eq!(parse_connect("CONNECT example.com:443 HTTP/1.1", peer), Some(("example.com".into(), 443)));
        assert_eq!(parse_connect("CONNECT [::1]:443 HTTP/1.1", peer), Some(("::1".into(), 443)));
        for line in ["GET example.com:443 HTTP/1.1", "CONNECT example.com HTTP/1.1", "CONNECT example.com:0 HTTP/1.1", "CONNECT example.com:65536 HTTP/1.1", "CONNECT example.com:443 HTTP/1.0", "CONNECT user@example.com:443 HTTP/1.1"] {
            assert!(parse_connect(line, peer).is_none(), "{line}");
        }
        let long = format!("CONNECT {}:443 HTTP/1.1", "a".repeat(sieve_engine::flow::http::MAX_HEAD));
        assert!(parse_connect(&long, peer).is_none());
        assert!(parse_connect("CONNECT example.com:443 HTTP/1.1", "192.0.2.1:1234".parse().unwrap()).is_none());
    }

    #[test]
    fn final_json_has_separate_cpu_times_and_payload_counters() {
        let summary = Summary { user_cpu_seconds: 0.25, kernel_cpu_seconds: 0.5, bytes_up: 17, bytes_down: 31, tunnels: 1, cancelled_connections: 0, failed_connections: 0, rejected_connections: 0 };
        let line = serde_json::to_string(&summary).unwrap();
        assert!(!line.contains('\n'));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&line).unwrap(), serde_json::json!({
            "user_cpu_seconds": 0.25, "kernel_cpu_seconds": 0.5,
            "bytes_up": 17, "bytes_down": 31, "tunnels": 1,
            "cancelled_connections": 0, "failed_connections": 0, "rejected_connections": 0
        }));
    }
}
