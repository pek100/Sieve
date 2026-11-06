//! The real fetch: rustls on aws-lc-rs with `webpki-roots` (plan 2.7) over a
//! pinned socket, HTTP/1.1, `Connection: close`, one status check, a
//! `Content-Length` or a close-delimited body, no chunked encoding, no
//! redirects. hyper does not earn a place for one GET. Its own sockets must
//! bypass the TUN, or the loop guard refuses them.
//!
//! This layer only moves bytes: everything it returns is still checked against
//! its signature, so a compromised host gets no further than serving a file.

use std::io::Write;
use std::sync::Arc;

use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::fetch::FetchError;

/// A response head larger than this is not one this client talks to.
const MAX_HEAD_BYTES: usize = 16 * 1024;
const READ_CHUNK: usize = 64 * 1024;
const STATUS_OK: u16 = 200;
const STATUS_NOT_FOUND: u16 = 404;
const REDIRECTS: std::ops::Range<u16> = 300..400;

fn network(what: impl std::fmt::Display) -> FetchError {
    FetchError::Network(what.to_string())
}

/// The parts of a response head this client acts on.
#[derive(Debug, PartialEq, Eq)]
struct Head {
    status: u16,
    length: Option<u64>,
}

fn parse_head(head: &str) -> Result<Head, FetchError> {
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split(' ');
    let version = parts.next().unwrap_or_default();
    let status = parts.next().and_then(|s| s.parse().ok()).filter(|_| version.starts_with("HTTP/1."));
    let status = status.ok_or_else(|| network(format!("not an HTTP response: {status_line}")))?;
    let mut length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(value.parse().map_err(|_| network(format!("bad Content-Length: {value}")))?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(network(format!("Transfer-Encoding not supported: {value}")));
        }
    }
    Ok(Head { status, length })
}

/// One GET over any stream. The body goes to `out`, cut at `max_bytes`.
pub async fn http_get<S, W>(stream: &mut S, host: &str, path: &str, file: &str, max_bytes: u64, out: &mut W) -> Result<(), FetchError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    W: Write,
{
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: sieve-engine\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.map_err(network)?;
    stream.flush().await.map_err(network)?;

    let mut buffer = vec![0u8; READ_CHUNK];
    let mut read = Vec::new();
    let (head, rest) = loop {
        if let Some(end) = read.windows(4).position(|w| w == b"\r\n\r\n") {
            break (String::from_utf8_lossy(&read[..end]).into_owned(), read[end + 4..].to_vec());
        }
        if read.len() > MAX_HEAD_BYTES {
            return Err(network("the response head is too long"));
        }
        let n = stream.read(&mut buffer).await.map_err(network)?;
        if n == 0 {
            return Err(network("the connection closed before a response"));
        }
        read.extend_from_slice(&buffer[..n]);
    };
    let head = parse_head(&head)?;
    if REDIRECTS.contains(&head.status) {
        return Err(network(format!("the host redirected {file} (status {}); redirects are not followed", head.status)));
    }
    if head.status == STATUS_NOT_FOUND {
        return Err(FetchError::NotFound(file.to_string()));
    }
    if head.status != STATUS_OK {
        return Err(network(format!("status {} for {file}", head.status)));
    }
    if head.length.is_some_and(|n| n > max_bytes) {
        return Err(FetchError::OverCap(file.to_string()));
    }

    let mut written = 0u64;
    let mut chunk = rest;
    loop {
        written += chunk.len() as u64;
        if written > max_bytes {
            return Err(FetchError::OverCap(file.to_string()));
        }
        out.write_all(&chunk).map_err(network)?;
        if head.length == Some(written) {
            return Ok(());
        }
        let n = match stream.read(&mut buffer).await {
            Ok(n) => n,
            // A peer that drops without TLS close_notify, on a close-delimited
            // body: the size and signature checks decide about what arrived.
            Err(e) if head.length.is_none() && e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(network(e)),
        };
        if n == 0 {
            return match head.length {
                Some(want) => Err(network(format!("{file} ended after {written} of {want} bytes"))),
                None => Ok(()),
            };
        }
        chunk = buffer[..n].to_vec();
    }
}

/// A client that trusts exactly these roots.
pub fn client_config(roots: rustls::RootCertStore) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The update client's trust store (plan 2.7), never the Windows store.
pub fn web_roots() -> rustls::RootCertStore {
    rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }
}

/// One GET through TLS over any stream.
pub async fn tls_get<S, W>(
    config: Arc<ClientConfig>,
    stream: S,
    host: &str,
    path: &str,
    file: &str,
    max_bytes: u64,
    out: &mut W,
) -> Result<(), FetchError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    W: Write,
{
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(network)?;
    let mut tls = tokio_rustls::TlsConnector::from(config).connect(name, stream).await.map_err(network)?;
    http_get(&mut tls, host, path, file, max_bytes, out).await
}

#[cfg(windows)]
pub use real::HttpsFetcher;

#[cfg(windows)]
mod real {
    use std::net::SocketAddr;
    use std::path::Path;
    use std::time::Duration;

    use tokio::net::{TcpSocket, TcpStream};
    use url::Url;

    use super::super::fetch::{FetchError, Fetcher};
    use super::*;
    use crate::route::pin;
    use crate::route::table::read as os;

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
    /// A whole transfer: installers are tens of MB on a slow link at worst.
    const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30 * 60);
    const DEFAULT_TLS_PORT: u16 = 443;

    /// Fetches by bare name from the one compiled host.
    pub struct HttpsFetcher {
        base: Url,
        config: Arc<ClientConfig>,
        runtime: tokio::runtime::Runtime,
    }

    impl HttpsFetcher {
        pub fn new(base_url: &str) -> Result<Self, String> {
            let base = Url::parse(base_url).map_err(|e| format!("{base_url}: {e}"))?;
            if base.scheme() != "https" {
                return Err(format!("{base_url}: updates are fetched over https only"));
            }
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
            Ok(Self { base, config: client_config(web_roots())?, runtime })
        }

        /// Pinned to the interface Windows would choose with Sieve's routes
        /// ignored, read fresh per connection.
        async fn connect(&self, host: &str, port: u16) -> Result<TcpStream, String> {
            let tables = os::tables()?;
            let mut last = format!("{host} did not resolve");
            for target in tokio::net::lookup_host((host, port)).await.map_err(|e| format!("{host}: {e}"))? {
                match connect_pinned(&tables, target).await {
                    Ok(stream) => return Ok(stream),
                    Err(why) => last = why,
                }
            }
            Err(last)
        }

        async fn get_async(&self, file: &str, max_bytes: u64, dest: &Path) -> Result<(), FetchError> {
            let host = self.base.host_str().ok_or_else(|| network("no host in the update URL"))?;
            let port = self.base.port().unwrap_or(DEFAULT_TLS_PORT);
            let url = self.base.join(file).map_err(network)?;
            let stream = self.connect(host, port).await.map_err(network)?;
            let mut out = std::fs::File::create(dest).map_err(network)?;
            tls_get(self.config.clone(), stream, host, url.path(), file, max_bytes, &mut out).await
        }
    }

    async fn connect_pinned(tables: &crate::route::table::NetTables, target: SocketAddr) -> Result<TcpStream, String> {
        let egress = pin::egress(tables, None, target.ip()).map_err(|e| e.to_string())?;
        let socket = TcpSocket::from_std_stream(pin::egress_socket(egress, target, false)?.into());
        match tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(target)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(format!("connect {target}: {e}")),
            Err(_) => Err(format!("connect {target}: timeout")),
        }
    }

    impl Fetcher for HttpsFetcher {
        fn get(&self, file: &str, max_bytes: u64, dest: &Path) -> Result<(), FetchError> {
            self.runtime.block_on(async {
                match tokio::time::timeout(TRANSFER_TIMEOUT, self.get_async(file, max_bytes, dest)).await {
                    Ok(done) => done,
                    Err(_) => Err(network(format!("{file}: the transfer timed out"))),
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    const CAP: u64 = 100;

    /// A host that answers one request with `response`, then closes.
    async fn serve_once(response: Vec<u8>) -> (Result<(), FetchError>, Vec<u8>, String) {
        let (mut client, mut server) = duplex(1 << 16);
        let host = tokio::spawn(async move {
            let mut seen = vec![0u8; 4096];
            let n = server.read(&mut seen).await.unwrap();
            server.write_all(&response).await.unwrap();
            server.shutdown().await.unwrap();
            String::from_utf8_lossy(&seen[..n]).into_owned()
        });
        let mut body = Vec::new();
        let result = http_get(&mut client, "updates.example", "/index.json", "index.json", CAP, &mut body).await;
        drop(client);
        (result, body, host.await.unwrap())
    }

    #[tokio::test]
    async fn a_200_body_is_written_and_capped() {
        let (result, body, request) = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec()).await;
        result.unwrap();
        assert_eq!(body, b"hello");
        assert!(request.starts_with("GET /index.json HTTP/1.1\r\nHost: updates.example\r\n"), "{request}");
        assert!(request.contains("Connection: close\r\n"), "{request}");

        let (result, body, _) = serve_once(b"HTTP/1.1 200 OK\r\n\r\nclose delimited".to_vec()).await;
        result.unwrap();
        assert_eq!(body, b"close delimited");

        let over = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", CAP + 1);
        let (result, body, _) = serve_once(over.into_bytes()).await;
        assert_eq!(result, Err(FetchError::OverCap("index.json".into())));
        assert!(body.is_empty(), "a declared overrun reads nothing");

        let mut lying = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        lying.extend(vec![b'x'; CAP as usize + 1]);
        let (result, body, _) = serve_once(lying).await;
        assert_eq!(result, Err(FetchError::OverCap("index.json".into())));
        assert!(body.len() as u64 <= CAP, "cut at the cap");
    }

    #[tokio::test]
    async fn a_redirect_is_refused() {
        for status in ["301 Moved", "302 Found", "307 Temporary Redirect"] {
            let response = format!("HTTP/1.1 {status}\r\nLocation: https://elsewhere.example/x\r\n\r\n");
            let (result, body, _) = serve_once(response.into_bytes()).await;
            assert!(matches!(&result, Err(FetchError::Network(m)) if m.contains("redirect")), "{result:?}");
            assert!(body.is_empty());
        }
    }

    #[tokio::test]
    async fn a_non_200_is_refused() {
        let (result, ..) = serve_once(b"HTTP/1.1 500 Oops\r\n\r\nno".to_vec()).await;
        assert!(matches!(result, Err(FetchError::Network(_))));
        let (result, ..) = serve_once(b"HTTP/1.1 404 Not Found\r\n\r\n".to_vec()).await;
        assert_eq!(result, Err(FetchError::NotFound("index.json".into())));
        let (result, ..) = serve_once(b"SSH-2.0-nope\r\n\r\n".to_vec()).await;
        assert!(matches!(result, Err(FetchError::Network(_))));
        let (result, ..) = serve_once(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec()).await;
        assert!(matches!(&result, Err(FetchError::Network(m)) if m.contains("Transfer-Encoding")), "{result:?}");
    }

    #[tokio::test]
    async fn a_short_body_is_refused() {
        let (result, ..) = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort".to_vec()).await;
        assert!(matches!(&result, Err(FetchError::Network(m)) if m.contains("ended after 5 of 50")), "{result:?}");
        let (result, ..) = serve_once(b"HTTP/1.1 200 OK\r\n".to_vec()).await;
        assert!(matches!(result, Err(FetchError::Network(_))), "no head at all");
    }

    /// In memory: rustls itself refuses a chain to a root the client does not
    /// hold, and accepts the same server with that root (the control). The real
    /// chain to a real host stays UNVERIFIED.
    #[tokio::test]
    async fn tls_refuses_an_untrusted_root() {
        use rcgen::{CertificateParams, CertifiedIssuer, KeyPair};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        const HOST: &str = "updates.example";
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec![HOST.to_string()]).unwrap().signed_by(&leaf_key, &ca).unwrap();

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![leaf.der().clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())))
                .unwrap(),
        );

        let attempt = |roots: rustls::RootCertStore| {
            let server = server.clone();
            async move {
                let (client_end, server_end) = duplex(1 << 16);
                let host = tokio::spawn(async move {
                    let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(server).accept(server_end).await else { return };
                    let mut seen = [0u8; 2048];
                    let _ = tls.read(&mut seen).await;
                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
                    let _ = tls.shutdown().await;
                });
                let mut body = Vec::new();
                let out = tls_get(client_config(roots).unwrap(), client_end, HOST, "/f", "f", CAP, &mut body).await;
                host.await.unwrap();
                (out, body)
            }
        };

        let (refused, body) = attempt(web_roots()).await;
        assert!(matches!(&refused, Err(FetchError::Network(m)) if m.to_lowercase().contains("certificate")), "{refused:?}");
        assert!(body.is_empty());

        let mut own = rustls::RootCertStore::empty();
        own.add(ca.der().clone()).unwrap();
        let (accepted, body) = attempt(own).await;
        accepted.unwrap();
        assert_eq!(body, b"ok", "control: the same server with its root trusted");
    }

    #[test]
    fn the_trust_store_is_not_empty() {
        assert!(web_roots().len() > 50);
    }
}
