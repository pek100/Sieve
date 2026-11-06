//! The real list download: one HTTPS/1.1 GET over a socket pinned off Sieve's
//! adapter (`Relay::connect`), validated by rustls on aws-lc-rs with
//! X25519MLKEM768 preferred. Redirects are refused, not followed (S24): a
//! catalogue URL is what the user's lists come from, and a redirect shows up
//! as a recorded failure. The name is looked up through Windows like any app's
//! lookup, so it follows the DNS the engine relays.

use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::header::{ACCEPT_ENCODING, CONTENT_TYPE, ETAG, HOST, HeaderMap, HeaderName, LAST_MODIFIED, USER_AGENT};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use sieve_filter::lists::{FetchResponse, MAX_LIST_BYTES};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use url::Url;

use super::Fetcher;
use crate::stack::relay::Relay;

const HTTPS_PORT: u16 = 443;
const AGENT: &str = concat!("Sieve/", env!("CARGO_PKG_VERSION"));
const NO_COMPRESSION: &str = "identity";
const ALPN_HTTP1: &[u8] = b"http/1.1";

/// The engine's TLS client: post-quantum key exchange first, the Mozilla root
/// set. Not the Windows store: the engine's own downloads must not trust
/// whatever a local filter (AdGuard's or anyone's root) put there.
pub fn client_config() -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_HTTP1.to_vec()];
    Ok(config)
}

#[derive(Debug, PartialEq, Eq)]
struct Target {
    host: String,
    path: String,
}

/// Only an https URL with a host is ever fetched.
fn parse_target(url: &str) -> Result<Target, String> {
    let parsed = Url::parse(url).map_err(|e| format!("{url}: {e}"))?;
    if parsed.scheme() != "https" {
        return Err(format!("{url}: only https is fetched"));
    }
    let host = parsed.host_str().ok_or_else(|| format!("{url}: no host"))?.to_string();
    let path = match parsed.query() {
        Some(q) => format!("{}?{q}", parsed.path()),
        None => parsed.path().to_string(),
    };
    Ok(Target { host, path })
}

fn header(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

/// One GET over `stream`, generic so it runs in memory in tests. The body is
/// read up to [`MAX_LIST_BYTES`]; past it the download stops at once.
async fn get_over<S>(stream: S, target: &Target, conditional: Vec<(&'static str, String)>) -> Result<FetchResponse, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|e| format!("HTTP: {e}"))?;
    let driver = tokio::spawn(connection);
    let mut request = hyper::Request::get(&target.path).header(HOST, &target.host).header(USER_AGENT, AGENT).header(ACCEPT_ENCODING, NO_COMPRESSION);
    for (name, value) in conditional {
        request = request.header(name, value);
    }
    let request = request.body(Empty::<Bytes>::new()).map_err(|e| format!("request: {e}"))?;
    let result = async {
        let response = sender.send_request(request).await.map_err(|e| format!("HTTP: {e}"))?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame.map_err(|e| format!("body: {e}"))?.into_data() {
                if bytes.len() + data.len() > MAX_LIST_BYTES {
                    return Err(format!("the body is over the {MAX_LIST_BYTES} byte limit"));
                }
                bytes.extend_from_slice(&data);
            }
        }
        Ok(FetchResponse {
            status,
            etag: header(&headers, ETAG),
            last_modified: header(&headers, LAST_MODIFIED),
            content_type: header(&headers, CONTENT_TYPE),
            body: bytes,
        })
    }
    .await;
    driver.abort();
    result
}

/// The fetcher of a routing engine: its sockets come from the relay, pinned
/// to the physical interface and never through the engine's adapter.
pub struct HttpsFetcher {
    relay: Arc<Relay>,
}

impl HttpsFetcher {
    pub fn new(relay: Arc<Relay>) -> Self {
        Self { relay }
    }

    async fn connect(&self, host: &str) -> Result<tokio::net::TcpStream, String> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, HTTPS_PORT)).await.map_err(|e| format!("lookup {host}: {e}"))?.collect();
        let mut last = format!("lookup {host}: no address");
        for addr in addrs {
            match self.relay.connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(why) => last = why,
            }
        }
        Err(last)
    }
}

impl Fetcher for HttpsFetcher {
    async fn fetch(&self, url: &str, headers: Vec<(&'static str, String)>) -> Result<FetchResponse, String> {
        let target = parse_target(url)?;
        let name = ServerName::try_from(target.host.clone()).map_err(|e| format!("{}: {e}", target.host))?;
        let tcp = self.connect(&target.host).await?;
        let tls = TlsConnector::from(Arc::new(client_config()?)).connect(name, tcp).await.map_err(|e| format!("TLS {}: {e}", target.host))?;
        get_over(tls, &target, headers).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::NamedGroup;
    use sieve_filter::catalogue::LISTS;
    use sieve_filter::lists::{Applied, FetchState};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    const PIPE_BYTES: usize = 1 << 20;
    const RULE: &str = "||ads.example^\n";

    fn target() -> Target {
        Target { host: "lists.example".into(), path: "/f.txt".into() }
    }

    async fn read_head(server: &mut DuplexStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if server.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            head.push(byte[0]);
        }
        String::from_utf8(head).unwrap()
    }

    /// A server that answers one request with `reply`, returning what it read.
    fn serve(reply: Vec<u8>) -> (DuplexStream, tokio::task::JoinHandle<String>) {
        let (client, mut server) = tokio::io::duplex(PIPE_BYTES);
        let task = tokio::spawn(async move {
            let head = read_head(&mut server).await;
            let _ = server.write_all(&reply).await;
            let _ = server.shutdown().await;
            head
        });
        (client, task)
    }

    #[tokio::test]
    async fn https_fetcher_reads_chunked_and_caps_size() {
        let reply = format!(
            "HTTP/1.1 200 OK\r\nETag: \"v9\"\r\nLast-Modified: then\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{RULE}\r\n0\r\n\r\n",
            RULE.len()
        );
        let (client, server) = serve(reply.into_bytes());
        let got = get_over(client, &target(), vec![("If-None-Match", "\"v8\"".to_string())]).await.unwrap();
        assert_eq!((got.status, got.etag.as_deref(), got.last_modified.as_deref()), (200, Some("\"v9\""), Some("then")));
        assert_eq!(got.content_type.as_deref(), Some("text/plain"));
        assert_eq!(got.body, RULE.as_bytes());
        let head = server.await.unwrap().to_ascii_lowercase();
        assert!(head.starts_with("get /f.txt http/1.1\r\n"), "{head}");
        assert!(head.contains("host: lists.example\r\n") && head.contains("if-none-match: \"v8\"\r\n"), "{head}");
        assert!(head.contains("accept-encoding: identity\r\n"), "{head}");

        // A body past the cap, chunked so no Content-Length warned of it.
        let (client, mut server) = tokio::io::duplex(PIPE_BYTES);
        let serving = tokio::spawn(async move {
            read_head(&mut server).await;
            server.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
            let chunk = vec![b'a'; 1 << 20];
            let mut sent = 0;
            while sent <= MAX_LIST_BYTES {
                let framed = [format!("{:x}\r\n", chunk.len()).as_bytes(), &chunk, b"\r\n"].concat();
                if server.write_all(&framed).await.is_err() {
                    return;
                }
                sent += chunk.len();
            }
        });
        let why = get_over(client, &target(), vec![]).await.unwrap_err();
        assert!(why.contains("limit"), "{why}");
        serving.abort();
    }

    #[tokio::test]
    async fn https_fetcher_refuses_a_redirect_and_plain_http() {
        assert!(parse_target("http://lists.example/f.txt").unwrap_err().contains("only https"));
        assert!(parse_target("ftp://lists.example/f.txt").is_err());
        assert!(parse_target("not a url").is_err());
        assert_eq!(parse_target("https://lists.example/a/f.txt?v=1").unwrap(), Target { host: "lists.example".into(), path: "/a/f.txt?v=1".into() });

        let reply = b"HTTP/1.1 302 Found\r\nLocation: http://portal.example/\r\nContent-Length: 0\r\n\r\n".to_vec();
        let (client, server) = serve(reply);
        let got = get_over(client, &target(), vec![]).await.unwrap();
        assert_eq!(got.status, 302, "reported, never followed");
        server.await.unwrap();
        let mut state = FetchState::default();
        assert_eq!(state.apply(got, 0), Applied::Refused);
        assert_eq!(state.last_error.as_deref(), Some("HTTP 302"));
    }

    #[test]
    fn tls_config_prefers_x25519mlkem768() {
        let config = client_config().unwrap();
        assert_eq!(config.crypto_provider().kx_groups[0].name(), NamedGroup::X25519MLKEM768);
        assert_eq!(config.alpn_protocols, [ALPN_HTTP1.to_vec()], "the fetcher speaks HTTP/1.1 only");
    }

    #[test]
    fn every_catalogue_url_is_one_the_fetcher_takes() {
        for list in LISTS {
            assert!(parse_target(list.url).is_ok(), "{}", list.id);
        }
    }
}
