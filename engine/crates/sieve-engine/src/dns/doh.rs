//! DNS over HTTPS (RFC 8484) on HTTP/2: POST with `application/dns-message`
//! and wire ID 0. A server that does not negotiate `h2`, answers other than
//! 200, or labels its answer differently is a failed upstream.

use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::client::conn::http2::{self, SendRequest};
use hyper::header::{ACCEPT, CONTENT_TYPE};
use hyper::{Request, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use super::pool::{Fail, TlsFacts};
use super::{Connector, MAX_MESSAGE, Owned, id_of, with_id};

pub const ALPN: &[u8] = b"h2";
const MESSAGE_TYPE: &str = "application/dns-message";
/// RFC 8484 4.1: the wire ID is 0, for HTTP caches.
const WIRE_ID: u16 = 0;

pub struct Session {
    send: SendRequest<Full<Bytes>>,
    uri: Uri,
    _driver: Owned,
}

pub async fn connect(connector: &dyn Connector, addr: SocketAddr, name: ServerName<'static>, uri: Uri, config: Arc<ClientConfig>) -> Result<(Session, TlsFacts), String> {
    let tcp = connector.tcp(addr).await?;
    tcp.set_nodelay(true).map_err(|e| format!("nodelay: {e}"))?;
    let tls = TlsConnector::from(config).connect(name, tcp).await.map_err(|e| format!("TLS to {addr}: {e}"))?;
    let facts = TlsFacts::of(tls.get_ref().1);
    if tls.get_ref().1.alpn_protocol() != Some(ALPN) {
        return Err(format!("{addr} did not negotiate HTTP/2"));
    }
    let (send, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls)).await.map_err(|e| format!("HTTP/2 to {addr}: {e}"))?;
    let driver = Owned::spawn(async move {
        let _ = connection.await;
    });
    Ok((Session { send, uri, _driver: driver }, facts))
}

impl Session {
    pub fn alive(&self) -> bool {
        !self.send.is_closed()
    }

    pub async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, Fail> {
        let client_id = id_of(query).ok_or_else(|| Fail::Reply("a query without an ID".into()))?;
        let request = Request::post(self.uri.clone())
            .header(CONTENT_TYPE, MESSAGE_TYPE)
            .header(ACCEPT, MESSAGE_TYPE)
            .body(Full::new(Bytes::from(with_id(query, WIRE_ID))))
            .map_err(|e| Fail::Reply(format!("request: {e}")))?;
        let mut send = self.send.clone();
        send.ready().await.map_err(|e| Fail::Link(format!("HTTP/2: {e}")))?;
        let response = send.send_request(request).await.map_err(|e| Fail::Link(format!("HTTP/2: {e}")))?;
        if response.status() != StatusCode::OK {
            return Err(Fail::Reply(format!("HTTP status {}", response.status())));
        }
        let labelled = response.headers().get(CONTENT_TYPE).is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(MESSAGE_TYPE.as_bytes()));
        if !labelled {
            return Err(Fail::Reply("the answer is not application/dns-message".into()));
        }
        let body = Limited::new(response.into_body(), MAX_MESSAGE).collect().await.map_err(|e| Fail::Reply(format!("the answer's body: {e}")))?.to_bytes();
        if id_of(&body) != Some(WIRE_ID) {
            return Err(Fail::Reply("the answer's ID is not 0".into()));
        }
        Ok(with_id(&body, client_id))
    }
}
