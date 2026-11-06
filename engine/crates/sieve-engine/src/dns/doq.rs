//! DNS over QUIC (RFC 9250): one connection, one bidirectional stream per
//! query with 2-byte framing, wire ID 0. A reply with another ID is a failure
//! (RFC 9250 4.2.1). quinn exposes no negotiated key exchange group, so the
//! session reports none (a test proves the group is offered).

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{HandshakeData, QuicClientConfig};
use quinn::{ClientConfig, Connection, Endpoint, EndpointConfig, TokioRuntime};

use super::pool::{Fail, TlsFacts};
use super::{Connector, MAX_MESSAGE, id_of, with_id};

pub const ALPN: &[u8] = b"doq";
const WIRE_ID: u16 = 0;
/// A framed reply: the 2-byte length and the message.
const MAX_FRAMED: usize = MAX_MESSAGE + 2;

/// The QUIC form of a rustls client configuration.
pub fn quic_config(tls: rustls::ClientConfig) -> Result<ClientConfig, String> {
    let quic = QuicClientConfig::try_from(tls).map_err(|e| format!("QUIC TLS: {e}"))?;
    Ok(ClientConfig::new(Arc::new(quic)))
}

pub struct Session {
    connection: Connection,
    /// The socket's owner; the connection cannot move packets without it.
    _endpoint: Endpoint,
}

pub async fn connect(connector: &dyn Connector, addr: SocketAddr, name: &str, config: ClientConfig) -> Result<(Session, TlsFacts), String> {
    let socket = connector.udp(addr)?;
    let endpoint = Endpoint::new(EndpointConfig::default(), None, socket.into(), Arc::new(TokioRuntime)).map_err(|e| format!("QUIC endpoint: {e}"))?;
    let connecting = endpoint.connect_with(config, connector.address(addr), name).map_err(|e| format!("QUIC to {addr}: {e}"))?;
    let connection = connecting.await.map_err(|e| format!("QUIC to {addr}: {e}"))?;
    let alpn = connection.handshake_data().and_then(|d| d.downcast::<HandshakeData>().ok()).and_then(|d| d.protocol);
    let facts = TlsFacts { kx_group: None, alpn: alpn.map(|p| String::from_utf8_lossy(&p).into_owned()) };
    Ok((Session { connection, _endpoint: endpoint }, facts))
}

impl Session {
    pub fn alive(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    pub async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, Fail> {
        let client_id = id_of(query).ok_or_else(|| Fail::Reply("a query without an ID".into()))?;
        let len = u16::try_from(query.len()).map_err(|_| Fail::Reply("a query over the size limit".into()))?;
        let (mut send, mut recv) = self.connection.open_bi().await.map_err(|e| Fail::Link(format!("QUIC: {e}")))?;
        let mut frame = Vec::with_capacity(query.len() + 2);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&with_id(query, WIRE_ID));
        send.write_all(&frame).await.map_err(|e| Fail::Link(format!("QUIC: {e}")))?;
        send.finish().map_err(|e| Fail::Link(format!("QUIC: {e}")))?;
        let framed = recv.read_to_end(MAX_FRAMED).await.map_err(|e| match e {
            quinn::ReadToEndError::TooLong => Fail::Reply("the answer is over the size limit".into()),
            other => Fail::Link(format!("QUIC: {other}")),
        })?;
        let body = framed.get(2..).filter(|b| u16::from_be_bytes([framed[0], framed[1]]) as usize == b.len());
        let body = body.ok_or_else(|| Fail::Reply("the answer's framing is wrong".into()))?;
        if id_of(body) != Some(WIRE_ID) {
            return Err(Fail::Reply("the answer's ID is not 0".into()));
        }
        Ok(with_id(body, client_id))
    }
}
