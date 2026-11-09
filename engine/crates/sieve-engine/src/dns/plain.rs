//! The one plain exchange in the engine, on two paths only (`upstream::Path`):
//! a name under an adapter's own suffix or a private reverse name, to a private
//! server excluded from routing, so that never leaves the LAN; and, only when the
//! user turned DNS encryption off, any other name to the server the client
//! addressed, the one Windows uses without Sieve.

use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{Connector, MAX_MESSAGE, is_truncated, reply_fits};
use crate::stack::DNS_PORT;

/// UDP first; a truncated answer retries over TCP. The caller's deadline bounds
/// the wait. Datagrams that do not fit the query are ignored, not failures.
/// `may_send` is asked before each send, the UDP one and the TCP retry: false
/// sends nothing more and fails the exchange (the user turned encryption back
/// on while the query was in flight).
pub async fn exchange(connector: &dyn Connector, server: IpAddr, query: &[u8], may_send: impl Fn() -> bool) -> Result<Vec<u8>, String> {
    let target = SocketAddr::new(server, DNS_PORT);
    let refused = || format!("{server}: plain DNS is off now");
    if !may_send() {
        return Err(refused());
    }
    let socket = crate::stack::datagram_socket(connector.udp(target)?).map_err(|e| format!("socket: {e}"))?;
    socket.connect(connector.address(target)).await.map_err(|e| format!("connect {server}: {e}"))?;
    socket.send(query).await.map_err(|e| format!("send to {server}: {e}"))?;
    let mut buffer = vec![0u8; MAX_MESSAGE];
    loop {
        let n = socket.recv(&mut buffer).await.map_err(|e| format!("receive from {server}: {e}"))?;
        let reply = &buffer[..n];
        if !reply_fits(query, reply) {
            continue;
        }
        if !is_truncated(reply) {
            return Ok(reply.to_vec());
        }
        if !may_send() {
            return Err(refused());
        }
        return over_tcp(connector, target, query).await;
    }
}

/// Over TCP from the start, for a message the client itself sent over TCP and
/// that must reach the server as it was (a key negotiation too large for a
/// datagram, or a signed message).
pub async fn exchange_over_tcp(connector: &dyn Connector, server: IpAddr, query: &[u8]) -> Result<Vec<u8>, String> {
    over_tcp(connector, SocketAddr::new(server, DNS_PORT), query).await
}

async fn over_tcp(connector: &dyn Connector, target: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
    let len = u16::try_from(query.len()).map_err(|_| "a query over the size limit")?;
    let mut stream = connector.tcp(target).await?;
    let mut frame = Vec::with_capacity(query.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(query);
    stream.write_all(&frame).await.map_err(|e| format!("send to {target}: {e}"))?;
    let size = stream.read_u16().await.map_err(|e| format!("receive from {target}: {e}"))?;
    let mut reply = vec![0u8; usize::from(size)];
    stream.read_exact(&mut reply).await.map_err(|e| format!("receive from {target}: {e}"))?;
    if reply_fits(query, &reply) { Ok(reply) } else { Err(format!("{target} answered another question")) }
}
