//! The device's local proxy: SOCKS5 (no authentication, CONNECT only) and
//! HTTP CONNECT on one loopback port, told apart by the first byte. Any
//! program that can use a proxy uses the link with no code change. Names are
//! passed to the hub unresolved (SOCKS5 domain addresses, CONNECT authority).
//!
//! It binds loopback only: other machines on the device's network must not
//! be able to send traffic out through the hub.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::device::{LinkClient, LinkStream};
use crate::error::{LinkError, Result};
use crate::wire::{Status, valid_host};

const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);
const MAX_HEAD: usize = 8 * 1024;
const MAX_CLIENTS: usize = 512;

/// Binds the proxy port. Refuses any address that is not loopback.
pub async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    if !addr.ip().is_loopback() {
        return Err(LinkError::Store(format!("the local proxy binds loopback only, not {addr}")));
    }
    Ok(TcpListener::bind(addr).await?)
}

/// Serves proxy clients until `stop` fires.
pub async fn serve(listener: TcpListener, client: LinkClient, stop: CancellationToken) {
    let slots = Arc::new(Semaphore::new(MAX_CLIENTS));
    loop {
        let r = tokio::select! {
            _ = stop.cancelled() => return,
            r = listener.accept() => r,
        };
        let Ok((tcp, _)) = r else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
        let client = client.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let _ = handle(tcp, client, stop).await;
            drop(permit);
        });
    }
}

async fn handle(mut tcp: TcpStream, client: LinkClient, stop: CancellationToken) -> Result<()> {
    let _ = tcp.set_nodelay(true);
    let mut first = [0u8; 1];
    tokio::time::timeout(HANDSHAKE_LIMIT, tcp.read_exact(&mut first)).await.map_err(|_| LinkError::Timeout("proxy"))??;
    let (upstream, leftover) = if first[0] == 0x05 {
        (socks5(&mut tcp, &client).await?, Vec::new())
    } else {
        http_connect(&mut tcp, first[0], &client).await?
    };
    let mut upstream = upstream;
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await?;
    }
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut tcp, &mut upstream) => {}
        _ = stop.cancelled() => {}
    }
    Ok(())
}

fn socks_reply_code(e: &LinkError) -> u8 {
    match e {
        LinkError::Refused { status: Status::Denied, .. } => 0x02,
        LinkError::Refused { status: Status::Unreachable, .. } => 0x04,
        _ => 0x01,
    }
}

async fn socks5(tcp: &mut TcpStream, client: &LinkClient) -> Result<LinkStream> {
    let (host, port) = tokio::time::timeout(HANDSHAKE_LIMIT, socks5_request(tcp)).await.map_err(|_| LinkError::Timeout("socks5"))??;
    match client.open(&host, port).await {
        Ok(s) => {
            tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            Ok(s)
        }
        Err(e) => {
            let _ = tcp.write_all(&[0x05, socks_reply_code(&e), 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            Err(e)
        }
    }
}

/// Reads the method negotiation and the request (after the version byte).
async fn socks5_request<S: AsyncRead + AsyncWrite + Unpin>(tcp: &mut S) -> Result<(String, u16)> {
    let n = tcp.read_u8().await? as usize;
    let mut methods = [0u8; 255];
    tcp.read_exact(&mut methods[..n]).await?;
    if !methods[..n].contains(&0x00) {
        tcp.write_all(&[0x05, 0xff]).await?;
        return Err(LinkError::Protocol("socks5: no acceptable method".into()));
    }
    tcp.write_all(&[0x05, 0x00]).await?;
    let mut head = [0u8; 4];
    tcp.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(LinkError::Protocol("socks5: bad version".into()));
    }
    if head[1] != 0x01 {
        tcp.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(LinkError::Protocol("socks5: only CONNECT".into()));
    }
    let host = match head[3] {
        0x01 => {
            let mut a = [0u8; 4];
            tcp.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        0x03 => {
            let len = tcp.read_u8().await? as usize;
            let mut a = vec![0u8; len];
            tcp.read_exact(&mut a).await?;
            String::from_utf8(a).map_err(|_| LinkError::Protocol("socks5: name".into()))?
        }
        0x04 => {
            let mut a = [0u8; 16];
            tcp.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        _ => {
            tcp.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(LinkError::Protocol("socks5: address type".into()));
        }
    };
    let port = tcp.read_u16().await?;
    if !valid_host(&host) || port == 0 {
        tcp.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(LinkError::Protocol("socks5: bad target".into()));
    }
    Ok((host, port))
}

/// Parses `host:port` or `[v6]:port`.
pub fn split_authority(s: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        (h, p)
    } else {
        s.rsplit_once(':')?
    };
    let port: u16 = port.parse().ok()?;
    (valid_host(host) && port != 0).then(|| (host.to_string(), port))
}

async fn http_connect(tcp: &mut TcpStream, first: u8, client: &LinkClient) -> Result<(LinkStream, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    buf.push(first);
    let end = tokio::time::timeout(HANDSHAKE_LIMIT, async {
        let mut chunk = [0u8; 1024];
        loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return Ok(i + 4);
            }
            if buf.len() > MAX_HEAD {
                return Err(LinkError::Protocol("http: head too large".into()));
            }
            let n = tcp.read(&mut chunk).await?;
            if n == 0 {
                return Err(LinkError::Protocol("http: closed".into()));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .map_err(|_| LinkError::Timeout("http"))??;
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    let leftover = buf[end..].to_vec();
    let line = head.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let (method, authority) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if !method.eq_ignore_ascii_case("CONNECT") {
        tcp.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
        return Err(LinkError::Protocol("http: only CONNECT".into()));
    }
    let Some((host, port)) = split_authority(authority) else {
        tcp.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
        return Err(LinkError::Protocol("http: bad authority".into()));
    };
    match client.open(&host, port).await {
        Ok(s) => {
            tcp.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
            Ok((s, leftover))
        }
        Err(e) => {
            let status: &[u8] = match &e {
                LinkError::Refused { status: Status::Denied, .. } => b"HTTP/1.1 403 Forbidden",
                LinkError::Refused { status: Status::RateLimited | Status::Busy, .. } => b"HTTP/1.1 429 Too Many Requests",
                LinkError::HubDown => b"HTTP/1.1 503 Service Unavailable",
                _ => b"HTTP/1.1 502 Bad Gateway",
            };
            let mut resp = status.to_vec();
            resp.extend_from_slice(b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = tcp.write_all(&resp).await;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_parsing() {
        assert_eq!(split_authority("example.com:443"), Some(("example.com".into(), 443)));
        assert_eq!(split_authority("[2001:db8::1]:8443"), Some(("2001:db8::1".into(), 8443)));
        assert_eq!(split_authority("example.com"), None);
        assert_eq!(split_authority("example.com:0"), None);
        assert_eq!(split_authority("bad host:80"), None);
    }

    #[tokio::test]
    async fn non_loopback_bind_is_refused() {
        assert!(bind("0.0.0.0:0".parse().unwrap()).await.is_err());
    }
}
