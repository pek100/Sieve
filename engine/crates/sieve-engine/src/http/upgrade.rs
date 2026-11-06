//! What is the connection's and not the request's (RFC 9110 section 7.6.1), and
//! the WebSocket splice (plan 2.8, task D12). HTTP/1.1 `Upgrade` is spliced after
//! the URL rule, and nothing is filtered after it. Extended CONNECT is not
//! advertised: without knowing the upstream's setting (hyper exposes it only
//! after its SETTINGS arrive), advertising it breaks working sites, so an RFC
//! 8441 client opens an HTTP/1.1 connection for its WebSocket and lands here.

use ::http::HeaderMap;
use ::http::header::{CONNECTION, HeaderName, TE, TRANSFER_ENCODING, UPGRADE};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;

const KEEP_ALIVE: &str = "keep-alive";
const PROXY_AUTHENTICATE: &str = "proxy-authenticate";
const PROXY_AUTHORIZATION: &str = "proxy-authorization";
const PROXY_CONNECTION: &str = "proxy-connection";
const TRAILERS: &str = "trailers";

/// A task that ends when its handle goes: an intercepted flow closed by a
/// revocation or by the switch takes its splice with it.
pub struct AbortOnDrop<T>(pub tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A request asking to change protocol on this connection.
pub fn is_upgrade(headers: &HeaderMap) -> bool {
    let connection_says = headers.get_all(CONNECTION).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',')).any(|t| t.trim().eq_ignore_ascii_case(UPGRADE.as_str()));
    connection_says && headers.contains_key(UPGRADE)
}

/// Removes the hop-by-hop headers. `TE: trailers` and `Trailer` stay, or trailers
/// would not survive; on an upgrade `Connection` and `Upgrade` are the point.
pub fn strip_hop_by_hop(headers: &mut HeaderMap, upgrading: bool) {
    if !upgrading {
        let listed: Vec<HeaderName> = headers.get_all(CONNECTION).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',')).filter_map(|t| t.trim().parse().ok()).collect();
        for name in listed {
            if name != TE {
                headers.remove(name);
            }
        }
        headers.remove(CONNECTION);
        headers.remove(UPGRADE);
    }
    headers.remove(KEEP_ALIVE);
    headers.remove(PROXY_AUTHENTICATE);
    headers.remove(PROXY_AUTHORIZATION);
    headers.remove(PROXY_CONNECTION);
    headers.remove(TRANSFER_ENCODING);
    if headers.get(TE).and_then(|v| v.to_str().ok()).is_some_and(|v| !v.trim().eq_ignore_ascii_case(TRAILERS)) {
        headers.remove(TE);
    }
}

/// Copies both upgraded connections until either ends.
pub fn splice(client: OnUpgrade, upstream: OnUpgrade) -> AbortOnDrop<()> {
    AbortOnDrop(tokio::spawn(async move {
        let (Ok(client), Ok(upstream)) = tokio::join!(client, upstream) else { return };
        let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(client), &mut TokioIo::new(upstream)).await;
    }))
}
