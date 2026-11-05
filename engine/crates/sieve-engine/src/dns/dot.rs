//! DNS over TLS (RFC 7858): one TLS stream, pipelined queries with 2-byte
//! framing, answered in any order. The session assigns each query an ID unique
//! among those in flight and restores the client's on the reply.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsConnector;

use super::pool::{Fail, TlsFacts};
use super::{Connector, Owned, id_of, with_id};

/// The protocol name offered; a server that ignores ALPN still connects.
pub const ALPN: &[u8] = b"dot";
/// Writes queued for one session; a full queue waits, inside the query's share.
const WRITE_QUEUE: usize = 64;
const CLOSED: &str = "the DNS over TLS session closed";

/// None once the stream ended: no query can be answered any more.
type Pending = Mutex<Option<HashMap<u16, oneshot::Sender<Vec<u8>>>>>;

struct Shared {
    pending: Pending,
    next: AtomicU16,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<HashMap<u16, oneshot::Sender<Vec<u8>>>>> {
        self.pending.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Every waiting query fails at once, and no new one starts.
    fn close(&self) {
        *self.lock() = None;
    }
}

/// Forgets a query whose caller went away, so its ID can be used again.
struct Waiting<'a> {
    shared: &'a Shared,
    id: u16,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if let Some(pending) = self.shared.lock().as_mut() {
            pending.remove(&self.id);
        }
    }
}

pub struct Session {
    shared: Arc<Shared>,
    writes: mpsc::Sender<Vec<u8>>,
    _reader: Owned,
    _writer: Owned,
}

pub async fn connect(connector: &dyn Connector, addr: SocketAddr, name: ServerName<'static>, config: Arc<ClientConfig>) -> Result<(Session, TlsFacts), String> {
    let tcp = connector.tcp(addr).await?;
    tcp.set_nodelay(true).map_err(|e| format!("nodelay: {e}"))?;
    let tls = TlsConnector::from(config).connect(name, tcp).await.map_err(|e| format!("TLS to {addr}: {e}"))?;
    let facts = TlsFacts::of(tls.get_ref().1);
    let (reader, writer) = tokio::io::split(tls);
    let shared = Arc::new(Shared { pending: Mutex::new(Some(HashMap::new())), next: AtomicU16::new(1) });
    let (writes, queue) = mpsc::channel(WRITE_QUEUE);
    let session = Session {
        _reader: Owned::spawn(read_replies(reader, shared.clone())),
        _writer: Owned::spawn(write_queries(writer, queue, shared.clone())),
        shared,
        writes,
    };
    Ok((session, facts))
}

async fn read_replies(mut stream: impl AsyncRead + Unpin, shared: Arc<Shared>) {
    while let Ok(len) = stream.read_u16().await {
        let mut reply = vec![0u8; usize::from(len)];
        if stream.read_exact(&mut reply).await.is_err() {
            break;
        }
        let waiter = id_of(&reply).and_then(|id| shared.lock().as_mut()?.remove(&id));
        if let Some(waiter) = waiter {
            let _ = waiter.send(reply);
        }
    }
    shared.close();
}

async fn write_queries(mut stream: impl AsyncWrite + Unpin, mut queue: mpsc::Receiver<Vec<u8>>, shared: Arc<Shared>) {
    while let Some(frame) = queue.recv().await {
        if stream.write_all(&frame).await.is_err() || stream.flush().await.is_err() {
            break;
        }
    }
    shared.close();
}

impl Session {
    pub fn alive(&self) -> bool {
        self.shared.lock().is_some()
    }

    pub async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, Fail> {
        let client_id = id_of(query).ok_or_else(|| Fail::Reply("a query without an ID".into()))?;
        let len = u16::try_from(query.len()).map_err(|_| Fail::Reply("a query over the size limit".into()))?;
        let (id, answer) = self.register()?;
        let _waiting = Waiting { shared: &self.shared, id };
        let mut frame = Vec::with_capacity(query.len() + 2);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&with_id(query, id));
        self.writes.send(frame).await.map_err(|_| Fail::Link(CLOSED.into()))?;
        let reply = answer.await.map_err(|_| Fail::Link(CLOSED.into()))?;
        Ok(with_id(&reply, client_id))
    }

    /// The next ID not in flight (the in-flight cap keeps one free).
    fn register(&self) -> Result<(u16, oneshot::Receiver<Vec<u8>>), Fail> {
        let mut guard = self.shared.lock();
        let pending = guard.as_mut().ok_or_else(|| Fail::Link(CLOSED.into()))?;
        let (tx, rx) = oneshot::channel();
        loop {
            let id = self.shared.next.fetch_add(1, Ordering::Relaxed);
            if let Entry::Vacant(free) = pending.entry(id) {
                free.insert(tx);
                return Ok((id, rx));
            }
        }
    }
}
