//! Loopback resolvers for the DNS tests: an rcgen CA, local DoH, DoT, DoQ and
//! plain servers on ephemeral ports, and a connector that records every target.
//! No test reaches further than 127.0.0.1.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::crypto::{CryptoProvider, SupportedKxGroup, aws_lc_rs};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{NamedGroup, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use super::pool::{Context, Tls};
use super::upstream::{Kind, Resolver};
use super::{BoxFuture, Connector, Owned, build, doh, doq, dot};
use crate::tls;

/// The name the test CA's certificates are for by default.
pub const LOOPBACK: &str = "127.0.0.1";
/// The address local resolvers answer with for type A.
pub const ANSWER: &str = "192.0.2.1";

/// A client query for `name`, type A, with `id`.
pub fn client_query(id: u16, name: &str) -> Vec<u8> {
    super::with_id(&super::query_for(name, super::TYPE_A).unwrap(), id)
}

pub struct Ca {
    params: CertificateParams,
    key: KeyPair,
    pub roots: Arc<RootCertStore>,
}

impl Ca {
    pub fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        Self { params, key, roots: Arc::new(roots) }
    }

    fn leaf(&self, name: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![name.to_string()]).unwrap();
        let cert = params.signed_by(&key, &Issuer::from_params(&self.params, &self.key)).unwrap();
        (vec![cert.der().clone()], PrivateKeyDer::try_from(key.serialize_der()).unwrap())
    }

    fn server_config(&self, name: &str, alpn: &[&[u8]], groups: Option<Vec<&'static dyn SupportedKxGroup>>) -> ServerConfig {
        let provider = CryptoProvider { kx_groups: groups.unwrap_or_else(tls::kx_groups), ..aws_lc_rs::default_provider() };
        let (chain, key) = self.leaf(name);
        let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        config
    }

    pub fn context(&self, connector: Arc<Loopback>, resolvers: Vec<Resolver>) -> Context {
        Context { connector, tls: Arc::new(Tls::new(self.roots.clone()).unwrap()), resolvers }
    }
}

/// What the local server does with one wire query.
#[derive(Debug, Clone)]
pub enum Step {
    Answer(Vec<u8>),
    AnswerAfter(Duration, Vec<u8>),
    /// Accepts the query and never answers.
    Silent,
    /// Closes the connection.
    Close,
}

pub type Script = Arc<dyn Fn(&[u8]) -> Step + Send + Sync>;

/// A resolver's plain behaviour: answers with the query's own ID and question.
pub fn answering() -> Script {
    Arc::new(|query| Step::Answer(answer_to(query)))
}

/// The reply to a wire query: its ID and question, one address for type A.
pub fn answer_to(query: &[u8]) -> Vec<u8> {
    let parsed = super::parse(query).unwrap();
    let id = parsed.id;
    let name = parsed.question.unwrap();
    if parsed.question_type == super::TYPE_A {
        return build::response(id, &name, &[(ANSWER.parse().unwrap(), 60)]);
    }
    // The same question and no records, with the query's type.
    let mut reply = build::response(id, &name, &[]);
    let end = reply.len();
    reply[end - 4..end - 2].copy_from_slice(&parsed.question_type.to_be_bytes());
    reply
}

/// What a local server saw of one query.
#[derive(Debug, Clone, Default)]
pub struct Seen {
    pub message: Vec<u8>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub content_type: Option<String>,
}

#[derive(Clone)]
pub struct Options {
    pub script: Script,
    pub name: String,
    pub alpn: Option<Vec<Vec<u8>>>,
    pub groups: Option<Vec<&'static dyn SupportedKxGroup>>,
    pub handshake_delay: Duration,
    pub status: u16,
    pub content_type: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            script: answering(),
            name: LOOPBACK.into(),
            alpn: None,
            groups: None,
            handshake_delay: Duration::ZERO,
            status: 200,
            content_type: "application/dns-message".into(),
        }
    }
}

/// One local resolver, ended when dropped.
pub struct Server {
    pub port: u16,
    pub kind: Kind,
    pub accepts: Arc<AtomicUsize>,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    /// The group each accepted TLS session negotiated, on the server's side.
    pub groups: Arc<Mutex<Vec<NamedGroup>>>,
    _task: Owned,
}

impl Server {
    pub async fn start(kind: Kind, ca: &Ca, options: Options) -> Self {
        let accepts = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let groups = Arc::new(Mutex::new(Vec::new()));
        let shared = Shared { accepts: accepts.clone(), seen: seen.clone(), groups: groups.clone(), options: options.clone() };
        let default_alpn: &[u8] = match kind {
            Kind::Https => doh::ALPN,
            Kind::Tls => dot::ALPN,
            Kind::Quic => doq::ALPN,
        };
        let alpn = options.alpn.clone().unwrap_or_else(|| vec![default_alpn.to_vec()]);
        let alpn: Vec<&[u8]> = alpn.iter().map(Vec::as_slice).collect();
        let config = ca.server_config(&options.name, &alpn, options.groups.clone());
        let (port, task) = match kind {
            Kind::Https => {
                let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
                (listener.local_addr().unwrap().port(), Owned::spawn(serve_doh(listener, config, shared)))
            }
            Kind::Tls => {
                let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
                (listener.local_addr().unwrap().port(), Owned::spawn(serve_dot(listener, config, shared)))
            }
            Kind::Quic => {
                let quic = QuicServerConfig::try_from(config).unwrap();
                let endpoint = quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(quic)), (LOOPBACK.parse::<IpAddr>().unwrap(), 0).into()).unwrap();
                (endpoint.local_addr().unwrap().port(), Owned::spawn(serve_doq(endpoint, shared)))
            }
        };
        Self { port, kind, accepts, seen, groups, _task: task }
    }

    pub fn url(&self) -> String {
        match self.kind {
            Kind::Https => format!("https://{LOOPBACK}:{}/dns-query", self.port),
            Kind::Tls => format!("tls://{LOOPBACK}:{}", self.port),
            Kind::Quic => format!("quic://{LOOPBACK}:{}", self.port),
        }
    }

    pub fn accepted(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

#[derive(Clone)]
struct Shared {
    accepts: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Seen>>>,
    groups: Arc<Mutex<Vec<NamedGroup>>>,
    options: Options,
}

impl Shared {
    fn step(&self, seen: Seen) -> Step {
        let step = (self.options.script)(&seen.message);
        self.seen.lock().unwrap().push(seen);
        step
    }
}

async fn serve_dot(listener: TcpListener, config: ServerConfig, shared: Shared) {
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let mut connections = tokio::task::JoinSet::new();
    while let Ok((tcp, _)) = listener.accept().await {
        shared.accepts.fetch_add(1, Ordering::SeqCst);
        let (acceptor, shared) = (acceptor.clone(), shared.clone());
        connections.spawn(async move {
            tokio::time::sleep(shared.options.handshake_delay).await;
            let Ok(tls) = acceptor.accept(tcp).await else { return };
            shared.groups.lock().unwrap().extend(tls.get_ref().1.negotiated_key_exchange_group().map(|g| g.name()));
            let (mut reader, mut writer) = tokio::io::split(tls);
            let (replies, mut queue) = mpsc::unbounded_channel::<Vec<u8>>();
            let pump = tokio::spawn(async move {
                while let Some(frame) = queue.recv().await {
                    if writer.write_all(&frame).await.is_err() || writer.flush().await.is_err() {
                        return;
                    }
                }
            });
            let mut answers = tokio::task::JoinSet::new();
            while let Ok(len) = reader.read_u16().await {
                let mut message = vec![0u8; usize::from(len)];
                if reader.read_exact(&mut message).await.is_err() {
                    break;
                }
                let step = shared.step(Seen { message, ..Seen::default() });
                let replies = replies.clone();
                match step {
                    Step::Answer(reply) => {
                        let _ = replies.send(framed(&reply));
                    }
                    Step::AnswerAfter(delay, reply) => {
                        answers.spawn(async move {
                            tokio::time::sleep(delay).await;
                            let _ = replies.send(framed(&reply));
                        });
                    }
                    Step::Silent => {}
                    Step::Close => break,
                }
            }
            pump.abort();
        });
    }
}

fn framed(reply: &[u8]) -> Vec<u8> {
    let mut frame = (reply.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(reply);
    frame
}

async fn serve_doh(listener: TcpListener, config: ServerConfig, shared: Shared) {
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let mut connections = tokio::task::JoinSet::new();
    while let Ok((tcp, _)) = listener.accept().await {
        shared.accepts.fetch_add(1, Ordering::SeqCst);
        let (acceptor, shared) = (acceptor.clone(), shared.clone());
        connections.spawn(async move {
            tokio::time::sleep(shared.options.handshake_delay).await;
            let Ok(tls) = acceptor.accept(tcp).await else { return };
            shared.groups.lock().unwrap().extend(tls.get_ref().1.negotiated_key_exchange_group().map(|g| g.name()));
            let (closer, mut close) = mpsc::unbounded_channel::<()>();
            let handler = {
                let shared = shared.clone();
                service_fn(move |request: Request<Incoming>| {
                    let (shared, closer) = (shared.clone(), closer.clone());
                    async move {
                        let seen = Seen {
                            method: Some(request.method().to_string()),
                            path: Some(request.uri().path_and_query().map(ToString::to_string).unwrap_or_default()),
                            content_type: request.headers().get("content-type").map(|v| v.to_str().unwrap_or_default().to_string()),
                            message: Vec::new(),
                        };
                        let message = request.into_body().collect().await.map(|b| b.to_bytes().to_vec()).unwrap_or_default();
                        let body = match shared.step(Seen { message, ..seen }) {
                            Step::Answer(reply) => reply,
                            Step::AnswerAfter(delay, reply) => {
                                tokio::time::sleep(delay).await;
                                reply
                            }
                            Step::Silent => std::future::pending().await,
                            Step::Close => {
                                let _ = closer.send(());
                                std::future::pending().await
                            }
                        };
                        Response::builder()
                            .status(shared.options.status)
                            .header("content-type", shared.options.content_type.as_str())
                            .body(Full::new(Bytes::from(body)))
                    }
                })
            };
            let connection = hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), handler);
            tokio::select! {
                _ = connection => {}
                _ = close.recv() => {}
            }
        });
    }
}

async fn serve_doq(endpoint: quinn::Endpoint, shared: Shared) {
    let mut connections = tokio::task::JoinSet::new();
    while let Some(incoming) = endpoint.accept().await {
        shared.accepts.fetch_add(1, Ordering::SeqCst);
        let shared = shared.clone();
        connections.spawn(async move {
            tokio::time::sleep(shared.options.handshake_delay).await;
            let Ok(connecting) = incoming.accept() else { return };
            let Ok(connection) = connecting.await else { return };
            let mut streams = tokio::task::JoinSet::new();
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                let (shared, connection) = (shared.clone(), connection.clone());
                streams.spawn(async move {
                    let Ok(frame) = recv.read_to_end(usize::from(u16::MAX) + 2).await else { return };
                    assert_eq!(usize::from(u16::from_be_bytes([frame[0], frame[1]])), frame.len() - 2, "DoQ framing");
                    let step = shared.step(Seen { message: frame[2..].to_vec(), ..Seen::default() });
                    let reply = match step {
                        Step::Answer(reply) => reply,
                        Step::AnswerAfter(delay, reply) => {
                            tokio::time::sleep(delay).await;
                            reply
                        }
                        Step::Silent => return std::future::pending().await,
                        Step::Close => return connection.close(1u32.into(), b"closing"),
                    };
                    let _ = send.write_all(&raw_framed(&reply)).await;
                    let _ = send.finish();
                    let _ = send.stopped().await;
                });
            }
        });
    }
}

/// Like [`framed`], for a reply the script made oversized on purpose.
fn raw_framed(reply: &[u8]) -> Vec<u8> {
    let mut frame = (reply.len().min(usize::from(u16::MAX)) as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(reply);
    frame
}

/// A connector that opens loopback sockets and records every target.
#[derive(Default)]
pub struct Loopback {
    pub tcp_targets: Mutex<Vec<SocketAddr>>,
    pub udp_targets: Mutex<Vec<SocketAddr>>,
    /// A LAN address's stand-ins on this machine.
    pub lan_udp: Mutex<HashMap<IpAddr, SocketAddr>>,
    pub lan_tcp: Mutex<HashMap<IpAddr, SocketAddr>>,
}

impl Loopback {
    pub fn tcp_recorded(&self) -> Vec<SocketAddr> {
        self.tcp_targets.lock().unwrap().clone()
    }

    pub fn udp_recorded(&self) -> Vec<SocketAddr> {
        self.udp_targets.lock().unwrap().clone()
    }
}

impl Connector for Loopback {
    fn tcp(&self, target: SocketAddr) -> BoxFuture<'_, Result<TcpStream, String>> {
        self.tcp_targets.lock().unwrap().push(target);
        let mapped = self.lan_tcp.lock().unwrap().get(&target.ip()).copied().unwrap_or(target);
        Box::pin(async move { TcpStream::connect(mapped).await.map_err(|e| format!("connect {mapped}: {e}")) })
    }

    fn udp(&self, target: SocketAddr) -> Result<socket2::Socket, String> {
        use socket2::{Domain, Protocol, Socket, Type};
        self.udp_targets.lock().unwrap().push(target);
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| e.to_string())?;
        socket.set_nonblocking(true).map_err(|e| e.to_string())?;
        socket.bind(&SocketAddr::new(LOOPBACK.parse::<IpAddr>().map_err(|e| e.to_string())?, 0).into()).map_err(|e| e.to_string())?;
        Ok(socket)
    }

    fn address(&self, target: SocketAddr) -> SocketAddr {
        self.lan_udp.lock().unwrap().get(&target.ip()).copied().unwrap_or(target)
    }
}

/// A plain DNS server on loopback, a LAN router's stand-in or a trap.
pub struct Plain {
    pub udp: SocketAddr,
    pub tcp: SocketAddr,
    pub udp_queries: Arc<AtomicUsize>,
    pub tcp_queries: Arc<AtomicUsize>,
    _udp: Owned,
    _tcp: Owned,
}

impl Plain {
    /// `udp_script` answers datagrams and `tcp_script` answers TCP queries.
    pub async fn start(udp_script: Script, tcp_script: Script) -> Self {
        let socket = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
        let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
        let (udp, tcp) = (socket.local_addr().unwrap(), listener.local_addr().unwrap());
        let (udp_queries, tcp_queries) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let counted = udp_queries.clone();
        let udp_task = Owned::spawn(async move {
            let mut buffer = vec![0u8; super::MAX_MESSAGE];
            while let Ok((n, peer)) = socket.recv_from(&mut buffer).await {
                counted.fetch_add(1, Ordering::SeqCst);
                if let Step::Answer(reply) = udp_script(&buffer[..n]) {
                    let _ = socket.send_to(&reply, peer).await;
                }
            }
        });
        let counted = tcp_queries.clone();
        let tcp_task = Owned::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let Ok(len) = stream.read_u16().await else { continue };
                let mut query = vec![0u8; usize::from(len)];
                if stream.read_exact(&mut query).await.is_err() {
                    continue;
                }
                counted.fetch_add(1, Ordering::SeqCst);
                if let Step::Answer(reply) = tcp_script(&query) {
                    let _ = stream.write_all(&framed(&reply)).await;
                }
            }
        });
        Self { udp, tcp, udp_queries, tcp_queries, _udp: udp_task, _tcp: tcp_task }
    }
}

/// A datagram stream in memory: each write is one read on the other side.
pub struct DatagramPipe {
    incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    outgoing: mpsc::UnboundedSender<Vec<u8>>,
}

impl DatagramPipe {
    pub fn pair() -> (Self, Self) {
        let (a_tx, a_rx) = mpsc::unbounded_channel();
        let (b_tx, b_rx) = mpsc::unbounded_channel();
        (Self { incoming: a_rx, outgoing: b_tx }, Self { incoming: b_rx, outgoing: a_tx })
    }

    pub fn send(&self, datagram: &[u8]) {
        self.outgoing.send(datagram.to_vec()).unwrap();
    }

    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.incoming.recv().await
    }
}

impl AsyncRead for DatagramPipe {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.incoming.poll_recv(cx) {
            Poll::Ready(Some(datagram)) => {
                buf.put_slice(&datagram);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for DatagramPipe {
    fn poll_write(self: Pin<&mut Self>, _: &mut TaskContext<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let sent = self.outgoing.send(buf.to_vec()).map(|()| buf.len()).map_err(|_| std::io::ErrorKind::BrokenPipe.into());
        Poll::Ready(sent)
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
