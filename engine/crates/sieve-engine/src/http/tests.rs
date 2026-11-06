//! Decrypted requests end to end: a client over the intercepting side, hyper
//! both ways, a hyper origin behind a test chain.

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ::http::{HeaderMap, Method, Request, Response, StatusCode, Version};
use bytes::Bytes;
use http_body_util::channel::Channel;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use sieve_filter::resources::{load_bundle, sha256_hex};
use sieve_filter::rules::{RuleEngine, RuleSet};
use sieve_ipc::{LogOutcome, LogRow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::facts::{self, RequestFacts};
use super::hook::{BodyRewrite, HookError, NoRewrite, ResponseHook};
use super::serve::{CLOSE_GRACE, Proto, Serve, serve};
use super::upgrade::{is_upgrade, strip_hop_by_hop};
use crate::policy::wall_ms;
use crate::tls::intercept::{NoWatch, Outcome};
use crate::tls::tests::{Arm, ClientTls, GOOD, HOST, Pki, Rig, RigOpts, TestDial, arms, client_tls, connect, flow_opts, list_rules, server_tls, shown_is_sieves, tls_server};

type Body = UnsyncBoxBody<Bytes, Infallible>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

const H2: &str = "h2";
const H1: &str = "http/1.1";
const NEWS: &str = "news.example";
const BENCH_BLOCK: usize = 64 * 1024;
const BENCH_BYTES: usize = 256 * 1024 * 1024;
const BENCH_HANDSHAKES: usize = 200;

fn empty() -> Body {
    UnsyncBoxBody::new(Empty::new())
}

fn text(s: &'static str) -> Body {
    UnsyncBoxBody::new(Full::new(Bytes::from_static(s.as_bytes())))
}

/// What the origin was asked.
#[derive(Clone, Default)]
struct Origin {
    requests: Arc<Mutex<Vec<(Method, String, HeaderMap)>>>,
    connections: Arc<AtomicUsize>,
    /// `/stream` holds its second chunk until the client saw the first.
    release: Arc<Notify>,
    /// Starts a graceful GOAWAY on the h2 connection that is open.
    goaway: Arc<Notify>,
}

impl Origin {
    fn paths(&self) -> Vec<String> {
        self.requests.lock().unwrap().iter().map(|(_, p, _)| p.clone()).collect()
    }
}

async fn origin_answer(origin: Origin, req: Request<Incoming>) -> Result<Response<UnsyncBoxBody<Bytes, BoxError>>, Infallible> {
    let path = req.uri().path_and_query().map_or("/".to_string(), |p| p.to_string());
    origin.requests.lock().unwrap().push((req.method().clone(), path.clone(), req.headers().clone()));
    let body: UnsyncBoxBody<Bytes, BoxError> = match path.as_str() {
        "/stream" => {
            // The second chunk waits for the client to have the first, so a
            // buffering path deadlocks and the test fails by its limit.
            let (mut tx, rx) = Channel::<Bytes, BoxError>::new(4);
            let release = origin.release.clone();
            tokio::spawn(async move {
                let _ = tx.send_data(Bytes::from_static(b"first")).await;
                release.notified().await;
                let _ = tx.send_data(Bytes::from_static(b"second")).await;
                let mut trailers = HeaderMap::new();
                trailers.insert("x-sum", "42".parse().unwrap());
                let _ = tx.send_trailers(trailers).await;
            });
            UnsyncBoxBody::new(rx)
        }
        "/big" => {
            let (mut tx, rx) = Channel::<Bytes, BoxError>::new(4);
            tokio::spawn(async move {
                let block = Bytes::from(vec![7u8; BENCH_BLOCK]);
                for _ in 0..BENCH_BYTES / BENCH_BLOCK {
                    if tx.send_data(block.clone()).await.is_err() {
                        break;
                    }
                }
            });
            UnsyncBoxBody::new(rx)
        }
        "/echo" => req.into_body().map_err(|e| Box::new(e) as BoxError).boxed_unsync(),
        _ => Full::new(Bytes::from(format!("origin:{path}"))).map_err(|e: Infallible| match e {}).boxed_unsync(),
    };
    let mut response = Response::new(body);
    if path == "/stream" {
        response.headers_mut().insert("trailer", "x-sum".parse().unwrap());
    }
    Ok(response)
}

/// The origin's WebSocket stand-in: 101, then an echo over the upgrade.
async fn origin_upgrade(origin: Origin, mut req: Request<Incoming>) -> Result<Response<UnsyncBoxBody<Bytes, BoxError>>, Infallible> {
    if !is_upgrade(req.headers()) {
        return origin_answer(origin, req).await;
    }
    origin.requests.lock().unwrap().push((req.method().clone(), req.uri().to_string(), req.headers().clone()));
    let on = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        if let Ok(upgraded) = on.await {
            crate::tls::tests::echo(TokioIo::new(upgraded)).await;
        }
    });
    let mut response = Response::new(Full::new(Bytes::new()).map_err(|e: Infallible| match e {}).boxed_unsync());
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    response.headers_mut().insert(::http::header::CONNECTION, "upgrade".parse().unwrap());
    response.headers_mut().insert(::http::header::UPGRADE, "websocket".parse().unwrap());
    Ok(response)
}

/// A dial whose TLS server speaks hyper in the protocol it negotiated.
fn origin_dial(arm: Arm, pki: &Pki, alpn: &[&str], origin: Origin) -> TestDial {
    let config = server_tls(pki.leaf(HOST, GOOD), alpn, None);
    let handler = tls_server(vec![config], Arc::default(), move |_, tls| {
        let origin = origin.clone();
        async move {
            origin.connections.fetch_add(1, Ordering::Relaxed);
            let h2 = tls.get_ref().1.alpn_protocol() == Some(H2.as_bytes());
            let io = TokioIo::new(tls);
            let goaway = origin.goaway.clone();
            let service = service_fn(move |req| origin_upgrade(origin.clone(), req));
            if h2 {
                let connection = hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(io, service);
                tokio::pin!(connection);
                tokio::select! {
                    _ = &mut connection => {}
                    () = goaway.notified() => {
                        connection.as_mut().graceful_shutdown();
                        let _ = connection.await;
                    }
                }
            } else {
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, service).with_upgrades().await;
            }
        }
    });
    TestDial::new(arm, handler)
}

enum Client {
    H1(hyper::client::conn::http1::SendRequest<Body>),
    H2(hyper::client::conn::http2::SendRequest<Body>),
}

impl Client {
    async fn start(tls: ClientTls) -> Self {
        let h2 = tls.get_ref().1.alpn_protocol() == Some(H2.as_bytes());
        let io = TokioIo::new(tls);
        if h2 {
            let (sender, connection) = hyper::client::conn::http2::handshake::<_, _, Body>(TokioExecutor::new(), io).await.unwrap();
            tokio::spawn(connection);
            Self::H2(sender)
        } else {
            let (sender, connection) = hyper::client::conn::http1::handshake::<_, Body>(io).await.unwrap();
            tokio::spawn(connection.with_upgrades());
            Self::H1(sender)
        }
    }

    fn version(&self) -> Version {
        match self {
            Self::H1(_) => Version::HTTP_11,
            Self::H2(_) => Version::HTTP_2,
        }
    }

    async fn send(&mut self, req: Request<Body>) -> hyper::Result<Response<Incoming>> {
        match self {
            Self::H1(s) => {
                s.ready().await?;
                s.send_request(req).await
            }
            Self::H2(s) => {
                s.ready().await?;
                s.send_request(req).await
            }
        }
    }

    /// A request for `path` on `authority`, in the form this protocol writes it.
    fn request(&self, method: Method, authority: &str, path: &str) -> ::http::request::Builder {
        let builder = Request::builder().method(method);
        match self {
            Self::H1(_) => builder.uri(path).header(::http::header::HOST, authority),
            Self::H2(_) => builder.uri(format!("https://{authority}{path}")),
        }
    }

    async fn get(&mut self, authority: &str, path: &str, headers: &[(&str, &str)]) -> Response<Incoming> {
        let mut builder = self.request(Method::GET, authority, path);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        self.send(builder.body(empty()).unwrap()).await.unwrap()
    }
}

async fn body_of(response: Response<Incoming>) -> Vec<u8> {
    response.into_body().collect().await.unwrap().to_bytes().to_vec()
}

struct Setup {
    rig: Rig,
    client: Client,
    task: JoinHandle<Outcome>,
    origin: Origin,
}

async fn setup_with(arm: Arm, alpn: &str, rules: RuleSet, hook: Arc<dyn ResponseHook>) -> Setup {
    let pki = Pki::new("Test Public Root");
    let origin = Origin::default();
    let dial = origin_dial(arm, &pki, &[alpn], origin.clone());
    let rig = Rig::new(dial, RigOpts { rules, hook, ..RigOpts::new(pki.roots()) });
    let (app, task) = rig.flow(flow_opts()).await;
    let (config, shown) = client_tls(&[alpn], None);
    let tls = connect(app, config, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig), "decrypted");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(alpn.as_bytes()));
    let client = Client::start(tls).await;
    Setup { rig, client, task, origin }
}

async fn setup(arm: Arm, alpn: &str, rules: &str) -> Setup {
    setup_with(arm, alpn, list_rules(rules), Arc::new(NoRewrite)).await
}

fn rows(rig: &Rig) -> Vec<LogRow> {
    rig.deps.book.lock().unwrap().take_log()
}

const BOTH: [&str; 2] = [H2, H1];

arms!(h1_and_h2_end_to_end_with_streaming_body_and_trailers, |arm| async move {
    for alpn in BOTH {
        let mut s = setup(arm, alpn, "").await;
        // Te: trailers, or hyper's h1 side would not send them.
        let response = s.client.get(HOST, "/stream", &[("te", "trailers")]).await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(&first[..], b"first", "{alpn}: it came alone");
        s.origin.release.notify_one();
        let (mut data, mut trailers) = (Vec::new(), None);
        while let Some(frame) = body.frame().await {
            let frame = frame.unwrap();
            match frame.into_data() {
                Ok(d) => data.extend_from_slice(&d),
                Err(f) => trailers = f.into_trailers().ok(),
            }
        }
        assert_eq!(data, b"second", "{alpn}");
        assert_eq!(trailers.expect("trailers").get("x-sum").unwrap(), "42", "{alpn}");
        drop(body);
        // A request body streams up the same way.
        let post = s.client.request(Method::POST, HOST, "/echo").body(text("uploaded")).unwrap();
        assert_eq!(body_of(s.client.send(post).await.unwrap()).await, b"uploaded", "{alpn}");
        drop(s.client);
        s.task.await.unwrap();
    }
});

arms!(no_alpn_http_gets_the_rules_too, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let origin = Origin::default();
    let dial = origin_dial(arm, &pki, &[], origin.clone());
    let rig = Rig::new(dial, RigOpts { rules: list_rules("||site.example/ads^\n"), ..RigOpts::new(pki.roots()) });
    let (app, task) = rig.flow(flow_opts()).await;
    let (config, shown) = client_tls(&[], None);
    let tls = connect(app, config, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    assert!(shown_is_sieves(&shown, &rig));
    let mut client = Client::start(tls).await;
    assert_eq!(client.get(HOST, "/ads/1", &[]).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_of(client.get(HOST, "/page", &[]).await).await, b"origin:/page", "the first decrypted bytes were HTTP, and were replayed");
    assert_eq!(origin.paths(), ["/page"]);
    drop(client);
    task.await.unwrap();
});

arms!(one_upstream_per_client_connection, |arm| async move {
    for alpn in BOTH {
        let mut s = setup(arm, alpn, "").await;
        for path in ["/a", "/b", "/c"] {
            assert_eq!(body_of(s.client.get(HOST, path, &[]).await).await, format!("origin:{path}").into_bytes());
        }
        assert_eq!(s.origin.connections.load(Ordering::Relaxed), 1, "{alpn}");
        assert_eq!(s.rig.deps.connector.count(), 1, "{alpn}");
        drop(s.client);
        s.task.await.unwrap();
    }
});

arms!(upstream_end_ends_the_client_connection, |arm| async move {
    for alpn in BOTH {
        let pki = Pki::new("Test Public Root");
        // An origin that answers one request and closes the connection.
        let handler = tls_server(vec![server_tls(pki.leaf(HOST, GOOD), &[alpn], None)], Arc::default(), move |_, tls| async move {
            let h2 = tls.get_ref().1.alpn_protocol() == Some(H2.as_bytes());
            let io = TokioIo::new(tls);
            let service = service_fn(|_req: Request<Incoming>| async { Ok::<_, Infallible>(Response::new(text("bye"))) });
            if h2 {
                let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(io, service);
                let _ = tokio::time::timeout(Duration::from_millis(200), conn).await;
            } else {
                let mut b = hyper::server::conn::http1::Builder::new();
                b.keep_alive(false);
                let _ = b.serve_connection(io, service).await;
            }
        });
        let rig = Rig::new(TestDial::new(arm, handler), RigOpts::new(pki.roots()));
        let (app, task) = rig.flow(flow_opts()).await;
        let (config, _) = client_tls(&[alpn], None);
        let tls = connect(app, config, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
        let mut client = Client::start(tls).await;
        assert_eq!(body_of(client.get(HOST, "/", &[]).await).await, b"bye", "{alpn}");
        tokio::time::timeout(Duration::from_secs(15), task).await.unwrap_or_else(|_| panic!("{alpn}: the client side stayed open")).unwrap();
    }
});

fn h2_reason(error: &hyper::Error) -> Option<h2::Reason> {
    std::error::Error::source(error)?.downcast_ref::<h2::Error>()?.reason()
}

arms!(origin_goaway_refuses_the_next_request_and_keeps_the_stream_in_flight, |arm| async move {
    let mut s = setup(arm, H2, "").await;
    let mut in_flight = s.client.get(HOST, "/stream", &[]).await.into_body();
    assert_eq!(&in_flight.frame().await.unwrap().unwrap().into_data().unwrap()[..], b"first");
    s.origin.goaway.notify_one();
    // Requests the origin took before its GOAWAY arrived are fine; none is a 502.
    let (refused_path, refusal) = {
        let mut n = 0;
        loop {
            n += 1;
            let path = format!("/next{n}");
            let req = s.client.request(Method::GET, HOST, &path).body(empty()).unwrap();
            match s.client.send(req).await {
                Ok(response) => {
                    assert_eq!(response.status(), StatusCode::OK);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(e) => break (path, e),
            }
        }
    };
    assert_eq!(h2_reason(&refusal), Some(h2::Reason::REFUSED_STREAM), "{refusal}: a client retries this by itself");
    assert!(!s.origin.paths().contains(&refused_path), "the refused request never went upstream");
    // The retry, on a new connection, as a browser does it.
    let (app, retry_task) = s.rig.flow(flow_opts()).await;
    let (config, _) = client_tls(&[H2], None);
    let tls = connect(app, config, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    let mut retry = Client::start(tls).await;
    assert_eq!(body_of(retry.get(HOST, &refused_path, &[]).await).await, format!("origin:{refused_path}").into_bytes());
    drop(retry);
    retry_task.await.unwrap();
    // The stream the origin accepted outlives any fixed grace.
    tokio::time::sleep(CLOSE_GRACE + Duration::from_millis(500)).await;
    s.origin.release.notify_one();
    let mut data = Vec::new();
    while let Some(frame) = in_flight.frame().await {
        if let Ok(d) = frame.unwrap().into_data() {
            data.extend_from_slice(&d);
        }
    }
    assert_eq!(data, b"second");
    // Nothing left in flight: the flow ends though the client has not left.
    tokio::time::timeout(CLOSE_GRACE * 2, s.task).await.expect("the flow ended").unwrap();
});

#[tokio::test(start_paused = true)]
async fn the_engine_timing_out_a_head_is_not_a_client_close() {
    let pki = Pki::new("Test Public Root");
    let rig = Rig::new(origin_dial(Arm::Duplex, &pki, &[H1], Origin::default()), RigOpts::new(pki.roots()));
    let run = |client| {
        let (far, upstream) = tokio::io::duplex(1024);
        let pair = crate::tls::intercept::Pair { exe: None, host: HOST.to_string() };
        let ctx = Arc::new(Serve::new(rig.deps.filter.clone(), rig.deps.book.clone(), Arc::new(NoRewrite), Arc::new(NoWatch), 0, pair, HOST.to_string(), 443, wall_ms));
        async move {
            let ended = serve(ctx, client, upstream, Proto::H1).await;
            drop(far);
            ended
        }
    };
    let (mut open, near) = tokio::io::duplex(1024);
    open.write_all(b"GET / HTTP/1.1\r\nHo").await.unwrap();
    assert!(!run(near).await.client_ended, "hyper's header timeout, the client still open");
    // The control: the same head, and the client leaves.
    let (mut leaving, near) = tokio::io::duplex(1024);
    leaving.write_all(b"GET / HTTP/1.1\r\nHo").await.unwrap();
    drop(leaving);
    assert!(run(near).await.client_ended);
    drop(open);
}

/// An HTTP/2 origin by hand: `on_headers` gives the bytes to answer a stream's
/// HEADERS with, so a test can name what hyper's server does not expose.
fn raw_h2_dial(arm: Arm, pki: &Pki, on_headers: impl Fn(u32) -> Vec<u8> + Send + Sync + Clone + 'static) -> TestDial {
    const SETTINGS: u8 = 4;
    const HEADERS: u8 = 1;
    const ACK: u8 = 1;
    let handler = tls_server(vec![server_tls(pki.leaf(HOST, GOOD), &[H2], None)], Arc::default(), move |_, mut tls| {
        let on_headers = on_headers.clone();
        async move {
            let mut preface = [0u8; 24];
            if tls.read_exact(&mut preface).await.is_err() {
                return;
            }
            let _ = tls.write_all(&[0, 0, 0, SETTINGS, 0, 0, 0, 0, 0]).await;
            let _ = tls.flush().await;
            let mut head = [0u8; 9];
            while tls.read_exact(&mut head).await.is_ok() {
                let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
                let id = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
                let mut payload = vec![0u8; len];
                if tls.read_exact(&mut payload).await.is_err() {
                    return;
                }
                let answer = match head[3] {
                    SETTINGS if head[4] & ACK == 0 => vec![0, 0, 0, SETTINGS, ACK, 0, 0, 0, 0],
                    HEADERS => on_headers(id),
                    _ => continue,
                };
                let _ = tls.write_all(&answer).await;
                let _ = tls.flush().await;
            }
        }
    });
    TestDial::new(arm, handler)
}

async fn raw_h2_flow(pki: &Pki, dial: TestDial) -> (Rig, hyper::client::conn::http2::SendRequest<Body>, JoinHandle<Outcome>) {
    let rig = Rig::new(dial, RigOpts::new(pki.roots()));
    let (app, task) = rig.flow(flow_opts()).await;
    let (config, _) = client_tls(&[H2], None);
    let tls = connect(app, config, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    let Client::H2(sender) = Client::start(tls).await else { panic!("h2 was negotiated") };
    (rig, sender, task)
}

fn raw_h2_get(path: &str) -> Request<Body> {
    Request::builder().uri(format!("https://{HOST}{path}")).body(empty()).unwrap()
}

arms!(a_stream_above_the_goaway_is_refused_and_the_one_below_it_finishes, |arm| async move {
    // GOAWAY with last stream 1, then stream 1's answer: `:status 200`, ended.
    const GOAWAY_LAST_1: [u8; 17] = [0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    const ANSWER_1: [u8; 10] = [0, 0, 1, 1, 5, 0, 0, 0, 1, 0x88];
    let pki = Pki::new("Test Public Root");
    let took_first = Arc::new(Notify::new());
    let took = took_first.clone();
    let dial = raw_h2_dial(arm, &pki, move |id| {
        if id == 1 {
            took.notify_one();
            return Vec::new();
        }
        [GOAWAY_LAST_1.as_slice(), ANSWER_1.as_slice()].concat()
    });
    let (_rig, sender, task) = raw_h2_flow(&pki, dial).await;
    let mut below = sender.clone();
    let below = tokio::spawn(async move { below.send_request(raw_h2_get("/below")).await });
    took_first.notified().await;
    let mut above = sender;
    let refusal = above.send_request(raw_h2_get("/above")).await.expect_err("above the GOAWAY");
    assert_eq!(h2_reason(&refusal), Some(h2::Reason::REFUSED_STREAM), "{refusal}");
    assert_eq!(below.await.unwrap().unwrap().status(), StatusCode::OK);
    drop(above);
    tokio::time::timeout(CLOSE_GRACE * 2, task).await.expect("the flow ended").unwrap();
});

arms!(an_upstream_refused_stream_reaches_the_client_as_a_refusal, |arm| async move {
    const RST_REFUSED_1: [u8; 13] = [0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 7];
    let pki = Pki::new("Test Public Root");
    let dial = raw_h2_dial(arm, &pki, |_| RST_REFUSED_1.to_vec());
    let (_rig, mut sender, task) = raw_h2_flow(&pki, dial).await;
    let refusal = sender.send_request(raw_h2_get("/")).await.expect_err("refused");
    assert_eq!(h2_reason(&refusal), Some(h2::Reason::REFUSED_STREAM), "{refusal}");
    drop(sender);
    task.await.unwrap();
});

arms!(h2_coalescing_produces_421_and_nothing_goes_upstream, |arm| async move {
    let mut s = setup(arm, H2, "").await;
    assert_eq!(s.client.get("bank.example", "/", &[]).await.status(), StatusCode::MISDIRECTED_REQUEST);
    assert!(s.origin.paths().is_empty(), "nothing went upstream");
    assert_eq!(s.client.get("SITE.example.", "/ok", &[]).await.status(), StatusCode::OK, "case and a trailing dot are normalised");
    drop(s.client);
    s.task.await.unwrap();
});

arms!(h1_host_mismatch_produces_421, |arm| async move {
    let mut s = setup(arm, H1, "").await;
    let response = s.client.get("bank.example", "/", &[]).await;
    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(response.headers().get(::http::header::CONNECTION).unwrap(), "close");
    assert!(s.origin.paths().is_empty());
    drop(s.client);
    s.task.await.unwrap();
});

arms!(port_mismatch_produces_421, |arm| async move {
    for alpn in BOTH {
        let mut s = setup(arm, alpn, "").await;
        assert_eq!(s.client.get(&format!("{HOST}:8443"), "/", &[]).await.status(), StatusCode::MISDIRECTED_REQUEST, "{alpn}");
        assert!(s.origin.paths().is_empty(), "{alpn}");
        drop(s.client);
        s.task.await.unwrap();
    }
    let mut s = setup(arm, H2, "").await;
    assert_eq!(s.client.get(&format!("{HOST}:443"), "/fine", &[]).await.status(), StatusCode::OK, "the flow's own port");
    drop(s.client);
    s.task.await.unwrap();
});

/// An h1 upgrade by hand: the head, then whatever comes.
async fn upgrade_request(s: &mut Setup, path: &str) -> Response<Incoming> {
    let req = s.client.request(Method::GET, HOST, path).header(::http::header::CONNECTION, "upgrade").header(::http::header::UPGRADE, "websocket").header("sec-fetch-mode", "websocket").body(empty()).unwrap();
    s.client.send(req).await.unwrap()
}

arms!(websocket_upgrade_is_spliced_after_the_url_rule, |arm| async move {
    let mut s = setup(arm, H1, "||site.example/blocked^$websocket\n").await;
    let mut response = upgrade_request(&mut s, "/socket").await;
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    let upgraded = hyper::upgrade::on(&mut response).await.unwrap();
    let mut io = TokioIo::new(upgraded);
    io.write_all(b"frame").await.unwrap();
    io.flush().await.unwrap();
    let mut got = [0u8; 5];
    io.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"frame", "bytes cross the splice");
    let row = rows(&s.rig).into_iter().find(|r| r.url.as_deref().is_some_and(|u| u.ends_with("/socket"))).expect("a row");
    assert_eq!(row.request_type.as_deref(), Some("websocket"));
    assert_eq!(row.url.as_deref(), Some("wss://site.example/socket"), "the socket's real scheme");
    assert_eq!(s.origin.paths(), ["/socket"], "the upstream's request line has no scheme of ours");
    drop(io);
    drop(s.client);
    s.task.await.unwrap();
});

arms!(blocked_websocket_never_reaches_upstream, |arm| async move {
    let mut s = setup(arm, H1, "||site.example/blocked^$websocket\n|wss://site.example/anchored^\n").await;
    let response = upgrade_request(&mut s, "/blocked").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = upgrade_request(&mut s, "/anchored").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN, "a rule anchored on the socket's scheme");
    assert!(s.origin.paths().is_empty());
    drop(s.client);
    s.task.await.unwrap();
});

arms!(h2_does_not_advertise_extended_connect, |arm| async move {
    let pki = Pki::new("Test Public Root");
    let rig = Rig::new(origin_dial(arm, &pki, &[H2], Origin::default()), RigOpts::new(pki.roots()));
    let (app, task) = rig.flow(flow_opts()).await;
    let (config, _) = client_tls(&[H2], None);
    let tls = connect(app, config, HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
    let (mut sender, connection) = hyper::client::conn::http2::handshake::<_, _, Body>(TokioExecutor::new(), TokioIo::new(tls)).await.unwrap();
    let mut connection = Box::pin(connection);
    // A request first, so the server's SETTINGS have arrived.
    let req = Request::builder().uri(format!("https://{HOST}/")).body(empty()).unwrap();
    tokio::select! {
        response = sender.send_request(req) => assert_eq!(response.unwrap().status(), StatusCode::OK),
        ended = &mut connection => panic!("the connection ended: {ended:?}"),
    }
    assert!(!connection.is_extended_connect_protocol_enabled(), "task D12");
    drop(sender);
    drop(connection);
    task.await.unwrap();
});

arms!(block_rule_answers_403_and_nothing_goes_upstream, |arm| async move {
    for alpn in BOTH {
        let mut s = setup(arm, alpn, "||site.example/ads^\n").await;
        let response = s.client.get(HOST, "/ads/1.js", &[("sec-fetch-dest", "script"), ("referer", "https://news.example/")]).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{alpn}");
        assert_eq!(response.headers().get(::http::header::CACHE_CONTROL).unwrap(), "no-store");
        assert!(body_of(response).await.is_empty());
        assert!(s.origin.paths().is_empty(), "{alpn}");
        assert_eq!(s.client.get(HOST, "/page", &[]).await.status(), StatusCode::OK, "other paths pass");
        drop(s.client);
        s.task.await.unwrap();
    }
});

fn redirect_rules(text: &str) -> RuleSet {
    const BUNDLE: &[u8] = include_bytes!("../../../sieve-filter/testdata/resources-fixture.json");
    let mut engine = RuleEngine::compile(&[sieve_filter::rules::ListText { id: "fixture", text, trusted: false }]);
    engine.use_resources(&load_bundle(BUNDLE, &sha256_hex(BUNDLE)).unwrap());
    RuleSet { user: Arc::new(RuleEngine::empty()), lists: Arc::new(engine) }
}

arms!(redirect_rule_serves_the_resource, |arm| async move {
    for alpn in BOTH {
        let mut s = setup_with(arm, alpn, redirect_rules("||site.example/ad.js$redirect=sieve-noop.js\n"), Arc::new(NoRewrite)).await;
        let response = s.client.get(HOST, "/ad.js", &[("sec-fetch-dest", "script"), ("referer", "https://news.example/")]).await;
        assert_eq!(response.status(), StatusCode::OK, "{alpn}");
        assert_eq!(response.headers().get(::http::header::CONTENT_TYPE).unwrap(), "application/javascript");
        assert_eq!(response.headers().get(::http::header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "*");
        assert_eq!(response.headers().get("cross-origin-resource-policy").unwrap(), "cross-origin");
        assert_eq!(body_of(response).await, b"(function () {})();\n");
        assert!(s.origin.paths().is_empty(), "{alpn}");
        assert!(rows(&s.rig).iter().any(|r| r.outcome == LogOutcome::Redirected));
        drop(s.client);
        s.task.await.unwrap();
    }
});

arms!(redirect_without_a_bundle_blocks, |arm| async move {
    let mut s = setup(arm, H2, "||site.example/ad.js$redirect=sieve-noop.js\n").await;
    assert_eq!(s.client.get(HOST, "/ad.js", &[("sec-fetch-dest", "script"), ("referer", "https://news.example/")]).await.status(), StatusCode::FORBIDDEN);
    assert!(s.origin.paths().is_empty());
    assert!(rows(&s.rig).iter().any(|r| r.outcome == LogOutcome::Blocked));
    drop(s.client);
    s.task.await.unwrap();
});

arms!(removeparam_rewrites_a_subresource_upstream, |arm| async move {
    for alpn in BOTH {
        let mut s = setup(arm, alpn, "||site.example^$removeparam=utm_source\n").await;
        // An XHR: the dialect applies `$removeparam` to documents and XHRs by default.
        let status = s.client.get(HOST, "/api?utm_source=x&id=1", &[("sec-fetch-dest", "empty"), ("referer", "https://site.example/")]).await.status();
        assert_eq!(status, StatusCode::OK, "{alpn}");
        assert_eq!(s.origin.paths(), ["/api?id=1"], "{alpn}");
        assert!(rows(&s.rig).iter().any(|r| r.outcome == LogOutcome::ParamsRemoved));
        drop(s.client);
        s.task.await.unwrap();
    }
});

arms!(removeparam_redirects_a_document_once, |arm| async move {
    for alpn in BOTH {
        let mut s = setup(arm, alpn, "||site.example^$removeparam=utm_source\n").await;
        let response = s.client.get(HOST, "/page?utm_source=x&id=1", &[("sec-fetch-dest", "document")]).await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT, "{alpn}");
        let location = response.headers().get(::http::header::LOCATION).unwrap().to_str().unwrap().to_string();
        assert_eq!(location, format!("https://{HOST}/page?id=1"));
        drop(response);
        assert!(s.origin.paths().is_empty(), "the redirect went nowhere");
        let clean = s.client.get(HOST, "/page?id=1", &[("sec-fetch-dest", "document")]).await.status();
        assert_eq!(clean, StatusCode::OK, "the clean URL has no parameter: no loop");
        assert_eq!(s.origin.paths(), ["/page?id=1"]);
        drop(s.client);
        s.task.await.unwrap();
    }
});

const SCRIPT_FROM_NEWS: [(&str, &str); 2] = [("sec-fetch-dest", "script"), ("referer", "https://news.example/")];

arms!(document_exception_on_the_initiator_beats_a_block, |arm| async move {
    let mut s = setup(arm, H2, &format!("||site.example/ad.js\n@@||{NEWS}^$document\n")).await;
    assert_eq!(s.client.get(HOST, "/ad.js", &SCRIPT_FROM_NEWS).await.status(), StatusCode::OK);
    assert_eq!(s.client.get(HOST, "/ad.js", &[("sec-fetch-dest", "script"), ("referer", "https://other.example/")]).await.status(), StatusCode::FORBIDDEN);
    drop(s.client);
    s.task.await.unwrap();
});

arms!(important_beats_it, |arm| async move {
    let mut s = setup(arm, H2, &format!("||site.example/ad.js$important\n@@||{NEWS}^$document\n")).await;
    assert_eq!(s.client.get(HOST, "/ad.js", &SCRIPT_FROM_NEWS).await.status(), StatusCode::FORBIDDEN);
    drop(s.client);
    s.task.await.unwrap();
});

arms!(user_allow_beats_a_list_block, |arm| async move {
    let rules = RuleSet { user: Arc::new(RuleEngine::compile_user_rules(std::iter::empty(), ["@@||site.example/ad.js"])), lists: list_rules("||site.example/ad.js\n").lists };
    let mut s = setup_with(arm, H2, rules, Arc::new(NoRewrite)).await;
    assert_eq!(s.client.get(HOST, "/ad.js", &SCRIPT_FROM_NEWS).await.status(), StatusCode::OK);
    drop(s.client);
    s.task.await.unwrap();
});

#[test]
fn request_type_table() {
    let of = |headers: &[(&str, &str)], path: &str| {
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            map.insert(k.parse::<::http::header::HeaderName>().unwrap(), v.parse().unwrap());
        }
        facts::request_type(&map, path)
    };
    // Every value of the Fetch standard's destination list.
    for (dest, kind) in [
        ("audio", "media"),
        ("audioworklet", "script"),
        ("document", "document"),
        ("embed", "object"),
        ("empty", "xhr"),
        ("fencedframe", "sub_frame"),
        ("font", "font"),
        ("frame", "sub_frame"),
        ("iframe", "sub_frame"),
        ("image", "image"),
        ("manifest", "other"),
        ("object", "object"),
        ("paintworklet", "script"),
        ("report", "ping"),
        ("script", "script"),
        ("serviceworker", "script"),
        ("sharedworker", "script"),
        ("style", "stylesheet"),
        ("track", "media"),
        ("video", "media"),
        ("webidentity", "xhr"),
        ("websocket", "websocket"),
        ("worker", "script"),
        ("xslt", "stylesheet"),
    ] {
        assert_eq!(of(&[("sec-fetch-dest", dest)], "/x"), kind, "{dest}");
    }
    assert_eq!(of(&[("sec-fetch-mode", "websocket"), ("sec-fetch-dest", "empty")], "/x"), "websocket");
    assert_eq!(of(&[("upgrade", "WebSocket")], "/x"), "websocket");
    // Accept, when the browser says nothing.
    for (accept, kind) in [("text/html,application/xhtml+xml", "document"), ("text/css", "stylesheet"), ("image/avif,image/webp", "image"), ("application/json", "xhr"), ("video/mp4", "media"), ("font/woff2", "font")] {
        assert_eq!(of(&[("accept", accept)], "/x"), kind, "{accept}");
    }
    // The extension, last.
    for (path, kind) in [("/a.js?v=1", "script"), ("/a.CSS", "stylesheet"), ("/a.png", "image"), ("/a.woff2", "font"), ("/a.mp4", "media"), ("/a.html", "document"), ("/a", "other"), ("/a.unknown", "other")] {
        assert_eq!(of(&[("accept", "*/*")], path), kind, "{path}");
    }
    assert_eq!(of(&[("sec-fetch-dest", "script"), ("accept", "text/css")], "/a.png"), "script", "the browser's word first");
}

#[test]
fn a_navigation_has_no_initiator_and_a_subresource_names_its_page() {
    let req = Request::builder().uri("/a.js?x=1").header("sec-fetch-dest", "script").header("origin", "https://page.example").header("referer", "https://page.example/deep").body(()).unwrap();
    let f = facts::of(&req, HOST);
    let RequestFacts { url, initiator, is_document, .. } = f.borrowed();
    assert_eq!((url, initiator, is_document), ("https://site.example/a.js?x=1", "https://page.example", false));
    let nav = Request::builder().uri("/").header("sec-fetch-dest", "document").header("referer", "https://away.example/").body(()).unwrap();
    assert_eq!(facts::of(&nav, HOST).borrowed().initiator, "");
    let opaque = Request::builder().uri("/a.js").header("sec-fetch-dest", "script").header("origin", "null").header("referer", "https://page.example/").body(()).unwrap();
    assert_eq!(facts::of(&opaque, HOST).initiator, "https://page.example/");
}

#[test]
fn hop_by_hop_headers_stop_here_and_trailers_survive() {
    let mut headers = HeaderMap::new();
    for (k, v) in [("connection", "close, x-private"), ("keep-alive", "1"), ("x-private", "secret"), ("proxy-authorization", "a"), ("transfer-encoding", "chunked"), ("upgrade", "h2c"), ("te", "trailers"), ("trailer", "x-sum"), ("x-kept", "yes")] {
        headers.insert(k.parse::<::http::header::HeaderName>().unwrap(), v.parse().unwrap());
    }
    assert!(!is_upgrade(&headers));
    strip_hop_by_hop(&mut headers, false);
    let mut names: Vec<&str> = headers.keys().map(|k| k.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["te", "trailer", "x-kept"]);
    let mut gzip = HeaderMap::new();
    gzip.insert("te", "gzip".parse().unwrap());
    strip_hop_by_hop(&mut gzip, false);
    assert!(gzip.is_empty());
    let mut upgrading = HeaderMap::new();
    upgrading.insert("connection", "keep-alive, Upgrade".parse().unwrap());
    upgrading.insert("upgrade", "websocket".parse().unwrap());
    assert!(is_upgrade(&upgrading));
    strip_hop_by_hop(&mut upgrading, true);
    assert_eq!(upgrading.len(), 2);
}

arms!(a_log_row_has_url_and_type_but_no_body_cookie_or_auth, |arm| async move {
    let mut s = setup(arm, H2, "||site.example/ads^\n").await;
    let secret = "COOKIE-SECRET";
    let req = s.client.request(Method::POST, HOST, "/form?q=1").header("cookie", format!("a={secret}")).header("authorization", format!("Bearer {secret}")).header("sec-fetch-dest", "empty").body(text("BODY-SECRET")).unwrap();
    assert_eq!(s.client.send(req).await.unwrap().status(), StatusCode::OK);
    let rows = rows(&s.rig);
    let row = rows.iter().find(|r| r.url.is_some()).expect("a request row");
    assert_eq!(row.url.as_deref(), Some("https://site.example/form?q=1"));
    assert_eq!(row.request_type.as_deref(), Some("xhr"));
    let json = serde_json::to_string(&rows).unwrap();
    assert!(!json.contains(secret) && !json.contains("BODY-SECRET"), "{json}");
    drop(s.client);
    s.task.await.unwrap();
});

/// Upper-cases a body; a chunk holding `poison` fails it.
struct TestHook;

struct Upper;

impl BodyRewrite for Upper {
    fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, HookError> {
        if chunk.windows(6).any(|w| w == b"poison") {
            return Err(HookError("poisoned".into()));
        }
        Ok(chunk.to_ascii_uppercase())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, HookError> {
        Ok(b"!END".to_vec())
    }
}

impl ResponseHook for TestHook {
    fn wants(&self, req: &RequestFacts<'_>, _: StatusCode, _: &HeaderMap) -> bool {
        !req.url.ends_with("/skip")
    }

    fn begin(&self, req: &RequestFacts<'_>, status: StatusCode, headers: &mut HeaderMap, body_start: &[u8]) -> Option<Box<dyn BodyRewrite>> {
        assert_eq!(status, StatusCode::OK);
        assert!(!body_start.is_empty() || req.url.ends_with("/empty"), "the first frame is held for begin");
        if req.url.ends_with("/asis") {
            return None;
        }
        headers.remove(::http::header::CONTENT_LENGTH);
        Some(Box::new(Upper))
    }
}

arms!(response_hook_rewrites_a_body_and_its_error_resets_the_stream, |arm| async move {
    for alpn in BOTH {
        let mut s = setup_with(arm, alpn, RuleSet::empty(), Arc::new(TestHook)).await;
        let body = body_of(s.client.get(HOST, "/rewrite", &[]).await).await;
        assert_eq!(body, b"ORIGIN:/REWRITE!END", "{alpn}");
        assert_eq!(body_of(s.client.get(HOST, "/asis", &[]).await).await, b"origin:/asis", "{alpn}: begin said None");
        assert_eq!(body_of(s.client.get(HOST, "/skip", &[]).await).await, b"origin:/skip", "{alpn}: not wanted");
        // The head may arrive or lose the race with the reset; a clean end never comes.
        let req = s.client.request(Method::GET, HOST, "/poison").body(empty()).unwrap();
        if let Ok(response) = s.client.send(req).await {
            assert!(response.into_body().collect().await.is_err(), "{alpn}: the stream was reset");
        }
        if s.client.version() == Version::HTTP_2 {
            assert_eq!(body_of(s.client.get(HOST, "/after", &[]).await).await, b"ORIGIN:/AFTER!END", "h2: only that stream");
        }
        drop(s.client);
        s.task.await.unwrap();
    }
});

arms!(no_rewrite_passes_bytes_unchanged, |arm| async move {
    for alpn in BOTH {
        let mut s = setup(arm, alpn, "").await;
        let response = s.client.get(HOST, "/bytes", &[]).await;
        assert_eq!(response.headers().get(::http::header::CONTENT_LENGTH).map(|v| v.to_str().unwrap().to_string()), Some("13".to_string()), "{alpn}: the origin's length stands");
        assert_eq!(body_of(response).await, b"origin:/bytes");
        drop(s.client);
        s.task.await.unwrap();
    }
});

#[test]
fn the_plain_lists_are_not_consulted_when_filtering_is_off() {
    use crate::domain::DomainFilter;
    use sieve_ipc::Policy;

    use super::rules::{Action, rule};
    let policy = Policy { sieving: false, ..Policy::default() };
    let filter = DomainFilter::new(&policy, list_rules("||site.example^\n"));
    let f = RequestFacts { url: "https://site.example/ad.js", method: "GET", is_document: false, request_type: "script", initiator: "https://news.example/" };
    let ruling = rule(&filter, &f);
    assert_eq!(ruling.action, Action::Forward { rewritten: None });
    assert_eq!(ruling.rule, None);
    let on = DomainFilter::new(&Policy { sieving: true, ..Policy::default() }, list_rules("||site.example^\n"));
    assert_eq!(rule(&on, &f).action, Action::Block, "the control");
}

/// A client that handshakes and leaves, many times: the shape of a preconnect.
/// Each flow must end by itself, in both protocols.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_closes_end_every_flow() {
    const ROUNDS: usize = 40;
    for alpn in BOTH {
        let pki = Pki::new("Test Public Root");
        let rig = Rig::new(origin_dial(Arm::Duplex, &pki, &[alpn], Origin::default()), RigOpts::new(pki.roots()));
        let (config, _) = client_tls(&[alpn], None);
        for round in 0..ROUNDS {
            let (app, task) = rig.flow(flow_opts()).await;
            let tls = tokio::time::timeout(Duration::from_secs(20), connect(app, config.clone(), HOST)).await.unwrap_or_else(|_| panic!("{alpn} round {round}: handshake")).unwrap_or_else(|(e, _)| panic!("{e}"));
            drop(tls);
            tokio::time::timeout(Duration::from_secs(20), task).await.unwrap_or_else(|_| panic!("{alpn} round {round}: the flow stayed open")).unwrap();
        }
    }
}

/// Evidence, not a gate, and in memory: the signer is in memory and nothing
/// crosses a network. Run with `--ignored --nocapture`; the live budgets are U10.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "bench: prints in-memory numbers"]
async fn bench_intercepted_h1_h2_in_memory() {
    for alpn in BOTH {
        let pki = Pki::new("Test Public Root");
        let rig = Rig::new(origin_dial(Arm::Duplex, &pki, &[alpn], Origin::default()), RigOpts::new(pki.roots()));
        let (config, _) = client_tls(&[alpn], None);
        let mut handshakes = Vec::with_capacity(BENCH_HANDSHAKES);
        for _ in 0..BENCH_HANDSHAKES {
            let started = std::time::Instant::now();
            let (app, task) = rig.flow(flow_opts()).await;
            let tls = connect(app, config.clone(), HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
            handshakes.push(started.elapsed());
            drop(tls);
            let _ = task.await;
        }
        handshakes.sort();
        println!("{alpn}: both handshakes, in memory: p50 {:?} p99 {:?}", handshakes[BENCH_HANDSHAKES / 2], handshakes[BENCH_HANDSHAKES * 99 / 100]);
        let (app, task) = rig.flow(flow_opts()).await;
        let tls = connect(app, config.clone(), HOST).await.unwrap_or_else(|(e, _)| panic!("{e}"));
        let mut client = Client::start(tls).await;
        let started = std::time::Instant::now();
        let mut body = client.get(HOST, "/big", &[]).await.into_body();
        let mut got = 0;
        while let Some(frame) = body.frame().await {
            got += frame.unwrap().data_ref().map_or(0, Bytes::len);
        }
        let seconds = started.elapsed().as_secs_f64();
        println!("{alpn}: a {got} byte response through both sessions, in memory: {:.0} Mbit/s", (got * 8) as f64 / seconds / 1e6);
        // A held stream keeps an h2 connection, and so this flow, open.
        drop(body);
        drop(client);
        let _ = task.await;
    }
}
