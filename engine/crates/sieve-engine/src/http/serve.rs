//! One client connection and its one upstream connection (plan 2.8, task D15):
//! the same protocol on each side, since the ALPN came from the server. There is
//! no pool to fall back on, so either side ending ends the other, by GOAWAY or
//! a close; an end of the upstream's lets the streams it accepted finish first.
//! Connection settings and errors stay one-to-one.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use ::http::header::{ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONNECTION, CONTENT_TYPE, HeaderValue, LOCATION};
use ::http::uri::{PathAndQuery, Uri};
use ::http::{Request, Response, StatusCode};
use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::AlertDescription;
use sieve_ipc::{LogChange, LogOutcome};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

use super::facts;
use super::hook::{self, ResponseHook};
use super::rules::{self, Action};
use super::tracking::{self, Changes, Protection, Protections};
use super::upgrade::{AbortOnDrop, is_upgrade, splice, strip_hop_by_hop};
use crate::domain::FilterSlot;
use crate::stack::book::{FlowBook, RequestRow};
use crate::tls::intercept::{ClientWatch, Pair};
use crate::tls::upstream::alert_in;

pub type BodyError = Box<dyn std::error::Error + Send + Sync>;
pub type ResponseBody = UnsyncBoxBody<Bytes, BodyError>;

/// HTTP/2 flow control, set for the 500 Mbit/s budget (plan 6): at 50 ms of
/// bridged round trip that is about 3 MiB in flight. Declared dials, tuned live
/// (`docs/live/engine-slice-6.md`, U10).
pub const H2_STREAM_WINDOW: u32 = 4 * 1024 * 1024;
pub const H2_CONNECTION_WINDOW: u32 = 16 * 1024 * 1024;
/// The largest header list either h2 side takes: what Chromium advertises
/// (`kSpdyMaxHeaderListSize`), so a head a browser takes without Sieve passes with
/// it. hyper's default is 16 KiB, and a large video site's response head is about
/// 20 KiB (live run 2026-11-08: every load a 502 from the engine, so Edge showed
/// ERR_HTTP_RESPONSE_CODE_FAILURE).
pub const H2_MAX_HEADER_LIST: u32 = 256 * 1024;
/// After the upstream's end and its last stream, how long the client gets to
/// finish the close (an h2 GOAWAY needs its PING answered). Streams in flight do
/// not count against it: they run until the upstream ends them.
pub const CLOSE_GRACE: Duration = Duration::from_secs(5);
/// The CORS and cross-origin headers a served resource carries.
const CROSS_ORIGIN_RESOURCE_POLICY: &str = "cross-origin-resource-policy";
const CROSS_ORIGIN: &str = "cross-origin";
const ANY: &str = "*";
const NO_STORE: &str = "no-store";
const CLOSE: &str = "close";
const MISDIRECTED: &str = "misdirected";
/// The reason of a page the site sent back to its parameters, passed as asked.
const PARAMS_KEPT: &str = "params_kept";
/// How long a connection remembers a 307 it sent to remove parameters, and how
/// many: the site's redirect back comes within the same chain, well under a
/// second; ten seconds is room for a slow origin, sixteen for the pages one
/// connection opens in that time. Declared dials, not measured.
const MOVE_MEMORY: Duration = Duration::from_secs(10);
const MOVES_KEPT: usize = 16;

/// A 307 this connection sent, to `target`; `bounced` once the site answered
/// that target with a redirect of its own.
struct Move {
    target: String,
    at: Instant,
    bounced: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    H1,
    H2,
}

/// The per-connection facts every request asks.
pub struct Serve {
    filter: Arc<FilterSlot>,
    book: Arc<Mutex<FlowBook>>,
    hook: Arc<dyn ResponseHook>,
    watch: Arc<dyn ClientWatch>,
    flow_id: u64,
    pair: Pair,
    sni: String,
    port: u16,
    clock: fn() -> u64,
    seen: AtomicBool,
    splice: Mutex<Option<AbortOnDrop<()>>>,
    in_flight: Arc<watch::Sender<usize>>,
    /// The 307s sent to remove parameters, newest last, at most [`MOVES_KEPT`].
    moves: Mutex<Vec<Move>>,
}

impl Serve {
    #[allow(clippy::too_many_arguments)]
    pub fn new(filter: Arc<FilterSlot>, book: Arc<Mutex<FlowBook>>, hook: Arc<dyn ResponseHook>, watch: Arc<dyn ClientWatch>, flow_id: u64, pair: Pair, sni: String, port: u16, clock: fn() -> u64) -> Self {
        Self { filter, book, hook, watch, flow_id, pair, sni, port, clock, seen: AtomicBool::new(false), splice: Mutex::new(None), in_flight: Arc::new(watch::Sender::new(0)), moves: Mutex::new(Vec::new()) }
    }

    fn moves(&self) -> std::sync::MutexGuard<'_, Vec<Move>> {
        let mut moves = self.moves.lock().unwrap_or_else(|p| p.into_inner());
        moves.retain(|m| m.at.elapsed() < MOVE_MEMORY);
        moves
    }

    fn remember_move(&self, target: &str) {
        let mut moves = self.moves();
        moves.retain(|m| m.target != target);
        if moves.len() == MOVES_KEPT {
            moves.remove(0);
        }
        moves.push(Move { target: target.to_string(), at: Instant::now(), bounced: false });
    }

    /// The site answered `url` with a redirect.
    fn note_bounce(&self, url: &str) {
        for m in self.moves().iter_mut().filter(|m| m.target == url) {
            m.bounced = true;
        }
    }

    /// This connection sent a 307 to `target` and the site sent it straight back
    /// (with the parameters, or the redirect to it would not be asked): another
    /// 307 would loop.
    fn bounced_back(&self, target: &str) -> bool {
        self.moves().iter().any(|m| m.target == target && m.bounced)
    }

    pub fn request_was_seen(&self) -> bool {
        self.seen.load(Ordering::Relaxed)
    }

    fn stream_in_flight(&self) -> InFlight {
        self.in_flight.send_modify(|n| *n += 1);
        InFlight(self.in_flight.clone())
    }

    /// Resolves once no stream is in flight and the close has had its grace.
    async fn settled(&self) {
        let _ = self.in_flight.subscribe().wait_for(|n| *n == 0).await;
        tokio::time::sleep(CLOSE_GRACE).await;
    }

    fn log(&self, facts: &facts::OwnedFacts, outcome: LogOutcome, rule: Option<&str>, list: Option<&str>, changes: Vec<LogChange>) {
        let row = RequestRow { url: &facts.url, request_type: facts.request_type, outcome, rule, list, changes };
        self.book.lock().unwrap_or_else(|p| p.into_inner()).log_request(self.flow_id, row, (self.clock)());
    }
}

/// A request's log row, with what tracking protection changed on the way. Written
/// once: by [`Row::write`], or when the request ends without it (the client went,
/// the upstream failed), so a request is never missing from the log.
struct Row {
    ctx: Arc<Serve>,
    facts: facts::OwnedFacts,
    outcome: LogOutcome,
    rule: Option<String>,
    list: Option<String>,
    changes: Changes,
    written: bool,
}

impl Row {
    fn new(ctx: Arc<Serve>, facts: facts::OwnedFacts, ruling: &rules::Ruling) -> Self {
        Self { ctx, facts, outcome: ruling.outcome.clone(), rule: ruling.rule.clone(), list: ruling.list.clone(), changes: ruling.changes.clone(), written: false }
    }

    /// The request goes as the browser sent it: what removing its parameters
    /// would have changed is not done, and the row says why.
    fn keep_params(&mut self) {
        self.outcome = LogOutcome::Passed { reason: PARAMS_KEPT.to_string() };
        self.changes = Changes::default();
    }

    fn write(&mut self) {
        if std::mem::replace(&mut self.written, true) {
            return;
        }
        let changes = std::mem::take(&mut self.changes).into_vec();
        self.ctx.log(&self.facts, self.outcome.clone(), self.rule.as_deref(), self.list.as_deref(), changes);
    }
}

impl Drop for Row {
    fn drop(&mut self) {
        self.write();
    }
}

/// How a pair of connections ended.
pub struct Ended {
    /// What ended the upstream, when something did. `tls::intercept` looks in
    /// it for a post-handshake certificate request.
    pub upstream_error: Option<hyper::Error>,
    /// The client's side ended first, and not by the engine's timeout nor on bytes
    /// that did not parse, which are not silence. What `ClientWatch` may read as
    /// evidence about the client.
    pub client_ended: bool,
    /// The alert it ended with, when it sent one (plan 4.3's "right after"); the
    /// watch judges whether it is fatal.
    pub client_alert: Option<AlertDescription>,
}

impl Ended {
    pub fn without_error(client_ended: bool) -> Self {
        Self { upstream_error: None, client_ended, client_alert: None }
    }

    /// The server future's result, when it ended first.
    fn by_client(served: Result<(), hyper::Error>) -> Self {
        let Err(error) = served else { return Self::without_error(true) };
        // h1 calls bad bytes a parse error; on h2 the library goes away over them.
        let spoke = error.is_parse() || std::error::Error::source(&error).and_then(|e| e.downcast_ref::<h2::Error>()).is_some_and(h2::Error::is_library);
        let client_alert = alert_in(&error);
        Self { upstream_error: None, client_ended: !error.is_timeout() && (client_alert.is_some() || !spoke), client_alert }
    }
}

/// One stream open toward the upstream. Gone when that stream ends.
struct InFlight(Arc<watch::Sender<usize>>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n -= 1);
    }
}

/// A response body that holds its stream in flight until the body ends. Hints
/// pass through: hyper reads `Content-Length` and END_STREAM from them.
struct Counted {
    body: ResponseBody,
    stream: Option<InFlight>,
}

impl Body for Counted {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let frame = ready!(Pin::new(&mut self.body).poll_frame(cx));
        if matches!(frame, None | Some(Err(_))) {
            self.stream = None;
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

enum Upstream {
    H1(tokio::sync::Mutex<hyper::client::conn::http1::SendRequest<ResponseBody>>),
    H2(hyper::client::conn::http2::SendRequest<ResponseBody>),
}

impl Upstream {
    async fn send(&self, req: Request<ResponseBody>) -> hyper::Result<Response<Incoming>> {
        match self {
            Self::H1(sender) => {
                let mut sender = sender.lock().await;
                sender.ready().await?;
                sender.send_request(req).await
            }
            Self::H2(sender) => {
                let mut sender = sender.clone();
                sender.ready().await?;
                sender.send_request(req).await
            }
        }
    }

    /// On h2, a failure that proves the origin did not process the request
    /// (RFC 9113 8.7), so the client may send it again: the connection was gone
    /// before it went out, the stream is above the origin's GOAWAY, or the
    /// origin refused it. hyper hides an origin's graceful GOAWAY until a request
    /// wakes its task, so this is how such a request first learns of it. A
    /// stream at or below the GOAWAY is not in this set: it keeps running.
    fn refused(&self, error: &hyper::Error) -> bool {
        if matches!(self, Self::H1(_)) {
            return false;
        }
        let stream = std::error::Error::source(error).and_then(|e| e.downcast_ref::<h2::Error>());
        error.is_closed() || error.is_canceled() || stream.is_some_and(|e| (e.is_go_away() && e.is_remote()) || e.reason() == Some(h2::Reason::REFUSED_STREAM))
    }
}

fn empty() -> ResponseBody {
    UnsyncBoxBody::new(Empty::new().map_err(|e: Infallible| match e {}))
}

fn full(bytes: Vec<u8>) -> ResponseBody {
    UnsyncBoxBody::new(Full::new(Bytes::from(bytes)).map_err(|e: Infallible| match e {}))
}

fn answer(status: StatusCode) -> Response<ResponseBody> {
    let mut response = Response::new(empty());
    *response.status_mut() = status;
    response
}

/// One form of a host: lower case, no trailing dot.
fn normal_host(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// A request for a host this connection's leaf does not name, or for another
/// port: the exclusion check ran only for the SNI (plan 2.5, task D14).
fn misdirected(authority: Option<&str>, sni: &str, port: u16) -> bool {
    let Some(authority) = authority else { return true };
    let (host, explicit) = match authority.rsplit_once(':') {
        Some((host, p)) => match p.parse::<u16>() {
            Ok(p) => (host, Some(p)),
            Err(_) => return true,
        },
        None => (authority, None),
    };
    normal_host(host) != normal_host(sni) || explicit.is_some_and(|p| p != port)
}

/// The block answer: 403, empty, never cached.
fn blocked() -> Response<ResponseBody> {
    let mut response = answer(StatusCode::FORBIDDEN);
    response.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
    response
}

fn served(content_type: &str, body: Vec<u8>) -> Response<ResponseBody> {
    let mut response = Response::new(full(body));
    let headers = response.headers_mut();
    if let Ok(kind) = HeaderValue::from_str(content_type) {
        headers.insert(CONTENT_TYPE, kind);
    }
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static(ANY));
    headers.insert(CROSS_ORIGIN_RESOURCE_POLICY, HeaderValue::from_static(CROSS_ORIGIN));
    response
}

fn moved(to: &str) -> Response<ResponseBody> {
    let mut response = answer(StatusCode::TEMPORARY_REDIRECT);
    if let Ok(location) = HeaderValue::from_str(to) {
        response.headers_mut().insert(LOCATION, location);
    }
    response
}

/// The path and query of `url`, on `uri`'s scheme and authority.
fn with_path_of(uri: &Uri, url: &str) -> Option<Uri> {
    let target = url.parse::<Uri>().ok()?;
    let path: PathAndQuery = target.path_and_query()?.clone();
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(path);
    Uri::from_parts(parts).ok()
}

/// The per-request path. What the origin did not process is refused as a stream,
/// which a client retries by itself (hyper resets with the reason in the error);
/// anything else that cannot be answered is a 502.
async fn handle(ctx: Arc<Serve>, upstream: Arc<Upstream>, mut req: Request<Incoming>) -> Result<Response<ResponseBody>, BodyError> {
    // Once per connection: a busy h2 connection must not buy unbounded credit.
    if !ctx.seen.swap(true, Ordering::Relaxed) {
        ctx.watch.request_seen(&ctx.pair);
    }
    let authority = facts::authority_of(&req);
    if misdirected(authority.as_deref(), &ctx.sni, ctx.port) {
        let f = facts::of(&req, authority.as_deref().unwrap_or(&ctx.sni));
        ctx.log(&f, LogOutcome::Passed { reason: MISDIRECTED.to_string() }, None, None, Vec::new());
        let mut response = answer(StatusCode::MISDIRECTED_REQUEST);
        if req.version() < ::http::Version::HTTP_2 {
            response.headers_mut().insert(CONNECTION, HeaderValue::from_static(CLOSE));
        }
        return Ok(response);
    }
    let f = facts::of(&req, authority.as_deref().unwrap_or(&ctx.sni));
    // One snapshot for the request: the rules and the protections are read as one.
    let snapshot = ctx.filter.get();
    let ruling = rules::rule(&snapshot, &f.borrowed());
    let mut row = Row::new(ctx.clone(), f.clone(), &ruling);
    let rewritten = match ruling.action {
        Action::Block => return Ok(blocked()),
        Action::Serve { content_type, body } => return Ok(served(&content_type, body)),
        // The site sent the clean address back to this one: a loop, so this time
        // the page goes as asked.
        Action::RedirectTo(clean) if ctx.bounced_back(&clean) => {
            row.keep_params();
            None
        }
        Action::RedirectTo(clean) => {
            ctx.remember_move(&clean);
            return Ok(moved(&clean));
        }
        Action::Forward { rewritten } => rewritten,
    };
    if let Some(uri) = rewritten.as_deref().and_then(|url| with_path_of(req.uri(), url)) {
        *req.uri_mut() = uri;
    }
    let protections = snapshot.tracking_in_force();
    tracking::prepare_request(protections, tracking::party(req.headers()), req.headers_mut(), &mut row.changes);
    // A row waits for the response head only when a protection may change it, so
    // with none on every row is written when the request is ruled, as it always was.
    let cookies = tracking::cookie_cap(protections, tracking::cookie_party(req.headers()));
    let page = f.borrowed().is_page();
    if cookies.is_none() && !(page && (protections.has(Protection::QueryParams) || (snapshot.content && page_script(protections)))) {
        row.write();
    }
    let upgrading = is_upgrade(req.headers());
    let on_client_upgrade = upgrading.then(|| hyper::upgrade::on(&mut req));
    ctx.hook.prepare_request(&f.borrowed(), req.headers_mut());
    strip_hop_by_hop(req.headers_mut(), upgrading);
    let req = req.map(hook::boxed);
    let stream = ctx.stream_in_flight();
    let mut response = match upstream.send(req).await {
        Ok(response) => response,
        Err(e) if upstream.refused(&e) => return Err(Box::new(h2::Error::from(h2::Reason::REFUSED_STREAM))),
        Err(_) => return Ok(answer(StatusCode::BAD_GATEWAY)),
    };
    if let Some(p) = cookies {
        row.changes.add(p, tracking::cap_set_cookies(response.headers_mut(), tracking::now_s()));
    }
    let location = response.headers().get(LOCATION).and_then(|v| v.to_str().ok()).map(str::to_string);
    if page && response.status().is_redirection() && let Some(location) = location {
        // Only a redirect that carries a query can bring a parameter back.
        if location.contains('?') {
            ctx.note_bounce(&f.url);
        }
        if let Some((clean, removed)) = rules::clean_location(&snapshot, &f.borrowed(), &location)
            && let Ok(value) = HeaderValue::from_str(&clean)
        {
            response.headers_mut().insert(LOCATION, value);
            row.changes.add(Protection::QueryParams, removed);
        }
    }
    if let (StatusCode::SWITCHING_PROTOCOLS, Some(client)) = (response.status(), on_client_upgrade) {
        let on_upstream_upgrade = hyper::upgrade::on(&mut response);
        *ctx.splice.lock().unwrap_or_else(|p| p.into_inner()) = Some(splice(client, on_upstream_upgrade));
        return Ok(response.map(|_| empty()));
    }
    strip_hop_by_hop(response.headers_mut(), false);
    let (mut parts, body) = response.into_parts();
    let (body, page_changes) = hook::apply(ctx.hook.as_ref(), &f.borrowed(), parts.status, &mut parts.headers, body).await;
    row.changes.extend(page_changes);
    row.write();
    Ok(Response::from_parts(parts, UnsyncBoxBody::new(Counted { body, stream: Some(stream) })))
}

/// A protection that lives in the page's script, which only the content hook writes.
fn page_script(on: Protections) -> bool {
    [Protection::WebRtc, Protection::Push, Protection::Location].into_iter().any(|p| on.has(p))
}

/// Takes the pair to its end, however it ends.
pub async fn serve<C, U>(ctx: Arc<Serve>, client: C, upstream: U, proto: Proto) -> Ended
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (client, upstream) = (TokioIo::new(client), TokioIo::new(upstream));
    let shared = ctx.clone();
    macro_rules! race {
        ($server:expr, $connection:expr, $sender:expr) => {{
            let sender = Arc::new($sender);
            let service = service_fn(move |req| handle(shared.clone(), sender.clone(), req));
            // Its own task, as a select could otherwise drop it: an upgrade hands
            // its socket over only after this connection read the head.
            let mut connection = AbortOnDrop(tokio::spawn($connection));
            let server = $server(service);
            tokio::pin!(server);
            let ended = tokio::select! {
                served = &mut server => Ended::by_client(served),
                result = &mut connection.0 => {
                    let upstream_error = result.ok().and_then(Result::err);
                    // The client hears it, and what the origin accepted runs on:
                    // hyper drives those streams apart from this future.
                    server.as_mut().graceful_shutdown();
                    tokio::select! {
                        _ = &mut server => {}
                        () = ctx.settled() => {}
                    }
                    Ended { upstream_error, client_ended: false, client_alert: None }
                }
            };
            let upgraded = ctx.splice.lock().unwrap_or_else(|p| p.into_inner()).take();
            if let Some(mut task) = upgraded {
                let _ = (&mut task.0).await;
            }
            ended
        }};
    }
    match proto {
        Proto::H1 => {
            let Ok((sender, connection)) = hyper::client::conn::http1::Builder::new().preserve_header_case(true).handshake(upstream).await else {
                return Ended::without_error(false);
            };
            let builder = {
                let mut b = hyper::server::conn::http1::Builder::new();
                b.preserve_header_case(true).timer(TokioTimer::new());
                b
            };
            race!(|service| builder.serve_connection(client, service).with_upgrades(), connection.with_upgrades(), Upstream::H1(tokio::sync::Mutex::new(sender)))
        }
        Proto::H2 => {
            let Ok((sender, connection)) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .initial_stream_window_size(H2_STREAM_WINDOW)
                .initial_connection_window_size(H2_CONNECTION_WINDOW)
                .max_header_list_size(H2_MAX_HEADER_LIST)
                .handshake(upstream)
                .await
            else {
                return Ended::without_error(false);
            };
            let builder = {
                let mut b = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                b.initial_stream_window_size(H2_STREAM_WINDOW).initial_connection_window_size(H2_CONNECTION_WINDOW).max_header_list_size(H2_MAX_HEADER_LIST);
                b
            };
            race!(|service| builder.serve_connection(client, service), connection, Upstream::H2(sender))
        }
    }
}
