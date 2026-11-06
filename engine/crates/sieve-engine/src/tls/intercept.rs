//! The path of one TLS flow with `filtering.https` on (plan 2.6, task D4). Nothing
//! is answered to the client until step 6, so every "do not decrypt" found on
//! the way is a clean pass-through: the client then judges the real certificate.
//! 1. First bytes: client read and upstream read; a server that speaks first
//!    means the flow can only splice.
//! 2. The host-level decision, as on the plain path. A drop closes.
//! 3. `decrypt` with the cached verdict. PassThrough: the held bytes on the
//!    unused SYN-time socket, then splice.
//! 4. The upstream handshake on that socket, with ECH when the name's record has
//!    a config (a failure of that retries plain on a fresh socket), then its
//!    validation.
//! 5. `decrypt` with the verdict. PassThrough: a fresh TCP, replay, splice.
//! 6. Intercept: a minted leaf, the local handshake over the held bytes, then
//!    `http::serve`.
//!
//! TENSION (S14): two first-byte loops exist while the switch can be off,
//! `flow::relay::relay_tcp` and [`first_bytes`]. Off must provably be the old
//! path (`stack::relay::handle_tcp` asks [`HttpsSlot`] once), and both share
//! `TcpClassifier`, so they cannot disagree about what a flow is.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use rustls::{AlertDescription, NamedGroup};
use sieve_filter::exclusions::{AutoReason, Decrypt, Floor, FlowFacts, PassReason, Transport, UpstreamVerdict, decrypt};
use sieve_ipc::FlowAction;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;

use super::active::{Active, Registered};
use super::ech::{EchCache, usable_config};
use super::first_bytes::{First, read_first};
use super::server::{server_config, speaks_to};
use super::splice::{AppSide, Prefixed, splice};
use super::upstream::{HandshakeEnd, Handshaken, LeafFacts, Verifier, filter_alpn, handshake, is_post_handshake_auth, leaf_facts, rustls_error};
use super::verdict::VerdictCache;
use crate::ca::{CaError, LeafRequest, Minter};
use crate::dns::NameMap;
use crate::domain::FilterSlot;
use crate::exclusions::{AutoEntry, ExclusionSlot};
use crate::flow::classify::{Decoded, Kind};
use crate::flow::flows::Action;
use crate::flow::relay::relay_tcp;
use crate::http::hook::ResponseHook;
use crate::http::serve::{Ended, Proto, Serve, serve};
use crate::stack::Meters;
use crate::stack::book::FlowBook;

/// A flow that sends nothing this long is decided without a name.
pub const FIRST_BYTES_WAIT: Duration = Duration::from_secs(5);
/// How long a client may take over the local handshake.
pub const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const H2: &[u8] = b"h2";
const HTTP1: &[u8] = b"http/1.1";

pub type DialFuture<'a, S> = Pin<Box<dyn Future<Output = Result<S, String>> + Send + 'a>>;

/// Where a fresh upstream socket comes from: `stack::egress::Egress` in
/// production (pinned outside Sieve's routes), an in-memory or loopback one in
/// tests. The only way this path opens a socket.
pub trait Dial: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn dial(&self, target: SocketAddr) -> DialFuture<'_, Self::Stream>;
}

/// An (app, host) as slice 7's evidence reads it (plan 4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pair {
    pub exe: Option<String>,
    pub host: String,
}

/// What the client side did, for self-healing (slice 7). `NoWatch` until then.
pub trait ClientWatch: Send + Sync {
    /// The client refused our handshake, with its alert when it sent one.
    fn handshake_failed(&self, pair: &Pair, alert: Option<AlertDescription>);
    /// A request arrived on an intercepted connection.
    fn request_seen(&self, pair: &Pair);
    /// The client closed after the handshake without one request.
    fn closed_without_request(&self, pair: &Pair, after: Duration);
}

pub struct NoWatch;

impl ClientWatch for NoWatch {
    fn handshake_failed(&self, _: &Pair, _: Option<AlertDescription>) {}
    fn request_seen(&self, _: &Pair) {}
    fn closed_without_request(&self, _: &Pair, _: Duration) {}
}

/// What every intercepted flow shares. Built only with the switch on.
pub struct Interception<C> {
    pub connector: Arc<C>,
    pub exclusions: Arc<ExclusionSlot>,
    pub verifier: Arc<Verifier>,
    pub verdicts: VerdictCache,
    /// The upstream hello's ECH configs (plan 2.9).
    pub ech: Arc<EchCache>,
    pub active: Active,
    /// The CA's minter now; None while no installed, in-date root exists.
    pub minter: Box<dyn Fn() -> Option<Arc<Minter>> + Send + Sync>,
    pub filter: Arc<FilterSlot>,
    pub names: Arc<Mutex<NameMap>>,
    pub book: Arc<Mutex<FlowBook>>,
    pub meters: Arc<Meters>,
    pub watch: Arc<dyn ClientWatch>,
    pub hook: Arc<dyn ResponseHook>,
    /// The wall clock, in ms (S15).
    pub clock: fn() -> u64,
}

/// One flow as the relay knows it.
pub struct FlowMeta<'a> {
    /// In the flow book.
    pub id: u64,
    pub remote: SocketAddr,
    pub exe: Option<&'a str>,
    pub session: Option<u32>,
    /// `domain::Owner::may_decrypt`.
    pub may_decrypt: bool,
    /// The app's row is Off (`DomainFilter::is_off`).
    pub app_off: bool,
    /// Monotonic ms of the name map's clock.
    pub names_now_ms: u64,
    /// The host-level decision: called exactly once.
    pub decide: &'a (dyn Fn(&Decoded) -> Action + Send + Sync),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub action: FlowAction,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

/// How `filtering.https` reaches the relay. `None` (switch off, or not sieving)
/// means today's `relay_tcp`, unchanged. Asked once per flow.
pub struct HttpsSlot<C>(RwLock<Option<Arc<Interception<C>>>>);

impl<C> Default for HttpsSlot<C> {
    fn default() -> Self {
        Self(RwLock::new(None))
    }
}

impl<C> HttpsSlot<C> {
    pub fn get(&self) -> Option<Arc<Interception<C>>> {
        self.0.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Replaces what new flows get. Taking it away closes every intercepted
    /// flow: nobody stays decrypted after the switch went off.
    pub fn set(&self, next: Option<Arc<Interception<C>>>) {
        let before = std::mem::replace(&mut *self.0.write().unwrap_or_else(|p| p.into_inner()), next);
        if let Some(before) = before {
            before.active.close_all();
        }
    }
}

/// The switch of one policy: HTTPS filtering only while sieving (plan 8).
pub fn wanted(policy: &sieve_ipc::Policy) -> bool {
    policy.https && policy.sieving
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// A rejected verdict stands in for the handshake; an `Eligible` does not, since
/// each client connection needs its own upstream.
fn rejection(verdict: UpstreamVerdict) -> Option<UpstreamVerdict> {
    (verdict != UpstreamVerdict::Eligible).then_some(verdict)
}

impl<C: Dial> Interception<C> {
    fn says(&self, facts: &FlowFacts<'_>) -> Decrypt {
        let store = self.exclusions.get_at((self.clock)());
        // A closed set means the switch went off after this flow took the slot.
        let switches = self.exclusions.switches(!self.active.is_closed(), (self.minter)().is_some());
        decrypt(facts, &store, &switches)
    }

    fn not_decrypted(&self, id: u64, reason: &PassReason) {
        Meters::bump(&self.meters.https.passed);
        lock(&self.book).log_not_decrypted(id, &reason.slug(), (self.clock)());
    }

    /// An entry the engine writes itself. One that cannot reach the disk still
    /// holds for this run, and comes back at its next sighting after a restart.
    fn exclude(&self, host: &str, reason: AutoReason, expires_ms: Option<u64>) {
        let now = (self.clock)();
        self.exclusions.add_auto(AutoEntry::host(host, reason, now, expires_ms), now);
    }

    /// The pass-through after an upstream handshake: its socket has spoken, so
    /// the client's bytes go on a fresh one. A failed connect closes the app.
    async fn fresh_splice<A>(&self, app: &mut AppSide<A>, remote: SocketAddr, held: &[u8]) -> FlowAction
    where
        A: AsyncRead + AsyncWrite + Unpin,
    {
        let Ok(fresh) = self.connector.dial(remote).await else { return FlowAction::Failed };
        if splice(app, fresh, held).await { FlowAction::Relayed } else { FlowAction::Failed }
    }

    /// Step 4's handshake. A config rustls cannot use is no config. Any failure of
    /// an attempt with ECH leaves no verdict, marks the host and dials a fresh
    /// socket for the plain handshake; a failed dial is `Unavailable`, which ends
    /// in `fresh_splice`.
    async fn shake(&self, upstream: C::Stream, host: &str, remote: SocketAddr, alpn: Vec<Vec<u8>>) -> HandshakeEnd<C::Stream> {
        let now = (self.clock)();
        let config = self.ech.config_for(host, remote.port(), now).await.and_then(|list| usable_config(&list));
        let Some(config) = config else { return handshake(upstream, host, alpn, None).await };
        let meters = &self.meters.https;
        Meters::bump(&meters.ech_offered);
        match handshake(upstream, host, alpn.clone(), Some(config)).await {
            HandshakeEnd::EchFailed => {
                Meters::bump(&meters.ech_failed);
                self.ech.mark_negative(host, now);
                let Ok(fresh) = self.connector.dial(remote).await else { return HandshakeEnd::Failed(UpstreamVerdict::Unavailable) };
                handshake(fresh, host, alpn, None).await
            }
            end => {
                if matches!(end, HandshakeEnd::Done(_)) {
                    Meters::bump(&meters.ech_accepted);
                }
                end
            }
        }
    }

    /// The rest of the path once an intercepted connection ended.
    fn after_serve(&self, host: &str, upstream_error: Option<&hyper::Error>) {
        let auth = upstream_error.and_then(|e| rustls_error(e)).is_some_and(is_post_handshake_auth);
        if auth {
            self.exclude(host, AutoReason::ClientCert, None);
        }
    }
}

/// Meters the key exchange of one side (task D18).
fn count_group(meters: &[std::sync::atomic::AtomicU64; crate::stack::KX_GROUPS], group: Option<NamedGroup>) {
    let slot = match group {
        Some(NamedGroup::X25519MLKEM768) => 0,
        Some(NamedGroup::X25519) => 1,
        Some(NamedGroup::secp256r1) => 2,
        _ => return,
    };
    meters[slot].fetch_add(1, Ordering::Relaxed);
}

/// The alert a client's refusal carried, if it sent one.
fn client_alert(error: &std::io::Error) -> Option<AlertDescription> {
    match rustls_error(error) {
        Some(rustls::Error::AlertReceived(alert)) => Some(*alert),
        _ => None,
    }
}

/// One flow, to its end. The app side is closed before this returns unless the
/// flow ended by itself.
pub async fn run<A, C>(deps: &Interception<C>, app: A, upstream: C::Stream, flow: FlowMeta<'_>) -> Outcome
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C: Dial,
{
    let side = AppSide::new(app);
    let action = drive(deps, side.clone(), upstream, &flow).await;
    side.close().await;
    let (bytes_up, bytes_down) = side.counted();
    Outcome { action, bytes_up, bytes_down }
}

async fn drive<A, C>(deps: &Interception<C>, mut app: AppSide<A>, mut upstream: C::Stream, flow: &FlowMeta<'_>) -> FlowAction
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C: Dial,
{
    let (decoded, held) = match read_first(&mut app, &mut upstream, FIRST_BYTES_WAIT).await {
        First::ClientGone => return FlowAction::Relayed,
        First::ServerSpoke { server, held } => return server_first(app, upstream, server, held, flow).await,
        First::Decoded { decoded, held } => (decoded, held),
    };
    if (flow.decide)(&decoded) == Action::Drop {
        return FlowAction::Blocked;
    }
    if decoded.kind != Some(Kind::Tls) {
        return if splice(&mut app, upstream, &held).await { FlowAction::Relayed } else { FlowAction::Failed };
    }
    let host = decoded.domain.as_deref();
    // Task D9: the engine's own DNS answered this SNI for this address, so the
    // app resolved the SNI itself and the extension is GREASE. A wrong "GREASE"
    // cannot leak: the client reads our answer as ECH rejected, authenticates
    // the public name and retries without ECH under a normal decision.
    let ech = decoded.ech && !host.is_some_and(|h| lock(&deps.names).names(flow.remote.ip(), flow.names_now_ms).contains(&h));
    let facts = FlowFacts {
        transport: Transport::Tcp,
        may_decrypt: flow.may_decrypt,
        exe: flow.exe,
        session: flow.session,
        host,
        ip: flow.remote.ip(),
        port: flow.remote.port(),
        alpn: &decoded.alpn,
        ech,
        client_compatible: speaks_to(&decoded.offer),
        app_in_scope: deps.exclusions.in_scope(flow.exe),
        app_off: flow.app_off,
        upstream: None,
    };
    // Before the cache is read: see `active`, no close can fall in the gap.
    let registered = host.map(|h| deps.active.register(h));
    let cached = host.and_then(|h| deps.verdicts.get(h, flow.remote.port(), (deps.clock)()));
    let before = FlowFacts { upstream: cached.and_then(|c| rejection(c.verdict)), ..facts };
    if let Decrypt::PassThrough(reason) = deps.says(&before) {
        drop(registered);
        deps.not_decrypted(flow.id, &reason);
        return if splice(&mut app, upstream, &held).await { FlowAction::Relayed } else { FlowAction::Failed };
    }
    // `decrypt` said a name is there, or it would have been `floor:no-sni`.
    let (Some(host), Some(registered)) = (host, registered) else { return FlowAction::Relayed };

    let (shaken, verdict) = match deps.shake(upstream, host, flow.remote, filter_alpn(&decoded.alpn)).await {
        // Written down only if the chain is good: anyone can ask, and the rest
        // stay in the bounded verdict cache. No trust call: the flow passes
        // through either way.
        HandshakeEnd::ClientCertificate(chain) => {
            let verdict = deps.verifier.verify(&chain, host, true, (deps.clock)()).await;
            if verdict == UpstreamVerdict::Eligible {
                deps.exclude(host, AutoReason::ClientCert, None);
            } else {
                let facts_of_leaf = leaf_facts(&chain.end_entity);
                deps.verdicts.put(host, flow.remote.port(), verdict, facts_of_leaf.map(|l| l.hash), facts_of_leaf.map(|l| l.not_after_ms), (deps.clock)());
            }
            (None, verdict)
        }
        HandshakeEnd::Failed(verdict) => {
            deps.verdicts.put(host, flow.remote.port(), verdict, None, None, (deps.clock)());
            (None, verdict)
        }
        // `shake` retries it, and the retry offers no ECH: this cannot come back.
        HandshakeEnd::EchFailed => (None, UpstreamVerdict::Unavailable),
        HandshakeEnd::Done(shaken) => {
            let facts_of_leaf = leaf_facts(&shaken.chain.end_entity);
            let leaf = facts_of_leaf.map(|l| l.hash);
            let known = cached.is_some_and(|c| c.verdict == UpstreamVerdict::Eligible && c.leaf.is_some() && c.leaf == leaf);
            let verdict = deps.verifier.verify(&shaken.chain, host, known, (deps.clock)()).await;
            // Whoever closed this flow knows better than its `Eligible`, which
            // is then not a fact to keep. A known leaf keeps its expiry: the 24 h
            // run from the trust call that was really made, or a visited host
            // would never reach it again.
            let closed = registered.is_closed();
            if !(verdict == UpstreamVerdict::Eligible && (known || closed)) {
                deps.verdicts.put(host, flow.remote.port(), verdict, leaf, facts_of_leaf.map(|l| l.not_after_ms), (deps.clock)());
            }
            if verdict == UpstreamVerdict::Eligible
                && !closed
                && let Some(l) = facts_of_leaf.filter(|l| l.ev)
            {
                deps.exclude(host, AutoReason::Ev, Some(l.not_after_ms));
            }
            (Some((shaken, facts_of_leaf)), verdict)
        }
    };
    // However the handshake ended: the cached verdict makes later flows skip
    // theirs, so no other flow would close the open ones.
    if verdict == UpstreamVerdict::Revoked {
        deps.active.close_host(host);
    }
    // Another flow found this host revoked while this one was asking.
    let verdict = if verdict == UpstreamVerdict::Eligible && registered.is_closed() { UpstreamVerdict::Revoked } else { verdict };
    let after = FlowFacts { upstream: Some(verdict), ..facts };
    let judged = deps.says(&after);
    let (shaken, leaf) = match (judged, shaken) {
        (Decrypt::Intercept, Some((shaken, Some(leaf)))) => (shaken, leaf),
        (judged, shaken) => {
            let reason = match judged {
                Decrypt::PassThrough(reason) => reason,
                Decrypt::Intercept => PassReason::Floor(Floor::UpstreamInvalid),
            };
            // The handshaken session is of no more use: the server must not
            // hold two connections for this flow.
            drop(shaken);
            drop(registered);
            deps.not_decrypted(flow.id, &reason);
            return deps.fresh_splice(&mut app, flow.remote, &held).await;
        }
    };
    intercept(deps, app, *shaken, leaf, registered, held, flow).await
}

/// Step 1's other ending: the server's bytes go to the app and the flow can
/// only splice, on the offline-tested relay, which still asks the decision.
async fn server_first<A, U>(mut app: AppSide<A>, upstream: U, server: Vec<u8>, held: Vec<u8>, flow: &FlowMeta<'_>) -> FlowAction
where
    A: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    if app.write_all(&server).await.is_err() {
        return FlowAction::Failed;
    }
    let mut replayed = Prefixed::new(held, app);
    let out = relay_tcp(&mut replayed, upstream, FIRST_BYTES_WAIT, |d| (flow.decide)(d)).await;
    match (out.dropped, out.upstream_write_failed) {
        (true, _) => FlowAction::Blocked,
        (_, true) => FlowAction::Failed,
        _ => FlowAction::Relayed,
    }
}

/// Step 6.
async fn intercept<A, C>(deps: &Interception<C>, mut app: AppSide<A>, shaken: Handshaken<C::Stream>, leaf: LeafFacts, registered: Registered, held: Vec<u8>, flow: &FlowMeta<'_>) -> FlowAction
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C: Dial,
{
    let host = registered.host();
    let now = (deps.clock)();
    let minted = (deps.minter)().ok_or(PassReason::Floor(Floor::NoRoot)).and_then(|minter| match minter.leaf(LeafRequest { host, upstream_not_after_ms: leaf.not_after_ms }, now) {
        Ok(minted) => Ok((minter, minted)),
        Err(CaError::Host(_)) => Err(PassReason::Floor(Floor::NoSni)),
        Err(_) => Err(PassReason::Floor(Floor::NoRoot)),
    });
    let config = minted.and_then(|(minter, minted)| {
        let alpn = shaken.alpn.iter().cloned().collect();
        server_config(minted.der.clone(), minter.root_der().to_vec(), minter.leaf_key_pkcs8().to_vec(), alpn).map_err(|_| PassReason::Floor(Floor::NoRoot))
    });
    let config = match config {
        Ok(config) => config,
        Err(reason) => {
            drop(shaken);
            drop(registered);
            deps.not_decrypted(flow.id, &reason);
            return deps.fresh_splice(&mut app, flow.remote, &held).await;
        }
    };
    let pair = Pair { exe: flow.exe.map(str::to_string), host: host.to_string() };
    // The client has our answer by now, so a close can only end the flow. That
    // says nothing about the client, so the watch does not hear of it.
    let accepted = tokio::select! {
        biased;
        () = registered.closed() => return FlowAction::Relayed,
        accepted = tokio::time::timeout(CLIENT_HANDSHAKE_TIMEOUT, TlsAcceptor::from(config).accept(Prefixed::new(held, app))) => accepted,
    };
    let client = match accepted {
        Ok(Ok(client)) => client,
        Ok(Err(e)) => {
            deps.watch.handshake_failed(&pair, client_alert(&e));
            return FlowAction::Failed;
        }
        Err(_) => {
            deps.watch.handshake_failed(&pair, None);
            return FlowAction::Failed;
        }
    };
    Meters::bump(&deps.meters.https.intercepted);
    count_group(&deps.meters.https.upstream_groups, shaken.group);
    count_group(&deps.meters.https.client_groups, client.get_ref().1.negotiated_key_exchange_group().map(|g| g.name()));

    let started = Instant::now();
    let ctx = Arc::new(Serve::new(deps.filter.clone(), deps.book.clone(), deps.hook.clone(), deps.watch.clone(), flow.id, pair.clone(), host.to_string(), flow.remote.port(), deps.clock));
    let ended = tokio::select! {
        biased;
        () = registered.closed() => Ended::without_error(false),
        ended = run_protocol(ctx.clone(), client, shaken.tls, shaken.alpn.as_deref()) => ended,
    };
    deps.after_serve(host, ended.upstream_error.as_ref());
    // Evidence about the client only if the client did it (task D17, plan 4.3).
    if ended.client_ended && !ctx.request_was_seen() {
        deps.watch.closed_without_request(&pair, started.elapsed());
    }
    FlowAction::Relayed
}

/// Which protocol the pair of sessions speaks: what the server chose. With no
/// ALPN at all, HTTP/1.1 only if the first decrypted bytes parse as HTTP; else
/// the two sessions are copied as plain bytes (plan 2.8), and a copy cannot say
/// which side ended it, so it is no evidence about the client.
async fn run_protocol<C, U>(ctx: Arc<Serve>, mut client: C, mut upstream: U, alpn: Option<&[u8]>) -> Ended
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match alpn {
        Some(H2) => serve(ctx, client, upstream, Proto::H2).await,
        Some(HTTP1) => serve(ctx, client, upstream, Proto::H1).await,
        Some(_) => Ended::without_error(false),
        None => match read_first(&mut client, &mut upstream, FIRST_BYTES_WAIT).await {
            First::ClientGone => Ended::without_error(true),
            First::Decoded { decoded, held } if decoded.kind == Some(Kind::Http) && decoded.domain.is_some() => serve(ctx, Prefixed::new(held, client), upstream, Proto::H1).await,
            First::Decoded { held, .. } => {
                let _ = splice(&mut client, upstream, &held).await;
                Ended::without_error(false)
            }
            First::ServerSpoke { server, held } => {
                if client.write_all(&server).await.is_ok() {
                    let _ = splice(&mut client, upstream, &held).await;
                }
                Ended::without_error(false)
            }
        },
    }
}
