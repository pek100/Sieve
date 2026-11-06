//! One kept-open session per upstream (plan 1.4), and the [`Exchange`] the
//! failover runs on.
//!
//! - Connecting runs in a task owned by the upstream's slot: a query cut off by
//!   its share does not throw away a handshake on a slow link, and concurrent
//!   queries share one connect. Dropping the pool ends everything, so nothing
//!   outlives the engine's routes.
//! - A query cancelled while it waited on a session marks that session suspect,
//!   and the next query replaces it. This replaces a dead NAT mapping with no
//!   keep-alive pings.
//! - A reused session whose link fails gets one retry on a fresh session (DNS
//!   queries are idempotent; servers close idle connections).
//! - An upstream's address is an IP literal, or a [`Resolver`] entry, or else
//!   is looked up over those resolvers, encrypted. Never over plain DNS.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use serde::Serialize;
use tokio::sync::watch;

use super::upstream::{self, Exchange, Health, Kind, Resolver, Upstream};
use super::{BoxFuture, Connector, Owned, TYPE_A, TYPE_AAAA, doh, doq, dot, parse, query_for, reply_fits};
use crate::tls;

/// One address gets this long to connect and finish its handshake.
const CONNECT_ATTEMPT: Duration = Duration::from_secs(3);

/// Why a query got no answer from a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fail {
    /// The session cannot carry queries any more.
    Link(String),
    /// The session is fine; this reply is not an answer.
    Reply(String),
}

impl Fail {
    fn message(self) -> String {
        match self {
            Fail::Link(m) | Fail::Reply(m) => m,
        }
    }
}

/// What a session negotiated, for `dns-status.json` (plan 2.7's live check).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TlsFacts {
    pub kx_group: Option<String>,
    pub alpn: Option<String>,
}

impl TlsFacts {
    pub(crate) fn of(connection: &rustls::ClientConnection) -> Self {
        Self {
            kx_group: connection.negotiated_key_exchange_group().map(|g| format!("{:?}", g.name())),
            alpn: connection.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned()),
        }
    }
}

/// One upstream's facts; never a queried name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamReport {
    pub address: String,
    pub connected: bool,
    #[serde(flatten)]
    pub tls: TlsFacts,
    pub answers: u64,
    pub failures: u64,
}

/// The client configurations of the three kinds, built once.
pub struct Tls {
    doh: Arc<rustls::ClientConfig>,
    dot: Arc<rustls::ClientConfig>,
    doq: quinn::ClientConfig,
}

impl Tls {
    pub fn new(roots: Arc<RootCertStore>) -> Result<Self, String> {
        Ok(Self {
            doh: Arc::new(tls::client_config(roots.clone(), &[doh::ALPN])?),
            dot: Arc::new(tls::client_config(roots.clone(), &[dot::ALPN])?),
            doq: doq::quic_config(tls::client_config(roots, &[doq::ALPN])?)?,
        })
    }
}

/// What every pool is built from.
#[derive(Clone)]
pub struct Context {
    pub connector: Arc<dyn Connector>,
    pub tls: Arc<Tls>,
    /// The resolvers whose addresses are known, used for bootstrap.
    pub resolvers: Vec<Resolver>,
}

enum Session {
    Doh(doh::Session),
    Dot(dot::Session),
    Doq(doq::Session),
}

/// A session and whether the next query may use it.
struct Live {
    session: Session,
    facts: TlsFacts,
    suspect: AtomicBool,
}

/// Marks the session suspect unless the query ran to its end.
struct Cancelled<'a>(Option<&'a Live>);

impl Drop for Cancelled<'_> {
    fn drop(&mut self) {
        if let Some(live) = self.0 {
            live.suspect.store(true, Ordering::Relaxed);
        }
    }
}

impl Live {
    fn usable(&self) -> bool {
        !self.suspect.load(Ordering::Relaxed)
            && match &self.session {
                Session::Doh(s) => s.alive(),
                Session::Dot(s) => s.alive(),
                Session::Doq(s) => s.alive(),
            }
    }

    async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, Fail> {
        let mut cancelled = Cancelled(Some(self));
        let out = match &self.session {
            Session::Doh(s) => s.exchange(query).await,
            Session::Dot(s) => s.exchange(query).await,
            Session::Doq(s) => s.exchange(query).await,
        };
        cancelled.0 = None;
        out
    }
}

type Connected = Option<Result<Arc<Live>, String>>;

struct Connecting {
    done: watch::Receiver<Connected>,
    _task: Owned,
}

#[derive(Default)]
struct State {
    session: Option<Arc<Live>>,
    connecting: Option<Connecting>,
}

struct Slot {
    upstream: Upstream,
    state: Mutex<State>,
    answers: AtomicU64,
    failures: AtomicU64,
}

impl Slot {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn discard(&self, live: &Arc<Live>) {
        let mut state = self.lock();
        if state.session.as_ref().is_some_and(|s| Arc::ptr_eq(s, live)) {
            state.session = None;
        }
    }
}

/// The encrypted lookup of an upstream's own name.
struct Bootstrap {
    endpoints: Vec<Upstream>,
    pool: Pool,
    health: Health,
}

struct Links {
    connector: Arc<dyn Connector>,
    tls: Arc<Tls>,
    resolvers: Vec<Resolver>,
    bootstrap: Option<Bootstrap>,
}

pub struct Pool {
    slots: Vec<Arc<Slot>>,
    links: Arc<Links>,
}

fn slots(endpoints: &[Upstream]) -> Vec<Arc<Slot>> {
    endpoints
        .iter()
        .map(|upstream| Arc::new(Slot { upstream: upstream.clone(), state: Mutex::default(), answers: AtomicU64::new(0), failures: AtomicU64::new(0) }))
        .collect()
}

impl Pool {
    pub fn new(endpoints: &[Upstream], context: &Context) -> Self {
        let known = |u: &Upstream| u.host.parse::<IpAddr>().is_ok() || context.resolvers.iter().any(|r| r.upstream.host == u.host);
        let bootstrap = (!endpoints.iter().all(known)).then(|| {
            let endpoints: Vec<Upstream> = context.resolvers.iter().map(|r| r.upstream.clone()).collect();
            let links = Links { connector: context.connector.clone(), tls: context.tls.clone(), resolvers: context.resolvers.clone(), bootstrap: None };
            Bootstrap { pool: Pool { slots: slots(&endpoints), links: Arc::new(links) }, endpoints, health: Health::default() }
        });
        let links = Links { connector: context.connector.clone(), tls: context.tls.clone(), resolvers: context.resolvers.clone(), bootstrap };
        Self { slots: slots(endpoints), links: Arc::new(links) }
    }

    pub fn report(&self) -> Vec<UpstreamReport> {
        self.slots
            .iter()
            .map(|slot| {
                let live = slot.lock().session.clone().filter(|l| l.usable());
                UpstreamReport {
                    address: slot.upstream.to_string(),
                    connected: live.is_some(),
                    tls: live.map(|l| l.facts.clone()).unwrap_or_default(),
                    answers: slot.answers.load(Ordering::Relaxed),
                    failures: slot.failures.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    /// The kept session, or the shared connect's result. True when reused.
    async fn session(&self, slot: &Arc<Slot>) -> Result<(Arc<Live>, bool), String> {
        let mut done = {
            let mut state = slot.lock();
            if let Some(live) = state.session.clone() {
                if live.usable() {
                    return Ok((live, true));
                }
                state.session = None;
            }
            if state.connecting.is_none() {
                state.connecting = Some(start_connect(slot, self.links.clone()));
            }
            state.connecting.as_ref().map(|c| c.done.clone()).ok_or("no connect is running")?
        };
        let connected = done.wait_for(Option::is_some).await.map_err(|_| "the connect was cancelled")?.clone();
        connected.ok_or("the connect gave no result")?.map(|live| (live, false))
    }

    async fn attempt(&self, slot: &Arc<Slot>, query: &[u8]) -> Result<Vec<u8>, String> {
        let (live, reused) = self.session(slot).await?;
        let reply = match live.exchange(query).await {
            Err(Fail::Link(why)) => {
                slot.discard(&live);
                if !reused {
                    return Err(why);
                }
                let (fresh, _) = self.session(slot).await?;
                let retried = fresh.exchange(query).await;
                if matches!(retried, Err(Fail::Link(_))) {
                    slot.discard(&fresh);
                }
                retried
            }
            other => other,
        };
        let reply = reply.map_err(Fail::message)?;
        if reply_fits(query, &reply) { Ok(reply) } else { Err(format!("{} answered another question", slot.upstream)) }
    }
}

impl Exchange for Pool {
    async fn exchange(&self, upstream: &Upstream, query: &[u8]) -> Result<Vec<u8>, String> {
        let slot = self.slots.iter().find(|s| s.upstream == *upstream).ok_or("the upstream is not in this pool")?;
        let mut unanswered = Unanswered(Some(&slot.failures));
        let out = self.attempt(slot, query).await;
        if out.is_ok() {
            unanswered.0 = None;
            slot.answers.fetch_add(1, Ordering::Relaxed);
        }
        out
    }
}

/// Counts a failure unless the query was answered, cancellation included.
struct Unanswered<'a>(Option<&'a AtomicU64>);

impl Drop for Unanswered<'_> {
    fn drop(&mut self) {
        if let Some(failures) = self.0 {
            failures.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Runs one connect in a task that ends with its slot.
fn start_connect(slot: &Arc<Slot>, links: Arc<Links>) -> Connecting {
    let weak: Weak<Slot> = Arc::downgrade(slot);
    let upstream = slot.upstream.clone();
    let (publish, done) = watch::channel(None);
    let task = Owned::spawn(async move {
        let connected = connect(&links, &upstream).await.map(Arc::new);
        let Some(slot) = weak.upgrade() else { return };
        // Taken out, and dropped after the publish: this task's own handle.
        let handle = {
            let mut state = slot.lock();
            if let Ok(live) = &connected {
                state.session = Some(live.clone());
            }
            state.connecting.take()
        };
        let _ = publish.send(Some(connected));
        drop(handle);
    });
    Connecting { done, _task: task }
}

async fn connect(links: &Links, upstream: &Upstream) -> Result<Live, String> {
    let addresses = addresses(links, upstream).await?;
    let mut failures = Vec::new();
    for address in addresses {
        match tokio::time::timeout(CONNECT_ATTEMPT, open(links, upstream, address)).await {
            Ok(Ok(live)) => return Ok(live),
            Ok(Err(why)) => failures.push(why),
            Err(_) => failures.push(format!("{address}: no handshake in time")),
        }
    }
    Err(format!("{upstream}: {}", failures.join("; ")))
}

async fn open(links: &Links, upstream: &Upstream, address: SocketAddr) -> Result<Live, String> {
    let connector = links.connector.as_ref();
    let name = || ServerName::try_from(upstream.host.clone()).map_err(|e| format!("{}: {e}", upstream.host));
    let (session, facts) = match upstream.kind {
        Kind::Https => {
            let uri = upstream.to_string().parse().map_err(|e| format!("{upstream}: {e}"))?;
            let (s, f) = doh::connect(connector, address, name()?, uri, links.tls.doh.clone()).await?;
            (Session::Doh(s), f)
        }
        Kind::Tls => {
            let (s, f) = dot::connect(connector, address, name()?, links.tls.dot.clone()).await?;
            (Session::Dot(s), f)
        }
        Kind::Quic => {
            let (s, f) = doq::connect(connector, address, &upstream.host, links.tls.doq.clone()).await?;
            (Session::Doq(s), f)
        }
    };
    Ok(Live { session, facts, suspect: AtomicBool::new(false) })
}

async fn addresses(links: &Links, upstream: &Upstream) -> Result<Vec<SocketAddr>, String> {
    let at = |ips: &[IpAddr]| ips.iter().map(|ip| SocketAddr::new(*ip, upstream.port)).collect::<Vec<_>>();
    if let Ok(ip) = upstream.host.parse::<IpAddr>() {
        return Ok(at(&[ip]));
    }
    if let Some(known) = links.resolvers.iter().find(|r| r.upstream.host == upstream.host) {
        return Ok(at(&known.ips));
    }
    let bootstrap = links.bootstrap.as_ref().ok_or("this pool cannot look up names")?;
    let ips = look_up(bootstrap, &upstream.host).await;
    if ips.is_empty() { Err(format!("{}: the encrypted lookup found no address", upstream.host)) } else { Ok(at(&ips)) }
}

/// A then AAAA over the known resolvers. Boxed: this is the pool calling a pool,
/// so its future's type would otherwise contain itself.
fn look_up<'a>(bootstrap: &'a Bootstrap, host: &'a str) -> BoxFuture<'a, Vec<IpAddr>> {
    Box::pin(async move {
        let mut ips = Vec::new();
        for ty in [TYPE_A, TYPE_AAAA] {
            let Some(query) = query_for(host, ty) else { continue };
            let Ok(reply) = upstream::resolve(&bootstrap.endpoints, &query, &bootstrap.pool, &bootstrap.health).await else { continue };
            ips.extend(parse(&reply).into_iter().flat_map(|m| m.answers).map(|(ip, _)| ip));
        }
        ips
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    use rustls::NamedGroup;
    use rustls::crypto::aws_lc_rs::kx_group::{X25519, X25519MLKEM768};

    use super::*;
    use crate::dns::testing::{ANSWER, Ca, Loopback, Options, Script, Server, Step, answer_to, answering, client_query};
    use crate::dns::{MAX_MESSAGE, id_of};

    const KINDS: [Kind; 3] = [Kind::Https, Kind::Tls, Kind::Quic];
    const PATIENT: Duration = Duration::from_secs(20);

    struct Fixture {
        server: Server,
        upstream: Upstream,
        pool: Pool,
        connector: Arc<Loopback>,
    }

    async fn fixture(kind: Kind, options: Options) -> Fixture {
        let ca = Ca::new();
        let server = Server::start(kind, &ca, options).await;
        let upstream: Upstream = server.url().parse().unwrap();
        let connector = Arc::new(Loopback::default());
        let pool = Pool::new(std::slice::from_ref(&upstream), &ca.context(connector.clone(), Vec::new()));
        Fixture { server, upstream, pool, connector }
    }

    impl Fixture {
        async fn ask(&self, id: u16) -> Result<Vec<u8>, String> {
            tokio::time::timeout(PATIENT, self.pool.exchange(&self.upstream, &client_query(id, "dns.example"))).await.unwrap()
        }

        /// A query that this test gives up on.
        async fn abandon(&self, id: u16) {
            let query = client_query(id, "dns.example");
            assert!(tokio::time::timeout(Duration::from_millis(100), self.pool.exchange(&self.upstream, &query)).await.is_err());
        }
    }

    fn scripted(script: Script) -> Options {
        Options { script, ..Options::default() }
    }

    /// Runs `first` for the first wire query and answers every later one.
    fn first_then_answers(first: Step) -> Script {
        let count = AtomicUsize::new(0);
        Arc::new(move |query| if count.fetch_add(1, Ordering::SeqCst) == 0 { first.clone() } else { Step::Answer(answer_to(query)) })
    }

    fn assert_answer(reply: &[u8], id: u16) {
        let message = crate::dns::parse(reply).unwrap();
        assert_eq!(message.id, id);
        assert_eq!(message.question.as_deref(), Some("dns.example"));
        assert_eq!(message.answers, vec![(ANSWER.parse().unwrap(), 60)]);
    }

    #[tokio::test]
    async fn doh_answers_with_the_clients_id_and_sends_the_wire_id_the_rfc_requires() {
        let f = fixture(Kind::Https, Options::default()).await;
        assert_answer(&f.ask(0x1234).await.unwrap(), 0x1234);
        let seen = f.server.seen().remove(0);
        assert_eq!(id_of(&seen.message), Some(0), "RFC 8484 4.1");
        assert_eq!(seen.method.as_deref(), Some("POST"));
        assert_eq!(seen.path.as_deref(), Some("/dns-query"));
        assert_eq!(seen.content_type.as_deref(), Some("application/dns-message"));
        assert!(f.connector.udp_recorded().is_empty());
    }

    #[tokio::test]
    async fn dot_answers_with_the_clients_id_and_sends_the_wire_id_the_rfc_requires() {
        let f = fixture(Kind::Tls, Options::default()).await;
        assert_answer(&f.ask(0x1234).await.unwrap(), 0x1234);
        let wire = id_of(&f.server.seen()[0].message).unwrap();
        assert_ne!(wire, 0x1234, "the session's own ID, unique among those in flight");
        assert!(f.connector.udp_recorded().is_empty());
    }

    #[tokio::test]
    async fn doq_answers_with_the_clients_id_and_sends_the_wire_id_the_rfc_requires() {
        let f = fixture(Kind::Quic, Options::default()).await;
        assert_answer(&f.ask(0x1234).await.unwrap(), 0x1234);
        assert_eq!(id_of(&f.server.seen()[0].message), Some(0), "RFC 9250 4.2.1");
        assert!(f.connector.tcp_recorded().is_empty());
    }

    #[tokio::test]
    async fn one_connection_serves_many_queries() {
        for kind in KINDS {
            let f = fixture(kind, Options::default()).await;
            for id in 1..=5 {
                assert_answer(&f.ask(id).await.unwrap(), id);
            }
            assert_eq!(f.server.accepted(), 1, "{kind:?}");
            let report = f.pool.report().remove(0);
            assert_eq!((report.connected, report.answers, report.failures), (true, 5, 0), "{kind:?}");
        }
    }

    #[tokio::test]
    async fn dot_serves_concurrent_queries_answered_out_of_order() {
        // The first query on the wire is answered after the second.
        let count = AtomicUsize::new(0);
        let script: Script = Arc::new(move |query| {
            let reply = answer_to(query);
            if count.fetch_add(1, Ordering::SeqCst) == 0 { Step::AnswerAfter(Duration::from_millis(300), reply) } else { Step::Answer(reply) }
        });
        let f = fixture(Kind::Tls, scripted(script)).await;
        let (a, b) = tokio::join!(f.ask(100), f.ask(200));
        assert_answer(&a.unwrap(), 100);
        assert_answer(&b.unwrap(), 200);
        assert_eq!(f.server.accepted(), 1, "pipelined over one stream");
    }

    #[tokio::test]
    async fn a_slow_handshake_outlives_a_cancelled_query_and_the_next_query_reuses_it() {
        for kind in KINDS {
            let f = fixture(kind, Options { handshake_delay: Duration::from_millis(500), ..Options::default() }).await;
            f.abandon(1).await;
            tokio::time::sleep(Duration::from_millis(1_000)).await;
            assert_answer(&f.ask(2).await.unwrap(), 2);
            assert_eq!(f.server.accepted(), 1, "{kind:?}: the one handshake was kept");
        }
    }

    #[tokio::test]
    async fn concurrent_queries_share_one_connect() {
        for kind in KINDS {
            let f = fixture(kind, Options { handshake_delay: Duration::from_millis(200), ..Options::default() }).await;
            let (a, b, c) = tokio::join!(f.ask(1), f.ask(2), f.ask(3));
            assert!(a.is_ok() && b.is_ok() && c.is_ok());
            assert_eq!(f.server.accepted(), 1, "{kind:?}");
        }
    }

    #[tokio::test]
    async fn a_session_that_stopped_answering_is_replaced() {
        for kind in KINDS {
            let f = fixture(kind, scripted(first_then_answers(Step::Silent))).await;
            f.abandon_after_connect().await;
            assert_answer(&f.ask(2).await.unwrap(), 2);
            assert_eq!(f.server.accepted(), 2, "{kind:?}: the suspect session was replaced");
            assert_eq!(f.pool.report()[0].failures, 1, "{kind:?}: a cancelled query counts as failed");
        }
    }

    impl Fixture {
        /// Waits for the session, then gives up on one query it never answers.
        async fn abandon_after_connect(&self) {
            let query = client_query(1, "dns.example");
            let slot = &self.pool.slots[0];
            self.pool.session(slot).await.unwrap();
            assert!(tokio::time::timeout(Duration::from_millis(300), self.pool.exchange(&self.upstream, &query)).await.is_err());
        }
    }

    #[tokio::test]
    async fn a_closed_idle_session_is_retried_once_on_a_fresh_one() {
        for kind in KINDS {
            let count = AtomicUsize::new(0);
            // The second query finds its reused session closing under it.
            let script: Script = Arc::new(move |query| if count.fetch_add(1, Ordering::SeqCst) == 1 { Step::Close } else { Step::Answer(answer_to(query)) });
            let f = fixture(kind, scripted(script)).await;
            assert_answer(&f.ask(1).await.unwrap(), 1);
            assert_answer(&f.ask(2).await.unwrap(), 2);
            assert_eq!(f.server.accepted(), 2, "{kind:?}");
            assert_eq!(f.server.seen().len(), 3, "{kind:?}: one retry");
        }
    }

    #[tokio::test]
    async fn a_fresh_session_that_fails_is_not_retried() {
        for kind in KINDS {
            let f = fixture(kind, scripted(Arc::new(|_| Step::Close))).await;
            assert!(f.ask(1).await.is_err(), "{kind:?}");
            assert_eq!(f.server.accepted(), 1, "{kind:?}");
        }
    }

    #[tokio::test]
    async fn a_certificate_from_another_root_is_refused() {
        for kind in KINDS {
            let server = Server::start(kind, &Ca::new(), Options::default()).await;
            let upstream: Upstream = server.url().parse().unwrap();
            let other = Ca::new();
            let pool = Pool::new(std::slice::from_ref(&upstream), &other.context(Arc::new(Loopback::default()), Vec::new()));
            let out = tokio::time::timeout(PATIENT, pool.exchange(&upstream, &client_query(1, "dns.example"))).await.unwrap();
            assert!(out.is_err(), "{kind:?}");
            assert!(server.seen().is_empty(), "{kind:?}: no query crossed an unverified session");
        }
    }

    #[tokio::test]
    async fn a_certificate_for_another_name_is_refused() {
        for kind in KINDS {
            let f = fixture(kind, Options { name: "other.example".into(), ..Options::default() }).await;
            assert!(f.ask(1).await.is_err(), "{kind:?}");
            assert!(f.server.seen().is_empty(), "{kind:?}");
        }
    }

    #[tokio::test]
    async fn a_doh_server_without_h2_is_refused() {
        for alpn in [vec![], vec![b"http/1.1".to_vec()]] {
            let f = fixture(Kind::Https, Options { alpn: Some(alpn), ..Options::default() }).await;
            assert!(f.ask(1).await.is_err());
            assert!(f.server.seen().is_empty());
        }
    }

    #[tokio::test]
    async fn a_doh_answer_other_than_a_200_dns_message_is_refused_and_keeps_the_session() {
        let f = fixture(Kind::Https, Options { status: 503, ..Options::default() }).await;
        assert!(f.ask(1).await.unwrap_err().contains("503"));
        let f = fixture(Kind::Https, Options { content_type: "text/html".into(), ..Options::default() }).await;
        assert!(f.ask(1).await.unwrap_err().contains("dns-message"));
        assert!(f.ask(2).await.is_err());
        assert_eq!(f.server.accepted(), 1, "the link is fine, only the answer is not");
    }

    #[tokio::test]
    async fn an_oversized_answer_is_refused() {
        for kind in [Kind::Https, Kind::Quic] {
            let script: Script = Arc::new(|query| {
                let mut reply = answer_to(query);
                reply.resize(MAX_MESSAGE + 100, 0);
                Step::Answer(reply)
            });
            let f = fixture(kind, scripted(script)).await;
            assert!(f.ask(1).await.is_err(), "{kind:?}");
        }
    }

    #[tokio::test]
    async fn an_answer_to_another_question_is_refused() {
        for kind in KINDS {
            let script: Script = Arc::new(|query| Step::Answer(answer_to(&crate::dns::with_id(&client_query(0, "other.example"), id_of(query).unwrap()))));
            let f = fixture(kind, scripted(script)).await;
            assert!(f.ask(1).await.is_err(), "{kind:?}");
        }
    }

    #[tokio::test]
    async fn a_doq_or_doh_reply_with_a_nonzero_id_is_refused() {
        for kind in [Kind::Https, Kind::Quic] {
            let script: Script = Arc::new(|query| Step::Answer(crate::dns::with_id(&answer_to(query), 9)));
            let f = fixture(kind, scripted(script)).await;
            assert!(f.ask(9).await.unwrap_err().contains("ID"), "{kind:?}");
        }
    }

    #[tokio::test]
    async fn a_local_rustls_server_offering_x25519mlkem768_negotiates_it() {
        for kind in [Kind::Https, Kind::Tls] {
            let f = fixture(kind, Options::default()).await;
            f.ask(1).await.unwrap();
            assert_eq!(f.pool.report()[0].tls.kx_group.as_deref(), Some("X25519MLKEM768"), "{kind:?}: the client's session");
            assert_eq!(*f.server.groups.lock().unwrap(), [NamedGroup::X25519MLKEM768], "{kind:?}: the server agrees");
        }
    }

    #[tokio::test]
    async fn a_server_offering_only_x25519_still_connects_with_x25519() {
        for kind in [Kind::Https, Kind::Tls] {
            let f = fixture(kind, Options { groups: Some(vec![X25519]), ..Options::default() }).await;
            f.ask(1).await.unwrap();
            assert_eq!(f.pool.report()[0].tls.kx_group.as_deref(), Some("X25519"), "{kind:?}");
        }
    }

    #[tokio::test]
    async fn doq_offers_x25519mlkem768() {
        // The server accepts that one group alone, so a client not offering it
        // fails the handshake: the control arm below shows the check can fail.
        let only_pq = || Options { groups: Some(vec![X25519MLKEM768]), ..Options::default() };
        let f = fixture(Kind::Quic, only_pq()).await;
        assert_answer(&f.ask(1).await.unwrap(), 1);
        let report = f.pool.report().remove(0);
        assert_eq!(report.tls.kx_group, None, "quinn exposes no group, so none is voiced");
        assert_eq!(report.tls.alpn.as_deref(), Some("doq"));

        let ca = Ca::new();
        let server = Server::start(Kind::Quic, &ca, only_pq()).await;
        let provider = rustls::crypto::CryptoProvider { kx_groups: vec![X25519], ..rustls::crypto::aws_lc_rs::default_provider() };
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(ca.roots.clone())
            .with_no_client_auth();
        client.alpn_protocols = vec![doq::ALPN.to_vec()];
        let address: SocketAddr = (crate::dns::testing::LOOPBACK.parse::<IpAddr>().unwrap(), server.port).into();
        let out = doq::connect(&Loopback::default(), address, crate::dns::testing::LOOPBACK, doq::quic_config(client).unwrap()).await;
        assert!(out.is_err(), "without the group the handshake fails");
    }

    #[tokio::test]
    async fn a_named_custom_upstream_bootstraps_over_the_encrypted_defaults() {
        let ca = Ca::new();
        // The custom resolver's name resolves, over DoH, to this machine.
        let custom = Server::start(Kind::Tls, &ca, Options { name: "custom.test".into(), script: answering(), ..Options::default() }).await;
        let boot = Server::start(Kind::Https, &ca, Options { name: "boot.test".into(), script: address_of_loopback(), ..Options::default() }).await;
        let boot_url = format!("https://boot.test:{}/dns-query", boot.port);
        let resolvers = vec![Resolver { upstream: boot_url.parse().unwrap(), ips: vec!["127.0.0.1".parse().unwrap()] }];
        let upstream: Upstream = format!("tls://custom.test:{}", custom.port).parse().unwrap();
        let connector = Arc::new(Loopback::default());
        let pool = Pool::new(std::slice::from_ref(&upstream), &ca.context(connector.clone(), resolvers));
        let reply = tokio::time::timeout(PATIENT, pool.exchange(&upstream, &client_query(5, "dns.example"))).await.unwrap().unwrap();
        assert_answer(&reply, 5);
        assert_eq!(boot.seen().len(), 2, "A then AAAA");
        assert_eq!(connector.tcp_recorded().len(), 2, "the resolver and the custom upstream");
        assert!(connector.udp_recorded().is_empty(), "no plain lookup");
    }

    #[tokio::test]
    async fn a_named_custom_upstream_fails_with_no_plain_socket_when_the_defaults_are_down() {
        let ca = Ca::new();
        let custom = Server::start(Kind::Tls, &ca, Options { name: "custom.test".into(), ..Options::default() }).await;
        let boot = Server::start(Kind::Https, &ca, Options { name: "boot.test".into(), status: 500, ..Options::default() }).await;
        let boot_url = format!("https://boot.test:{}/dns-query", boot.port);
        let resolvers = vec![Resolver { upstream: boot_url.parse().unwrap(), ips: vec!["127.0.0.1".parse().unwrap()] }];
        let upstream: Upstream = format!("tls://custom.test:{}", custom.port).parse().unwrap();
        let connector = Arc::new(Loopback::default());
        let pool = Pool::new(std::slice::from_ref(&upstream), &ca.context(connector.clone(), resolvers));
        let out = tokio::time::timeout(PATIENT, pool.exchange(&upstream, &client_query(5, "dns.example"))).await.unwrap();
        assert!(out.unwrap_err().contains("no address"));
        assert!(connector.udp_recorded().is_empty());
        assert_eq!(custom.accepted(), 0);
    }

    /// A resolver that answers A lookups with 127.0.0.1.
    fn address_of_loopback() -> Script {
        Arc::new(|query| {
            let parsed = crate::dns::parse(query).unwrap();
            let name = parsed.question.unwrap();
            if parsed.question_type == crate::dns::TYPE_A {
                Step::Answer(crate::dns::build::response(parsed.id, &name, &[("127.0.0.1".parse().unwrap(), 60)]))
            } else {
                Step::Answer(answer_to(query))
            }
        })
    }

    #[tokio::test]
    async fn real_sockets_failover() {
        // The first upstream accepts TCP and never does anything else.
        let ca = Ca::new();
        let silent = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let first: Upstream = format!("tls://127.0.0.1:{}", silent.local_addr().unwrap().port()).parse().unwrap();
        let second = Server::start(Kind::Https, &ca, Options::default()).await;
        let list = vec![first, second.url().parse().unwrap()];
        let pool = Pool::new(&list, &ca.context(Arc::new(Loopback::default()), Vec::new()));
        let start = Instant::now();
        let reply = upstream::resolve(&list, &client_query(3, "dns.example"), &pool, &Health::default()).await.unwrap();
        assert_answer(&reply, 3);
        assert!(start.elapsed() < upstream::REQUEST_BUDGET, "{:?}", start.elapsed());
    }

    #[tokio::test]
    async fn dropping_the_pool_ends_its_sessions_and_connects() {
        let f = fixture(Kind::Tls, Options { handshake_delay: Duration::from_secs(60), ..Options::default() }).await;
        f.abandon(1).await;
        let slot = Arc::downgrade(&f.pool.slots[0]);
        drop(f.pool);
        assert!(slot.upgrade().is_none(), "the connect task holds no strong reference");
    }
}