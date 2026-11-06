//! One query to one answer, and the two loops that serve a flow's queries. All
//! of it runs on any stream and any platform; `stack::dns_flow` only attributes
//! and books.
//!
//! - A QUERY goes to the adapter's LAN server when its name is under that
//!   adapter's suffix, else to the encrypted upstreams. The suffix check reads
//!   the wire, so a name the evidence parser refuses is still checked. A matched
//!   name whose server fails, or that has none, gets SERVFAIL: the public
//!   upstream would publish a corporate name.
//! - A reverse lookup for a private range goes to a LAN server, or gets NXDOMAIN
//!   here when there is none. It never reaches the public upstream
//!   (`upstream::path_of`).
//! - Firefox's canary ([`CANARY_DOMAIN`]) gets NXDOMAIN here.
//! - An `ech` parameter comes out of an encrypted answer for a name that may be
//!   intercepted ([`Service::without_ech`]). The LAN path is never stripped: its
//!   answers are for addresses that never enter the stack.
//! - Other opcodes (Windows' dynamic DNS UPDATE carries the host name) are
//!   answered NOTIMP here and nothing leaves.
//! - When nothing answers, the client gets SERVFAIL at the deadline. No path
//!   reaches a plain socket beyond the LAN exchange.
//! - No answer cache: the DNS Client service caches.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::ech::{self, Stripped};
use super::pool::{Context, Pool, UpstreamReport};
use super::upstream::{self, Health, Path, REQUEST_BUDGET, Upstream};
use super::{FLAG_OPCODE, FLAG_QR, HttpsRecord, MAX_MESSAGE, NameMap, TYPE_HTTPS, TYPE_SVCB, edns, flags_of, lan, notimp, nxdomain, parse, query_for, reply_answers, reverse, servfail, truncated, udp_limit, with_id};
use crate::route::table::NetTables;
use crate::stack::Meters;
use crate::watchdog::monotonic_ms;

/// Queries one service works on at once. Past it a datagram is dropped (the
/// client retries) and a TCP flow waits.
pub const MAX_IN_FLIGHT: usize = 256;
/// The name Firefox asks before it moves itself to its own DoH: NXDOMAIN keeps it
/// on system DNS, so its lookups reach this service. It is Mozilla's protocol
/// signal, one spelling with the standing of `upstream::DEFAULTS`, not a site list:
/// nothing can derive it. Children of the name are ordinary names.
pub const CANARY_DOMAIN: &str = "use-application-dns.net";
/// A DNS flow ends this long after its last query was answered, so the DNS
/// Client's one-port-per-query traffic holds nothing for long.
pub const DNS_IDLE: Duration = Duration::from_secs(5);
/// The shortest message: a header.
const MIN_MESSAGE: usize = 12;

/// How the reply will travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// The reply respects the client's size and the adapter's packet.
    Datagram,
    Stream,
}

/// Who asks, as far as an answer depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asker {
    /// `domain::Owner::may_decrypt`. A VM's or WSL's flows are never decrypted, so
    /// stripping would cost their ECH for nothing. The DNS Client service does
    /// count: it is how browsers resolve, so the service floor does not apply here.
    pub may_decrypt: bool,
}

/// True when a flow to this name may be decrypted: `Interception::may_intercept_name`
/// while `filtering.https` holds its slot, else false.
pub type NameGate = Box<dyn Fn(&str) -> bool + Send + Sync>;

/// A reply and whether it is a definite answer: from an upstream or a LAN server,
/// or the engine's own NXDOMAIN. SERVFAIL and NOTIMP are not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answered {
    pub reply: Vec<u8>,
    pub resolved: bool,
}

/// What the service did to answers, for `dns-status.json`. Counts, never a name.
#[derive(Debug, Default)]
struct Facts {
    ech_stripped: AtomicU64,
    ech_left: AtomicU64,
    canary: AtomicU64,
    reverse_lan: AtomicU64,
    reverse_local: AtomicU64,
}

/// [`Facts`] as read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct Counts {
    /// Replies that lost an `ech` here.
    pub ech_stripped: u64,
    /// Replies with an `ech` that stayed, for any reason.
    pub ech_left: u64,
    pub canary: u64,
    /// Private reverse lookups sent to a LAN server.
    pub reverse_lan: u64,
    /// Private reverse lookups answered NXDOMAIN here.
    pub reverse_local: u64,
}

/// `name` without the attrleaf labels of an HTTPS or SVCB query:
/// `_8443._https.example.net` asks about `example.net`.
fn without_attrleaf(mut name: &str) -> &str {
    while let Some((_, rest)) = name.split_once('.').filter(|(label, _)| label.starts_with('_')) {
        name = rest;
    }
    name
}

/// What a flow carried.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub queries: u64,
    pub resolved: u64,
}

/// One list of upstreams and the sessions it has open. Queries in flight hold
/// their own reference, so a change of list lets them finish on the old one.
struct Active {
    endpoints: Vec<Upstream>,
    pool: Pool,
    health: Health,
}

impl Active {
    fn new(endpoints: Vec<Upstream>, context: &Context) -> Self {
        let pool = Pool::new(&endpoints, context);
        Self { endpoints, pool, health: Health::default() }
    }
}

pub struct Service {
    context: Context,
    active: RwLock<Arc<Active>>,
    tables: Arc<RwLock<NetTables>>,
    names: Arc<Mutex<NameMap>>,
    meters: Arc<Meters>,
    mtu: usize,
    in_flight: Arc<Semaphore>,
    may_intercept: NameGate,
    facts: Facts,
}

impl Service {
    pub fn new(endpoints: Vec<Upstream>, context: Context, tables: Arc<RwLock<NetTables>>, names: Arc<Mutex<NameMap>>, meters: Arc<Meters>, mtu: usize, may_intercept: NameGate) -> Self {
        let active = RwLock::new(Arc::new(Active::new(endpoints, &context)));
        Self { context, active, tables, names, meters, mtu, in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)), may_intercept, facts: Facts::default() }
    }

    fn active(&self) -> Arc<Active> {
        self.active.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The next query uses this list; queries in flight finish on the old one.
    pub fn set_list(&self, endpoints: Vec<Upstream>) {
        *self.active.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(Active::new(endpoints, &self.context));
    }

    /// Sessions are pinned to the old egress: a network change drops them all.
    /// The list is read and replaced under one lock, so a list set meanwhile is
    /// never written over with the one it replaced.
    pub fn reset(&self) {
        let mut active = self.active.write().unwrap_or_else(|p| p.into_inner());
        *active = Arc::new(Active::new(active.endpoints.clone(), &self.context));
    }

    pub fn report(&self) -> Vec<UpstreamReport> {
        self.active().pool.report()
    }

    pub fn counts(&self) -> Counts {
        let read = |count: &AtomicU64| count.load(Ordering::Relaxed);
        let f = &self.facts;
        Counts { ech_stripped: read(&f.ech_stripped), ech_left: read(&f.ech_left), canary: read(&f.canary), reverse_lan: read(&f.reverse_lan), reverse_local: read(&f.reverse_local) }
    }

    fn try_permit(&self) -> Option<OwnedSemaphorePermit> {
        self.in_flight.clone().try_acquire_owned().ok()
    }

    async fn permit(&self) -> Option<OwnedSemaphorePermit> {
        self.in_flight.clone().acquire_owned().await.ok()
    }

    /// The reply to one message, or None when it is not worth one: shorter than
    /// a header, or itself a response.
    pub async fn answer(&self, query: &[u8], transport: Transport, asker: Asker) -> Option<Answered> {
        let flags = flags_of(query).filter(|_| query.len() >= MIN_MESSAGE)?;
        if flags & FLAG_QR != 0 {
            return None;
        }
        if flags & FLAG_OPCODE != 0 {
            return notimp(query).map(|reply| Answered { reply, resolved: false });
        }
        let question = parse(query);
        let name = question.as_ref().and_then(|m| m.question.as_deref());
        if name == Some(CANARY_DOMAIN) {
            Meters::bump(&self.facts.canary);
            return nxdomain(query).map(|reply| Answered { reply, resolved: true });
        }
        let path = self.path(query, name);
        if path == Path::NoServer {
            Meters::bump(&self.facts.reverse_local);
            return nxdomain(query).map(|reply| Answered { reply, resolved: true });
        }
        if matches!(path, Path::Lan(_)) && name.and_then(reverse::private_address).is_some() {
            Meters::bump(&self.facts.reverse_lan);
        }
        let Ok(reply) = self.exchange(path, query).await else {
            return servfail(query).map(|reply| Answered { reply, resolved: false });
        };
        // Before the size check: a smaller reply may now fit.
        let reply = match (path, &question) {
            (Path::Encrypted, Some(message)) => self.without_ech(query, message, reply, asker),
            _ => reply,
        };
        if let Some(message) = reply_answers(query, &reply) {
            self.names.lock().unwrap_or_else(|p| p.into_inner()).record_message(&message, monotonic_ms());
            Meters::bump(&self.meters.dns_answers);
        }
        let over = transport == Transport::Datagram && reply.len() > udp_limit(query, self.mtu);
        Some(Answered { reply: if over { truncated(&reply)? } else { reply }, resolved: true })
    }

    /// The engine's own HTTPS lookup, for its upstream hello (task D9). The same
    /// `resolve`: encrypted, or LAN for a matched suffix, and never plain beyond
    /// that. It takes no permit a client is waiting for: past the bound it fails,
    /// and the flow goes on without ECH.
    pub async fn https_records(&self, name: &str) -> Result<Vec<HttpsRecord>, String> {
        let _permit = self.try_permit().ok_or("too many queries in flight")?;
        let mut id = [0u8; 2];
        getrandom::fill(&mut id).map_err(|e| e.to_string())?;
        let query = with_id(&query_for(name, TYPE_HTTPS).ok_or("a name that cannot be sent")?, u16::from_be_bytes(id));
        let reply = self.exchange(self.path(&query, Some(name)), &query).await?;
        Ok(reply_answers(&query, &reply).ok_or("an answer to another question")?.https)
    }

    fn path(&self, query: &[u8], name: Option<&str>) -> Path {
        upstream::path_of(query, name, &self.tables.read().unwrap_or_else(|p| p.into_inner()))
    }

    /// The one exchange on a path. A path with nowhere to go is an error here.
    async fn exchange(&self, path: Path, query: &[u8]) -> Result<Vec<u8>, String> {
        match path {
            Path::Lan(server) => match tokio::time::timeout(REQUEST_BUDGET, lan::exchange(self.context.connector.as_ref(), server, query)).await {
                Ok(reply) => reply,
                Err(_) => Err(format!("{server} did not answer in time")),
            },
            Path::Refused => Err("it may be a LAN name, and no LAN server can take it".to_string()),
            Path::NoServer => Err("a private reverse name, and no LAN server to ask".to_string()),
            Path::Encrypted => {
                let active = self.active();
                upstream::resolve(&active.endpoints, query, &active.pool, &active.health).await
            }
        }
    }

    /// `reply` without `ech`, when the browser's real name could be of use: an
    /// HTTPS or SVCB question from an asker whose flows may be decrypted, who does
    /// not ask for DNSSEC (a stripped record would fail its RRSIG, breaking a
    /// working name), for a name `filtering.https` may intercept. The name judged
    /// is the question's, also for a CNAME target's record, since the client's SNI
    /// is the name it asked for. Everything else keeps the reply as it came, and an
    /// unstripped hello then takes `floor:ech`.
    fn without_ech(&self, query: &[u8], question: &super::Message, reply: Vec<u8>, asker: Asker) -> Vec<u8> {
        if !matches!(question.question_type, TYPE_HTTPS | TYPE_SVCB) {
            return reply;
        }
        let cut = match ech::strip(&reply) {
            Stripped::Clean => return reply,
            Stripped::Left => {
                Meters::bump(&self.facts.ech_left);
                return reply;
            }
            Stripped::Cut(cut) => cut,
        };
        let asks_dnssec = edns(query).is_some_and(|e| e.dnssec_ok);
        let name = question.question.as_deref().map(without_attrleaf);
        if asker.may_decrypt && !asks_dnssec && name.is_some_and(|name| (self.may_intercept)(name)) {
            Meters::bump(&self.facts.ech_stripped);
            return cut;
        }
        Meters::bump(&self.facts.ech_left);
        reply
    }
}

/// Serves one datagram flow until it has been idle for [`DNS_IDLE`] with nothing
/// in flight, or its stream ends. `on_question` hears each query's name.
pub async fn serve_datagrams<S>(service: &Arc<Service>, stream: &mut S, asker: Asker, on_question: impl FnMut(&str)) -> Totals
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    serve(service, stream, Transport::Datagram, asker, on_question).await
}

/// Serves one TCP flow the same way: framed queries, pipelined, answered as they
/// complete (RFC 7766 6.2.1). A length too short for a header closes the flow.
pub async fn serve_tcp<S>(service: &Arc<Service>, stream: &mut S, asker: Asker, on_question: impl FnMut(&str)) -> Totals
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    serve(service, stream, Transport::Stream, asker, on_question).await
}

async fn serve<S>(service: &Arc<Service>, stream: &mut S, transport: Transport, asker: Asker, mut on_question: impl FnMut(&str)) -> Totals
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut totals = Totals::default();
    let mut working: JoinSet<Option<Answered>> = JoinSet::new();
    let mut buffer = vec![0u8; MAX_MESSAGE];
    let mut received: Vec<u8> = Vec::new();
    let mut open = true;
    let mut idle_from = Instant::now();
    while open || !working.is_empty() {
        tokio::select! {
            read = stream.read(&mut buffer), if open => match read {
                Ok(n) if n > 0 => {
                    idle_from = Instant::now();
                    totals.bytes_up += n as u64;
                    let queries = match transport {
                        Transport::Datagram => vec![buffer[..n].to_vec()],
                        Transport::Stream => {
                            received.extend_from_slice(&buffer[..n]);
                            let Some(frames) = take_frames(&mut received) else { break };
                            frames
                        }
                    };
                    for query in queries {
                        note_question(&query, &mut on_question);
                        let permit = match transport {
                            Transport::Datagram => service.try_permit(),
                            Transport::Stream => service.permit().await,
                        };
                        let Some(permit) = permit else { continue };
                        totals.queries += 1;
                        let service = service.clone();
                        working.spawn(async move {
                            let _permit = permit;
                            service.answer(&query, transport, asker).await
                        });
                    }
                }
                _ => open = false,
            },
            Some(done) = working.join_next() => {
                idle_from = Instant::now();
                let Ok(Some(answered)) = done else { continue };
                totals.resolved += u64::from(answered.resolved);
                let Some(wire) = on_the_wire(answered.reply, transport) else { continue };
                // Bounded: while this waits nothing else in the select is polled,
                // so a client that stopped reading would hold the flow for good.
                if !matches!(tokio::time::timeout(DNS_IDLE, stream.write_all(&wire)).await, Ok(Ok(()))) {
                    break;
                }
                totals.bytes_down += wire.len() as u64;
            },
            () = tokio::time::sleep_until(idle_from + DNS_IDLE), if working.is_empty() => break,
            else => break,
        }
    }
    totals
}

/// A reply as its transport carries it. Replies are at most [`MAX_MESSAGE`].
fn on_the_wire(reply: Vec<u8>, transport: Transport) -> Option<Vec<u8>> {
    if transport == Transport::Datagram {
        return Some(reply);
    }
    let len = u16::try_from(reply.len()).ok()?;
    let mut frame = Vec::with_capacity(reply.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&reply);
    Some(frame)
}

fn note_question(query: &[u8], on_question: &mut impl FnMut(&str)) {
    if let Some(name) = parse(query).and_then(|m| m.question) {
        on_question(&name);
    }
}

/// The whole frames at the front of `received`, removed from it. None when a
/// length is too short for a header: nothing after it can be trusted.
fn take_frames(received: &mut Vec<u8>) -> Option<Vec<Vec<u8>>> {
    let mut frames = Vec::new();
    let mut at = 0;
    while let Some(head) = received.get(at..at + 2) {
        let len = usize::from(u16::from_be_bytes([head[0], head[1]]));
        if len < MIN_MESSAGE {
            return None;
        }
        let Some(body) = received.get(at + 2..at + 2 + len) else { break };
        frames.push(body.to_vec());
        at += 2 + len;
    }
    received.drain(..at);
    Some(frames)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, SocketAddr};

    use super::*;
    use crate::dns::testing::{ANSWER, Ca, DatagramPipe, Loopback, Options, Plain, Script, Server, Step, answer_to, answering, client_query};
    use crate::dns::upstream::Kind;
    use crate::dns::{build, id_of};
    use crate::route::table::fixtures::{HOME, load};

    const ROUTER: &str = "192.168.7.1";
    const MTU: usize = 1500;
    const PATIENT: Duration = Duration::from_secs(20);

    /// The host's own lookups, through the DNS Client service.
    const HOST: Asker = Asker { may_decrypt: true };
    const GUEST: Asker = Asker { may_decrypt: false };

    struct Bed {
        service: Arc<Service>,
        connector: Arc<Loopback>,
        names: Arc<Mutex<NameMap>>,
        meters: Arc<Meters>,
        /// What the gate says, and each name it heard.
        gate_open: Arc<std::sync::atomic::AtomicBool>,
        gate_heard: Arc<Mutex<Vec<String>>>,
    }

    /// The home tables, with `lan` as the Wi-Fi's suffix when given.
    fn bed(ca: &Ca, urls: &[String], suffix: Option<&str>, connector: Arc<Loopback>) -> Bed {
        let mut tables = load(HOME);
        if let Some(suffix) = suffix {
            tables.adapters.iter_mut().find(|a| a.alias == "Wi-Fi").unwrap().dns_suffixes.push(suffix.into());
        }
        bed_on(ca, urls, tables, connector)
    }

    fn bed_on(ca: &Ca, urls: &[String], tables: NetTables, connector: Arc<Loopback>) -> Bed {
        let names: Arc<Mutex<NameMap>> = Arc::default();
        let meters: Arc<Meters> = Arc::default();
        let endpoints = urls.iter().map(|u| u.parse().unwrap()).collect();
        let context = ca.context(connector.clone(), Vec::new());
        let gate_open = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let gate_heard: Arc<Mutex<Vec<String>>> = Arc::default();
        let (open, heard) = (gate_open.clone(), gate_heard.clone());
        let gate: NameGate = Box::new(move |name| {
            heard.lock().unwrap().push(name.to_string());
            open.load(Ordering::SeqCst)
        });
        let service = Arc::new(Service::new(endpoints, context, Arc::new(RwLock::new(tables)), names.clone(), meters.clone(), MTU, gate));
        Bed { service, connector, names, meters, gate_open, gate_heard }
    }

    impl Bed {
        async fn ask(&self, query: &[u8], transport: Transport) -> Answered {
            self.ask_as(query, transport, HOST).await
        }

        async fn ask_as(&self, query: &[u8], transport: Transport, asker: Asker) -> Answered {
            tokio::time::timeout(PATIENT, self.service.answer(query, transport, asker)).await.unwrap().unwrap()
        }

        fn heard(&self) -> Vec<String> {
            self.gate_heard.lock().unwrap().clone()
        }

        fn names_of(&self, ip: &str) -> Vec<String> {
            self.names.lock().unwrap().names(ip.parse().unwrap(), monotonic_ms()).iter().map(ToString::to_string).collect()
        }
    }

    fn rcode(reply: &[u8]) -> u16 {
        flags_of(reply).unwrap() & 0xf
    }

    fn lan_target() -> SocketAddr {
        SocketAddr::new(ROUTER.parse().unwrap(), 53)
    }

    /// A connector with the router's address standing in on this machine.
    fn connector_with(router: &Plain) -> Arc<Loopback> {
        let connector = Loopback::default();
        let ip: IpAddr = ROUTER.parse().unwrap();
        *connector.lan_udp.lock().unwrap() = HashMap::from([(ip, router.udp)]);
        *connector.lan_tcp.lock().unwrap() = HashMap::from([(ip, router.tcp)]);
        Arc::new(connector)
    }

    #[tokio::test]
    async fn with_every_upstream_failing_the_client_gets_servfail_and_no_plain_socket_is_opened() {
        let ca = Ca::new();
        let close: Script = Arc::new(|_| Step::Close);
        let doh = Server::start(Kind::Https, &ca, Options { status: 500, ..Options::default() }).await;
        let dot = Server::start(Kind::Tls, &ca, Options { script: close, ..Options::default() }).await;
        let trap = Plain::start(answering(), answering()).await;
        let connector = connector_with(&trap);
        let urls = [doh.url(), dot.url()];
        let b = bed(&ca, &urls, None, connector);
        let answered = b.ask(&client_query(77, "www.example"), Transport::Datagram).await;
        assert_eq!((id_of(&answered.reply), rcode(&answered.reply), answered.resolved), (Some(77), 2, false));
        assert_eq!(crate::dns::parse(&answered.reply).unwrap().question.as_deref(), Some("www.example"));
        assert!(b.connector.udp_recorded().is_empty(), "no UDP socket at all");
        let configured: Vec<u16> = vec![doh.port, dot.port];
        assert!(b.connector.tcp_recorded().iter().all(|t| configured.contains(&t.port())), "TCP only to the configured upstreams");
        assert_eq!(trap.udp_queries.load(std::sync::atomic::Ordering::SeqCst) + trap.tcp_queries.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn lookup_goes_through_the_encrypted_upstream() {
        const CONFIG: [u8; 3] = [9, 8, 7];
        let ca = Ca::new();
        // The record for whatever was asked: compressed owner, as resolvers send.
        let script: Script = Arc::new(|query| {
            let mut reply = answer_to(query);
            reply[6..8].copy_from_slice(&1u16.to_be_bytes());
            reply.extend_from_slice(&[0xc0, 0x0c]);
            reply.extend_from_slice(&TYPE_HTTPS.to_be_bytes());
            reply.extend_from_slice(&1u16.to_be_bytes());
            reply.extend_from_slice(&300u32.to_be_bytes());
            let mut data = vec![0, 1, 0, 0, 5];
            data.extend_from_slice(&u16::try_from(CONFIG.len()).unwrap().to_be_bytes());
            data.extend_from_slice(&CONFIG);
            reply.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            reply.extend_from_slice(&data);
            Step::Answer(reply)
        });
        let doh = Server::start(Kind::Https, &ca, Options { script, ..Options::default() }).await;
        let trap = Plain::start(answering(), answering()).await;
        let b = bed(&ca, &[doh.url()], None, connector_with(&trap));
        let records = tokio::time::timeout(PATIENT, b.service.https_records("www.example")).await.unwrap().unwrap();
        assert_eq!(records, [HttpsRecord { priority: 1, ech: Some(CONFIG.to_vec()), ttl: 300 }]);
        let asked = parse(&doh.seen()[0].message).unwrap();
        assert_eq!((asked.question.as_deref(), asked.question_type), (Some("www.example"), TYPE_HTTPS));
        assert!(b.connector.udp_recorded().is_empty(), "the plain path untouched");
        assert_eq!(trap.udp_queries.load(std::sync::atomic::Ordering::SeqCst) + trap.tcp_queries.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(b.connector.tcp_recorded().iter().all(|t| t.port() == doh.port), "TCP only to the configured upstream");
    }

    #[tokio::test]
    async fn a_non_query_opcode_is_answered_locally_and_nothing_leaves() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let b = bed(&ca, &[doh.url()], Some("lan"), Arc::new(Loopback::default()));
        let mut update = client_query(5, "host.lan");
        update[2] = 0x28; // opcode 5, UPDATE
        let answered = b.ask(&update, Transport::Datagram).await;
        assert_eq!((id_of(&answered.reply), rcode(&answered.reply)), (Some(5), 4));
        assert!(doh.seen().is_empty() && b.connector.tcp_recorded().is_empty() && b.connector.udp_recorded().is_empty());
    }

    #[tokio::test]
    async fn a_response_or_a_runt_is_dropped_and_an_opaque_query_goes_encrypted() {
        let ca = Ca::new();
        let echo: Script = Arc::new(|query| {
            let mut reply = query.to_vec();
            reply[2] |= 0x80;
            Step::Answer(reply)
        });
        let doh = Server::start(Kind::Https, &ca, Options { script: echo, ..Options::default() }).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        assert!(b.service.answer(&[1, 2, 3], Transport::Datagram, HOST).await.is_none());
        assert!(b.service.answer(&build::response(1, "a.example", &[]), Transport::Datagram, HOST).await.is_none());
        // A label the name parser refuses.
        let opaque = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, b'a', 0xff, 0, 0, 1, 0, 1];
        let answered = b.ask(&opaque, Transport::Datagram).await;
        assert_eq!((id_of(&answered.reply), answered.resolved), (Some(7), true));
        assert_eq!(doh.seen().len(), 1);
        assert_eq!(b.meters.dns_answers.load(std::sync::atomic::Ordering::Relaxed), 0, "no evidence");
    }

    #[tokio::test]
    async fn a_name_the_parser_refuses_stays_under_its_suffix() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let echo: Script = Arc::new(|query| {
            let mut reply = query.to_vec();
            reply[2] |= 0x80;
            Step::Answer(reply)
        });
        let router = Plain::start(echo.clone(), echo).await;
        let b = bed(&ca, &[doh.url()], Some("lan"), connector_with(&router));
        const UTF8_LABEL: &[u8] = b"\xc3\xa9";
        let mut query = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.push(UTF8_LABEL.len() as u8);
        query.extend_from_slice(UTF8_LABEL);
        query.extend_from_slice(b"\x03lan\0\0\x01\0\x01");
        let answered = b.ask(&query, Transport::Datagram).await;
        assert_eq!((id_of(&answered.reply), answered.resolved), (Some(7), true));
        assert_eq!(b.connector.udp_recorded(), [lan_target()]);
        assert!(doh.seen().is_empty(), "nothing went public");

        let mut two = query.clone();
        two[5] = 2;
        two.extend_from_slice(b"\x01a\x07example\0\0\x01\0\x01");
        let answered = b.ask(&two, Transport::Datagram).await;
        assert_eq!((rcode(&answered.reply), answered.resolved), (2, false), "the questions disagree");
        assert!(doh.seen().is_empty());
    }

    #[tokio::test]
    async fn a_suffix_whose_only_server_is_link_local_is_servfail_not_public() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let b = bed(&ca, &[doh.url()], Some("corp.example"), Arc::new(Loopback::default()));
        b.service.tables.write().unwrap().adapters.iter_mut().find(|a| a.alias == "Wi-Fi").unwrap().dns = vec!["fe80::1".parse().unwrap()];
        let answered = b.ask(&client_query(9, "payroll.corp.example"), Transport::Datagram).await;
        assert_eq!((rcode(&answered.reply), answered.resolved), (2, false));
        assert!(doh.seen().is_empty(), "never the public upstream");
        assert!(b.connector.udp_recorded().is_empty());
        let answered = b.ask(&client_query(9, "www.example"), Transport::Datagram).await;
        assert_eq!(rcode(&answered.reply), 0, "other names are untouched");
    }

    /// A client that sends a query and never reads: the flow ends by itself.
    #[tokio::test(start_paused = true)]
    async fn a_client_that_stops_reading_does_not_hold_its_flow() {
        const SMALLER_THAN_A_REPLY: usize = 4;
        let ca = Ca::new();
        let b = bed(&ca, &["tls://127.0.0.1:1".to_string()], None, Arc::new(Loopback::default()));
        let (mut client, mut flow) = tokio::io::duplex(SMALLER_THAN_A_REPLY);
        let service = b.service.clone();
        let task = tokio::spawn(async move { serve_tcp(&service, &mut flow, HOST, |_| {}).await });
        let mut update = client_query(5, "host.example");
        update[2] = 0x28; // opcode 5, UPDATE: answered here, with no upstream
        client.write_all(&framed(&update)).await.unwrap();
        let ended = tokio::time::timeout(PATIENT, task).await;
        assert!(ended.is_ok(), "the flow outlived its idle time with its client open");
        drop(client);
    }

    #[tokio::test]
    async fn a_matched_name_goes_only_to_the_lan_server() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let router = Plain::start(answering(), answering()).await;
        let b = bed(&ca, &[doh.url()], Some("lan"), connector_with(&router));
        let answered = b.ask(&client_query(9, "router.LAN"), Transport::Datagram).await;
        assert_eq!((id_of(&answered.reply), rcode(&answered.reply)), (Some(9), 0));
        assert_eq!(b.connector.udp_recorded(), [lan_target()]);
        assert!(doh.seen().is_empty(), "nothing went public");
        assert_eq!(b.names_of(ANSWER), ["router.lan"]);
    }

    #[tokio::test]
    async fn a_failed_lan_server_is_servfail_not_the_public_upstream() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let silent: Script = Arc::new(|_| Step::Silent);
        let router = Plain::start(silent.clone(), silent).await;
        let b = bed(&ca, &[doh.url()], Some("lan"), connector_with(&router));
        let start = std::time::Instant::now();
        let answered = b.ask(&client_query(9, "router.lan"), Transport::Datagram).await;
        assert_eq!((rcode(&answered.reply), answered.resolved), (2, false));
        assert!(start.elapsed() >= REQUEST_BUDGET);
        assert!(doh.seen().is_empty());
    }

    #[tokio::test]
    async fn tc_from_the_lan_server_retries_over_tcp() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let cut: Script = Arc::new(|query| Step::Answer(crate::dns::truncated(&answer_to(query)).unwrap()));
        let router = Plain::start(cut, answering()).await;
        let b = bed(&ca, &[doh.url()], Some("lan"), connector_with(&router));
        let answered = b.ask(&client_query(9, "router.lan"), Transport::Stream).await;
        assert_eq!(crate::dns::parse(&answered.reply).unwrap().answers.len(), 1, "the whole answer");
        assert_eq!(b.connector.tcp_recorded(), [lan_target()]);
        assert_eq!(router.tcp_queries.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(doh.seen().is_empty());
    }

    #[tokio::test]
    async fn a_lan_datagram_for_another_query_is_ignored() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let wrong: Script = Arc::new(|query| Step::Answer(crate::dns::with_id(&answer_to(query), 999)));
        let router = Plain::start(wrong, answering()).await;
        let b = bed(&ca, &[doh.url()], Some("lan"), connector_with(&router));
        let answered = b.ask(&client_query(9, "router.lan"), Transport::Datagram).await;
        assert_eq!(rcode(&answered.reply), 2, "never taken for the answer");
    }

    #[tokio::test]
    async fn other_names_go_encrypted() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let router = Plain::start(answering(), answering()).await;
        let b = bed(&ca, &[doh.url()], Some("lan"), connector_with(&router));
        for name in ["www.example", "notlan", "lan.example"] {
            let answered = b.ask(&client_query(9, name), Transport::Datagram).await;
            assert_eq!(rcode(&answered.reply), 0, "{name}");
        }
        assert_eq!(doh.seen().len(), 3);
        assert!(b.connector.udp_recorded().is_empty());
    }

    #[tokio::test]
    async fn the_answer_is_recorded_in_the_name_map_only_when_it_matches_its_query() {
        let ca = Ca::new();
        let count = std::sync::atomic::AtomicUsize::new(0);
        // Second query: a resolver answering a question nobody asked. It fails
        // as an upstream, so nothing of it may reach the map.
        let script: Script = Arc::new(move |query| {
            if count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Step::Answer(answer_to(query))
            } else {
                Step::Answer(build::response(id_of(query).unwrap(), "evil.example", &[("192.0.2.66".parse().unwrap(), 60)]))
            }
        });
        let doh = Server::start(Kind::Https, &ca, Options { script, ..Options::default() }).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        b.ask(&client_query(1, "good.example"), Transport::Datagram).await;
        assert_eq!(b.names_of(ANSWER), ["good.example"]);
        let answered = b.ask(&client_query(2, "other.example"), Transport::Datagram).await;
        assert_eq!(rcode(&answered.reply), 2);
        assert!(b.names_of("192.0.2.66").is_empty());
        assert_eq!(b.meters.dns_answers.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn an_upstream_servfail_is_passed_on_without_failover() {
        let ca = Ca::new();
        let refuses: Script = Arc::new(|query| Step::Answer(crate::dns::servfail(query).unwrap()));
        let first = Server::start(Kind::Https, &ca, Options { script: refuses, ..Options::default() }).await;
        let second = Server::start(Kind::Https, &ca, Options::default()).await;
        let b = bed(&ca, &[first.url(), second.url()], None, Arc::new(Loopback::default()));
        let answered = b.ask(&client_query(1, "a.example"), Transport::Datagram).await;
        assert_eq!((rcode(&answered.reply), answered.resolved), (2, true));
        assert!(second.seen().is_empty());
    }

    /// An upstream that answers with `size` bytes past a valid message.
    fn long_answers(size: usize) -> Script {
        Arc::new(move |query| {
            let mut reply = answer_to(query);
            reply.resize(size, 0);
            Step::Answer(reply)
        })
    }

    #[tokio::test]
    async fn an_over_limit_udp_reply_is_truncated_with_tc_and_tcp_gets_it_whole() {
        use crate::dns::is_truncated;
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options { script: long_answers(2_000), ..Options::default() }).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        let plain = client_query(1, "a.example");
        let short = b.ask(&plain, Transport::Datagram).await;
        assert!(is_truncated(&short.reply) && short.reply.len() <= 512, "the 512 default");
        let mut edns = plain.clone();
        edns[10..12].copy_from_slice(&1u16.to_be_bytes());
        edns.extend_from_slice(&[0, 0, 41, 0x0f, 0xa0, 0, 0, 0, 0, 0, 0]); // 4000 bytes
        let bounded = b.ask(&edns, Transport::Datagram).await;
        assert!(is_truncated(&bounded.reply), "the MTU bound beats the client's 4000");
        let whole = b.ask(&plain, Transport::Stream).await;
        assert_eq!(whole.reply.len(), 2_000);
        assert!(!is_truncated(&whole.reply));

        let doh = Server::start(Kind::Https, &ca, Options { script: long_answers(1_000), ..Options::default() }).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        let fits = b.ask(&edns, Transport::Datagram).await;
        assert_eq!(fits.reply.len(), 1_000, "under the client's size and the packet");
    }

    fn framed(query: &[u8]) -> Vec<u8> {
        let mut frame = (query.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(query);
        frame
    }

    async fn read_frame(stream: &mut tokio::io::DuplexStream) -> Vec<u8> {
        let len = stream.read_u16().await.unwrap();
        let mut reply = vec![0u8; usize::from(len)];
        stream.read_exact(&mut reply).await.unwrap();
        reply
    }

    #[tokio::test]
    async fn serve_tcp_answers_framed_pipelined_queries_and_a_split_frame_waits() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        let (mut client, mut flow) = tokio::io::duplex(MAX_MESSAGE);
        let service = b.service.clone();
        let names = Arc::new(Mutex::new(Vec::new()));
        let heard = names.clone();
        let task = tokio::spawn(async move { serve_tcp(&service, &mut flow, HOST, |n| heard.lock().unwrap().push(n.to_string())).await });
        let mut both = framed(&client_query(1, "one.example"));
        both.extend(framed(&client_query(2, "two.example")));
        let second = framed(&client_query(3, "three.example"));
        client.write_all(&both).await.unwrap();
        client.write_all(&second[..5]).await.unwrap();
        let mut ids = vec![id_of(&read_frame(&mut client).await), id_of(&read_frame(&mut client).await)];
        ids.sort();
        assert_eq!(ids, [Some(1), Some(2)]);
        client.write_all(&second[5..]).await.unwrap();
        assert_eq!(id_of(&read_frame(&mut client).await), Some(3));
        drop(client);
        let totals = task.await.unwrap();
        assert_eq!((totals.queries, totals.resolved), (3, 3));
        assert_eq!(names.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn serve_tcp_closes_on_a_length_too_short_for_a_header() {
        let ca = Ca::new();
        let b = bed(&ca, &["tls://127.0.0.1:1".to_string()], None, Arc::new(Loopback::default()));
        let (mut client, mut flow) = tokio::io::duplex(1024);
        let service = b.service.clone();
        let task = tokio::spawn(async move { serve_tcp(&service, &mut flow, HOST, |_| {}).await });
        client.write_all(&[0, 3, 1, 2, 3]).await.unwrap();
        assert_eq!(task.await.unwrap().queries, 0);
        assert_eq!(client.read(&mut [0u8; 8]).await.unwrap(), 0, "closed");
    }

    #[tokio::test]
    async fn serve_datagrams_returns_concurrent_queries_with_their_own_ids() {
        let ca = Ca::new();
        // The first query takes longer than the second: replies cross.
        let count = std::sync::atomic::AtomicUsize::new(0);
        let script: Script = Arc::new(move |query| {
            if count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 { Step::AnswerAfter(Duration::from_millis(300), answer_to(query)) } else { Step::Answer(answer_to(query)) }
        });
        let doh = Server::start(Kind::Https, &ca, Options { script, ..Options::default() }).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        let (mut client, mut flow) = DatagramPipe::pair();
        let service = b.service.clone();
        let task = tokio::spawn(async move { serve_datagrams(&service, &mut flow, HOST, |_| {}).await });
        client.send(&client_query(1, "one.example"));
        client.send(&client_query(2, "two.example"));
        let mut ids = vec![id_of(&client.recv().await.unwrap()), id_of(&client.recv().await.unwrap())];
        ids.sort();
        assert_eq!(ids, [Some(1), Some(2)]);
        drop(client);
        let totals = task.await.unwrap();
        assert_eq!((totals.queries, totals.resolved), (2, 2));
        assert!(totals.bytes_up > 0 && totals.bytes_down > 0);
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_flow_ends_after_its_idle_time() {
        let ca = Ca::new();
        let b = bed(&ca, &["tls://127.0.0.1:1".to_string()], None, Arc::new(Loopback::default()));
        let (client, mut flow) = DatagramPipe::pair();
        let start = Instant::now();
        let totals = serve_datagrams(&b.service, &mut flow, HOST, |_| {}).await;
        assert_eq!(start.elapsed(), DNS_IDLE);
        assert_eq!(totals, Totals::default());
        drop(client);
    }

    #[tokio::test]
    async fn in_flight_queries_are_capped_and_a_datagram_past_the_cap_is_dropped() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        let held = b.service.in_flight.clone().acquire_many_owned(MAX_IN_FLIGHT as u32).await.unwrap();
        let (mut client, mut flow) = DatagramPipe::pair();
        let service = b.service.clone();
        let task = tokio::spawn(async move { serve_datagrams(&service, &mut flow, HOST, |_| {}).await });
        client.send(&client_query(1, "one.example"));
        assert!(tokio::time::timeout(Duration::from_millis(200), client.recv()).await.is_err(), "dropped");
        assert!(doh.seen().is_empty());
        drop(held);
        client.send(&client_query(2, "two.example"));
        assert_eq!(id_of(&client.recv().await.unwrap()), Some(2), "the client's retry goes through");
        drop(client);
        assert_eq!(task.await.unwrap().queries, 1);
    }

    #[tokio::test]
    async fn changing_the_list_applies_to_the_next_query_and_old_queries_finish() {
        let ca = Ca::new();
        let slow: Script = Arc::new(|query| Step::AnswerAfter(Duration::from_millis(400), answer_to(query)));
        let old = Server::start(Kind::Https, &ca, Options { script: slow, ..Options::default() }).await;
        let new = Server::start(Kind::Https, &ca, Options::default()).await;
        let b = bed(&ca, &[old.url()], None, Arc::new(Loopback::default()));
        let service = b.service.clone();
        let in_flight = tokio::spawn(async move { service.answer(&client_query(1, "a.example"), Transport::Stream, HOST).await });
        while old.seen().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        b.service.set_list(vec![new.url().parse().unwrap()]);
        let next = b.ask(&client_query(2, "b.example"), Transport::Stream).await;
        assert_eq!((id_of(&next.reply), next.resolved), (Some(2), true));
        assert_eq!(new.seen().len(), 1);
        let finished = in_flight.await.unwrap().unwrap();
        assert_eq!((id_of(&finished.reply), finished.resolved), (Some(1), true), "it finished on the old list");
        assert_eq!(old.seen().len(), 1);
        assert_eq!(b.service.report()[0].address, new.url());
    }

    #[tokio::test]
    async fn a_network_change_drops_every_session() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        b.ask(&client_query(1, "a.example"), Transport::Stream).await;
        assert!(b.service.report()[0].connected);
        b.service.reset();
        assert!(!b.service.report()[0].connected);
        b.ask(&client_query(2, "a.example"), Transport::Stream).await;
        assert_eq!(doh.accepted(), 2);
    }

    /// Lists set while another thread resets without pause. Each is checked once
    /// every reset that began before it has ended.
    const RESET_ROUNDS: usize = 5_000;
    /// Completed resets that guarantee one began after a given moment and ended.
    const RESETS_TO_SETTLE: usize = 2;

    #[test]
    fn a_list_set_around_a_reset_survives_it() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let ca = Ca::new();
        let b = bed(&ca, &["tls://first.example".to_string()], None, Arc::new(Loopback::default()));
        let (stop, resets) = (AtomicBool::new(false), AtomicUsize::new(0));
        let lost = std::thread::scope(|scope| {
            scope.spawn(|| {
                while !stop.load(Ordering::SeqCst) {
                    b.service.reset();
                    resets.fetch_add(1, Ordering::SeqCst);
                }
            });
            let lost = (0..RESET_ROUNDS).find_map(|round| {
                let address = format!("tls://list{round}.example");
                b.service.set_list(vec![address.parse().unwrap()]);
                let settled = resets.load(Ordering::SeqCst) + RESETS_TO_SETTLE;
                while resets.load(Ordering::SeqCst) < settled {
                    std::thread::yield_now();
                }
                let held = b.service.report()[0].address.clone();
                (held != address).then(|| format!("round {round}: set {address}, holds {held}"))
            });
            stop.store(true, Ordering::SeqCst);
            lost
        });
        assert_eq!(lost, None);
    }

    // ---- ECH, the canary and private reverse lookups.

    const ECH_VALUE: [u8; 7] = [0xfe, 0x0d, 0, 3, 1, 2, 3];

    fn https_query(id: u16, name: &str) -> Vec<u8> {
        crate::dns::with_id(&crate::dns::query_for(name, TYPE_HTTPS).unwrap(), id)
    }

    /// `query` with an EDNS record, DO set when asked.
    fn with_edns(query: &[u8], dnssec: bool) -> Vec<u8> {
        let mut out = query.to_vec();
        out[10..12].copy_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, if dnssec { 0x80 } else { 0 }, 0, 0, 0]);
        out
    }

    /// The HTTPS record of a name that publishes ECH, with `value` as its config.
    fn publishing(value: Vec<u8>) -> Script {
        Arc::new(move |query| {
            let end = crate::dns::question_end(query).unwrap();
            let mut reply = query[..end].to_vec();
            reply[2..4].copy_from_slice(&0x81a0u16.to_be_bytes());
            reply[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
            reply.extend_from_slice(&[0xc0, 0x0c]);
            reply.extend_from_slice(&TYPE_HTTPS.to_be_bytes());
            reply.extend_from_slice(&[0, 1, 0, 0, 1, 44]);
            let mut rdata = vec![0, 1, 0, 0, 1, 0, 3, 2, b'h', b'2', 0, 5];
            rdata.extend_from_slice(&(value.len() as u16).to_be_bytes());
            rdata.extend_from_slice(&value);
            reply.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            reply.extend_from_slice(&rdata);
            Step::Answer(reply)
        })
    }

    async fn publishing_doh(ca: &Ca) -> Server {
        Server::start(Kind::Https, ca, Options { script: publishing(ECH_VALUE.to_vec()), ..Options::default() }).await
    }

    /// True when the reply holds the ECH config as the upstream sent it.
    fn has_ech(reply: &[u8]) -> bool {
        reply.windows(ECH_VALUE.len()).any(|w| w == ECH_VALUE)
    }

    /// The exact bytes the upstream sends for a query.
    fn upstream_bytes(query: &[u8]) -> Vec<u8> {
        match publishing(ECH_VALUE.to_vec())(query) {
            Step::Answer(reply) => reply,
            _ => unreachable!(),
        }
    }

    #[tokio::test]
    async fn ech_is_stripped_only_when_the_gate_says_so() {
        let ca = Ca::new();
        let doh = publishing_doh(&ca).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        let query = https_query(3, "a.example");
        let open = b.ask(&query, Transport::Stream).await;
        assert!(!has_ech(&open.reply) && open.resolved);
        assert_eq!((id_of(&open.reply), crate::dns::parse(&open.reply).unwrap().question.as_deref()), (Some(3), Some("a.example")));
        assert_eq!(flags_of(&open.reply).unwrap() & 0x0020, 0, "AD cleared");
        b.gate_open.store(false, Ordering::SeqCst);
        let closed = b.ask(&query, Transport::Stream).await;
        assert_eq!(closed.reply, upstream_bytes(&query), "byte-identical from the upstream");
        let counts = b.service.counts();
        assert_eq!((counts.ech_stripped, counts.ech_left), (1, 1));
    }

    #[tokio::test]
    async fn the_gate_hears_the_question_without_its_attrleaf() {
        let ca = Ca::new();
        let doh = publishing_doh(&ca).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        b.ask(&https_query(1, "_8443._https.a.example"), Transport::Stream).await;
        b.ask(&https_query(2, "b.example"), Transport::Stream).await;
        assert_eq!(b.heard(), ["a.example", "b.example"]);
    }

    #[tokio::test]
    async fn a_forwarded_asker_keeps_ech() {
        let ca = Ca::new();
        let doh = publishing_doh(&ca).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        let query = https_query(1, "a.example");
        assert_eq!(b.ask_as(&query, Transport::Stream, GUEST).await.reply, upstream_bytes(&query));

        let (mut client, mut flow) = DatagramPipe::pair();
        let service = b.service.clone();
        let task = tokio::spawn(async move { serve_datagrams(&service, &mut flow, GUEST, |_| {}).await });
        client.send(&query);
        assert!(has_ech(&client.recv().await.unwrap()), "datagram");
        drop(client);
        task.await.unwrap();

        let (mut client, mut flow) = tokio::io::duplex(MAX_MESSAGE);
        let service = b.service.clone();
        let task = tokio::spawn(async move { serve_tcp(&service, &mut flow, GUEST, |_| {}).await });
        client.write_all(&framed(&query)).await.unwrap();
        assert!(has_ech(&read_frame(&mut client).await), "stream");
        drop(client);
        task.await.unwrap();

        // The control: the host's flows, through the same two loops.
        let (mut client, mut flow) = DatagramPipe::pair();
        let service = b.service.clone();
        let task = tokio::spawn(async move { serve_datagrams(&service, &mut flow, HOST, |_| {}).await });
        client.send(&query);
        assert!(!has_ech(&client.recv().await.unwrap()));
        drop(client);
        task.await.unwrap();

        let (mut client, mut flow) = tokio::io::duplex(MAX_MESSAGE);
        let service = b.service.clone();
        let task = tokio::spawn(async move { serve_tcp(&service, &mut flow, HOST, |_| {}).await });
        client.write_all(&framed(&query)).await.unwrap();
        assert!(!has_ech(&read_frame(&mut client).await));
        drop(client);
        task.await.unwrap();
        assert!(b.heard().len() == 2, "a guest never asks the gate");
    }

    #[tokio::test]
    async fn a_do_query_keeps_ech() {
        let ca = Ca::new();
        let doh = publishing_doh(&ca).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        let query = with_edns(&https_query(1, "a.example"), true);
        assert!(has_ech(&b.ask(&query, Transport::Stream).await.reply));
        assert!(!has_ech(&b.ask(&with_edns(&https_query(2, "a.example"), false), Transport::Stream).await.reply), "EDNS without DO is stripped");
    }

    #[tokio::test]
    async fn a_lan_answer_keeps_ech() {
        let ca = Ca::new();
        let doh = publishing_doh(&ca).await;
        let router = Plain::start(publishing(ECH_VALUE.to_vec()), publishing(ECH_VALUE.to_vec())).await;
        let b = bed(&ca, &[doh.url()], Some("lan"), connector_with(&router));
        assert!(has_ech(&b.ask(&https_query(1, "nas.lan"), Transport::Datagram).await.reply));
        assert!(b.heard().is_empty() && doh.seen().is_empty());
    }

    #[tokio::test]
    async fn an_a_query_never_asks_the_gate() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options { script: publishing(ECH_VALUE.to_vec()), ..Options::default() }).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        let query = client_query(1, "a.example");
        assert_eq!(b.ask(&query, Transport::Stream).await.reply, upstream_bytes(&query), "even a reply that holds one");
        assert!(b.heard().is_empty());
        assert_eq!(b.service.counts(), Counts::default());
    }

    #[tokio::test]
    async fn a_stripped_reply_is_measured_after_the_cut() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options { script: publishing(vec![7; 600]), ..Options::default() }).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        let query = https_query(1, "a.example");
        let cut = b.ask(&query, Transport::Datagram).await;
        assert!(!crate::dns::is_truncated(&cut.reply), "it fits once the config is out");
        b.gate_open.store(false, Ordering::SeqCst);
        assert!(crate::dns::is_truncated(&b.ask(&query, Transport::Datagram).await.reply), "the control: over 512 with it");
    }

    #[tokio::test]
    async fn the_canary_is_nxdomain_and_nothing_leaves() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let b = bed(&ca, &[doh.url()], None, Arc::new(Loopback::default()));
        let types = [crate::dns::TYPE_A, crate::dns::TYPE_AAAA, TYPE_HTTPS];
        for (i, ty) in types.into_iter().enumerate() {
            for spelling in [CANARY_DOMAIN, "USE-application-DNS.net"] {
                let query = crate::dns::with_id(&crate::dns::query_for(spelling, ty).unwrap(), 40 + i as u16);
                let answered = b.ask(&query, Transport::Datagram).await;
                assert_eq!((id_of(&answered.reply), rcode(&answered.reply), answered.resolved), (Some(40 + i as u16), 3, true), "{spelling} {ty}");
                let message = crate::dns::parse(&answered.reply).unwrap();
                assert_eq!((message.question.as_deref(), message.question_type), (Some(CANARY_DOMAIN), ty));
            }
        }
        assert!(doh.seen().is_empty() && b.connector.tcp_recorded().is_empty() && b.connector.udp_recorded().is_empty(), "zero sockets");
        assert_eq!(b.service.counts().canary, 6);
        let child = b.ask(&client_query(1, "sub.use-application-dns.net"), Transport::Datagram).await;
        assert_eq!(rcode(&child.reply), 0);
        assert_eq!(doh.seen().len(), 1, "a child is an ordinary name");
    }

    fn no_lan_dns() -> NetTables {
        let mut tables = load(HOME);
        tables.adapters.iter_mut().find(|a| a.alias == "Wi-Fi").unwrap().dns = vec!["8.8.8.8".parse().unwrap()];
        tables
    }

    fn ptr_query(id: u16, name: &str) -> Vec<u8> {
        crate::dns::with_id(&crate::dns::query_for(name, 12).unwrap(), id)
    }

    #[tokio::test]
    async fn canary_and_local_nxdomain_flows_are_not_booked_failed() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let b = bed_on(&ca, &[doh.url()], no_lan_dns(), Arc::new(Loopback::default()));
        for query in [client_query(1, CANARY_DOMAIN), ptr_query(2, "7.168.192.in-addr.arpa")] {
            let (mut client, mut flow) = DatagramPipe::pair();
            let service = b.service.clone();
            let task = tokio::spawn(async move { serve_datagrams(&service, &mut flow, HOST, |_| {}).await });
            client.send(&query);
            assert_eq!(rcode(&client.recv().await.unwrap()), 3);
            drop(client);
            let totals = task.await.unwrap();
            assert_eq!((totals.queries, totals.resolved), (1, 1), "dns_flow books resolved == 0 as Failed");
        }
    }

    #[tokio::test]
    async fn a_private_reverse_lookup_goes_only_to_the_router() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let router = Plain::start(answering(), answering()).await;
        let b = bed(&ca, &[doh.url()], None, connector_with(&router));
        let answered = b.ask(&ptr_query(5, "7.168.192.in-addr.arpa"), Transport::Datagram).await;
        assert_eq!((id_of(&answered.reply), rcode(&answered.reply), answered.resolved), (Some(5), 0, true));
        assert_eq!(b.connector.udp_recorded(), [lan_target()]);
        assert!(doh.seen().is_empty(), "the law: nothing went public");
        let counts = b.service.counts();
        assert_eq!((counts.reverse_lan, counts.reverse_local), (1, 0));
    }

    #[tokio::test]
    async fn with_no_lan_server_it_is_nxdomain_and_no_socket_opens() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let b = bed_on(&ca, &[doh.url()], no_lan_dns(), Arc::new(Loopback::default()));
        let answered = b.ask(&ptr_query(5, "7.168.192.in-addr.arpa"), Transport::Datagram).await;
        assert_eq!((id_of(&answered.reply), rcode(&answered.reply), answered.resolved), (Some(5), 3, true));
        assert!(doh.seen().is_empty() && b.connector.tcp_recorded().is_empty() && b.connector.udp_recorded().is_empty());
        assert_eq!(b.service.counts().reverse_local, 1);
        // A public reverse name still goes encrypted.
        let public = b.ask(&ptr_query(6, "8.8.8.8.in-addr.arpa"), Transport::Datagram).await;
        assert_eq!(rcode(&public.reply), 0);
        assert_eq!(doh.seen().len(), 1);
    }

    #[tokio::test]
    async fn a_failed_lan_server_is_servfail_not_public() {
        let ca = Ca::new();
        let doh = Server::start(Kind::Https, &ca, Options::default()).await;
        let silent: Script = Arc::new(|_| Step::Silent);
        let router = Plain::start(silent.clone(), silent).await;
        let b = bed(&ca, &[doh.url()], None, connector_with(&router));
        let answered = b.ask(&ptr_query(5, "1.7.168.192.in-addr.arpa"), Transport::Datagram).await;
        assert_eq!((rcode(&answered.reply), answered.resolved), (2, false));
        assert!(doh.seen().is_empty());
    }

    #[test]
    fn the_report_holds_counts_and_never_a_name() {
        let json = serde_json::to_value(Counts { ech_stripped: 1, ech_left: 2, canary: 3, reverse_lan: 4, reverse_local: 5 }).unwrap();
        let object = json.as_object().unwrap();
        assert_eq!(object.len(), 5, "{object:?}");
        assert!(object.values().all(serde_json::Value::is_u64), "numbers, never a name");
    }

    /// The real path is the user's to run, with `docs/live/dns-extras.md`.
    #[test]
    #[ignore = "live: run by the user with docs/live/dns-extras.md"]
    fn live_dns_extras_on_the_real_path() {
        panic!("follow docs/live/dns-extras.md: ECH, the canary and reverse lookups need the real path and `filtering.https` after its own check");
    }

    #[test]
    fn the_report_never_holds_a_queried_name() {
        let report = crate::dns::pool::UpstreamReport { address: "tls://dns.example:853".into(), connected: true, tls: Default::default(), answers: 1, failures: 0 };
        let json = serde_json::to_value(&report).unwrap();
        let keys: Vec<&String> = json.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 6, "{keys:?}");
        assert!(json["kx_group"].is_null() && json["alpn"].is_null());
    }
}