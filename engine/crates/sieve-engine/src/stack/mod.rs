//! The relay of every flow (plan 1.1, slice 3, 4): ipstack terminates each
//! flow that enters the adapter, the flow is attributed to its process, its
//! first bytes are decoded (SNI, Host, QUIC Initial), the one decision
//! (`crate::domain`) is asked, and it is relayed to its destination through a
//! socket pinned to the interface Windows would use without Sieve, or closed
//! with nothing sent upstream. A flow to port 53 is answered by `dns::service`
//! instead, and is never blocked.
//!
//! - [`book`]: the flows as the app sees them, batched for the pipe;
//! - [`Meters`]: the engine's own counters (attribution is read from them);
//! - `relay` (Windows): the per-flow tasks; `dns_flow` (Windows): port 53;
//! - `egress` (Windows): the pinned sockets both of them leave through.

pub mod attribution;
pub mod book;
#[cfg(feature = "attribution-diagnostics")]
pub mod diagnostics;
#[cfg(windows)]
pub mod dns_flow;
#[cfg(windows)]
pub mod egress;
#[cfg(windows)]
pub mod relay;

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sieve_ipc::{Counters, FlowAction, FlowEvent, FlowKind, MAX_RULE_BYTES, cap_text};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::domain::Decision;
use crate::flow::classify::{Decoded, Kind};
use book::FlowBook;

/// Only datagram boundaries matter while draining; a smaller read loses nothing.
const DRAIN_BUFFER: usize = 2_048;

/// Counters since the engine started.
#[derive(Debug, Default)]
pub struct Meters {
    #[cfg(feature = "attribution-diagnostics")]
    pub attribution: std::sync::Mutex<diagnostics::Report>,
    pub flows: AtomicU64,
    pub attributed: AtomicU64,
    pub own_refused: AtomicU64,
    pub dns_answers: AtomicU64,
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub not_unicast: AtomicU64,
    pub blocked: AtomicU64,
    pub forwarded: AtomicU64,
    pub forwarded_named: AtomicU64,
    pub etw_found: AtomicU64,
    pub etw_disagreed: AtomicU64,
    pub etw_dropped: AtomicU64,
    pub https: HttpsMeters,
    pub quic: crate::quic::fallback::QuicMeters,
}

/// The key exchange groups the engine speaks, in `tls::kx_groups` order.
pub const KX_GROUPS: usize = 3;
const KX_GROUP_NAMES: [&str; KX_GROUPS] = ["X25519MLKEM768", "X25519", "secp256r1"];

/// Evidence of interception without a disk log (task D18): plan 7.1 keeps the
/// log in memory only, so no host goes in `status.json`, only these counts. The
/// live check reads their delta around one site. Not on the pipe.
#[derive(Debug, Default)]
pub struct HttpsMeters {
    pub intercepted: AtomicU64,
    pub passed: AtomicU64,
    pub upstream_groups: [AtomicU64; KX_GROUPS],
    pub client_groups: [AtomicU64; KX_GROUPS],
}

impl HttpsMeters {
    /// The `https` section of `status.json`.
    pub fn report(&self) -> serde_json::Value {
        let groups = |counts: &[AtomicU64; KX_GROUPS]| -> serde_json::Map<String, serde_json::Value> {
            KX_GROUP_NAMES.iter().zip(counts).map(|(name, count)| ((*name).to_string(), count.load(Ordering::Relaxed).into())).collect()
        };
        serde_json::json!({
            "intercepted": self.intercepted.load(Ordering::Relaxed),
            "passed": self.passed.load(Ordering::Relaxed),
            "upstream_groups": groups(&self.upstream_groups),
            "client_groups": groups(&self.client_groups),
        })
    }
}

impl Meters {
    pub fn bump(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn counters(&self) -> Counters {
        let l = |c: &AtomicU64| c.load(Ordering::Relaxed);
        Counters {
            flows: l(&self.flows),
            attributed: l(&self.attributed),
            own_refused: l(&self.own_refused),
            dns_answers: l(&self.dns_answers),
            packets_in: l(&self.packets_in),
            packets_out: l(&self.packets_out),
            not_unicast: l(&self.not_unicast),
            blocked: l(&self.blocked),
            forwarded: l(&self.forwarded),
            forwarded_named: l(&self.forwarded_named),
            etw_found: l(&self.etw_found),
            etw_disagreed: l(&self.etw_disagreed),
            etw_dropped: l(&self.etw_dropped),
        }
    }
}

/// Fills a decided flow's event: what its first bytes said and the decision.
pub fn record_decision(event: &mut FlowEvent, d: &Decoded, dns: bool, decision: &Decision) {
    event.kind = if dns { FlowKind::Dns } else { kind_of(d) };
    event.host.clone_from(&d.domain);
    event.reason = Some(decision.reason);
    event.rule = decision.rule.as_deref().map(|r| cap_text(r, MAX_RULE_BYTES).to_string());
    event.list.clone_from(&decision.list);
}

/// A flow the decision closed: one book entry, one count.
pub fn close_blocked(book: &Mutex<FlowBook>, meters: &Meters, id: u64) {
    book.lock().unwrap_or_else(|p| p.into_inner()).close(id, FlowAction::Blocked, 0, 0);
    Meters::bump(&meters.blocked);
}

/// Swallows a blocked UDP flow's datagrams until it has been idle for `idle`.
/// Ending at once would turn each QUIC retransmit into a new flow with a new
/// owner lookup; the stack's own timeout then frees the flow.
pub async fn drain_udp<S: AsyncRead + Unpin>(app: &mut S, idle: Duration) {
    let mut buf = vec![0u8; DRAIN_BUFFER];
    while let Ok(Ok(n)) = tokio::time::timeout(idle, app.read(&mut buf)).await {
        if n == 0 {
            return;
        }
    }
}

/// The wire kind of a decoded flow.
pub fn kind_of(d: &Decoded) -> FlowKind {
    match d.kind {
        Some(Kind::Tls) => FlowKind::Tls,
        Some(Kind::Http) => FlowKind::Http,
        Some(Kind::Quic) => FlowKind::Quic,
        None => FlowKind::Other,
    }
}

/// The port DNS is caught on (UDP and TCP), whatever the server address.
pub const DNS_PORT: u16 = 53;

/// A bound, non-blocking socket from a connector, handed to the runtime.
pub fn datagram_socket(socket: socket2::Socket) -> std::io::Result<tokio::net::UdpSocket> {
    tokio::net::UdpSocket::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_read_what_was_counted() {
        let m = Meters::default();
        Meters::bump(&m.flows);
        Meters::bump(&m.flows);
        Meters::bump(&m.attributed);
        let c = m.counters();
        assert_eq!((c.flows, c.attributed, c.own_refused), (2, 1, 0));
    }

    /// Fake clock: a retransmit inside the idle time keeps the drain alive,
    /// nothing is booked again, and silence ends it.
    #[tokio::test(start_paused = true)]
    async fn blocked_udp_drains_until_idle_and_books_one_flow() {
        use tokio::io::AsyncWriteExt;
        const IDLE: Duration = Duration::from_secs(30);
        let book = Mutex::new(FlowBook::default());
        let meters = Meters::default();
        let id = book.lock().unwrap().open(book::tests_event(Some(1))).unwrap();
        close_blocked(&book, &meters, id);
        let (mut app, mut stack) = tokio::io::duplex(4096);
        let started = tokio::time::Instant::now();
        let drain = tokio::spawn(async move { drain_udp(&mut stack, IDLE).await });
        for _ in 0..3 {
            tokio::time::sleep(IDLE - Duration::from_secs(1)).await;
            app.write_all(b"retransmit").await.unwrap();
        }
        assert!(!drain.is_finished(), "datagrams keep the flow alive");
        let last = tokio::time::Instant::now();
        drain.await.unwrap();
        assert_eq!(tokio::time::Instant::now() - last, IDLE);
        assert!(last - started >= IDLE * 2);
        let batch = book.lock().unwrap().take_batch();
        assert_eq!(batch.iter().map(|e| (e.action, e.open)).collect::<Vec<_>>(), [(FlowAction::Blocked, false)]);
        assert_eq!(meters.counters().blocked, 1);
        drop(app);
    }

    #[tokio::test]
    async fn a_closed_stack_ends_the_drain_at_once() {
        let (app, mut stack) = tokio::io::duplex(64);
        drop(app);
        tokio::time::timeout(Duration::from_secs(5), drain_udp(&mut stack, Duration::from_secs(3_600))).await.expect("ended");
    }

    #[test]
    fn a_decision_fills_the_event_and_a_long_rule_is_cut() {
        let mut e = book::tests_event(Some(1));
        let d = Decoded { kind: Some(Kind::Tls), domain: Some("ads.example".into()), ..Decoded::default() };
        let rule = "r".repeat(MAX_RULE_BYTES + 10);
        let decision = Decision { action: crate::flow::flows::Action::Drop, reason: sieve_ipc::FlowReason::NamedBlock, rule: Some(rule), list: Some("l".into()) };
        record_decision(&mut e, &d, false, &decision);
        assert_eq!((e.kind, e.host.as_deref(), e.reason), (FlowKind::Tls, Some("ads.example"), Some(sieve_ipc::FlowReason::NamedBlock)));
        assert_eq!(e.rule.map(|r| r.len()), Some(MAX_RULE_BYTES));
        assert_eq!(e.list.as_deref(), Some("l"));
    }

    #[test]
    fn decoded_kinds_map_to_wire_kinds() {
        let d = |kind| Decoded { kind, ..Decoded::default() };
        assert_eq!(kind_of(&d(Some(Kind::Tls))), FlowKind::Tls);
        assert_eq!(kind_of(&d(Some(Kind::Http))), FlowKind::Http);
        assert_eq!(kind_of(&d(Some(Kind::Quic))), FlowKind::Quic);
        assert_eq!(kind_of(&d(None)), FlowKind::Other);
    }
}
