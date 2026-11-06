//! How a blocked flow ends, through the real `handle_udp` and a real `IpStack` in
//! memory, with `filtering.https` off (its slot empty). No test sends a real
//! packet: answers end at [`FakeSink`], the empty route table refuses every
//! upstream socket, and the attributor only reads this machine's owner tables.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use ipstack::{IpStack, IpStackConfig, IpStackStream};
use sieve_filter::rules::{ListText, RuleEngine, RuleSet};
use sieve_ipc::{FlowAction, FlowEvent, LogOutcome, Policy};
use tokio::sync::mpsc;

use super::Meters;
use super::egress::Egress;
use super::relay::{Relay, RelayParts, handle_udp};
use crate::dns::NameMap;
use crate::dns::service::Service;
use crate::domain::{DomainFilter, FilterSlot};
use crate::flow::etw::Unwitnessed;
use crate::flow::nat::{NatTable, NoDirectory, VmDirectory};
use crate::quic::icmp::tests::assert_answers;
use crate::quic::tests::{FLOWS, FakeSink, MemDevice, sealed_initials, udp_packet};
use crate::route::table::NetTables;
use crate::watchdog::monotonic_ms;

const BLOCKED: &str = "ads.example";
const ALLOWED: &str = "news.example";
const RULES: &str = "||ads.example^\n";
const MTU: u16 = 1500;
const NAME_TTL_S: u32 = 300;
/// Far above the owner lookup's give-up time; only a failure waits this long.
const WAIT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(5);

pub(super) fn relay(sink: Arc<FakeSink>) -> Arc<Relay> {
    let tables: Arc<RwLock<NetTables>> = Arc::default();
    let names: Arc<Mutex<NameMap>> = Arc::default();
    let meters: Arc<Meters> = Arc::default();
    let lists = RuleEngine::compile(&[ListText { id: "test", text: RULES, trusted: false }]);
    let rules = RuleSet { user: Arc::new(RuleEngine::empty()), lists: Arc::new(lists) };
    let filter = Arc::new(FilterSlot::new(DomainFilter::new(&Policy { sieving: true, ..Policy::default() }, rules)));
    let context = crate::dns::testing::Ca::new().context(Arc::default(), Vec::new());
    let dns = Arc::new(Service::new(Vec::new(), context, tables.clone(), names.clone(), meters.clone(), usize::from(MTU), Box::new(|_| false)));
    let nat = Arc::new(NatTable::spawn(|| (Vec::new(), Box::new(NoDirectory) as Box<dyn VmDirectory>)));
    let egress = Arc::new(Egress::new(0, tables.clone()));
    Arc::new(Relay::new(RelayParts { tables, egress, dns, book: Arc::default(), names, meters, filter, witness: Box::new(Unwitnessed), nat, https: Arc::default(), sink }))
}

pub(super) struct Wire {
    pub(super) to_stack: mpsc::UnboundedSender<Vec<u8>>,
    pub(super) from_stack: mpsc::UnboundedReceiver<Vec<u8>>,
    pub(super) stack: IpStack,
}

pub(super) fn wire() -> Wire {
    let (to_stack, rx) = mpsc::unbounded_channel();
    let (tx, from_stack) = mpsc::unbounded_channel();
    let mut config = IpStackConfig::default();
    config.mtu(MTU).unwrap();
    Wire { to_stack, from_stack, stack: IpStack::new(config, MemDevice { rx, tx }) }
}

pub(super) fn ends(flow: (&str, &str)) -> (SocketAddr, SocketAddr) {
    (flow.0.parse().unwrap(), flow.1.parse().unwrap())
}

async fn until(what: &str, done: impl Fn() -> bool) {
    let polled = async {
        while !done() {
            tokio::time::sleep(POLL).await;
        }
    };
    tokio::time::timeout(WAIT, polled).await.unwrap_or_else(|_| panic!("{what}"));
}

/// The one thing the flow must have left in the book: one closed `Blocked`
/// event and one `Blocked` log row, counted once.
pub(super) fn assert_blocked_once(ctx: &Relay, host: &str) -> FlowEvent {
    let mut book = ctx.book.lock().unwrap();
    let batch = book.take_batch();
    assert_eq!(batch.iter().map(|e| (e.action, e.open)).collect::<Vec<_>>(), [(FlowAction::Blocked, false)]);
    assert_eq!(batch[0].host.as_deref(), Some(host));
    let rows = book.take_log();
    assert_eq!(rows.iter().map(|r| &r.outcome).collect::<Vec<_>>(), [&LogOutcome::Blocked]);
    let counters = ctx.meters.counters();
    assert_eq!((counters.flows, counters.blocked), (1, 1), "one owner lookup, one block");
    batch[0].clone()
}

async fn accept_udp(wire: &mut Wire) -> ipstack::IpStackUdpStream {
    let Ok(IpStackStream::Udp(app)) = wire.stack.accept().await else { panic!("no UDP stream") };
    app
}

async fn ended<T>(task: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, task).await.expect("the flow ended")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_quic_flow_is_answered_at_once_with_the_https_slot_empty() {
    for flow in FLOWS {
        let (local, remote) = ends(flow);
        let sink = Arc::new(FakeSink::default());
        let ctx = relay(sink.clone());
        assert!(ctx.https.get().is_none(), "filtering.https is off");
        let mut wire = wire();
        for initial in sealed_initials(BLOCKED) {
            wire.to_stack.send(udp_packet(local, remote, &initial)).unwrap();
        }
        let task = tokio::spawn(handle_udp(ctx.clone(), accept_udp(&mut wire).await));

        until("each held Initial is answered", || sink.count() == 2).await;
        wire.to_stack.send(udp_packet(local, remote, &sealed_initials(BLOCKED)[0])).unwrap();
        until("a retransmit is answered", || sink.count() == 3).await;

        for packet in sink.sent.lock().unwrap().iter() {
            assert_answers(packet, local, remote);
        }
        assert!(!task.is_finished(), "the flow stays until idle, so a retransmit is no new flow");
        assert_blocked_once(&ctx, BLOCKED);
        let quic = &ctx.meters.quic;
        assert_eq!(quic.blocked_replies.load(Ordering::Relaxed), 3);
        assert_eq!((quic.replies.load(Ordering::Relaxed), quic.refused.load(Ordering::Relaxed)), (0, 0), "a block is not a refusal");
        assert!(wire.from_stack.try_recv().is_err(), "the stack itself wrote nothing back");
        task.abort();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_datagram_that_is_not_quic_is_answered_too() {
    for flow in FLOWS {
        let (local, remote) = ends(flow);
        let sink = Arc::new(FakeSink::default());
        let ctx = relay(sink.clone());
        ctx.names.lock().unwrap().record(BLOCKED, remote.ip(), NAME_TTL_S, monotonic_ms());
        let mut wire = wire();
        wire.to_stack.send(udp_packet(local, remote, b"\x00\x01 not quic")).unwrap();
        let task = tokio::spawn(handle_udp(ctx.clone(), accept_udp(&mut wire).await));
        until("the datagram is answered", || sink.count() == 1).await;
        assert_answers(&sink.sent.lock().unwrap()[0], local, remote);
        assert_eq!(ctx.meters.counters().blocked, 1);
        task.abort();
    }
}

/// The control: the same flow to a host no rule blocks is not answered. It goes
/// on to its upstream socket, which the empty route table refuses.
#[tokio::test(flavor = "multi_thread")]
async fn an_allowed_flow_gets_no_answer() {
    for flow in FLOWS {
        let (local, remote) = ends(flow);
        let sink = Arc::new(FakeSink::default());
        let ctx = relay(sink.clone());
        let mut wire = wire();
        for initial in sealed_initials(ALLOWED) {
            wire.to_stack.send(udp_packet(local, remote, &initial)).unwrap();
        }
        let app = accept_udp(&mut wire).await;
        ended(handle_udp(ctx.clone(), app)).await;
        assert_eq!(sink.tried.load(Ordering::Relaxed), 0);
        assert_eq!(ctx.meters.counters().blocked, 0);
        let batch = ctx.book.lock().unwrap().take_batch();
        assert_eq!(batch.iter().map(|e| e.action).collect::<Vec<_>>(), [FlowAction::Failed], "no route, so nothing left");
    }
}
