//! Windows: one task per flow the stack accepts (the spike's forwarder,
//! with its live lessons kept):
//! - only unicast reaches the stack (`tun::admit`);
//! - a flow owned by the engine itself is refused and counted (loop guard);
//! - every upstream socket comes from [`Egress`], pinned outside Sieve's routes;
//! - a failed connect closes the app side with a FIN at once (live run 1:
//!   a dropped ipstack stream left curl waiting 20 s).
//!
//! TCP uses the offline-tested `flow::relay::relay_tcp` (server bytes flow at
//! once, client bytes are held until decoded, then relayed). UDP holds
//! datagrams until decoded, then relays both ways. Port 53 goes to
//! `stack::dns_flow` instead and is never relayed. Nothing is dropped for its
//! content in slice 3.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use ipstack::{IpStackTcpStream, IpStackUdpStream};
use sieve_ipc::{FlowAction, FlowEvent, FlowKind, FlowProto};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use super::book::FlowBook;
use super::dns_flow;
use super::egress::Egress;
use super::{DNS_PORT, Meters, kind_of};
use crate::dns::service::Service;
use crate::flow::classify::{Decoded, UdpClassifier};
use crate::flow::flows::os::IpHelper;
use crate::flow::flows::{Action, Attributor, ExeCache, FiveTuple, Owner, REFRESH_MIN_MS};
use crate::flow::packet::Proto;
use crate::flow::relay::relay_tcp;
use crate::route::table::NetTables;
use crate::watchdog::monotonic_ms;

/// A TCP flow that sends nothing this long is decided without a name.
pub const FIRST_BYTES_WAIT: Duration = Duration::from_secs(5);
/// A UDP flow idle this long ends (ipstack's own UDP timeout is the same).
pub const UDP_IDLE: Duration = Duration::from_secs(30);
const DATAGRAM: usize = 65_535;

type ExeLookup = fn(u32) -> Option<String>;

/// What every flow task shares.
pub struct Relay {
    #[cfg(feature = "relay-experiments")]
    pub experiments: crate::experiments::Settings,
    pub own_pid: u32,
    pub attributor: Mutex<Attributor<IpHelper>>,
    pub exes: Mutex<ExeCache<ExeLookup>>,
    /// Re-read on every route change (control); pinning and DNS's split rules
    /// read this same table.
    pub tables: Arc<RwLock<NetTables>>,
    pub egress: Arc<Egress>,
    pub dns: Arc<Service>,
    pub book: Arc<Mutex<FlowBook>>,
    pub meters: Arc<Meters>,
}

pub(super) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The Windows session of a process.
pub fn session_of(pid: u32) -> Option<u32> {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    let mut session = 0u32;
    // SAFETY: plain call with an out pointer.
    unsafe { ProcessIdToSessionId(pid, &mut session) }.ok().map(|()| session)
}

impl Relay {
    pub fn new(tables: Arc<RwLock<NetTables>>, egress: Arc<Egress>, dns: Arc<Service>, book: Arc<Mutex<FlowBook>>, meters: Arc<Meters>) -> Self {
        Self {
            #[cfg(feature = "relay-experiments")]
            experiments: crate::experiments::Settings::default(),
            own_pid: std::process::id(),
            attributor: Mutex::new(Attributor::new(IpHelper)),
            exes: Mutex::new(ExeCache::new(crate::flow::flows::os::exe_path as ExeLookup)),
            tables,
            egress,
            dns,
            book,
            meters,
        }
    }

    /// The owner pid, retried while the owner table lags (bounded by the
    /// attributor's give-up time).
    pub(super) async fn owner(&self, flow: FiveTuple) -> Option<u32> {
        #[cfg(feature = "attribution-diagnostics")]
        let started = monotonic_ms();
        loop {
            let answer = lock(&self.attributor).owner(&flow, monotonic_ms());
            match answer {
                Owner::Pid(pid) => {
                    #[cfg(feature = "attribution-diagnostics")]
                    lock(&self.meters.attribution).observe(flow, true, monotonic_ms(), None, None, monotonic_ms().saturating_sub(started));
                    return Some(pid);
                }
                Owner::Unknown => {
                    #[cfg(feature = "attribution-diagnostics")]
                    self.unknown_diagnostics(flow, monotonic_ms().saturating_sub(started));
                    return None;
                }
                Owner::Pending => tokio::time::sleep(Duration::from_millis(REFRESH_MIN_MS)).await,
            }
        }
    }

    #[cfg(feature = "attribution-diagnostics")]
    fn unknown_diagnostics(&self, flow: FiveTuple, lookup_elapsed_ms: u64) {
        use crate::flow::flows::{OwnerSource, Table};
        let same_table = Table::of(&flow);
        let other_table = match same_table {Table::Tcp4 => Table::Tcp6, Table::Tcp6 => Table::Tcp4, Table::Udp4 => Table::Udp6, Table::Udp6 => Table::Udp4};
        let same = IpHelper.read(same_table);
        let other = IpHelper.read(other_table);
        lock(&self.meters.attribution).observe(flow, false, monotonic_ms(), same.as_deref(), other.as_deref(), lookup_elapsed_ms);
    }

    /// Counts the flow and registers it in the book; None when it is the
    /// engine's own (refused) or the book is full.
    pub(super) fn admit(&self, flow: &FiveTuple, pid: Option<u32>, proto: FlowProto, kind: FlowKind) -> Option<u64> {
        if pid == Some(self.own_pid) {
            Meters::bump(&self.meters.own_refused);
            return None;
        }
        Meters::bump(&self.meters.flows);
        if pid.is_some() {
            Meters::bump(&self.meters.attributed);
        }
        let exe = pid.and_then(|p| lock(&self.exes).exe(p, monotonic_ms()));
        let event = FlowEvent {
            id: 0,
            pid,
            exe,
            session: pid.and_then(session_of),
            proto,
            local: flow.local.to_string(),
            remote: flow.remote.to_string(),
            kind,
            host: None,
            action: FlowAction::Relayed,
            bytes_up: 0,
            bytes_down: 0,
            open: true,
        };
        lock(&self.book).open(event)
    }

    fn decided(&self, id: u64, d: &Decoded) {
        lock(&self.book).update(id, |e| {
            e.kind = kind_of(d);
            e.host.clone_from(&d.domain);
        });
    }
}

/// Closes the app side promptly (FIN).
pub(super) async fn close_app(app: &mut IpStackTcpStream) {
    let _ = tokio::time::timeout(Duration::from_secs(1), app.shutdown()).await;
}

pub async fn handle_tcp(ctx: Arc<Relay>, mut app: IpStackTcpStream) {
    let flow = FiveTuple { proto: Proto::Tcp, local: app.local_addr(), remote: app.peer_addr() };
    if flow.remote.port() == DNS_PORT {
        return dns_flow::tcp(ctx, app, flow).await;
    }
    let (pid, upstream) = tokio::join!(ctx.owner(flow), ctx.egress.connect(flow.remote));
    let Some(id) = ctx.admit(&flow, pid, FlowProto::Tcp, FlowKind::Other) else { return close_app(&mut app).await };
    let upstream = match upstream {
        Ok(u) => u,
        Err(_) => {
            lock(&ctx.book).close(id, FlowAction::Failed, 0, 0);
            return close_app(&mut app).await;
        }
    };
    #[cfg(feature = "relay-experiments")]
    let out = if let Some(capacity) = ctx.experiments.copy_buffer_bytes {
        crate::flow::relay::relay_tcp_buffered(&mut app, upstream, FIRST_BYTES_WAIT, |d| {
            ctx.decided(id, d);
            Action::Pass
        }, capacity).await
    } else {
        relay_tcp(&mut app, upstream, FIRST_BYTES_WAIT, |d| {
            ctx.decided(id, d);
            Action::Pass
        }).await
    };
    #[cfg(not(feature = "relay-experiments"))]
    let out = relay_tcp(&mut app, upstream, FIRST_BYTES_WAIT, |d| {
        ctx.decided(id, d);
        Action::Pass
    })
    .await;
    let action = if out.upstream_write_failed { FlowAction::Failed } else { FlowAction::Relayed };
    lock(&ctx.book).close(id, action, out.bytes_up, out.bytes_down);
    if out.stop {
        close_app(&mut app).await;
    }
}

pub async fn handle_udp(ctx: Arc<Relay>, mut app: IpStackUdpStream) {
    let flow = FiveTuple { proto: Proto::Udp, local: app.local_addr(), remote: app.peer_addr() };
    if flow.remote.port() == DNS_PORT {
        return dns_flow::udp(ctx, app, flow).await;
    }
    let owner = {
        let c = ctx.clone();
        tokio::spawn(async move { c.owner(flow).await })
    };
    // Datagrams are held until the flow is decoded (a QUIC ClientHello can
    // span two Initials).
    let mut classifier = UdpClassifier::new();
    let mut held: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![0u8; DATAGRAM];
    let decided = loop {
        match tokio::time::timeout(UDP_IDLE, app.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                held.push(buf[..n].to_vec());
                if let Some(d) = classifier.push(&buf[..n]) {
                    break d;
                }
            }
            _ => return,
        }
    };
    let pid = owner.await.unwrap_or(None);
    let Some(id) = ctx.admit(&flow, pid, FlowProto::Udp, kind_of(&decided)) else { return };
    ctx.decided(id, &decided);
    let up = match ctx.egress.socket(flow.remote, true).and_then(|s| UdpSocket::from_std(s.into()).map_err(|e| e.to_string())) {
        Ok(u) => u,
        Err(_) => return lock(&ctx.book).close(id, FlowAction::Failed, 0, 0),
    };
    if up.connect(flow.remote).await.is_err() {
        return lock(&ctx.book).close(id, FlowAction::Failed, 0, 0);
    }
    let (mut bytes_up, mut bytes_down) = (0u64, 0u64);
    for d in &held {
        if up.send(d).await.is_err() {
            return lock(&ctx.book).close(id, FlowAction::Failed, 0, 0);
        }
        bytes_up += d.len() as u64;
    }
    let mut down = vec![0u8; DATAGRAM];
    loop {
        tokio::select! {
            r = tokio::time::timeout(UDP_IDLE, app.read(&mut buf)) => match r {
                Ok(Ok(n)) if n > 0 => {
                    if up.send(&buf[..n]).await.is_err() { break; }
                    bytes_up += n as u64;
                }
                _ => break,
            },
            r = tokio::time::timeout(UDP_IDLE, up.recv(&mut down)) => match r {
                Ok(Ok(n)) => {
                    if app.write_all(&down[..n]).await.is_err() { break; }
                    bytes_down += n as u64;
                }
                _ => break,
            },
        }
    }
    lock(&ctx.book).close(id, FlowAction::Relayed, bytes_up, bytes_down);
}
