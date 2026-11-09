//! Windows: a flow to port 53. It is attributed and booked like any other, and
//! `dns::service` answers it; the relay connects nothing to the server the client
//! addressed. Only `dns::service`, in the user's plain mode, sends there.

use std::sync::Arc;

use ipstack::{IpStackTcpStream, IpStackUdpStream};
use sieve_ipc::{FlowAction, FlowKind, FlowProto, FlowReason, Signal};

use super::relay::{Attributed, Relay, close_app, lock};
use crate::dns::service::{Asker, Totals, serve_datagrams, serve_tcp};
use crate::flow::flows::FiveTuple;

/// Remembers the flow's first question as its host (a flow is usually one query).
fn first_question(ctx: &Relay, id: u64) -> impl FnMut(&str) + use<'_> {
    let mut named = false;
    move |name| {
        if !std::mem::replace(&mut named, true) {
            lock(&ctx.book).update(id, |e| e.host = Some(name.to_string()));
        }
    }
}

/// Books the flow as DNS: a lookup is never blocked (`domain`), whoever asks. The
/// answer does depend on who asks: a guest's flows are never decrypted, and only
/// the DNS Client service's may have an NXDOMAIN rewritten (`dns::service`).
fn admit(ctx: &Relay, flow: &FiveTuple, attributed: &Attributed, proto: FlowProto) -> Option<(u64, Asker)> {
    let admitted = ctx.admit(flow, attributed, proto, FlowKind::Dns)?;
    lock(&ctx.book).update(admitted.id, |e| e.reason = Some(FlowReason::Dns));
    let dns_client = attributed.pid().is_some_and(|pid| dns_client_pid() == Some(pid));
    Some((admitted.id, Asker { may_decrypt: admitted.may_decrypt(), addressed: flow.remote.ip(), dns_client }))
}

/// How long the DNS Client service's process id is trusted before it is read again.
const DNS_CLIENT_PID_FOR_MS: u64 = 60_000;

/// The DNS Client's process id as last read, and when.
static CACHED: std::sync::Mutex<Option<(Option<u32>, u64)>> = std::sync::Mutex::new(None);

/// The next flow reads the DNS Client's process id afresh: a failed capture probe
/// may mean the service restarted under another one.
pub fn forget_dns_client_pid() {
    *CACHED.lock().unwrap_or_else(|p| p.into_inner()) = None;
}

/// The DNS Client service's process id, read from the service manager at most
/// once a [`DNS_CLIENT_PID_FOR_MS`]. None when it cannot be read.
fn dns_client_pid() -> Option<u32> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let now = crate::watchdog::monotonic_ms();
    let mut cached = CACHED.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((pid, at)) = *cached
        && now.saturating_sub(at) < DNS_CLIENT_PID_FOR_MS
    {
        return pid;
    }
    let pid = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .and_then(|m| m.open_service("Dnscache", ServiceAccess::QUERY_STATUS))
        .and_then(|s| s.query_status())
        .ok()
        .and_then(|status| status.process_id);
    *cached = Some((pid, now));
    pid
}

/// A lookup Sieve could not get an answer for is the flow's problem: `resolved`
/// counts every answer a server gave, failures included, so what is left is a
/// question no resolver answered.
fn finish(ctx: &Relay, id: u64, totals: Totals) {
    let action = if totals.queries > 0 && totals.resolved == 0 { FlowAction::Failed } else { FlowAction::Relayed };
    let mut book = lock(&ctx.book);
    if totals.queries > totals.resolved {
        book.problem(id, Signal::DnsUnanswered);
    }
    book.close(id, action, totals.bytes_up, totals.bytes_down);
}

pub async fn udp(ctx: Arc<Relay>, mut app: IpStackUdpStream, flow: FiveTuple) {
    let attributed = ctx.attribute(flow).await;
    let Some((id, asker)) = admit(&ctx, &flow, &attributed, FlowProto::Udp) else { return };
    let totals = serve_datagrams(&ctx.dns, &mut app, asker, first_question(&ctx, id)).await;
    finish(&ctx, id, totals);
}

pub async fn tcp(ctx: Arc<Relay>, mut app: IpStackTcpStream, flow: FiveTuple) {
    let attributed = ctx.attribute(flow).await;
    let Some((id, asker)) = admit(&ctx, &flow, &attributed, FlowProto::Tcp) else { return close_app(&mut app).await };
    let totals = serve_tcp(&ctx.dns, &mut app, asker, first_question(&ctx, id)).await;
    finish(&ctx, id, totals);
    close_app(&mut app).await;
}
