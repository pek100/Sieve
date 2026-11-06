//! Windows: a flow to port 53. It is attributed and booked like any other, and
//! `dns::service` answers it; nothing is connected to the server the client
//! addressed, so plain DNS has no path out of the relay.

use std::sync::Arc;

use ipstack::{IpStackTcpStream, IpStackUdpStream};
use sieve_ipc::{FlowAction, FlowKind, FlowProto, FlowReason};

use super::relay::{Attributed, Relay, close_app, lock};
use crate::dns::service::{Totals, serve_datagrams, serve_tcp};
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

/// Books the flow as DNS: a lookup is never blocked (`domain`), whoever asks.
fn admit(ctx: &Relay, flow: &FiveTuple, attributed: &Attributed, proto: FlowProto) -> Option<u64> {
    let id = ctx.admit(flow, attributed, proto, FlowKind::Dns)?.id;
    lock(&ctx.book).update(id, |e| e.reason = Some(FlowReason::Dns));
    Some(id)
}

fn finish(ctx: &Relay, id: u64, totals: Totals) {
    let action = if totals.queries > 0 && totals.resolved == 0 { FlowAction::Failed } else { FlowAction::Relayed };
    lock(&ctx.book).close(id, action, totals.bytes_up, totals.bytes_down);
}

pub async fn udp(ctx: Arc<Relay>, mut app: IpStackUdpStream, flow: FiveTuple) {
    let attributed = ctx.attribute(flow).await;
    let Some(id) = admit(&ctx, &flow, &attributed, FlowProto::Udp) else { return };
    let totals = serve_datagrams(&ctx.dns, &mut app, first_question(&ctx, id)).await;
    finish(&ctx, id, totals);
}

pub async fn tcp(ctx: Arc<Relay>, mut app: IpStackTcpStream, flow: FiveTuple) {
    let attributed = ctx.attribute(flow).await;
    let Some(id) = admit(&ctx, &flow, &attributed, FlowProto::Tcp) else { return close_app(&mut app).await };
    let totals = serve_tcp(&ctx.dns, &mut app, first_question(&ctx, id)).await;
    finish(&ctx, id, totals);
    close_app(&mut app).await;
}
