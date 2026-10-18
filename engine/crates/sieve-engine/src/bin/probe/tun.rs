//! A Wintun session as a tokio AsyncRead + AsyncWrite device, one IP
//! packet per read and per write, which is what ipstack expects.
//!
//! A plain thread blocks in `receive_blocking`. Only packets addressed to a
//! routed test address go on to the stack: Windows also sends multicast and
//! broadcast chatter (SSDP, LLMNR, mDNS, Steam discovery, neighbour
//! discovery) out of every interface, the TUN included, and forwarding that
//! chatter looped in live run 1. Everything else is counted and discarded
//! here, before any per-flow work. `Session::shutdown` makes the thread end.

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};

use sieve_engine::flow::packet::{self, Proto, TCP_ACK, TCP_SYN};
use crate::support::{Refusal, admit_destination};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use wintun_bindings::Session;

#[derive(Debug, Default)]
pub struct TunCounters {
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub not_unicast: AtomicU64,
    pub not_routed: AtomicU64,
    pub syn_v4: AtomicU64,
    pub syn_v6: AtomicU64,
    pub udp_v4: AtomicU64,
    pub udp_v6: AtomicU64,
}

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

pub struct TunDevice {
    session: Arc<Session>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    counters: Arc<TunCounters>,
}

impl TunDevice {
    pub fn new(session: Arc<Session>, routed: Vec<IpAddr>, counters: Arc<TunCounters>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let reader = session.clone();
        let c = counters.clone();
        std::thread::spawn(move || {
            while let Ok(p) = reader.receive_blocking() {
                let bytes = p.bytes();
                bump(&c.packets_in);
                let Some(dst) = packet::dst_ip(bytes) else { continue };
                match admit_destination(dst, &routed) {
                    Err(Refusal::NotUnicast) => {
                        bump(&c.not_unicast);
                        continue;
                    }
                    Err(_) => {
                        bump(&c.not_routed);
                        continue;
                    }
                    Ok(()) => {}
                }
                if let Some(pk) = packet::parse(bytes) {
                    let v4 = dst.is_ipv4();
                    match pk.proto {
                        Proto::Tcp if pk.tcp_flags & TCP_SYN != 0 && pk.tcp_flags & TCP_ACK == 0 => {
                            bump(if v4 { &c.syn_v4 } else { &c.syn_v6 })
                        }
                        Proto::Udp => bump(if v4 { &c.udp_v4 } else { &c.udp_v6 }),
                        Proto::Tcp => {}
                    }
                }
                if tx.send(bytes.to_vec()).is_err() {
                    break;
                }
            }
        });
        Self { session, rx, counters }
    }
}

impl AsyncRead for TunDevice {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match ready!(self.rx.poll_recv(cx)) {
            Some(packet) => {
                if packet.len() > buf.remaining() {
                    // Larger than ipstack's MTU buffer: drop it rather than
                    // hand over a truncated IP packet.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                buf.put_slice(&packet);
                Poll::Ready(Ok(()))
            }
            None => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let len = u16::try_from(buf.len()).map_err(|_| std::io::Error::other("packet larger than 65535"))?;
        let mut packet = self.session.allocate_send_packet(len).map_err(std::io::Error::other)?;
        packet.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(packet);
        bump(&self.counters.packets_out);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
