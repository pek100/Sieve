//! Windows: the one way a socket leaves the engine (plan 1.4). Every upstream
//! socket is bound to the egress interface's own source address and pinned with
//! IP_UNICAST_IF / IPV6_UNICAST_IF, both computed with Sieve's routes ignored
//! (`route::pin`); "would loop" is refused. The relay and DNS share it.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream};

use crate::dns::{BoxFuture, Connector};
use crate::route::pin;
use crate::route::table::NetTables;

/// The relay's flows take theirs from `stack::retry::BUDGET`, the same value.
const CONNECT_TIMEOUT: Duration = crate::stack::retry::BUDGET;

pub struct Egress {
    tun_index: u32,
    /// Re-read on every route change (control); pinning asks it.
    tables: Arc<RwLock<NetTables>>,
}

impl Egress {
    pub fn new(tun_index: u32, tables: Arc<RwLock<NetTables>>) -> Self {
        Self { tun_index, tables }
    }

    /// A socket for `target`, bound to the egress source and pinned to the
    /// egress interface (never the engine's adapter).
    pub fn socket(&self, target: SocketAddr, udp: bool) -> Result<socket2::Socket, String> {
        let e = {
            let tables = self.tables.read().unwrap_or_else(|p| p.into_inner());
            pin::egress(&tables, Some(self.tun_index), target.ip()).map_err(|e| e.to_string())?
        };
        pin::egress_socket(e, target, udp)
    }

    pub async fn connect(&self, target: SocketAddr) -> Result<TcpStream, String> {
        let sock = self.socket(target, false)?;
        let socket = TcpSocket::from_std_stream(sock.into());
        match tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(target)).await {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(format!("connect {target}: {e}")),
            Err(_) => Err(format!("connect {target}: timeout")),
        }
    }
}

/// One relay connect with no deadline of its own: `stack::retry` holds the
/// budget for all of a flow's connects.
impl crate::stack::retry::Attempt for Egress {
    type Stream = TcpStream;

    fn attempt(&self, target: SocketAddr) -> crate::stack::retry::AttemptFuture<'_, TcpStream> {
        use crate::stack::retry::Failure;
        Box::pin(async move {
            let sock = self.socket(target, false).map_err(Failure::Egress)?;
            TcpSocket::from_std_stream(sock.into()).connect(target).await.map_err(|e| Failure::from_io(&e))
        })
    }
}

impl crate::tls::intercept::Dial for Egress {
    type Stream = TcpStream;

    fn dial(&self, target: SocketAddr) -> crate::tls::intercept::DialFuture<'_, TcpStream> {
        Box::pin(self.connect(target))
    }
}

/// The link's network (`crate::link`): its own socket is one of these, so it
/// never enters Sieve's adapter.
impl crate::link::LinkNet for Egress {
    fn connect(&self, target: SocketAddr) -> BoxFuture<'_, Result<TcpStream, String>> {
        Box::pin(Egress::connect(self, target))
    }

    /// The first usable IPv4 address of the adapter Windows sends through
    /// (`NetTables::default_adapter`, Sieve's own left out), else its IPv6 one.
    fn listen_ip(&self) -> Option<std::net::IpAddr> {
        let tables = self.tables.read().unwrap_or_else(|p| p.into_inner());
        let adapter = tables.default_adapter()?;
        let usable = |ip: &std::net::IpAddr| match ip {
            std::net::IpAddr::V4(v4) => !(v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()),
            std::net::IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80),
        };
        let all: Vec<_> = adapter.addresses.iter().map(|a| a.ip).filter(usable).collect();
        all.iter().copied().find(std::net::IpAddr::is_ipv4).or_else(|| all.first().copied())
    }

    fn is_local(&self, ip: std::net::IpAddr) -> bool {
        let tables = self.tables.read().unwrap_or_else(|p| p.into_inner());
        tables.others().flat_map(|a| a.addresses.iter()).filter_map(|a| a.on_link()).any(|p| p.length() > 0 && p.contains(ip))
    }
}

impl Connector for Egress {
    fn tcp(&self, target: SocketAddr) -> BoxFuture<'_, Result<TcpStream, String>> {
        Box::pin(self.connect(target))
    }

    fn udp(&self, target: SocketAddr) -> Result<socket2::Socket, String> {
        self.socket(target, true)
    }
}
