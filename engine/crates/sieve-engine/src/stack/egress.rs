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

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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

impl Connector for Egress {
    fn tcp(&self, target: SocketAddr) -> BoxFuture<'_, Result<TcpStream, String>> {
        Box::pin(self.connect(target))
    }

    fn udp(&self, target: SocketAddr) -> Result<socket2::Socket, String> {
        self.socket(target, true)
    }
}
