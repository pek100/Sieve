//! For tests whose subject needs this machine's loopback as it is on a clean
//! Windows: TCP straight from socket to socket, and UDP datagrams delivered.
//! A filtering proxy in the loopback (AdGuard proxies the loopback TCP of new
//! executables, and on the dev PC no loopback datagram arrives at all) fails
//! such a test with a confusing assertion, so it fails here instead, saying so.
//! Not ignored: on the VM the check passes and the test runs.
//!
//! Each check runs once per test binary and its answer is kept.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::sync::OnceLock;
use std::time::Duration;

/// How long a loopback datagram may take before it counts as not delivered.
const DATAGRAM_WAIT: Duration = Duration::from_secs(2);

fn tcp_verdict() -> Result<(), String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let mut client = TcpStream::connect(listener.local_addr().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let (mut server, seen) = listener.accept().map_err(|e| e.to_string())?;
    let ours = client.local_addr().map_err(|e| e.to_string())?;
    client.write_all(b"x").map_err(|e| e.to_string())?;
    let mut one = [0u8; 1];
    server.read_exact(&mut one).map_err(|e| e.to_string())?;
    if ours == seen { Ok(()) } else { Err(format!("loopback is proxied on this machine (e.g. AdGuard); run on the VM (the server saw {seen}, the client's socket is {ours})")) }
}

fn udp_verdict() -> Result<(), String> {
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    receiver.set_read_timeout(Some(DATAGRAM_WAIT)).map_err(|e| e.to_string())?;
    sender.send_to(b"x", receiver.local_addr().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let ours = sender.local_addr().map_err(|e| e.to_string())?;
    let mut buffer = [0u8; 8];
    match receiver.recv_from(&mut buffer) {
        Ok((_, seen)) if seen == ours => Ok(()),
        Ok((_, seen)) => Err(format!("loopback is proxied on this machine (e.g. AdGuard); run on the VM (a datagram from {ours} arrived from {seen})")),
        Err(e) => Err(format!("loopback UDP is filtered on this machine (e.g. AdGuard); run on the VM (a loopback datagram was not delivered in {DATAGRAM_WAIT:?}: {e})")),
    }
}

/// Panics, saying why, unless a loopback TCP connection reaches its server unproxied.
pub(crate) fn needs_plain_tcp() {
    static VERDICT: OnceLock<Result<(), String>> = OnceLock::new();
    if let Err(why) = VERDICT.get_or_init(tcp_verdict) {
        panic!("{why}");
    }
}

/// Panics, saying why, unless a loopback datagram arrives from its sender's own socket.
pub(crate) fn needs_plain_udp() {
    static VERDICT: OnceLock<Result<(), String>> = OnceLock::new();
    if let Err(why) = VERDICT.get_or_init(udp_verdict) {
        panic!("{why}");
    }
}
