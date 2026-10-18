//! Read-only attribution experiment using only this process's loopback sockets.
//! Does not touch Sieve, services, adapters or routing.
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::{Ipv6Addr, SocketAddr};
    use sieve_engine::flow::flows::{OwnerSource, Table, os::IpHelper};
    use socket2::{Domain, Protocol, Socket, Type};
    for only_v6 in [false, true] {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(only_v6)?;
        socket.bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0).into())?;
        let port = socket.local_addr()?.as_socket().ok_or("missing address")?.port();
        println!("UDP only_v6={only_v6}, own_pid={}, bound_port={port}", std::process::id());
        for table in [Table::Udp4, Table::Udp6] {
            let rows = IpHelper.read(table).ok_or("table read failed")?;
            println!("{table:?}: {:?}", rows.into_iter().filter(|r| r.local.port() == port).collect::<Vec<_>>());
        }
    }
    // A v6 dual-mode client connects to our own IPv4 loopback listener.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let target = listener.local_addr()?;
    let client = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    client.set_only_v6(false)?;
    let mapped = SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(), target.port());
    client.connect(&mapped.into())?;
    let (_server, _) = listener.accept()?;
    let port = client.local_addr()?.as_socket().ok_or("missing local address")?.port();
    println!("TCP dual-mode client, own_pid={}, bound_port={port}", std::process::id());
    for table in [Table::Tcp4, Table::Tcp6] {
        let rows = IpHelper.read(table).ok_or("table read failed")?;
        println!("{table:?}: {:?}", rows.into_iter().filter(|r| r.local.port() == port).collect::<Vec<_>>());
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() { eprintln!("Windows only"); }
