//! Name resolution at the hub. The system resolver by default; a fixed map
//! for tests and for owners who want to pin names.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;

pub trait Resolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a>;
}

/// The operating system's resolver (getaddrinfo), off the runtime threads.
#[derive(Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) })
    }
}

/// A fixed map from names to addresses; unknown names fail.
#[derive(Debug, Default, Clone)]
pub struct StaticResolver(pub HashMap<String, Vec<IpAddr>>);

impl Resolver for StaticResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        let found = self.0.get(&host.to_ascii_lowercase()).cloned();
        Box::pin(async move {
            match found {
                Some(ips) => Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect()),
                None => Err(io::Error::new(io::ErrorKind::NotFound, "no such name")),
            }
        })
    }
}

/// Address literals never reach a resolver.
pub(crate) async fn resolve(r: &dyn Resolver, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    r.resolve(host, port).await
}
