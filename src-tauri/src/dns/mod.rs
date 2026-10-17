//! DNS filter engine (phase A): a local DNS proxy that answers blocked names
//! itself and forwards everything else to upstream resolvers.
//!
//! - `rules`: the filter-list syntax and the O(labels) matcher.
//! - `lists`: the downloaded list, its 24 h cache, and the user's rules.
//! - `proxy`: the UDP and TCP server, block answers, forwarding, counters.
//! - `probe`: a plain UDP client; the self check and the live test use it.
//! - `status`: the versioned `dns_status` wire shape.
//! - `engine`: rules + proxy + refresher as one start/status/check/stop unit.
//! - `commands`: the Tauri commands over the engine.
//!
//! Nothing here changes Windows DNS settings: pointing the system at the
//! proxy is `crate::sysdns`, behind the `filtering.systemDns` data switch.
//! The live check for `filtering.dns` is
//! `engine::tests::live_dns_filter_resolves_blocked_domain`. The filter is
//! system wide: every lookup arrives from the DNS Client service, so the
//! proxy never knows which app asked.

pub mod commands;
pub mod engine;
pub mod lists;
pub mod probe;
pub mod proxy;
pub mod rules;
pub mod status;

use std::net::SocketAddr;
use std::path::Path;

/// Errors of the DNS engine; strings only at the command boundary.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("cannot listen on {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("config: {0}")]
    Config(String),
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("list cache: {0}")]
    Cache(String),
}

impl DnsError {
    pub(crate) fn io(path: &Path, source: std::io::Error) -> Self {
        DnsError::Io { path: path.display().to_string(), source }
    }
}
