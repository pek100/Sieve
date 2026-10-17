//! DNS filter engine (phase A): a local DNS proxy that answers blocked names
//! itself and forwards everything else to upstream resolvers.
//!
//! - `rules`: the filter-list syntax and the O(labels) matcher.
//! - `lists`: the downloaded list, its 24 h cache, and the user's rules.
//!
//! Nothing here changes Windows DNS settings. Pointing the system at the
//! proxy is phase B, behind the `filtering.dns` data switch.

pub mod lists;
pub mod rules;

use std::path::Path;

/// Errors of the DNS engine; strings only at the command boundary.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
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
