//! DNS filter engine (phase A): a local DNS proxy that answers blocked names
//! itself and forwards everything else to upstream resolvers.
//!
//! - `rules`: the filter-list syntax and the O(labels) matcher.
//!
//! Nothing here changes Windows DNS settings. Pointing the system at the
//! proxy is phase B, behind the `filtering.dns` data switch.

pub mod rules;
