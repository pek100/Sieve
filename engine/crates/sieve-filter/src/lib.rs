//! Sieve's filtering knowledge, pure and offline (plan 1.2, section 5):
//! - [`catalogue`]: the lists Sieve knows, with licence, default and trust;
//! - [`lists`]: download metadata (the `! Expires:` refresh, conditional
//!   request headers);
//! - [`rules`]: the one rule engine (adblock-rust), compiled from list text
//!   with per-list applied and skipped counts, and the host-level check;
//! - [`exclusions`]: the HTTPS exclusion syntax (E10) and its matcher;
//! - [`resources`]: the pinned resource-archive hash check.
//!
//! No I/O happens here: the engine downloads, this crate decides.
pub mod catalogue;
pub mod exclusions;
pub mod lists;
pub mod resources;
pub mod rules;
