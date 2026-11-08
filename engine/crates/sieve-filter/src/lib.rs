//! Sieve's filtering knowledge, pure and offline (plan 1.2, section 5):
//! - [`catalogue`]: the lists Sieve knows, with licence, default and trust;
//! - [`lists`]: download state (the `! Expires:` refresh, conditional request
//!   headers, whether a response may replace the copy);
//! - [`rules`]: the one rule engine (adblock-rust), compiled from list text
//!   with a per-list report, and the host-level check;
//! - [`exclusions`]: the HTTPS exclusion syntax (E10) and its matcher;
//! - [`cosmetic`]: what one page gets (CSS, procedural filters, scriptlets);
//! - [`resources`]: the pinned resource bundle, verified then loaded;
//! - [`params`]: the built-in tracking parameters and their removal.
//!
//! No I/O happens here: the engine downloads, this crate decides.
pub mod catalogue;
pub mod cosmetic;
pub mod exclusions;
pub mod lists;
pub mod params;
pub mod resources;
pub mod rules;
