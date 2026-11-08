//! Decrypted HTTP (plan 2.8, 5.2, slice 6), through hyper both ways with one
//! upstream connection per client connection:
//! - [`facts`]: the one owner of a request's url, type, initiator and
//!   document-ness;
//! - [`rules`]: what the rules make of a request;
//! - [`serve`]: the connection pair and the per-request path, 421 included;
//! - [`upgrade`]: hop-by-hop headers and the WebSocket splice;
//! - [`hook`]: the response-body hook `inject::content` implements;
//! - [`tracking`]: what tracking protection does to a request and its response.
//!
//! Inside this module the HTTP types crate is written `::http::`.

pub mod facts;
pub mod hook;
pub mod rules;
pub mod serve;
#[cfg(test)]
mod tests;
pub mod tracking;
pub mod upgrade;
