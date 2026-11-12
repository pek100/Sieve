//! Trusted links: a device's TCP connections exit through a paired hub.
//!
//! A device and a hub hold one mutually authenticated TLS 1.3 connection
//! (raw public keys pinned at pairing, X25519MLKEM768 preferred), multiplexed
//! with yamux. Roles come from the keys, not from who dialled: a hub behind a
//! home router can dial out to a device and still be the hub. The device asks
//! for `connect host:port` streams; the hub resolves the name, applies that
//! device's rules and limits, relays bytes it never decrypts, and writes one
//! audit row per stream.
//!
//! The crate is licensed apart from the rest of Sieve and depends on none of
//! its other crates (see README.md).

pub mod audit;
pub mod device;
pub mod error;
pub mod hub;
pub mod identity;
pub mod mux;
pub mod pairing;
pub mod proxy;
pub mod resolve;
pub mod rules;
pub mod store;
pub mod tls;
pub mod wire;

pub use device::{HubRoute, LinkClient, LinkConfig, LinkStream, OnHubDown};
pub use error::LinkError;
pub use hub::{Hub, HubConfig};
pub use identity::{Fingerprint, Identity};
pub use pairing::PairingCode;
pub use rules::{Cidr, Limits, Rules};

/// Milliseconds since the Unix epoch (audit rows, keep-alive bookkeeping).
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Seconds since the Unix epoch (pairing-code expiry).
pub(crate) fn now_secs() -> u64 {
    now_ms() / 1000
}
