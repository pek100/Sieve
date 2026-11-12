# sieve-link

Trusted links: a device's TCP connections exit through a hub it was paired with.

- **Link.** One TLS 1.3 connection per device and hub, both sides authenticated
  by raw public keys (RFC 7250) pinned at pairing, X25519MLKEM768 preferred
  (rustls on aws-lc-rs), multiplexed with yamux. Either side may dial; roles
  come from the keys.
- **Pairing.** The hub's owner makes a one-time code (hub key fingerprint, a
  128-bit secret, an expiry, optionally the hub's address). The device proves
  it knows the secret with an HMAC bound to the TLS session and both keys.
  Until a code is outstanding the hub refuses every unknown key.
- **Hub.** Opens `connect host:port` streams for paired devices, resolving the
  name itself. Per-device rules (domain suffixes, address blocks; loopback,
  private, link-local and the hub's LAN denied by default), per-device limits,
  revocation that cuts a device's streams at once, and an append-only audit
  log (who, when, where to, bytes, outcome; never payload). The hub never
  decrypts what it relays.
- **Device.** Holds the link with back-off, serves SOCKS5 and HTTP CONNECT on
  a loopback port, and offers `LinkClient::open(host, port)`. While the hub
  is unreachable it refuses (`stop`, the default) or goes direct (`direct`),
  per device.

Binaries: `sieve-hub` (init, pair, devices, revoke, rule, limit, run) and
`sieve-link` (pair, run, show). Each prints its usage when run without arguments.

## Licence

This crate is licensed separately from the rest of Sieve and depends on none
of Sieve's other crates. **The Apache-2.0 licence in `LICENSE` is a
placeholder: the owner has not yet chosen this crate's licence.**
