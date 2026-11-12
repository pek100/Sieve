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
  name itself. By default a device cannot reach the hub or its network:
  loopback, private, link-local and other special address classes are
  denied, and so is every on-link prefix (IPv4 and IPv6), address and
  gateway the hub reads from its own interfaces, plus blocks the owner adds
  (`sieve-hub lan`). Names that only resolve on a local network (one label,
  `localhost`, `.local`, `.home.arpa`, `.internal`, `.lan`) and port 25 are
  refused. Per-device rules (domain suffixes, address blocks, ports),
  per-device limits, revocation that cuts a device's streams at once, and an
  audit log (who, when, where to, bytes, outcome; never payload), rotated by
  size. The hub never decrypts what it relays.
- **Device.** Holds the link with back-off, serves SOCKS5 and HTTP CONNECT on
  a loopback port, and offers `LinkClient::open(host, port)`. While the hub
  is unreachable it refuses (`stop`, the default) or goes direct (`direct`),
  per device.
- **Failing closed.** The hub refuses to start if it cannot read its own
  network interfaces (unless the owner passes `--allow-undetected-lan`), and
  opens no new stream while it cannot read its store, write its audit log, or
  read its interfaces. Both binaries refuse a directory that other users can
  read or write.

Binaries: `sieve-hub` (init, secure, pair, devices, revoke, rule, limit, lan,
run) and `sieve-link` (pair, run, show, secure). Each prints its usage when
run without arguments. Their directories default to
`%LOCALAPPDATA%\sieve-link\{hub,device}` on Windows and
`~/.local/state/sieve-link/{hub,device}` (or `$XDG_STATE_HOME`) on Unix,
created readable and writable by the current user only.

## Design facts

Things that are true by design, and worth knowing before you rely on it:

- **Any local process can use the device's proxy.** It listens on loopback
  only, without authentication: every program and every user on the device
  can send traffic through the hub.
- **`socks5://` resolves names on the device; `socks5h://` does not.** A
  client set to plain `socks5` looks the name up locally (the lookup leaks
  to the device's network and the hub sees only an address, so its domain
  rules do not apply). Use `socks5h` or HTTP CONNECT so the hub resolves.
- **`direct` mode is the device's own network.** With `on-hub-down =
  direct`, a connection made while the hub is down resolves and connects
  from the device itself.
- **The hub sees destinations, and plaintext.** It never decrypts TLS, but
  like any exit it sees where each stream goes, and the content of any
  protocol that is not encrypted end to end.
- **Domain deny rules do not cover address literals.** A `deny-suffix` rule
  stops names; a device can still ask for the address itself unless the
  device has an allow list (`allow-suffix`), which turns literals off except
  inside its `allow-cidr` blocks.
- **Keys are files.** `identity.key` is an unencrypted PKCS#8 file protected
  by file permissions: anyone who can act as that user, or as an
  administrator or root, can read it.
- **The pairing code is a password until used.** Give it at the prompt
  (`sieve-link pair` asks); as a command-line argument it shows in the
  process list and shell history.
- **The hub's public address is not detected.** Behind a router no interface
  shows it, and the hub never asks an outside service. Add it with
  `sieve-hub lan add <address>` if devices must not reach it.

## Licence

This crate is licensed separately from the rest of Sieve and depends on none
of Sieve's other crates. **The Apache-2.0 licence in `LICENSE` is a
placeholder: the owner has not yet chosen this crate's licence.**
