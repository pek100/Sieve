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
  denied, and so is everything the hub reads from its own machine: its
  interface addresses, every on-link prefix and gateway, the destination of
  every non-default route (sibling VLANs, VPN subnets), and the IPv6 /56
  around each of its global IPv6 addresses. It also learns its public
  address from each link (the device reports the address it reached the hub
  at) and denies it to that link, without asking any outside service. Blocks
  that disappear stay denied for 10 minutes. The owner can add blocks
  (`sieve-hub lan`). Names that only resolve on a local network (one label,
  `localhost`, `.local`, `.home.arpa`, `.internal`, `.lan`) and port 25 are
  refused. Per-device rules (domain suffixes, address blocks, ports, and the
  explicit `allow-lan` / `allow-self` kinds for anything local), per-device
  limits announced to the device, revocation that cuts a device's streams at
  once, rule changes that cut the open streams they now deny, and an audit
  log (who, when, where to, bytes, outcome; never payload) with a size cap
  and a 30-day retention floor. The hub never decrypts what it relays.
- **Device.** Holds the link with back-off, serves SOCKS5 and HTTP CONNECT on
  a loopback port, and offers `LinkClient::open(host, port)`. It keeps to the
  stream limit the hub announces (an open over it waits two seconds, then
  gets `Busy`), and waits for a new link rather than failing when the link is
  being replaced. While the hub is unreachable it refuses (`stop`, the
  default) or goes direct (`direct`), per device.
- **Failing closed.** The hub refuses to start if it cannot read its own
  network interfaces (unless the owner passes `--allow-undetected-lan`), and
  opens no new stream while it cannot read its store, write its audit log,
  keep its audit rows for the retention floor, or read its interfaces. A
  store unreadable for 60 seconds cuts every link. Both binaries refuse a
  directory that other users can read or write.

Binaries: `sieve-hub` (init, secure, pair, devices, revoke, rule, limit, lan,
audit, status, run) and `sieve-link` (pair, run, show, secure). Each prints
its usage when run without arguments. Their directories default to
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
- **`allow-cidr` opens nothing local.** It only lets a device with an allow
  list name address literals. Reaching part of the hub's network takes
  `allow-lan` (at most a /16 or /48), reaching the hub machine itself
  `allow-self`; both print a warning naming the device. Stores written
  before this split keep their `allow-cidr` entries, which no longer open
  the local network (`sieve-hub devices` and `run` say so).
- **The hub's public address is learned per link, from the device.** A
  device that lies about it only restricts itself. Until a device has linked
  once, nothing is learned; `sieve-hub lan` shows what was.
- **The IPv6 site prefix is a guess.** The hub denies the /56 around each of
  its global IPv6 addresses (home routers hand out a /56). On a network
  where other /64s of that /56 are someone else's, narrow it with
  `sieve-hub lan v6-prefix 64`.
- **Other Unix systems read no route table.** Linux and Windows deny routed
  prefixes; on macOS and the BSDs a routed subnet must be added by hand
  (`sieve-hub lan add`).
- **A full audit log stops new connections.** Rows younger than the floor
  (30 days) are never deleted to make room; when the cap (256 MiB, about
  15,000 streams a day for 30 days) would need that, the hub refuses new
  streams and `sieve-hub status` says why. Change both with `sieve-hub
  audit` (applies at the next start). Rotated files are `audit.log.N`, a
  higher N is newer.
- **Raising a device's limit far closes its link once.** A link has room for
  its limit plus spare streams; a raise within that applies at once, a
  larger one makes the device relink (its open connections end), and
  `sieve-hub limit` says so.
- **Keys are files.** `identity.key` is an unencrypted PKCS#8 file protected
  by file permissions: anyone who can act as that user, or as an
  administrator or root, can read it.
- **The pairing code is a password until used.** Give it at the prompt
  (`sieve-link pair` asks); as a command-line argument it shows in the
  process list and shell history.

## Before running a hub at home

What is still up to the owner:

1. **Firewall the device's listen port to the home address.** When the hub
   dials out to a device (`sieve-link run --listen`), anyone can reach that
   port; only the pinned hub key completes a handshake, but limit the port
   to the home's public IP in the device's firewall so strangers cannot
   even try.
2. **Do not pass `--allow-undetected-lan`.** Without it the hub refuses to
   run when it cannot read its own network; with it, its LAN is protected
   by the default address classes alone.

Everything else (the LAN, routed subnets, the IPv6 site prefix, the public
address, audit retention) the hub works out itself; check what it found with
`sieve-hub lan` and `sieve-hub status` once a device has linked.

## Licence

This crate is licensed separately from the rest of Sieve and depends on none
of Sieve's other crates. **The Apache-2.0 licence in `LICENSE` is a
placeholder: the owner has not yet chosen this crate's licence.**
