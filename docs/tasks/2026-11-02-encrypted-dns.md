# Task: encrypted DNS upstreams on the TUN (slice 4, plan 1.4)

Stream `encrypted-dns`, branch `wf-encrypted-dns`. Spec: `docs/plans/2026-10-17-https-filtering.md` 1.4, 2.7 (key exchange), slice 4 "Encrypted DNS upstream" and its unit-test acceptance.

## Goal

While the engine routes, every DNS lookup caught on the TUN (UDP and TCP port 53) is answered through an encrypted upstream: DoH by default (Cloudflare, then Quad9), DoT and DoQ selectable, tried in order, the second answering within 2 s when the first never answers. Names under an adapter's own suffixes go to that adapter's DNS server only when that server is in a private range excluded from routing. Plain DNS never reaches a non-LAN address, on any failure path. Every TLS session prefers X25519MLKEM768. The app can set the list over the pipe. With the engine stopped, killed or uninstalled, nothing remains: no Windows DNS setting is ever read for writing or written.

## What exists (read before designing, 2026-11-05)

- `src/dns.rs`: message parser, `Transactions`, `NameMap`. It already declares `pub mod upstream`.
- `src/dns/upstream.rs`: the parser for the three kinds, `DEFAULTS`, `resolve` with one shared 2 s deadline and equal shares, `Exchange` trait, `SplitHorizon`, `split_server`, with tests. **Nothing calls it**, and there is no real `Exchange`.
- `src/stack/relay.rs`: `handle_udp` and `handle_tcp` send port 53 to the original server. `Relay::egress_socket` and `Relay::connect` own pinning (Windows only).
- `route::table::Adapter` has `dns` but no suffixes. `route::plan::plan` computes `holes`, the "excluded from routing" set.
- `sieve-ipc` is at PROTOCOL 2. The fixture file is `src/data/fixtures/engine-ipc-v2.json`. The stream brief says `engine-ipc-v1.json`, and the law's header comment does too; both are stale, and `v2` is the real file.
- `engine/Cargo.lock` has no rustls, hyper or quinn. The engine has no log file: facts reach an admin prompt through `status.json` in the engine folder.

## Spike evidence (throwaway, loopback only, not committed)

A scratch crate built and ran on this machine, 2026-11-05, with CMake present and **NASM absent**:

```
pq server: Some(X25519MLKEM768) Some(TLSv1_3)
x25519-only server: Some(X25519) Some(TLSv1_3)
h2 alpn Some("h2") group Some(X25519MLKEM768)
h2: 200 OK b"query"
quic alpn Some("doq") (no public kx accessor expected)
quic: "query"
```

Versions resolved: rustls 0.23.46, tokio-rustls 0.26.6, quinn 0.11.12, hyper 1.12.0, hyper-util 0.1.21, http-body-util 0.1.5, rcgen 0.14.10, aws-lc-rs 1.19.0, aws-lc-sys 0.47.0. Feature sets that worked:

```toml
rustls = { version = "0.23", default-features = false, features = ["aws-lc-rs", "std", "tls12", "prefer-post-quantum"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["aws-lc-rs"] }
quinn = { version = "0.11", default-features = false, features = ["rustls-aws-lc-rs", "runtime-tokio"] }
hyper = { version = "1", features = ["client", "http2"] }   # dev: add "server"
hyper-util = { version = "0.1", features = ["tokio"] }
http-body-util = "0.1"
rcgen = { version = "0.14", default-features = false, features = ["aws_lc_rs", "pem"] }  # dev only
```

API facts this proved: `CryptoProvider { kx_groups, ..aws_lc_rs::default_provider() }`; `ConnectionCommon::negotiated_key_exchange_group()`; `hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))`; `quinn::Endpoint::new(EndpointConfig::default(), None, std_udp_socket, Arc::new(quinn::TokioRuntime))`, which takes a caller-owned socket, so the pinned socket fits; `QuicClientConfig::try_from(rustls::ClientConfig)`. quinn exposes no negotiated group.

## Design decisions

Each entry is a decision with its reason. D-numbers are referenced by the steps and the tests.

- **D1. Encrypted always, no "unconfigured" plain mode.** The brief says forwarding switches "when configured". The plan says "from this slice on no plain DNS leaves the machine while the engine runs". They agree only if no stored config means `DEFAULTS`, so that is the rule. An empty list is refused, never read as "plain". The plain forward path for port 53 is deleted from `relay.rs` (S52), not kept behind a condition.
- **D2. Bootstrap without plain DNS.** `https://cloudflare-dns.com/...` needs an address, and asking Windows or a port 53 server would either loop through the TUN or break "no plain DNS". So:
  1. an IP literal is its own address;
  2. each `DEFAULTS` entry carries its resolver IPs beside its URL (one table, one owner): Cloudflare `1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001`, Quad9 `9.9.9.9, 149.112.112.112, 2620:fe::fe, 2620:fe::9`;
  3. any other host name is looked up (A, then AAAA) over the default entries, encrypted, at each connect. That discloses a custom resolver's name to Cloudflare or Quad9 once per connect, the only cost, and an IP-literal upstream avoids it.

  The filter-list rule "no hardcoded site names" is not broken: `DEFAULTS` is the spec's own resolver table, and no other names enter engine source. If the defaults are unreachable, a custom named upstream fails: it never falls back to plain.
- **D3. One TLS owner, `src/tls.rs`.** Plan 2.7 requires X25519MLKEM768, X25519, secp256r1, in that order, on every session the engine makes or answers. A crate-level `tls::provider()` (with `KX_GROUPS` as a const list) and `tls::client_config(roots, alpn)` are the only builders, so slice 6 reuses them. TLS 1.2 and 1.3 per plan 2.6. Early data stays off (2.10).
- **D4. Trust for resolver connections: `webpki-roots`, not `rustls-platform-verifier`.** Plan 2.6 assigns the platform verifier to intercepted upstream flows. For a resolver it is a trap. CryptoAPI may fetch AIA, OCSP or CRLs inside the verify call, which runs synchronously on a tokio worker. That fetch needs DNS, DNS comes back through the TUN to this same engine, and it waits on the handshake being verified. Blocked workers also stop the relay's heartbeat, and the watchdog would take the routes down. `webpki-roots` needs no network and no OS call, is already the plan's public root set (2.6), and takes a test root through the same parameter. Costs: no revocation check on resolver certificates, and resolvers behind a private CA or a TLS-inspecting network do not validate. See open question Q2.
- **D5. HTTP/2 only for DoH, with hyper.** RFC 8484 names HTTP/2 as the minimum recommended version, both defaults speak it, and slice 6 brings hyper anyway (2.7), so no extra stack. A server that does not negotiate `h2` is a failed upstream and is failed over. POST, `application/dns-message`, status 200 and that content type required.
- **D6. The wire ID is the engine's business.** DoH and DoQ send ID 0 (RFC 8484 4.1, RFC 9250 4.2.1; a nonzero DoQ reply ID is a failure). DoT assigns an ID unique among its in-flight queries (it pipelines over one stream). The client's ID is restored on the reply. Sessions own this, so `resolve` and the service never see a rewritten ID.
- **D7. Replies are validated before they count.** A reply must have QR set, a matching ID, and, when the query parsed, the same question and type; size at most 65,535. Anything else is a failed upstream. An upstream's own SERVFAIL or NXDOMAIN is an **answer**, passed on with no failover: the plan's failover triggers are "no answer, or a TLS or HTTP error". `Transactions` retires (S52): its job was matching replies on a shared socket, but each query now holds its own task. Its still-relevant tests move to `reply_answers(query, reply) -> Option<Message>`.
- **D8. Sessions survive cancellation of a query, not of a suspect link.**
  - Connecting runs in a spawned task owned by the upstream's slot, so a query's 1 s share cannot throw away a handshake in progress on a slow link, and concurrent queries share one connect.
  - A query cancelled by its share marks the session suspect: the next query reconnects. This is the `Exchange` trait's existing cancellation rule, and it replaces a dead NAT mapping with no keep-alive pings.
  - A reused session that fails immediately gets one retry on a fresh session inside the same share (DNS queries are idempotent; servers close idle connections).
  - Route changes that change the tables drop every session (`follow` in `routing.rs`), since they are pinned to the old egress.
- **D9. Failover is `resolve` plus a cooldown.** Order and the shared 2 s budget stay as built. Without more, a dead first upstream adds 1 s to every lookup for as long as it is dead, so an upstream that just failed is tried after the healthy ones for `FAILED_COOLDOWN` (30 s), keeping configured order within each group. It is still tried when the healthy ones fail, so recovery needs no probe. This is the one addition beyond the literal spec, and it changes order only, never the 2 s guarantee.
- **D10. When nothing answers, SERVFAIL.** With the client's ID and question, at the deadline. No path reaches a plain socket. This is the spec; its real-world consequence is open question Q1.
- **D11. Split-horizon rules are derived, not stored.** `Adapter` gains `dns_suffixes` (`#[serde(default)]`, read-only from `DnsSuffix` and the `FirstDnsSuffix` list in the existing `GetAdaptersAddresses` reader). `split_rules(&NetTables) -> Vec<SplitHorizon>` is computed per query from the live tables (few adapters, no cache, S23). The LAN set handed to `SplitHorizon::new` is `route::plan`'s holes, extracted to `plan::holes(&NetTables)` so there is one definition of "excluded from routing"; `new` keeps its private-address check, so a public hole (a split-tunnel VPN's public /24) still qualifies nothing. Each suffix takes the adapter's first qualifying server; IPv6 link-local servers are skipped, because the address has no scope and `pin::egress` refuses a link-local source. A matched name whose LAN server fails gets SERVFAIL, never the public upstream: that would publish a corporate name. On TC the LAN exchange retries over TCP.
- **D12. Non-QUERY opcodes stay on the machine.** Windows sends dynamic DNS UPDATE to the adapter's server on port 53. Forwarding it would hand the host name to a public resolver. Opcode other than 0 gets NOTIMP locally. A query with QR set or under 12 bytes is dropped. A well-formed QUERY the parser refuses (non-ASCII labels, several questions) still goes to the encrypted upstream, opaque, with no name-map evidence (`dns.rs` already promises that forwarding).
- **D13. UDP replies respect the client's size.** An upstream over HTTP can return far more than a UDP client accepts. The limit is the query's EDNS payload size or 512, and never above `mtu - 48`. Over the limit the client gets header plus question with TC set and retries on TCP port 53, which is also served. Without this, large answers break silently; slice 3 never needed it because the server applied the limit itself.
- **D14. Connector seam.** `dns::Connector { tcp(SocketAddr), udp(SocketAddr) }` is the only way the DNS code opens a socket. Production is `stack::egress::Egress`: `egress_socket` and `connect` moved out of `Relay` (S14, one pinning helper), and `Relay` holds an `Arc<Egress>`. Tests use a loopback connector that records every target, and can map a LAN address to a local server, so `SplitHorizon`'s refusal of 127.0.0.1 stays as is.
- **D15. Config and lifetime.** `Engine` holds the list as data in a `watch` channel (like `routes_up`) and persists `dns.json` beside `policy.json` with `policy`'s atomic write (`write_atomic` becomes `pub(crate)`). The same rule as policy: a newer `revision` only. Missing file means defaults; a malformed or invalid file means defaults plus a reason in `last_error`, never plain and never off. The pool (`dns::service::Service`) is built in `bring_up` and dropped in `take_down`, so connections end with the routes and nothing outlives the engine (fail open). A list change swaps the pool; in-flight queries finish on the old one.
- **D16. IPC is append-only: two new message types, no PROTOCOL bump.** `ClientMessage::SetDnsUpstreams(DnsUpstreams)` (`set_dns_upstreams`) and `EngineMessage::DnsUpstreams(DnsUpstreams)` (`dns_upstreams`), with `DnsUpstreams { revision: u64, upstreams: Vec<String> }`, `deny_unknown_fields`. `Policy` stays untouched: it is `Copy` and every `Policy {..}` literal would move. A refusal is the existing `Error` frame with the parser's reason. No existing shape changes, a v2 peer that never sends the new type is unaffected, and app and engine ship together, so nothing bumps. The crate header's "any message shape" gets one clarifying clause. The brief's append-only rule decides this; if another stream bumps PROTOCOL, the merge takes the bump. The engine owns validation (S32): `sieve-ipc` stays free of parsing. The fixture's `dns_upstreams` example equals `DEFAULTS`, and an engine test pins that, so the settings stream can read its default from the fixture.
- **D17. Facts for the live PQ check: `dns-status.json`.** The plan's live check reads "the engine's log", and no log exists. Beside `status.json`, at the same cadence, admin-only: per upstream its address, connected or not, `kx_group`, `alpn`, answers, failures; never a queried name (S27). `kx_group` is `null` for DoQ because quinn does not expose it (S11: not voiced without a basis). It is not on the pipe: `EngineStatus` and `Counters` deny unknown fields, and adding a field is a shape change. The UI can use it later through its own message.
- **D18. Thin Windows flows, testable core.** `dns::service` holds the logic and runs on any platform: `answer(query, transport)` plus `serve_tcp<S: AsyncRead + AsyncWrite>` and `serve_datagrams<S>`. `stack/dns_flow.rs` (Windows) only attributes, books and calls them; `handle_udp` and `handle_tcp` get a one-line early branch for port 53. Concurrency per flow is a `JoinSet` inside the flow's `select!`; in-flight queries are capped per service by a semaphore (`MAX_IN_FLIGHT`, 256, the old `TRANSACTION_CAP`), and past it a datagram is dropped (the client retries). No answer cache: the DNS Client service caches, and the spec asks for none.

Design gate. Instantiates: plan 1.4 and the existing `Exchange` and `resolve`. Derived: split rules, LAN set, bootstrap. Retired: `Transactions`, the plain port 53 relay path, the DNS branches in the generic UDP loop. Owners: `tls` (groups), `upstream::DEFAULTS` (resolvers and bootstrap IPs), `Egress` (pinning), `dns.json` (the list).

## Files

Engine, new:
- `engine/crates/sieve-engine/src/tls.rs`
- `engine/crates/sieve-engine/src/dns/{service,pool,doh,dot,doq,lan,config,testing}.rs` (`testing` is `#[cfg(test)]`: rcgen CA, local DoH, DoT, DoQ and plain servers, recording connector)
- `engine/crates/sieve-engine/src/stack/{egress,dns_flow}.rs`

Engine, changed:
- `engine/crates/sieve-engine/src/dns.rs` (modules, `reply_answers`, `servfail`, `notimp`, `truncated`, `udp_limit`, retire `Transactions`, module docs)
- `engine/crates/sieve-engine/src/dns/upstream.rs` (`DEFAULTS` with IPs, cooldown, `split_rules`, header comment)
- `engine/crates/sieve-engine/src/stack/relay.rs`, `stack/mod.rs`
- `engine/crates/sieve-engine/src/control/{mod,routing}.rs`
- `engine/crates/sieve-engine/src/ipc/mod.rs` (`Backend::set_dns_upstreams`, its dispatch, the `Fake`)
- `engine/crates/sieve-engine/src/route/{plan,table}.rs`, `policy.rs`, `lib.rs`
- `engine/crates/sieve-engine/Cargo.toml`, `engine/Cargo.lock`

Shared, append-only:
- `engine/crates/sieve-ipc/src/lib.rs`, `src/data/fixtures/engine-ipc-v2.json`; `tests/laws/engine-ipc.test.ts` needs no change unless a new assertion is wanted (it reads the type lists).

Docs:
- `docs/live/encrypted-dns.md` (the user's runbook for the UNVERIFIED list)
- `docs/conventions.md` section 8, engine workspace (one paragraph)
- `docs/plans/2026-10-17-https-filtering.md` 1.4 (an "As built" line, in the file's existing style)

Not touched, owned elsewhere: app settings UI, `src/core/settings/*`, `src-tauri/src/dns/`, the settings migration.

## Offline acceptance criteria

Every test binds 127.0.0.1 or ::1 on ephemeral ports with rcgen certs. No test may reach the internet: `DEFAULTS` is never dialled in a test. Names below are the required behaviours; the executor may adjust wording.

Parser and policy, `dns/upstream.rs`, `dns/config.rs`:
- [ ] existing parser tests still pass for all three kinds, including the plaintext refusals; every `DEFAULTS` entry parses and all its IPs parse.
- [ ] `an_empty_list_too_long_a_list_or_a_plaintext_address_is_refused_with_its_reason`, including through IPC.
- [ ] `a_missing_file_reads_as_defaults_and_a_bad_file_reads_as_defaults_with_a_reason`; `an_older_revision_is_refused`; round trip in a tempdir.

Failover, fake clock (`start_paused`):
- [ ] `an_unresponsive_primary_leaves_time_for_the_second_upstream` (exists, must still pass): the second answers at 1 s, under `REQUEST_BUDGET`.
- [ ] `all_timeouts_share_one_deadline_and_do_not_fall_back_to_plaintext` (exists).
- [ ] `a_failed_upstream_is_tried_after_healthy_ones_during_its_cooldown_then_first_again`, and `a_cooling_upstream_is_still_tried_when_the_healthy_ones_fail`.

The three transports, real loopback sockets:
- [ ] `doh_`, `dot_`, `doq_`: `answers_with_the_clients_id_and_sends_the_wire_id_the_rfc_requires` (the server asserts ID 0 for DoH and DoQ, `POST`, content type, path, 2-byte framing).
- [ ] `one_connection_serves_many_queries` per kind (the server counts accepts); DoT serves concurrent queries answered out of order.
- [ ] `a_slow_handshake_outlives_a_cancelled_query_and_the_next_query_reuses_it`; `a_session_that_stopped_answering_is_replaced`; `a_closed_idle_session_is_retried_once_on_a_fresh_one`.
- [ ] each is refused, and the query fails: wrong-root certificate, wrong name, non-h2 ALPN, non-200, wrong content type, oversized reply, mismatched question.
- [ ] `real_sockets_failover`: first upstream is a local TCP listener that accepts and never answers, second is local DoH; answered under 2 s in real time.

Post-quantum:
- [ ] `a_local_rustls_server_offering_x25519mlkem768_negotiates_it`, asserted through `negotiated_key_exchange_group()` for DoT and for DoH, on the client's session.
- [ ] `a_server_offering_only_x25519_still_connects_with_x25519`.
- [ ] `doq_offers_x25519mlkem768`: a quinn server restricted to that single group accepts the handshake, so the check can fail. quinn exposes no group, hence the restriction.
- [ ] `key_exchange_preference_order_is_the_plans` on `tls::KX_GROUPS`.

No plaintext (the law), with the recording connector:
- [ ] `with_every_upstream_failing_the_client_gets_servfail_and_no_plain_socket_is_opened`: DoH and DoT upstreams failing; `Connector::udp` calls zero, TCP targets only the configured ones, a plain trap server on loopback receives nothing.
- [ ] `a_named_custom_upstream_bootstraps_over_the_encrypted_defaults`, and fails with no plain socket when they are down (bootstrap table injected with loopback addresses).
- [ ] `a_non_query_opcode_is_answered_locally_and_nothing_leaves` (D12).

Split-horizon:
- [ ] `split_horizon_cannot_leak_names_to_a_public_or_unrelated_server` and `the_most_specific_configured_suffix_wins` (exist).
- [ ] `rules_derive_from_adapter_suffixes_and_only_excluded_private_servers_qualify`, on `net-home.json` plus a suffix; a public hole and a v6 link-local server do not qualify; Sieve's own adapter contributes none.
- [ ] `a_matched_name_goes_only_to_the_lan_server`, `a_failed_lan_server_is_servfail_not_the_public_upstream`, `tc_from_the_lan_server_retries_over_tcp`, `other_names_go_encrypted`.
- [ ] old fixtures without `dns_suffixes` still parse.

Service and flows:
- [ ] `the_answer_is_recorded_in_the_name_map_only_when_it_matches_its_query`; `an_upstream_servfail_is_passed_on_without_failover`.
- [ ] `an_over_limit_udp_reply_is_truncated_with_tc_and_tcp_gets_it_whole` (EDNS size, default 512, MTU bound).
- [ ] `serve_tcp_` over `tokio::io::duplex`: framing, pipelined queries, a bad length closes. `serve_datagrams_`: concurrent queries return with their own IDs. In-flight cap holds.
- [ ] `changing_the_list_applies_to_the_next_query_and_old_queries_finish`.

IPC:
- [ ] crate tests pass with the new types in the fixture (round trip, type lists, `no_message_can_sign_export_or_mint`); `pnpm test` law `engine-ipc` passes; fixture `dns_upstreams` equals `DEFAULTS`.
- [ ] `set_dns_upstreams_answers_the_held_list_persists_it_and_refuses_a_stale_or_bad_one` through `serve_client`.

Commands (PowerShell; `$env:CARGO_BUILD_JOBS='8'` first):
- [ ] in `engine/`: `cargo test --workspace`
- [ ] in `engine/`: `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] in `engine/`: both again with `--features relay-experiments,attribution-diagnostics` (`-p sieve-engine`)
- [ ] repo root: `pnpm typecheck`, `pnpm lint`, `pnpm test`
- [ ] `git grep -n "Transactions" engine/crates/sieve-engine/src` finds nothing; no `UdpSocket` or `TcpSocket` in `src/dns/**` outside `testing.rs`.

## UNVERIFIED (live proofs, the user's; none may be run by the executor)

Written up with exact commands in `docs/live/encrypted-dns.md`.

1. **pktmon, 10 minutes of normal use, engine on:** no UDP or TCP 53 to a non-LAN address from anyone; resolver traffic only on 443, 853 and 853/UDP.
2. **Failover on the real path:** first upstream `https://192.0.2.1/dns-query`, lookups answer from the second within 2 s.
3. **PQ with the real resolver:** `dns-status.json` shows `X25519MLKEM768` for `cloudflare-dns.com`. Then for Quad9, whose server support is not known from here; `X25519` there would be a fact, not a failure.
4. **Bootstrap IPs:** Cloudflare and Quad9 serve those hostnames with valid certificates on the listed IPs, v4 and v6. From knowledge, not checked (no network in this stream).
5. **Real DoT and DoQ:** `tls://1.1.1.1`, `tls://dns.quad9.net`, `quic://` against a resolver the user chooses; which public resolvers currently offer DoQ was not checked.
6. **The `Egress` move on a real adapter:** pinned sockets to resolvers do not loop (`own_refused` flat) and LAN queries reach the router over the host route.
7. **Suffix reader:** `dns_suffixes` from `GetAdaptersAddresses` on this machine, and `router.lan`-style names resolving (unit tests use fixtures only). Plan 1.4 already marks corporate-zone coverage UNVERIFIED.
8. **Windows DNS Client behaviour** with SERVFAIL, TC and TCP fallback through the TUN, and a page load after a Wi-Fi to Ethernet switch (D8).
9. **Fail open:** kill, stop and uninstall leave adapter DNS settings unchanged and DNS working (`docs/live/engine-slice-3.md` flow).
10. **CPU and idle:** idle CPU stays under its gate with sessions open; the slice 3 relay gate is unaffected.
11. **Release build** on a machine without this one's tools: `pnpm engine:build` needs a C toolchain and probably CMake for aws-lc-sys. Here it built with CMake present and NASM absent; which path aws-lc-sys took was not determined. Plan 2.7 asks slice 6's build notes to say which; record it here first.

## Open questions

**For the user (each has a default, so nothing blocks; change it before merge if you disagree).**

- **Q1. No encrypted resolver reachable, including hotel, airport and other captive-portal Wi-Fi.** Portals usually need plain DNS to reach their sign-in page, and some networks block 443 and 853 to public resolvers. The spec says never plain, and a plan search for "captive" finds nothing. With the default, DNS answers SERVFAIL for as long as the engine is on, and the way out is turning filtering off (which restores normal DNS at once). The alternative would be a user-visible, time-limited "allow plain DNS to the network's server" exception. **Default: strict, as the spec says, documented in the runbook.** Do you want an exception or a notice instead?
- **Q2. Resolver certificate trust (D4).** `webpki-roots` means a resolver behind a private CA (a home DoH server) or a TLS-inspecting corporate network fails, and resolver certificates get no revocation check. In exchange, verification cannot deadlock on its own DNS. The alternative is the Windows verifier run off the runtime, and resolving the loop some other way, which is more code and a real risk to the watchdog. **Default: `webpki-roots`.** Is a private-CA resolver something you need?

**For the orchestrator (scope, not design).**

- **Q3. Who owns ECH stripping and the Firefox canary?** Plan 1.4 and slice 4 list them beside encrypted DNS, but this stream's brief does not, so they are **out of scope here**. `service::answer` is the natural hook for both, in a follow-up after merge. Until one lands, Firefox's canary resolves normally.
- **Q4. Merge hot spots.** `stack/relay.rs` (the domain-policy and attribution streams likely edit `handle_udp` and `handle_tcp`; this stream removes the DNS branches and moves `egress_socket` and `connect`), `route/table.rs`, the `Backend` trait, `Engine::new`, and `Cargo.lock` plus TLS dependency versions if the root-CA stream also adds rustls: use the versions above so one copy resolves.
- **Q5. Plan text.** The brief's fixture name (`engine-ipc-v1.json`) is stale; this plan uses `engine-ipc-v2.json`.

## Implementation steps (ordered, each a commit at green)

Load `anthropic-skills:coding` and `anthropic-skills:clean-architecture` first. Use PowerShell. Nothing here elevates or touches the system: every socket in tests is loopback.

1. **Dependencies and `tls.rs`.** Add the deps above to `sieve-engine/Cargo.toml` plus `webpki-roots`; dev: rcgen, hyper `server`. Write `provider()`, `KX_GROUPS`, `client_config(roots, alpn)`, and `testing.rs`'s rcgen CA with a plain rustls echo server. Tests: the post-quantum group for DoT-style TLS, X25519 fallback, order.
2. **`dns.rs` helpers.** `reply_answers`, `servfail`, `notimp`, `udp_limit` (EDNS OPT read), `truncated`. Move the relevant `Transactions` tests to `reply_answers`; `Transactions` stays until step 8, because `relay.rs` uses it.
3. **`Connector` and the three sessions.** `doh.rs`, `dot.rs`, `doq.rs` behind one session type, with the loopback connector and local servers in `testing.rs`. Transport tests per kind, including refusals and `doq_offers_x25519mlkem768`.
4. **`pool.rs`.** Slots, spawned connect, suspect-on-cancel, retry-once, bootstrap (D2), `Exchange` impl, report fields (D17). `reset()` for network changes. Tests for D8 and D2.
5. **`upstream.rs`.** `DEFAULTS` with IPs, cooldown in `resolve` (D9), and the failover tests. Keep the existing tests passing with only their `DEFAULTS` access adapted. Add `real_sockets_failover`.
6. **Split-horizon.** `plan::holes` extraction (`plan`'s behaviour byte-for-byte: its tests stay green), `Adapter.dns_suffixes` with the reader, `split_rules`, `lan.rs` exchange with TC retry. Tests on fixtures and the mapping connector.
7. **`service.rs`.** `answer`, `serve_tcp`, `serve_datagrams`, in-flight cap, name-map recording, the no-plaintext law. Fully tested off the TUN.
8. **Wire to the TUN.** `stack/egress.rs` (move, no behaviour change), `stack/dns_flow.rs`, one-line branches in `handle_udp` and `handle_tcp`, remove the DNS branches, retire `Transactions`, update the `relay.rs`, `stack/mod.rs`, `dns.rs` and `lib.rs` headers and the `Counters.dns_answers` comment (S53: comments are claims). `bring_up` builds the service, `follow` calls `reset()` when tables differ, `take_down` drops it. Build and run the suite with both feature sets.
9. **Config and IPC.** `config.rs`, `Engine` watch channel and load in `Engine::new`, `Backend::set_dns_upstreams`, append the two message types and the fixture entries, the crate header clause, the `serve_client` test. `write_status_file` writes `dns-status.json`.
10. **Docs and full suites.** `docs/live/encrypted-dns.md`, conventions paragraph, plan "As built" line. Run every command in the acceptance list; record real output in the report. No em dash U+2014 in new text.
