# Task: DNS extras (ECH stripping, Firefox canary, private reverse lookups, upstream editor)

Stream `dns-extras`, branch `wf2-dns-extras`, worktree `F:\Projects\Code\Sieve\.claude\worktrees\wf2-dns-extras`, based on `wf2-tls` at 400f3ce. Spec: `docs/plans/2026-10-17-https-filtering.md` 1.4, 2.9, slice 4's open items ("ECH stripping and the canary, the upstream editor"), and the cross-stream note in `docs/tasks/2026-11-06-tls.md` (F9).

## Goal

While the engine answers DNS:

1. An `ech` parameter is removed from HTTPS and SVCB answers for names Sieve would intercept, so the browser sends the real SNI. With `filtering.https` off nothing is removed.
2. `use-application-dns.net` is answered NXDOMAIN locally, so Firefox's default mode does not move itself to its own DoH.
3. A reverse lookup for a private range goes to the LAN server when one is known, else gets NXDOMAIN locally. It never reaches the public upstream.

In the app, Settings edits `filtering.upstreams`: add with DoH, DoT or DoQ selected, remove, reorder for failover, using the one grammar, and shows what the engine holds.

Sieve off, killed or uninstalled still means a normal network: all of this is in-memory behaviour of the engine's answers. Nothing here writes a system setting.

## What exists (read 2026-11-06)

- `dns/service.rs`: `Service::answer(query, transport)` is the one place a query becomes a reply; `resolve` picks LAN or encrypted. `stack/dns_flow.rs` attributes and books, then calls `serve_datagrams` and `serve_tcp`. `ctx.admit` returns `Admitted { id, owner }`, and `dns_flow::admit` throws the owner away.
- `dns.rs`: `parse` reads names, A, AAAA and CNAME and skips other types, `error_reply` builds SERVFAIL and NOTIMP, `edns_payload` reads the OPT record. There is no writer for answer records and no HTTPS or SVCB code.
- `dns/upstream.rs`: `split_rules`, `split_server`, `SplitHorizon::new` (the private-and-excluded check). `route::plan::EXCLUDED` is the declared list of ranges never routed, each with its reason; `plan::holes` adds live prefixes.
- `sieve_filter::exclusions`: `decrypt`, `floor`, `restricted_suffix`, `ExclusionSet::find`, `Switches`. `tls::intercept` line 180 builds the switches: `exclusions.switches(!active.is_closed(), (minter)().is_some())`. `Engine.https` is `Arc<HttpsSlot<Egress>>`, empty unless `intercept::wanted(policy)`.
- **The read-back already exists on the pipe.** `dns_upstreams` is a client and engine message, `EngineSource.dnsUpstreams()` calls it, and `syncUpstreams` in `engine-controller.ts` reads it every probe. It only compares and throws the answer away. No IPC change is needed: `sieve-ipc` and the fixtures stay untouched.
- `src/core/upstream.ts`: `parseUpstream`, held to `upstream-grammar.json` by the law and `engine/crates/sieve-engine/tests/upstream_grammar.rs`. `MAX_UPSTREAMS` is 8 in `dns/upstream.rs` only. The engine refuses an empty list, one over 8, and repeats after parsing (`config::validate`).
- `settings/setting-row.tsx`: a list row is a text summary plus Reset. `filters/domain-list.tsx` is the flat add and remove pattern to follow.
- **Traps found.**
  - `Totals.resolved == 0` books a flow `FlowAction::Failed` (`dns_flow::finish`), and most flows hold one query. A local NXDOMAIN with `resolved: false` would log every canary and private reverse lookup as a failure.
  - There is no React error boundary anywhere in `src` (see the orchestrator notes).
  - `settings.test.tsx` line 75 asserts the upstream row has no button unless changed, and `docs/live/encrypted-dns.md` line 11 says the row has no editor. Both become false.

## Design decisions

- **D1. ECH stripping has no switch of its own: it is behind `filtering.https`.** It has no reason to run unless interception could follow. With the slot empty, answers pass unchanged, so the switch stays the one gate and a browser keeps its ECH privacy while decryption is off. Its live proof joins that switch's check. `filtering.https` stays locked; nothing here unlocks it.

- **D2. "Would intercept this name" is one pure function beside `decrypt`.** No app is known at DNS time (plan 1.4; the lookups come from the DNS Client service). `sieve_filter::exclusions::name_may_intercept(host, store, switches)` is true when `https`, `root_ready` and `lists_ready` hold, `restricted_suffix(host)` is false, and no store entry names the host. It lives where `floor` lives and reuses `restricted_suffix` and the store (S14, S29). Its law: when it says false, `decrypt` answers `PassThrough` for every flow of that name, whatever the exe, session or ALPN. The reverse is not claimed: true means "may", and the flow is still judged by `decrypt`.
  - The store check counts **app-scoped entries as naming the host**, because `Exclusion::matches` with no exe already reads that way. A name excluded for one app stays unstripped for all. Keeping ECH is the conservative side: the worst result is a pass-through.
  - **Corrected while building:** the law as first written cannot hold for an app-scoped entry: another app's flow with no `ech` in its hello is not excluded, so `decrypt` may intercept it. The law holds for every-app entries (the property test), and an app-scoped name keeps its ECH, so another app's hello carries it and takes `floor:ech` (its own test). A name that publishes no ECH has nothing to strip either way.
  - `ExclusionSet` gains `names_host(host, skip_ev)`, sharing the suffix walk with `find` through one private iterator. `Pattern::Ip` entries cannot match, because no address is known yet. A name with only an IP exclusion can lose ECH and still pass through: a privacy cost on a rare entry, stated here and not built around.
  - Cached upstream verdicts are not consulted. `auto:ev` is in the store, and the others are short-lived and only end in a pass-through (S35).

- **D3. The name judged is the question's, with attrleaf labels dropped.** `_8443._https.example.net` is judged as `example.net`. A CNAME target's record is judged by the question too, because the client's SNI is the name it asked for. An AliasMode follow-up query is judged by its own name, which can strip for a target whose origin is excluded; the flow still passes through under `decrypt`. Accepted and stated.

- **D4. Forwarded flows are never stripped.** A VM's or WSL's flows are never decrypted, so stripping would cost their ECH for nothing. `dns_flow` keeps the owner and passes `Asker { may_decrypt: owner.may_decrypt() }` to `serve_*`, and from there to `answer`. It is a required argument, not an optional one (S47). The DNS Client service is `session 0` and must be stripped, since it is how browsers resolve, so the service floor deliberately does not apply here.

- **D5. Rewriting is a pure wire function, and anything it cannot prove safe leaves the reply byte-identical.** The safe failure is real: an unstripped ECH hello takes `floor:ech` and passes through (plan 2.9). `dns/ech.rs`:
  - Walks every record of the answer, authority and additional sections. For types 64 and 65 it reads priority, the uncompressed target (RFC 9460) and the params, with bounds checks and strictly ascending keys.
  - **Compression is the hard part.** Removing bytes moves everything after them, so every pointer whose target lies past a removed span must shift. Pointers are rewritten in owners and in the rdata of CNAME, NS, PTR, MX and SOA. A pointer into a removed span leaves the reply unchanged.
  - After the first removal, a record type outside the walked set and a declared no-names set (A, AAAA, TXT, OPT, HTTPS, SVCB, RRSIG, NSEC, NSEC3, DS, CAA) leaves the reply unchanged. An unknown type's rdata might hold a compressed name that cannot be found (RFC 3597). TSIG is outside the set for the same reason.
  - `mandatory` naming `ech`: the operator says the record is unusable without it. The reply stays unchanged and the flow passes through. This is simpler than editing `mandatory`, and it respects the record.
  - The rewrite fixes RDLENGTH for each cut and clears AD, because the data changed.
  - Only queries of type 64 or 65 are examined, so A and AAAA replies pay nothing.

- **D6. A query with EDNS DO is left unchanged.** A client asking for DNSSEC may validate, and a stripped record would fail its RRSIG, breaking a working name. Windows' DNS Client does not normally set DO (UNVERIFIED). `edns_payload` becomes `edns(msg) -> Option<Edns { payload, dnssec_ok }>`, with `udp_limit` unchanged in behaviour.

- **D7. The LAN path is never stripped.** Split-horizon and private reverse answers are for addresses in holes, which never enter the stack, so they are never intercepted. Stripping happens only on the encrypted path, before `udp_limit`, since a smaller reply may then fit.

- **D8. The engine's own lookups are unaffected.** The pool's bootstrap and slice 11's upstream ECH go through `Pool`, not `Service::answer`, so they see records unmodified.

- **D9. The canary is a named constant, exact match, answered before routing.** `CANARY_DOMAIN = "use-application-dns.net"`, any query type, class IN. Children are forwarded as usual (Mozilla's signal is the one name). This is the plan's protocol signal with one spelling, the same standing as `upstream::DEFAULTS`, not a site list. It is a comment-stated exception to "no hardcoded site names", and nothing derives it. Applies to every asker: a guest's Firefox is the same case and loses only its DoH hop. It follows `filtering.engine`, the only gate on DNS being answered here at all. Nothing is persisted, and with the engine off Firefox's normal behaviour returns on its own next check (UNVERIFIED how soon).

- **D10. Private reverse zones derive from `plan::EXCLUDED`, the one list of what is never routed (S49).** `declared()` becomes `pub(crate)`. No second range table. `dns/reverse.rs`:
  - Reads a name right to left under `in-addr.arpa` or `ip6.arpa`, taking labels while they are valid (a decimal octet with no leading zero, or one hex nibble), up to 4 or 32.
  - A name with `n` usable labels is the prefix of `n*8` or `n*4` bits. It is private when one `EXCLUDED` range holds that whole prefix. So `7.168.192`, `168.192` and `10` are private; `192` and `172` are not, since they also hold public space and stay encrypted; `16.172` is private.
  - **Labels left of the walk do not free a name.** `b._dns-sd._udp.7.168.192.in-addr.arpa` (DNS-SD domain enumeration) and `300.168.192.in-addr.arpa` are both under the zone.
  - Any query type counts: PTR, SOA (Windows' dynamic-update discovery), NS.
  - `plan::holes`' live prefixes are not used. A split-tunnel VPN can route public space, and that is not a private reverse zone.
  - An opaque name (one `parse` refuses, or several questions) stays on the encrypted path as today. Accepted: no resolver or OS sends one, and the disclosure goes only to the user's chosen upstream.

- **D11. Which LAN server.** First the server of the adapter whose on-link prefix holds the address, then the first server of any other adapter that qualifies. Qualifying is the existing rule, in one helper shared with `SplitHorizon::new`: private, inside a hole, not v6 link-local. No qualifying server (including when the adapter's DNS is a public resolver): NXDOMAIN locally, not cached by the client (no SOA, RFC 2308). A LAN server that fails gets SERVFAIL, never the public upstream, the same as D11 of the encrypted-DNS task. A configured split suffix (`split_server`) is checked first and wins. `upstream::path_of(name, tables) -> Path { Lan(ip), NoServer, Encrypted }` is the pure routing decision, and `Service::resolve` reads it. Recorded for review as Q1.

- **D12. `Answered.resolved` means a definite answer.** The canary and a local NXDOMAIN set it true, so their flows are booked Relayed, not Failed. SERVFAIL and NOTIMP stay false. Its doc comment changes (S53).

- **D13. Facts for the live proof: `dns-status.json` gains counters, never a name.** `Service` holds `ech_stripped`, `ech_left`, `canary`, `reverse_lan`, `reverse_local`; `report` grows beside `upstreams`. Not on the pipe: `Counters` denies unknown fields and nothing in the UI needs these. `ech_left` counts a reply with an `ech` it did not remove, for any reason.

- **D14. The editor's row is derived from the element shape.** `SettingRow` returns `<UpstreamRow>` when `d.kind === "list" && d.of.type === "upstream"`, so no key is named in the component, and it keeps `id`, `data-setting`, `role="group"`, the label ids and the lock note. The row stays generic for every other list.

- **D15. Adding: a kind segment and one address field, composed by a pure function.** `composeUpstream(kind, typed)` in `src/core/upstream.ts`, then `parseUpstream` decides: one grammar, no second validator.
  - Text with `://` is taken as written, and the segment follows its parsed kind, so a pasted URL just works.
  - Otherwise the scheme comes from the kind. DoH with no path gets `/dns-query`, since `https://host/` is almost never a resolver's path. A URL typed in full stays exact.
  - A bare IPv6 address is bracketed.
  - Refused forms show one line under the field: not an encrypted address, already listed (compared after parsing, as the engine does), or the limit.
  - Kind labels: `DoH`, `DoT`, `DoQ`, using the existing `Segmented`.

- **D16. Reorder by up and down icon buttons; no drag library.** They work by keyboard and touch at 375 px and add no dependency. An `<ol>` holds the order, the failover order. First row's up and last row's down are disabled. Remove is disabled on the only entry, because the engine refuses an empty list and an empty setting would silently send nothing. No per-row kind label: the scheme is in the address (no redundant chips). Flat: no card, border or tile; Reset stays as today.

- **D17. One limit, one table.** `upstream-grammar.json` gains `"max": 8`. TS exports `MAX_UPSTREAMS`; both laws assert it, the Rust test against `dns::upstream::MAX_UPSTREAMS`. The editor disables Add at the limit. An import over the limit still reaches the engine's refusal and shows as `dnsError`, as today.

- **D18. Read-back: the controller keeps what it read.** `EngineSlice.heldUpstreams?: readonly string[] | null`, written in `syncUpstreams` from the read and from the send's answer, emitted only when it changed, null when `engineTakesPolicy` is false. The controller stays the only writer. `upstreamReadback(want, held)` in `src/core/upstream.ts` (pure) gives:
  - `null` held: no line (the Engine block already says why).
  - Same list and order: "The engine uses this list."
  - Otherwise: "The engine still uses: a, b."

  `dnsError` moves from `engine-card.tsx` to this row, where it can be acted on (one place, S52); the engine card's test moves with it.

- **D19. No reachability check on Add.** AdGuard has one (parity row 40). A bad upstream fails over within the 2 s budget and is measured in `dns-status.json`. A probe needs engine work and a live path. The parity row stays "partial" for that and for named providers.

Design gate. Instantiates: plan 1.4 and 2.9, the existing `answer` and `split_rules`. Derived: reverse zones from `EXCLUDED`, the would-intercept check from `floor`'s parts, the row from `of.type`. New primitives: the wire rewriter (the basis has no writer for records) and `Path`. Retired: the upstream row's summary, `dnsError` in the engine card, the ad-hoc branch in `Service::resolve`. Owners: `dns/ech.rs` (record rewriting), `name_may_intercept` (the name decision), `EXCLUDED` (private ranges), `upstream-grammar.json` (forms and limit).

## Files

Engine, new:
- `engine/crates/sieve-engine/src/dns/ech.rs`
- `engine/crates/sieve-engine/src/dns/reverse.rs`

Engine, changed:
- `engine/crates/sieve-filter/src/exclusions.rs` (`name_may_intercept`, `names_host`, law)
- `engine/crates/sieve-engine/src/dns.rs` (modules, types 64 and 65, `nxdomain`, `edns`, header)
- `engine/crates/sieve-engine/src/dns/service.rs` (`Asker`, canary, `Path`, strip, facts)
- `engine/crates/sieve-engine/src/dns/upstream.rs` (`path_of`, the qualifying helper)
- `engine/crates/sieve-engine/src/route/plan.rs` (`declared` visibility only)
- `engine/crates/sieve-engine/src/stack/dns_flow.rs`
- `engine/crates/sieve-engine/src/tls/intercept.rs` (`Interception::may_intercept_name`)
- `engine/crates/sieve-engine/src/control/{routing,mod}.rs` (the gate closure, `dns-status.json`, test helper)
- `engine/crates/sieve-engine/tests/upstream_grammar.rs`
- `engine/crates/sieve-engine/Cargo.toml`, `engine/Cargo.lock` (dev only: `hickory-proto`, see the tests)

App, new:
- `src/components/sieve/settings/upstream-row.tsx`, `upstream-row.test.tsx`

App, changed:
- `src/core/upstream.ts` and a new `src/core/upstream.test.ts` (`MAX_UPSTREAMS`, `composeUpstream`, `upstreamReadback`)
- `src/core/engine.ts` (`heldUpstreams`), `src/data/engine-controller.ts` and its test
- `src/components/sieve/settings/setting-row.tsx`, `engine-card.tsx`, `engine-card.test.tsx`, `settings.test.tsx`
- `src/data/fixtures/upstream-grammar.json` (`max`), `tests/laws/upstream-grammar.test.ts`
- `tests/e2e/settings.spec.ts`

Docs:
- `docs/live/dns-extras.md` (new), `docs/live/encrypted-dns.md` line 11, `docs/live/engine-slice-6.md` (one line pointing at the ECH step)
- `docs/conventions.md` (Settings view, Engine facts, DNS paragraph), `docs/plans/2026-10-17-https-filtering.md` (1.4 as-built, 2.9, slice 4 status), `docs/plans/2026-10-17-parity.md` row 39

Not touched: `sieve-ipc`, the IPC fixtures, `registry.ts`, `migrate.ts`, `routes.ts`. No settings schema bump: the key and its shape are unchanged.

## Offline acceptance

All sockets are loopback, through the existing `dns::testing` servers and `Loopback` connector. No test reaches the internet. Names are the required behaviours; wording may change.

ECH wire (`dns/ech.rs`, pure):
- [ ] `removes_ech_and_keeps_every_other_param_in_order`, for HTTPS and SVCB, with RDLENGTH right and AD cleared.
- [ ] `a_reply_without_ech_is_untouched_and_not_copied`; `alias_mode_is_untouched`.
- [ ] `every_record_with_ech_in_any_section_is_stripped`, several records in one answer.
- [ ] `pointers_past_a_cut_are_shifted`: owner, CNAME, MX, SOA and NS names that point at a name after the first cut still decode to the same text. **This test must fail with the shift removed.**
- [ ] `pointers_before_a_cut_are_unchanged`.
- [ ] `left_unchanged_byte_for_byte`, one case each: `mandatory` naming ech; a pointer into the cut; descending keys; a param past RDLENGTH; a compressed target; an unknown type after the cut; TSIG.
- [ ] Proptest: arbitrary bytes never panic; any output is shorter than its input and walks clean.
- [ ] **Cross-witness (S3):** `hickory-proto` as a dev-dependency decodes the output of the pointer and multi-record cases and agrees: same records, no `ech`, other params equal. Our own parser reading our own output cannot catch a shared misreading. `cargo tree -p sieve-engine -e normal` must not list it.

The decision (`sieve-filter`):
- [ ] `name_may_intercept` false for: switch off, no root, lists not ready, a restricted suffix, a store entry (exact, subdomain, wildcard, app-scoped), `auto:ev` while `skip_ev`; true for a plain name. `auto:ev` with `skip_ev` off is true.
- [ ] Proptest law: `!name_may_intercept(h, store, sw)` implies `decrypt(facts with host h, store, sw)` is `PassThrough`, across generated exe, session, ALPN, app state and verdict.

Service (`dns/service.rs`, real loopback DoH):
- [ ] `ech_is_stripped_only_when_the_gate_says_so`: gate open, stripped; closed, byte-identical from the upstream.
- [ ] `the_gate_hears_the_question_without_its_attrleaf`: `_8443._https.a.example` asks about `a.example`.
- [ ] `a_forwarded_asker_keeps_ech`, through `serve_datagrams` and `serve_tcp`.
- [ ] `a_do_query_keeps_ech`; `a_lan_answer_keeps_ech`; `an_a_query_never_asks_the_gate`.
- [ ] `a_stripped_reply_is_measured_after_the_cut`: a reply over the UDP limit only because of `ech` now fits.
- [ ] `the_canary_is_nxdomain_and_nothing_leaves`: any type, any case; zero recorded sockets; ID and question kept; `resolved` true; `sub.use-application-dns.net` goes encrypted.
- [ ] `canary_and_local_nxdomain_flows_are_not_booked_failed`, at the `Totals` level.
- [ ] `the_report_holds_counts_and_never_a_name`.

Reverse (`dns/reverse.rs`, `upstream::path_of`, table tests on `net-home.json`):
- [ ] Table, names to private or not: `7.168.192`, `1.7.168.192`, `168.192`, `10`, `16.172`, `31.172`, `254.169`, `127`, `64.100`, `d.f.ip6`, `8.e.f.ip6` and a full ULA are private. `192`, `172`, `15.172`, `32.172`, `8.8.8.8`, `1.0.0.2`, bare `in-addr.arpa`, bare `ip6.arpa`, a global v6 name and `example.arpa` are not.
- [ ] `every_excluded_range_has_a_private_reverse_name`: derived from `EXCLUDED`, so a new range cannot be forgotten.
- [ ] `labels_left_of_the_zone_do_not_free_a_name`: the DNS-SD and `300.` forms, and `07.168.192` read as `168.192`.
- [ ] `path_of`: covering adapter's server; another adapter's when none covers; `NoServer` when the only server is public, or v6 link-local, or there is none; `Encrypted` for public names.
- [ ] `a_configured_suffix_wins_over_the_reverse_rule`.
- [ ] Service: `a_private_reverse_lookup_goes_only_to_the_router` (`7.168.192.in-addr.arpa`, PTR); `with_no_lan_server_it_is_nxdomain_and_no_socket_opens`; `a_failed_lan_server_is_servfail_not_public`. In all three the DoH server's `seen()` is empty, which is the law.

Grammar:
- [ ] Law and Rust test both read `max`, and `MAX_UPSTREAMS` agrees in both languages.

App, unit (`pnpm test`):
- [ ] `composeUpstream`: each kind with host, host and port, IP, bare IPv6; DoH path default; a typed path kept; a full URL unchanged and its kind reported; every result accepted by `parseUpstream`, and every `refuse` entry of the table that is typed in full refused.
- [ ] `upstreamReadback`: null held; same; different order counts as different.
- [ ] Controller: `heldUpstreams` follows the read and the send; no emit when unchanged; null when the engine stops taking policy; a broken answer sets `dnsError` and keeps rendering.
- [ ] `upstream-row.test.tsx`: add for each kind; refused forms show their reason and change nothing; duplicate after parsing refused; Add disabled at 8; move up and down change the setting's order and the first and last buttons are disabled; remove disabled on the only entry; Reset; locked by the password, every control disabled at the value in force.
- [ ] **Degraded data (frontend-resilience step 6):** `heldUpstreams` null, undefined, empty; an unparsable entry from an old store renders as text with Remove and does not crash; a mock engine answering a malformed `dns_upstreams`.
- [ ] `settings.test.tsx` updated: the row shows the entries; a stored bare address is still dropped by migration.
- [ ] Existing laws pass: flat, no-dividers, em-dash, tokens, registry, unavailable. `filtering.https` is still unavailable: `tests/laws/unavailable.test.ts` and the registry entry are unchanged.

E2e, through the lease only (`tests/e2e/settings.spec.ts`, mock engine `?engine=idle`, everything but 127.0.0.1 aborted):
- [ ] At 1280x800 and at 375x812 (the mobile project): add `tls://dns.example`, move it first, reload, the order holds; the read-back line appears; no horizontal scroll with a long DoH URL; each control at least 44 px at 375.
- [ ] The row count in `settings.spec.ts` is unchanged; `alignment.spec.ts`, `scroll.spec.ts`, `screens.spec.ts` pass.

Commands (PowerShell; `$env:CARGO_BUILD_JOBS='8'` first):
- [ ] First in the fresh worktree: `pnpm install --frozen-lockfile --offline`
- [ ] In `engine/`: `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] Root: `pnpm typecheck`, `pnpm lint`, `pnpm test`
- [ ] `powershell -NoProfile -File <tools>\procs\with-gpu.ps1 -Label sieve-e2e-dns-extras -- cmd /c pnpm e2e` (read `nvidia-smi` first; if another project holds over half the card, wait)
- [ ] `git diff --stat wf2-tls -- engine/crates/sieve-ipc src/data/fixtures/engine-ipc-v3.json src/core/settings/registry.ts src/core/settings/migrate.ts` is empty.

`src-tauri` is not changed, so the `pnpm rust:*` suites are not required. Features `relay-experiments` and `attribution-diagnostics` paths are not changed.

## UNVERIFIED (live proofs, the user's; none may be run by the executor)

Runbook `docs/live/dns-extras.md`; ignored test `live_dns_extras_on_the_real_path` in `dns/service.rs`, which panics pointing at the runbook, as `live_https_intercepts_public_and_passes_floor` does.

1. **ECH, with `filtering.https` on, after its own check:** `Resolve-DnsName -Type HTTPS` for a name that publishes ECH shows no `ech`; `ech_stripped` rises; Chrome and Edge show Sieve's issuer there. With the switch off the same query shows `ech`.
2. **Which clients ask where.** That Chrome's and Edge's HTTPS queries reach port 53 on the TUN when Secure DNS is off. Whether Firefox asks the OS for HTTPS records at all. Whether Windows' DNS Client sets DO.
3. **Address hints.** `ipv4hint` and `ipv6hint` are not recorded in the name map. A client connecting from a hint alone, with no A query, reads as "not resolved here" under plan 2.9's GREASE rule and passes through. Safe; how often it happens is not known.
4. **Canary:** `Resolve-DnsName use-application-dns.net` is NXDOMAIN, and Firefox in its default mode uses system DNS (`about:networking`). A user who chose Max Protection is not affected, by Firefox's own design. How soon Firefox re-enables DoH with the engine off.
5. **Reverse:** `Resolve-DnsName <router ip> -Type PTR` answers from the router and `reverse_lan` rises; on a network whose DNS is public, `reverse_local` rises; the pktmon capture from `encrypted-dns.md` shows nothing new. `nslookup`'s start-up reverse lookup and Windows' dynamic-update SOA probes do not delay anything visibly with NXDOMAIN.
6. **Guests:** WSL with DNS tunnelling reaches the host's resolver as a host process, not a forwarded flow, so a guest's answer may be stripped though its flow is never decrypted. A loss of ECH, nothing breaks. Whether this happens is not known.
7. **Editor end to end:** a list changed in the real app reaches `dns.json` and `dns-status.json`, in order; failover follows the new order; the read-back line matches.
8. **Fail open:** the kill, reboot and uninstall tests of `docs/conventions.md` section 0 with all of this active. A stripped answer in the DNS Client cache lasts its TTL after the engine stops, and only means no ECH until then.

## Open questions

**For the user (each has a default, so nothing blocks; change it before merge if you disagree).**

- **Q1. Private reverse lookups (recorded for your review, as asked).** Default as specified: a private-range reverse lookup goes to the LAN server when one is known, else NXDOMAIN locally, and never to the public upstream. "Private" is every range the engine already never routes (RFC 1918, CGNAT, loopback, link-local, ULA, multicast and reserved). "Known" is the adapter covering the address, then any adapter with a private DNS server. A LAN server that does not answer gives SERVFAIL. The cost: where the network's DNS is a public resolver (or a VPN's is absent), `Resolve-DnsName 192.168.1.5` says "no such name" even if some other server could know it. The alternative, sending them encrypted, tells Cloudflare your private addressing. Tell me if you want them forwarded on such networks.
- **Q2. A browser turned Off also loses ECH while `filtering.https` is on.** Its lookups go through the DNS Client service, so no app is known at DNS time. Its flows are not decrypted and work normally, but the real site name is visible on the wire, as if the site had no ECH. Plan 2.9 accepts this by saying "names", and there is no way to tell apps apart here. **Default: accept, and state it in the switch's help text when the switch is unlocked.** The alternative is not stripping at all, which sends every ECH site through as host-level only.
- **Q3. The canary and the reverse rule get no switch of their own.** The plan rule says traffic-changing features are data switches, and slice 4 says "Switch: none new (part of `filtering.engine`)". They change the answer for a handful of names, nothing leaves as a result, and they end with the engine. So a user who already passed the engine's check gets them without a new check. **Default: follow slice 4, no new switch; the live items above are run once.** Say if you want them held behind a check.

**For the orchestrator (scope, not design).**

- **Q4. Merge hot spots.** `dns/service.rs` (no other `wf2-*` task doc names it), `stack/dns_flow.rs`, `tls/intercept.rs` (one added method), `control/routing.rs` (one closure at the `Service::new` line), `sieve-filter/src/exclusions.rs` (additive), `settings/setting-row.tsx` (one early return; check `wf2-content-wire` and `wf2-heal` if they add rows), `upstream-grammar.json` (one key).
- **Q5. No error boundary exists in `src`.** The frontend-resilience policy wants one per screen. This stream normalizes and guards its own data and tests the degraded shapes, but a boundary is app-wide, so it is a follow-up proposal, not part of this diff.
- **Q6. Other special-use names** (`home.arpa`, `.local`, single labels) still go to the encrypted upstream unless a suffix claims them. Same kind of leak as Q1, not in this brief. Proposed follow-up, not built.

## Implementation steps (ordered, each a commit at green)

Load `anthropic-skills:coding`, `anthropic-skills:clean-architecture`, `anthropic-skills:frontend-resilience`. Use PowerShell. Read `node_modules/next/dist/docs/` before touching Next APIs (this is client components only). Nothing here elevates, touches the system or reaches the internet. Every commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

1. **`dns/ech.rs`.** Failing tests first from the case list, including the pointer law and the witness dev-dependency. Pure code only, not yet called. `dns.rs` gains the type constants.
2. **`name_may_intercept`.** `sieve-filter`, with `names_host`, tests and the proptest law. `Interception::may_intercept_name` in `tls/intercept.rs`, using the same switch expression as line 180 (extract one private method so there is one).
3. **Reverse.** `dns/reverse.rs`, `declared` visibility, the qualifying helper with `SplitHorizon::new` and `split_rules` behaviour unchanged (their tests stay green), `upstream::path_of`, `nxdomain`.
4. **`Service`.** `edns`, `Asker`, the required gate argument on `Service::new`, canary, `Path` in `resolve`, the strip step, `resolved`'s new meaning, facts and the report. Adapt `Bed`, `service_from` and the direct callers. Service tests.
5. **Wire.** `dns_flow` keeps the owner; `routing.rs` builds the gate from `engine.https`; `write_status_file` writes the counters. Full engine suites. The Windows path has no unit test beyond compile and clippy: say so in the report and list it under UNVERIFIED.
6. **App core.** `MAX_UPSTREAMS`, `composeUpstream`, `upstreamReadback`, the table's `max`, the law, the Rust grammar test.
7. **Read-back.** `heldUpstreams` in the slice and controller, with tests.
8. **Row.** `upstream-row.tsx`, the early return in `setting-row.tsx`, `dnsError` moved, unit and degraded-data tests. Then `ux-walkthrough` on the rendered row at both sizes before e2e.
9. **E2e** through the lease, both projects. Kill anything left, by tree.
10. **Docs and full suites.** The runbook, the ignored live test, conventions, plan as-built lines, parity row 39, `encrypted-dns.md` line 11. Run every command above; record real output in the report. No U+2014 in new text.
