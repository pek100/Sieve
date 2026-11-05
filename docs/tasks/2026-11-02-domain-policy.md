---
id: domain-policy
tags: [engine, filtering, policy, ipc, high]
related_files: [engine/crates/sieve-engine/src/domain.rs, engine/crates/sieve-filter/src/rules.rs, engine/crates/sieve-filter/src/lists.rs, engine/crates/sieve-ipc/src/lib.rs]
status: in-progress
last_sync: 2026-11-05
---

# Slice 4, engine side: domain filtering and per-app Off

Spec: `docs/plans/2026-10-17-https-filtering.md`, slice 4 (engine part), 1.4 (the IP-map rule), 4.4, 5.1 to 5.4. Forwarded traffic: `docs/plans/2026-10-18-slice-3-attribution-and-cpu.md`, A3 and decision 2. Base: main at f0fe2cb. Groundwork: merge 6006391 (`domain.rs`, strict owner matching).

## Goal

While the engine routes, a sieved app's flow to a blocked host is closed, an Off app's flow to the same host is relayed untouched, and DNS still resolves for everyone. Default lists are downloaded through an injected fetcher, compiled off the hot path and swapped atomically. Each list's applied and skipped counts are readable over the pipe.

Sieve off, killed or crashed stays a normal network. This stream adds files under `ProgramData\Sieve\engine\lists\` and no system state. A missing, broken or uncompiled list means fewer blocks, never a failed connection.

**Out of scope, other streams:** encrypted DNS and upstreams; removing the app-side DNS proxy and its settings keys; ECH stripping and the Firefox canary (no owner is named, see Coordination); the `/log/` route; the Settings view of the per-list report; ETW and NAT attribution.

## What reading the code found

These change the work compared with what the spec implies. Library facts come from reading `adblock-0.13.3` source, not from running it; step 1's tests pin them.

1. **Off keys are not executables.** `apps.levels` is keyed by `appIdentity` (`src/core/apps.ts`): lower-case ProductName, else exe stem. `AppPolicy` matches a path or a file name, so an Off "google chrome" would match nothing. The app also sends no off apps today: `Policy` is only `{revision, engine}`.
2. **The controller would wipe a grown policy.** `engine-controller.ts` sends `{revision, engine}` and compares only `engine`. Once `Policy` grows, that message would clear the other fields, and a change to them alone would never be sent.
3. **Two decision functions exist.** `flows::verdict` (spike, used by the probe and `examples/bench.rs`) and `domain::DomainFilter::decide`. S51 and S52: one must go.
4. **`$elemhide`, `$ehide`, `$specifichide`, `$shide`, `$genericblock` and `$denyallow` do not appear in adblock-rust 0.13.3's option table,** although plan 5.2 lists them as supported. `@@...$removeparam` is a parse error too (`RemoveparamWithException`). "Zero skipped exceptions" on the real lists will therefore almost certainly fail on count, and the "or each listed" branch is what can pass (open question 2).
5. **`check_host` has gaps.** An IPv6 literal from `http::host_of` is unbracketed, so `https://::1/` fails to parse and matches nothing. A `@@||host^$document` exception does not match the synthetic `other` request, so its host is still blocked.
6. **`ListReport.applied` overstates.** Cosmetic rules and `$removeparam` parse fine but do nothing at host level. The report must say so (S17).
7. **`Status.filtering` drives the app's "routing" phase** (`core/engine.ts:89`). It cannot take on a new meaning, so "is anything being blocked" needs its own field.
8. **`Policy` is `Copy`.** Growing it removes that, which touches `control/mod.rs`, `ipc/mod.rs` and `src-tauri/src/engine.rs`.
9. **The fixture is `engine-ipc-v2.json`,** not the v1 named in the workflow's shared-file list.

## Design decisions

| # | Decision | Why |
|---|---|---|
| D1 | `domain.rs` is the only decision. Delete `flows::{verdict, Decision, Reason}` and move the probe and `examples/bench.rs` onto `DomainFilter::decide`. | S51, S52. `Action`, `AppPolicy` and `Level` stay in `flows.rs`. |
| D2 | The engine derives each flow's app key with the same rule as `appIdentity`: `sieve_ipc::app_key(product, exe, process_name)`, compared with `off_apps`. Parity is pinned by a fixture `src/data/fixtures/app-keys-v1.json` that a Rust test and a TS law both read. | Expanding keys to exe paths on the app side misses an exe it has not seen yet, and misses everything while the app is closed. |
| D3 | Port `product_name` (version-info read, cached per path) from `src-tauri/src/netstat/process.rs` into `flow::flows::os`. Read outside the `exes` lock. | `sieve-ipc` and `sieve-filter` make no Windows calls and the engine never links Tauri. The pure rule is shared; the OS read is duplicated and recorded as a TENSION in a comment. |
| D4 | The flow's owner is an enum: `Owner::App{key}`, `Owner::Forwarded{vm: Option<&str>}`, `Owner::Unknown`. Only `App` checks an app row. `Forwarded` checks only the key `vm:<name>` or `vm:unidentified`. `Unknown` gets the default (sieved). `Owner::may_decrypt()` is false for `Forwarded`. | Michael's decision: guests are filtered by domain only, have their own Sieve/Off row, are never decrypted, and never inherit a host app's exemption. `wf-attribution` supplies `Forwarded`; until then those flows are `Unknown`, which has the same blocking policy. |
| D5 | `RuleSet { user, lists }` in `sieve-filter` holds two `RuleEngine`s. The user's engine answers first; the lists decide only if it has no rule. | In one engine a list's `$important` beats a user allow, and a list's `@@` beats a user block. Two engines make "the user wins" hold by construction, and a user edit recompiles only the small one. It is still one library and one dialect (5.1). |
| D6 | A snapshot is `RwLock<Arc<DomainFilter>>`, read once per flow. `DomainFilter` holds `Arc<RuleEngine>`s, so an Off-app change recompiles nothing. | Deviates from the plan's `ArcSwap`, keeping its property (atomic swap, decided flows unaffected) with no new dependency: the read is per flow, not per packet. |
| D7 | `check_host` stays the synthetic request, asked first-party and third-party, plus: normalise the name once at the top (lower case, no trailing dot, brackets for IPv6); a block verdict needs block rules for every other network request type too (`$~image` must not close a host), then is re-asked as type `document`, and an exception there gives Allow. It returns the decided rule text. | Over-blocking breaks sites (5.2). The further queries run only on the block path, so a no-rule host costs nothing extra. |
| D8 | An ECH flow is decided by its outer name, with no fallback to the IP map. | `sni.rs` sets `ech` whenever the extension is present, and Chrome's GREASE ECH makes that common while the SNI is the real name. Treating these as unnamed would move ordinary traffic onto the shared-IP rule. A real ECH inner name stays unblocked, a limit recorded here and reduced by ECH stripping (1.4). |
| D9 | A blocked TCP flow uses the existing drop path: nothing goes upstream, the app gets FIN. A blocked UDP flow closes its book entry as `blocked`, then swallows datagrams until `UDP_IDLE`. Decisions wait for first bytes as slice 3 does. | Ending at once would turn each QUIC retransmit into a new flow with a new owner lookup. The upstream TCP connect still happens before the decision and server-first bytes may reach the app, which is accepted slice 3 behaviour (a decoded name beats the IP map, so the decision cannot be earlier). |
| D10 | `sieve-filter` stays free of I/O: `FetchState::request` and `FetchState::apply(response, now)` are pure. The engine owns `trait Fetcher`, the disk cache, the loop and the real HTTPS client. | The crate's stated rule (`lib.rs`). |
| D11 | A response replaces the cached copy only if it is 200, UTF-8, within `MAX_LIST_BYTES` (32 MiB), not an HTML page, and yields at least one rule. A 304 renews the time. Anything else keeps the last good copy and records why. | 5.4. A captive portal's 200 must not erase a list. |
| D12 | Lists refresh only while routes are up, in a task started by `bring_up` and aborted by `take_down`, using `Relay::connect` for pinned sockets. Refused or failed fetches retry after `MIN_REFRESH`, or after `NO_COPY_RETRY` (5 min, annotated) when no copy exists. | Plan 6: the switch off means no timer. No pinned-socket code moves, and the shared `relay.rs` diff stays small. |
| D13 | The cached copies compile at `bring_up` in `spawn_blocking`. Flows pass until the first snapshot lands. A compile panic (`JoinError`) keeps the previous snapshot and records the error. | Fail open, and the relay and watchdog are never starved. |
| D14 | `Policy` grows: `sieving: bool`, `off_apps: Vec<String>`, `lists: Option<Vec<String>>` (None means catalogue defaults), `domain_lists: Vec<DomainList>`, all `#[serde(default)]`. `sieving` defaults to false. | An old `policy.json` keeps loading (S39). After an upgrade, nothing is blocked until the app has sent the Off list, so an Off app is never blocked by a missing field. |
| D15 | `DomainList { kind: Block or Allow, entries, enabled }` compiles through one function, `rules::domain_rule(entry, kind)`, to `||host^` or `@@||host^`, as list id `user`, `trusted: false`. A bad entry is skipped and counted. The B6 `scope` field arrives with its second value in slice 7. | B6, without speculative generality (S35). A newline or rule syntax in an entry cannot inject a rule. |
| D16 | The app stores two new string-list settings, `filtering.blockedDomains` and `filtering.allowedDomains`, sent as `domain_lists`. The controller builds the whole wanted policy from settings and compares all of it, order-normalised. | Fixes finding 2. Registry `list` settings bring validation, import and export with them. |
| D17 | Pipe: `PROTOCOL` 3. New requests `lists` and `lists_refresh`, new answer `lists {lists, compile_ms}`. `FlowAction::Blocked`. `FlowEvent` gains `reason`, `rule` (capped at 256 chars), `list`. `Counters.blocked`. `EngineStatus.blocking`. A `ListStatus` carries `id, enabled, fetched_at_ms, refresh_s, last_error, network, cosmetic, skipped, skip_reasons, skipped_exceptions (first 200 lines), skipped_exceptions_total`. | Plan 1.3 and 5.2. The report is requested, not in every 5 s Status, and the cap keeps it under `MAX_FRAME`; a law test checks the worst case. |
| D18 | Provenance: the rule text comes from adblock-rust's debug info; the list comes from a compile-time `HashMap<u64, u16>` of rule-text hash to list bitmask. | 5.3, and far less memory than a text-keyed map. Debug retention's memory is measured by the benchmark. |
| D19 | The benchmark is an ignored test run in release, with a counting global allocator. It refuses to run under `debug_assertions`. | Debug numbers mean nothing. `sieve-filter` makes no Windows calls, so allocator bytes stand in for RSS offline. Real RSS is a live check. |

**Deviations found while building, each with its reason:**

- **D18:** no rule-text hash map. adblock-rust's `source_location` already names the list, provided its pattern fusion is off, because fusion joins rules with ` <+> ` and drops the location. Engines are built with `Engine::new_with_filter_set_no_optimize`. That is one owner for the fact and less memory; the benchmark still passes. The library marks that constructor `#[doc(hidden)]`, so an upgrade must re-check it.
- **D7:** `check_host` always looks for exceptions (`check_network_request_subset(.., false, true)`), not only after a block rule. Without it a user's allow entry, alone in its engine with no block rule, answered None and the list's block won. `user_allow_beats_a_list_important_block` caught this.
- **Trust store:** `webpki-roots`, not `rustls-platform-verifier`, matching `wf-encrypted-dns` (S29) and keeping local filter roots out of the engine's own downloads.
- **`-case`:** adblock-rust refuses it except on regex rules, so `||host^$match-case` is pinned as skipped. It is not an exception modifier, so this only under-blocks.
- **Status guard:** `policy::accept` refuses a policy over half a frame, because the Status carries it back. The controller retries a refused send at the next probe instead of at once, which would have been a hot loop.
- **Hidden-exe apps:** the app names an app whose exe it cannot read by the services it hosts; the engine, running as SYSTEM, reads the exe and derives another key. Such an Off row does not match, and the flow stays sieved. Recorded where the code is (`AppKeys::of_pid`).
- **`MAX_LISTED_LINE_BYTES` (180):** a skipped exception line in the report is cut, so 200 lines per list fit one frame even when fully JSON-escaped.

**Design gate.** New quantities and their owners: app key, `sieve-ipc` (Rust) and `appIdentity` (TS), tied by a fixture; rule priority, `RuleSet`; list freshness, `FetchState`, with `refresh` recomputed from the text and never stored (S23). Retired: `flows::verdict`, `flows::Decision`, `flows::Reason`. New dials: `MAX_LIST_BYTES`, `NO_COPY_RETRY`, the 200-line and 256-char caps, each a named, commented constant. No site names in engine source; tests use `.invalid` and `.example`.

**TENSION, recorded where the code is:** an app key built from ProductName can be spoofed, since an exe that names itself like an Off product gets its exemption. Ad blocking is not a security boundary against local code, and this matches how the Apps page already groups apps.

## Files

**`engine/crates/sieve-filter`:** `src/rules.rs` (D5, D7, D15, report split, exception listing, provenance); `src/lists.rs` (D10, D11); `src/catalogue.rs` (`selected`); `tests/matcher_bench.rs`, new; `src/lib.rs` (docs).

**`engine/crates/sieve-ipc`:** `src/lib.rs` (D2, D14, D17). Shared file: append only.

**`engine/crates/sieve-engine`:**
- `src/domain.rs`: D1, D4, D8; `Flow::from_decoded`.
- `src/flow/flows.rs`: remove `verdict` and its tests (moved to `domain.rs`), add `os::product_name` and a path-to-key cache.
- `src/lists/mod.rs`, new: `Fetcher`, the refresh loop, compile and swap.
- `src/lists/cache.rs`, new: atomic text and state files, corrupt reads as absent.
- `src/lists/https.rs`, new: real fetcher, generic over the stream.
- `src/stack/relay.rs`: decision in the TCP and UDP paths, including the `relay-experiments` branch; drain.
- `src/stack/mod.rs`: `Meters.blocked`.
- `src/control/mod.rs`, `src/control/routing.rs`: snapshot ownership, rebuild on policy change, start and stop the refresh task, the new status field.
- `src/ipc/mod.rs`: `Backend` gains `lists` and `lists_refresh`.
- `src/policy.rs`: `pub(crate) write_atomic`, old-file test.
- `src/bin/probe/{forward,support}.rs`, `examples/bench.rs`: D1.
- `src/lib.rs`, `Cargo.toml`: `hyper`, `hyper-util`, `http-body-util`, `tokio-rustls`, `rustls` (aws-lc-rs), `rustls-platform-verifier`. Each is needed only by `lists/https.rs`; reuse whatever `wf-encrypted-dns` lands with.

**App:** `src-tauri/src/engine.rs` and `src-tauri/src/lib.rs` (non-`Copy` policy; commands `engine_lists`, `engine_lists_refresh`); `src/data/protocol.ts`, `engine-source.ts`, `engine-mock.ts`, `engine-controller.ts`; `src/core/settings/registry.ts` (two keys, plus truthful copy for `apps.levels`, `filtering.engine` and `sampling.enabled`, which now say "nothing is blocked" or "cannot exempt" wrongly); `src/core/settings/migrate.ts` only if a law requires a schema bump.

**Fixtures and laws:** `src/data/fixtures/engine-ipc-v2.json` renamed to `engine-ipc-v3.json` in its own commit (see Coordination); `engine-probe-v2.json` content; new `app-keys-v1.json`; `tests/laws/engine-ipc.test.ts`; new `tests/laws/app-key.test.ts`.

## Acceptance (offline, no internet, no elevation)

Run `$env:CARGO_BUILD_JOBS='8'` first. Test names are binding unless a better name is recorded here.

**Suites, all green:**
- [ ] In `engine/`: `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`, and again with `--features relay-experiments,attribution-diagnostics`
- [ ] `cargo test -p sieve-engine --features relay-experiments,attribution-diagnostics`
- [ ] Repo root: `pnpm typecheck`, `pnpm lint`, `pnpm test`
- [ ] `src-tauri`: `pnpm rust:test`, `pnpm rust:lint`
- [ ] Registry rows change UI, so `pnpm e2e` through the GPU lease, after reading `nvidia-smi`

**Policy (`domain.rs`):**
- [ ] `off_app_flow_to_a_blocked_host_is_relayed` and `sieved_app_flow_to_a_blocked_host_is_closed`: for each of TLS SNI, HTTP Host and QUIC SNI, built with the existing test builders and run through the real classifier
- [ ] `no_name_flow_every_name_blocked_is_closed`, `no_name_flow_mixed_names_is_relayed`, `no_name_flow_expired_or_no_names_is_relayed`
- [ ] `dns_is_never_blocked_even_for_a_blocked_question`
- [ ] `forwarded_flow_is_domain_filtered_and_never_decryptable`, `forwarded_flow_never_inherits_a_host_apps_off`, `vm_row_off_relays_only_that_vm`
- [ ] `unknown_owner_is_sieved`, `global_switch_off_relays_everything`
- [ ] `ech_flow_is_decided_by_its_outer_name`
- [ ] Relay-level, in-memory (`flow/relay.rs` tests): `blocked_flow_sends_nothing_upstream_and_closes_the_app`, `off_app_held_bytes_reach_upstream_intact`
- [ ] `blocked_udp_drains_until_idle_and_books_one_flow`, on the tokio fake clock

**Rules (`rules.rs`):**
- [ ] `user_allow_beats_a_list_important_block`, `user_block_beats_a_list_exception`
- [ ] `document_exception_allows_a_host`, `ipv6_literal_and_trailing_dot_and_case_are_normalised`
- [ ] `domain_rule_refuses_injection`: newline, `$`, `@@` and whitespace are skipped and counted
- [ ] `report_counts_every_syntax_form`: one fixture line per form in 5.2, including the "not supported first" list; the expected applied or skipped result of each is pinned
- [ ] `every_skipped_exception_is_listed_with_its_line`: `$elemhide`, `$ehide`, `$specifichide`, `$shide`, `$genericblock`, `@@...$removeparam`; total stays right past the 200 cap
- [ ] `report_splits_network_and_cosmetic`, `blocking_rule_names_its_list`
- [ ] proptest `compile_never_panics_on_arbitrary_lines`

**Lists (`lists.rs`, `lists/*`), fake fetcher and tempdir only:**
- [ ] `first_download_is_cached_compiled_and_swapped`, `not_modified_keeps_the_copy_and_renews_the_time`
- [ ] `failed_download_keeps_the_last_good_copy`, for each of: 500, timeout, HTML 200, empty, oversized, invalid UTF-8
- [ ] `conditional_headers_come_from_the_saved_state`, `refresh_follows_the_lists_expires`
- [ ] `no_copy_retries_sooner_than_a_failed_refresh`
- [ ] `corrupt_cache_reads_as_absent`, `state_survives_a_restart`
- [ ] `a_panicking_compile_keeps_the_previous_snapshot`
- [ ] `only_selected_lists_are_fetched`, `none_selects_the_catalogue_defaults`
- [ ] `https_fetcher_reads_chunked_and_caps_size`, over an in-memory stream; `https_fetcher_refuses_a_redirect_and_plain_http`
- [ ] `tls_config_prefers_x25519mlkem768`

**IPC and app:**
- [ ] `every_fixture_message_round_trips_unchanged` covers `lists`, `lists_refresh`, `blocked`
- [ ] `a_full_lists_frame_stays_under_the_frame_limit`, and `a_full_flows_frame_stays_under_the_frame_limit` with the rule text at its cap
- [ ] `an_old_policy_file_loads_with_sieving_off`
- [ ] App key parity: the Rust test and `tests/laws/app-key.test.ts` read the same fixture (product, exe stem, no exe, System)
- [ ] `engine-controller.test.ts`: `sends_the_whole_policy`, `an_off_app_change_alone_is_sent`, `same_policy_in_another_order_sends_nothing`
- [ ] Protocol parser tests against missing, partial and old-schema status (frontend-resilience)

**Benchmark:**
- [ ] `cargo test -p sieve-filter --release --test matcher_bench -- --ignored --nocapture` prints rule count, compile ms, live and peak heap, and p50, p99 and max for host decisions and URL decisions, and passes at p99 under 20 us. Offline input: a deterministic generator, at least 100k rules and 50k tuples, on `.example` names. `scrub_url` has a test: no query, no fragment, numeric and hex path segments reduced to shape.
- A slow run on this machine may be the CPU watchdog suspending the process. Report it and rerun; do not raise the threshold.

## UNVERIFIED (for the user, live)

Nothing below can run offline. A new `scripts/live/` script is not part of this stream; the steps belong in the slice 4 live doc.

1. **Zero skipped exceptions on the real default lists:** run the benchmark with `SIEVE_BENCH_LISTS` pointing at the engine's `lists\` folder, read the listing it prints. Expected non-zero (finding 4).
2. **p50 and p99 under 20 us on the real corpus,** at real rule counts. There is no recorded request log yet (the log route is another stream), so the offline number is on generated input and is not the spec's 50k real tuples. Point `SIEVE_BENCH_CORPUS` at a corpus once one exists.
3. **Real compile time, and engine memory** at most 300 MB RSS with default lists and 2,000 open flows (plan 6), with `FilterSet::new(true)` retaining rule text.
4. **`doubleclick.net` blocked in Edge while an Off copy of curl reaches it;** Windows adapter DNS unchanged throughout.
5. **The real downloads:** TLS against the catalogue hosts, X25519MLKEM768 negotiated, a pinned socket staying off the adapter, name lookup working while routed, 304s on later runs.
6. **Whether any list host answers with a redirect.** Redirects are refused (S24), so one would show as a recorded failure and the catalogue URL would need changing.
7. **Kill, reboot and uninstall tests** with this feature on. Uninstall removes `lists\` through `ProgramData\Sieve` removal (`service/scm.rs`), which is read in code, not run.
8. **QUIC fallback time** on a blocked host in Chrome, and whether the drain (D9) delays page load for mixed pages.
9. **`aws-lc-sys` building on this machine** is checked in step 8 below, not assumed. If it needs CMake or NASM that are missing, that is a blocker to report.
10. **Over-blocking in normal use** with URL-level lists at host level (open question 1).

## Open questions for the user

Implementation proceeds on the stated default, and each can be changed later.

1. **URL lists at host level before slice 6.** AdGuard Base and Tracking are written for per-URL matching. `||cdn.example^` with `@@||cdn.example/lib.js` closes the whole host, because no path is visible until decryption exists. Default, as the plan says: every default-on list decides host flows. The alternative is that only the AdGuard DNS filter decides host flows until slice 6, which blocks less but breaks less. It is one line in the catalogue either way, and the live run should inform it.
2. **Exception modifiers adblock-rust lacks.** `$elemhide`, `$specifichide` and `$genericblock` cannot be supported without patching the library. Default: list each skipped line (the spec's "or each listed") and revisit in slice 9, where they first have an effect. The alternative is vendoring a patched adblock-rust now.

## Coordination, for the orchestrator

- **Protocol v3 is one version for this whole wave.** The rename to `engine-ipc-v3.json` and the bump are a separate commit. If another stream lands v3 first, drop that commit and append. The workflow's shared-file list names `engine-ipc-v1.json`; the real file is v2.
- **`wf-attribution`:** must construct `Owner::Forwarded` in `stack/relay.rs`. Its off-row key is `vm:<name>` or `vm:unidentified`. If it adds its own owner type, merge onto `domain::Owner`.
- **`wf-encrypted-dns`:** will also add rustls and a client config. One `client_config()` should survive the merge (S29). `Policy` gets its `upstreams` by appending. ECH stripping and the canary need an owner; they are in slice 4 and not in this stream.
- **`wf-app-log`:** the host-level log reads `FlowEvent.reason`, `rule`, `list` and `FlowAction::Blocked`, so it should not add parallel fields.
- **`wf-ui-backlog` (or whichever stream owns Settings):** renders the per-list report from `engine_lists`, and owns list selection. This stream sends `lists: null`. Plan acceptance "report shown in Settings" stays open until then.
- **The DNS-removal stream:** edits the same `registry.ts` and `migrate.ts`. Keys here are appended, and the copy changes touch only three `help` strings.

## Implementation order

Each step ends green on the suites it touches, with its own commit.

1. **`rules.rs`:** D7, D15, the report split, exception listing, `RuleSet`, provenance. Pin the library facts of findings 4 and 5 with failing tests first (S9).
2. **`lists.rs`:** pure fetch state and response validation (D10, D11); `catalogue::selected`.
3. **Benchmark:** `tests/matcher_bench.rs`, first numbers. If p99 misses on generated input, stop and report it; the rest does not depend on a workaround.
4. **`sieve-ipc`:** D2, D14, D17; fixture and TS law; `app-keys-v1.json` with both readers. Keep the workspace compiling with minimal adaptations (`Policy` is no longer `Copy`). Rename the fixture in its own commit.
5. **`domain.rs`:** `Owner`, `RuleSet`, ECH and `Flow::from_decoded` with the policy tests; remove `flows::verdict` and move the probe and `examples/bench.rs`.
6. **`flows.rs`:** product name and key cache. **`stack/relay.rs`:** decision and drain, in both relay branches; `Meters.blocked`; in-memory relay tests.
7. **`control/`, `routing.rs`, `lists/mod.rs`, `lists/cache.rs`:** snapshot ownership, policy rebuild, refresh loop with a fake fetcher, compile and swap, `Backend::lists`.
8. **`lists/https.rs`:** the real fetcher and its dependencies, last, so a build problem blocks nothing else.
9. **App:** `src-tauri` commands, `protocol.ts`, source and mock, controller (D16), registry keys and copy; degraded-data tests.
10. **Full validation:** every suite and clippy feature set; e2e under the lease; update slice 4's status in the plan; list what stays UNVERIFIED. Kill any process started, by tree.
