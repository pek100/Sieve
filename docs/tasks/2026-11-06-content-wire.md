# Task: slice 9 wiring and slice 10 (stream "content-wire")

Spec: `docs/plans/2026-10-17-https-filtering.md` 5.4, 5.6, 5.7, slices 9 and 10. Library this wires: `docs/tasks/2026-11-02-content.md`. Path it plugs into: `docs/tasks/2026-11-06-tls.md`. Branch `wf2-content-wire`, worktree `F:\Projects\Code\Sieve\.claude\worktrees\wf2-content-wire`, based on `wf2-tls` at 400f3ce.

## Goal

With `filtering.https` and `filtering.content` both on, every decrypted HTML document response goes through `inject/` while streaming: cosmetic CSS, scriptlets and the procedural applier go in at the start, under the caps. With `filtering.content` off, `wants` answers false and bytes are exactly what slice 6 sends today. Both switches stay unavailable to users. Slice 10 ships `scripts/live/youtube.mjs` written and syntax-checked, never run; the default list set stays gated with its two arms named; `engine/tests/no_site_names.rs` becomes the law for site names in engine source.

Done means: the offline acceptance below passes, the UNVERIFIED list and its runbooks are handed over unrun, and with `filtering.content` off `http::tests::no_rewrite_passes_bytes_unchanged` still holds with the real hook in place.

## Rules that bind this task

- No test reaches the internet; loopback only (`127.0.0.1:0`, sequential, per conventions section 8). `youtube.mjs`, `engine-content.ps1` and every `live_*` are written and statically checked only.
- No elevation, service, route, adapter, DNS, firewall, certificate store, Firefox policy, `E:\Sieve`, `ProgramData\Sieve` or AdGuard.
- `filtering.https` and `filtering.content` keep `unavailableUntil`. No change unlocks them. The catalogue's gated lists stay gated.
- Forwarded (VM, WSL) flows never reach this path, since `decrypt` passes them through; nothing here adds a second check.
- PowerShell for shell commands. `$env:CARGO_BUILD_JOBS='8'` before cargo. A paused cargo may be the watchdog: rerun, do not kill. Kill anything started, by tree.
- Absolute paths only. Never edit `F:\Projects\Code\Sieve` itself.
- Shared files take small, append-only diffs: `sieve-ipc/src/lib.rs`, fixtures, `registry.ts`, `migrate.ts`, `routes.ts`, `Cargo.toml`.
- No site name in engine source, em dash law everywhere under `docs` and `engine/crates`.

## Findings from reading the code (2026-11-06)

Each was read or run on this branch. Each changes the design, so each is stated before it is used.

| # | Finding | Evidence | Consequence |
|---|---|---|---|
| F1 | **The gzip gap is already closed at the decoder.** Bytes after a member, and a later member whole, cut or broken, are ignored; a bad trailer of the first member still errors. | a13070f; run on this base: `cargo test -p sieve-engine --lib inject::` 85 passed, including `bytes_after_the_end_of_a_stream_are_ignored`, `a_later_gzip_member_is_ignored`, `a_later_gzip_member_cannot_trip_the_caps` | D9: no decoder change. What is missing is proof through the HTTP path, so a test pins it there. If that test is red, it is a new finding: report it and fix at its layer |
| F2 | **The `$document` gap is real and wider than stated.** Probe on this base, block rule plus exception on the same host: `$document` alone gives Allow. `$document,elemhide`, `$doc,ehide` and `$document,generichide` give Block, on `check_host` and on `check_request` with that page as initiator. `@@x$elemhide,script` also leaves the script blocked. | Temporary test, since removed. `page_exception` answers the cosmetic half; the parser refuses `elemhide`, so `set.add_filter_list` drops the line; `$document,generichide` parses but is held as a generichide filter | D8 |
| F3 | **`begin` takes one `RuleEngine`; a flow asks a `RuleSet`.** Wired as is, the user's rules would have no cosmetic effect, and a user's `@@||site^$document` would not stop the lists' injection. That contradicts "the user wins" (`rules.rs` header). | `inject/mod.rs` 113, `domain.rs` `DomainFilter.rules` | D3 |
| F4 | **`is_document` is false for iframes.** `OwnedFacts::borrowed` compares with `document` only and `sub_frame` is a separate type, while plan 5.6 rewrites both and `PageRequest.is_document` documents both. | `http/facts.rs` 36, `inject/response.rs` 26 | D4 |
| F5 | **Accept-Encoding is not narrowed.** Plan 5.6 item 1 has no code. A Chrome with a shared dictionary offers `dcb`, `dcz`; an answer in those passes through uninjected, which is safe but silently filters less. | grep of `sieve-engine/src` | D5 |
| F6 | **`wf2-tls` lacks 18 commits of main**, among them a869fd6: the ratio cap is judged once at the end of a body. Here it is still mid-stream, so a real page with a long compressible prefix can be reset depending on how the transport cut it. Harmless while nothing fed the library; a live bug once this stream wires it. Also applier patches, `lists/resources.rs` and `lists/mod.rs` fixes. | `git rev-list --count`, `git diff wf2-tls main`; `git merge-tree` shows one conflict: `control/mod.rs` | Step 0 and O1 |
| F7 | **A rewritten document keeps `ETag` and `Last-Modified`.** D8 of the content task kept them and slice 6 was to decide. A 304 then reuses a page whose nonce no longer matches any CSP in the 304, and a page's injected rules live on for as long as it revalidates. | `inject/response.rs` 97, `docs/tasks/2026-11-02-content.md` UNVERIFIED | D6 |
| F8 | **No path gets a real bundle onto a machine for a live run.** `RESOURCE_PIN` is None and no signed copy exists, so every scriptlet line is inert: slice 10 cannot pass until Q1 of the content task is answered. | `lists/resources.rs` 16 | Q1 below, runbook prerequisite |
| F9 | **The engine log cannot be read by a script.** It is memory-only (plan 7.1) and the pipe admits only `sieve.exe`, while 5.7 says `youtube.mjs` records rules "from the engine log". | `service` client check, `http/serve.rs` `Serve::log` | D11 |
| F10 | **`engine/tests/` is in no package**: the workspace root is virtual, so a file there compiles only if a manifest names it. A bare grep for a TLD also hits Rust field access (`self.app`, `e.app`, `entry.app`). | `engine/Cargo.toml`, grep over `engine/crates` | D13 |
| F11 | Slice 10 depends on slice 8: without QUIC refusal Chrome reaches the video site over HTTP/3, which is never decrypted, so nothing here applies. | plan 5.7 step 2, stream `wf2-quic` | Runbook prerequisite; the script calls such a run inconclusive |

## Design decisions

**D1. One data switch, one snapshot.** `Policy.content: bool` (`#[serde(default, skip_serializing_if = "std::ops::Not::not")]`) feeds a new `DomainFilter.content`, set in `DomainFilter::new`, false in `inert()`, carried by `with_lists`. The hook reads `FilterSlot::get()`, so the switch and the rules it applies are the same atomic snapshot, as with the global switch: no second flag, no new slot (S29). Off reaches the next response; a body already being rewritten finishes, since cutting it would break a page. `filtering.content` requires `filtering.https`; the hook exists only inside `Interception`, so `https` off means no hook by structure (S30).

Why not bump `PROTOCOL`: v3's own doc lists everything added during this wave without a bump, because no release separates them and app and engine ship together. Omitting a false value means no fixture diff in the stream most likely to collide, and one added `set_policy` example with `content: true` keeps the law honest. `sieve-ipc` header comment gains the field. This is O2.

**D2. The hook: `inject/content.rs`, type `ContentHook`.** It implements `http::hook::ResponseHook` and is the one consumer of `inject::begin`.
- `wants`: `snapshot.enabled && snapshot.content && req.is_page() && response::body_format(...).is_some()`. Anything else streams from its first byte, so a response no rewrite could touch never waits for a first frame.
- `begin`: reads the snapshot again and calls `inject::begin`. A swap between the two answers None and the body passes, which is safe.
- `BodyRewrite for Page(PageRewriter)`: `InjectError` becomes `HookError`, which resets per the existing contract, and bumps the `resets` meter.
- `control/routing.rs` `build_interception` swaps `NoRewrite` for `ContentHook::new(engine.filter.clone(), engine.meters.clone(), InjectLimits::default())`. `NoRewrite` stays for tests. `inject` keeps depending on `http::hook` and never the reverse.

Alternative rejected: choosing between `NoRewrite` and `ContentHook` when the slot is built. The switch would then need a rebuild of `Interception`, closing every decrypted flow on a cosmetic toggle.

**D3. `RuleSet::page_cosmetics(url)`; `begin` takes `&RuleSet`.** New in `sieve-filter/src/cosmetic.rs`, keeping the D2 table of the content task per engine:
- The user's engine is asked first for its page-level exceptions and `#@#` selectors (`UserGates`). User `$document` gives an empty page, with the user's own hide rules dropped too, matching the table.
- `RuleEngine::page_cosmetics(url)` becomes `page_cosmetics_under(url, Option<&UserGates>)`, so the lists are cut by the user's gates and there remains one implementation (S14). The plain method stays as the `None` case.
- A list's `@@...$document` does not silence the user's own `##` rules: the user wins both ways.
- Merge: `generic_css` keeps the lists' shared `Arc` when the user's part is empty (the common case, no copy); otherwise concatenated. Specific CSS, procedural, scriptlets and `dropped_rules` add up.
- A user's `host#@#+js(...)` cannot be cut out of the lists' assembled `injected_script` string. Each such line is derived, as in the content task's D2, into a private `no_scriptlets` engine (`@@||host^$generichide`), and on a match the lists' scriptlets are dropped for that page. A named exception therefore stops all list scriptlets there: over-broad in the safe direction (the page is less changed), annotated in code, and it needs no second matcher. This instantiates the existing trick (S48).
- Deferred on purpose: a user's own `##+js()` stays inert. `user_engine` never receives the bundle, and giving it one needs the policy at list-swap time. It is pinned by a test and listed as a follow-up.

**D4. `RequestFacts::is_page()` is the one owner.** True for `document` and `sub_frame`, added beside the facts. `is_document` keeps its current meaning for the removeparam 307 (`http/rules.rs`), which is not this stream's. The hook passes `is_page` as `PageRequest.is_document`. A service worker's fetch of a page says `Sec-Fetch-Dest: empty`, so it reads as `xhr` and gets no injection: fail open, listed under U8.

**D5. Request side.** `ResponseHook` gains `fn prepare_request(&self, req: &RequestFacts<'_>, headers: &mut HeaderMap) {}` with a default no-op; `http/serve.rs` calls it once, before `strip_hop_by_hop`. `ContentHook` narrows `Accept-Encoding` only for a page request with content on. `decode::readable_accept_encoding(value) -> String` keeps tokens `ContentEncoding::from_header` knows, plus `identity`, with their `q` values; drops `*` and anything else; nothing left becomes `identity`. `from_header` remains the one list of encodings (S29). Subresources are never touched: they are not rewritten, so narrowing would only cost bytes.

**D6. A rewrite removes `ETag` and `Last-Modified`.** Add both to `strip_falsified_headers`. The bytes differ per response because of the nonce, so a validator describing the origin's bytes is false by definition, and this removes the F7 cases at the root. Cost: a page revalidation becomes a full fetch once its freshness runs out. `Cache-Control` is untouched. The existing test `a_rewrite_removes_exactly_the_headers_it_falsifies` changes with it, and that row of content D8 gets a dated note. A browser's cached copy from before Sieve still revalidates and shows uninjected once, which is harmless. A rewritten page cached by a browser outlives Sieve off for its `max-age`: O3.

**D7. Meters, no log rows.** `Meters.content: ContentMeters` (`rewritten`, `with_scriptlets`, `with_procedural`, `resets`), reported as `status.json.content` beside `https`, as task D18 of slice 6 does: no host, not on the pipe. `LogOutcome::Hidden` and `Scriptlets` stay unemitted: a proxy cannot count elements, and `injected_script` is a joined string. Page rows belong to slice 12.

**D8. A page exception keeps its network half.** In `report()`, `page_exception` also yields `network_half()`: the line with its hide options removed. It exists when the line names `document`, or leaves a type constraint, and names at least one hide option. The test for "a type constraint" is the parsed filter's own mask (`NetworkFilterMask::FROM_NETWORK_TYPES` and the document bit, read from adblock-0.13.3 while implementing), not a second list of option names (S49).
- `@@||x^$document,elemhide` gives `@@||x^$document` in the main engine as well as the existing private ones. `@@||x^$elemhide,script` gives `@@||x^$script`.
- `@@||x^$elemhide` gives no half, so a hide exception can never open the network: a test pins this.
- Halves are appended to that list's text in the one `add_filter_list` call, so `source_index` and the list id stay right. A second call would shift every later list's provenance.
- `RuleEngine` keeps `written: HashMap<half, original line>`, and `rule_text` maps through it, so `HostDecision.rule` stays "the rule's text as its list wrote it" (S53).
- `ListReport` counts the line once, as today.

**D9. Gzip tail, end to end.** No code change (F1). `content_gzip_tail_does_not_reset_the_page` serves, over the real path in both arms and both protocols, a gzip page followed by junk, then by a second member, once in one frame and once with the tail in a frame of its own.

**D10. Live page.** `live_content_injects_into_test_page` is `#[ignore]` in `http/tests.rs` beside the hook tests and panics with "this check is the runbook", as slice 6's does: registry law 4 reads the name. The test page must be public, because only a chain that anchors in a public root is intercepted and loopback never crosses the adapter. So the runbook drives a user rule on `example.com` through `policy.json`: `scripts/live/engine-content.ps1` follows `engine-ca.ps1` (app closed, service stopped, higher revision, started again) with steps `before`, `on`, `arm`, `off`, under `live-lease.ps1`. It never touches anything but `policy.json` and `sc.exe` for the engine's own service.

**D11. `youtube.mjs` records what it can witness.** Per F9, rule hits come as counts per list: `FlowBook` adds `list_hits: BTreeMap<String, u64>` bumped by `log_request` on blocked, redirected and params-removed rows, reported in `status.json.content.list_hits`. List ids only, so 7.1 holds; the script reads the delta around each arm when run elevated, and records `null` (never 0, S17) when it cannot read the file. Per-rule text stays on the app's Log screen, and the runbook asks for those rows when a video shows an ad. Deviation from 5.7's wording, named in the plan's status note.

**D12. The script.**
- `scripts/live/youtube.mjs`: ES module, Node 22 global `WebSocket`, no dependency. `--browser chrome|edge|firefox`, `--arm adguard|adguard+ubo`, `--out <dir>`, `--videos <json>`.
- Temp profile, process tree killed in `finally`. Run under `with-gpu.ps1 -Label sieve-youtube`.
- One small `Driver` (`navigate`, `evaluate`, `screenshot`, `documentFacts`): CDP for Chrome and Edge, WebDriver BiDi for Firefox, since Firefox has no CDP.
- Pure parts are exported and main runs only when the file is the entry point, so importing it starts nothing: `parseArgs`, `armLists(fixture, arm)` (derived from each row's `default` in `src/data/fixtures/filter-lists-v1.json`, tied to `catalogue.rs` by law 13), `videoVerdict(samples)`, `runVerdict(videos)`.
- Asserts 5.7: `currentTime` advances, the player never carries its ad-showing state, no enforcement interstitial, no feed or masthead ad on the home page, seek, quality change and next-video autoplay work. Failure screenshots go to `--out`.
- A run is **inconclusive, never pass**, if any of: the document issuer is not Sieve's; the protocol is `h3` (F11); fewer than 10 videos played; no scriptlet payload in the served document (F8).
- `scripts/live/youtube-videos.json` holds the fixed set. The ids come from memory and have not been checked, so the runbook says to review them first, and an unavailable video counts as not played. Site knowledge lives in these two files only (5.7).

**D13. `engine/tests/no_site_names.rs`, compiled through `sieve-filter`** with `[[test]] name = "no_site_names"`, `path = "../../tests/no_site_names.rs"`: the plan's path, the workspace's cheapest crate, std only.
- Scans `engine/crates/**/*.rs` and `engine/injected/bootstrap.js`, string literals and comments only (a small lexer), so Rust field access cannot hit (F10). `engine/crates/sieve-filter/data/sensitive.txt` is data the user decided Sieve ships. `procedural_filters.ts` and its output are vendored at a pinned hash and are not ours to edit.
- A hit is a host-shaped token ending in `com net org io tv dev gov edu`, or a bare word from the sites plan 5.7 names (`youtube`, `googlevideo`, `ytimg`, `doubleclick`), case-insensitive. Not a hit: `.example`, `.invalid`, `.test`, `.localhost`, and `example.com/.org/.net` (RFC 2606).
- Declared exceptions, each a `(file, token, why)` row, with a test that every row still occurs, so a stale exemption fails (S26):
  - `sieve-engine/src/dns/upstream.rs`: `cloudflare-dns.com`, `dns.quad9.net`. The decided DoH defaults (decision table, encrypted DNS).
  - `sieve-filter/src/catalogue.rs`: `filters.adtidy.org`, `ublockorigin.github.io`, `adguardteam.github.io`, `github.com`. The lists' URLs and project pages, which are their identity.
  - `sieve-engine/src/exclusions/lists.rs`: `raw.githubusercontent.com`. A list URL like the catalogue's, disabled until Q1 of the TLS task.
  - `sieve-filter/src/exclusions.rs`: `go.com`, `service.gov`, `example.gov`. Those tests' subject is the public suffix table, and `.example` is no suffix.
- One path exception: `sieve-engine/src/bin/probe/`, the spike's developer tool, never bundled, whose subject is a named test domain.
- Everything else is fixed, not excused: test strings go to `.example` (`exclusions/mod.rs` 381, `dns/config.rs`, `dns/upstream.rs` 270 and 421, `flow/sni.rs` 451 and 464, `examples/bench.rs` 187), source comments lose the name (`flow/relay.rs` 396, `tun/mod.rs` 26), and `catalogue.rs` `UBO_SLICE` drops the site's name. The grep in this doc's Findings was cut at 120 lines; the first run of the law gives the real set, and any new exception needs the same justification or a fix.
- Controls in the same file: the scanner catches `ads.site.com` in a string and a comment, and leaves `self.app`, `x.example`, `page.sieve-test.invalid`.
- The narrower laws in `injected.test.ts` and `engine-trust.test.ts` stay.

**D14. Default list set: not decided here.** `Default::Gated(UBO_SLICE)` stays. `catalogue.rs` gains `enum ListArm { AdguardOnly, WithUbo }` and `arm_lists(arm)`, derived from the `default` field: the defaults, or the defaults plus every gated row. `UBO_SLICE`'s doc comment states the rule from 5.4: both arms pass turns the gated rows on, one passes makes that arm the default, and the numbers go in the plan. Slice 10 in the plan gets a status note and an empty results table (browser, arm, videos, ads seen, per-list hits). The one-word flip is left for after the live result.

## Design gate (clean-architecture)

- Laws instantiated: `decrypt`-style one owner per fact (S29), the private exception engines (S48), `Meters.https` (D7), the runbook-named ignored test (D10).
- New primitives and why the basis could not express them: `prepare_request` (the hook could only see responses, and 5.6 item 1 is a request-side fact), `UserGates` (two engines must agree on one page; S14), `written` (a derived rule would otherwise falsify `HostDecision.rule`).
- Redundant after this: `NoRewrite` in production. It stays as the default for tests of the path.
- Single owners: `body_format` (what qualifies), `from_header` (which encodings), `is_page` (what a page is), `catalogue.default` (which arm).
- Dials: none new. `InjectLimits` stays as declared.

## Files

New:
- `engine/crates/sieve-engine/src/inject/content.rs` (`ContentHook`, `Page`, tests)
- `engine/tests/no_site_names.rs`
- `scripts/live/youtube.mjs`, `scripts/live/youtube-videos.json`, `scripts/live/engine-content.ps1`
- `docs/live/engine-slice-9.md`, `docs/live/engine-slice-10.md`
- `tests/laws/youtube-live.test.ts`

Changed:
- `engine/crates/sieve-filter/src/cosmetic.rs` (D3, D8), `rules.rs` (D8; comment at 76), `catalogue.rs` (D13, D14), `exclusions.rs` only if the law asks, `sieve-filter/Cargo.toml` (`[[test]]`)
- `engine/crates/sieve-engine/src/inject/{mod.rs, response.rs, decode.rs}`: `begin` takes `&RuleSet`, D6, D5
- `engine/crates/sieve-engine/src/http/{hook.rs, serve.rs, facts.rs, tests.rs}`: `prepare_request`, `is_page`, tests, the ignored test
- `engine/crates/sieve-engine/src/domain.rs` (`content`), `control/routing.rs` (real hook), `control/mod.rs` (`status.json.content`), `stack/mod.rs` (`ContentMeters`), `stack/book.rs` (`list_hits`)
- `engine/crates/sieve-engine/tests/inject_page.rs`, `examples/inject_bench.rs`: the `&RuleSet` call only
- `engine/crates/sieve-ipc/src/lib.rs` (`Policy.content`), `src/data/fixtures/engine-ipc-v3.json` (one `set_policy` example)
- `src/core/settings/registry.ts` (`filtering.content`, `ENGINE_SLICE_9`), `src/core/engine.ts` (`CONTENT_SWITCH`), `src/data/protocol.ts` (`content`, `orDefault` false), `src/data/engine-controller.ts` (`wantedPolicy`, `normalised`), `src-tauri` only if `engine.rs` names policy fields
- `tests/laws/unavailable.test.ts` (both switches), `tests/laws/registry.test.ts` (`needsEngine` is three), `tests/laws/injected.test.ts` only if `begin` moves a scanned file
- Comments that become false (S53), in the same commits: `http/hook.rs` 1-2, `inject/mod.rs` 1-5, `rules.rs` 76, `migrate.ts` 50, `registry.ts` 404, `unavailable.test.ts` 4, `docs/tasks/2026-11-02-content.md` D8 note
- `docs/conventions.md`: section 3 interception row (hook wired), section 8 content note; `docs/plans/2026-10-17-https-filtering.md`: slice 9 and 10 status notes, 5.6 item on validators, 5.7 on D11
- `engine/Cargo.lock` only if the lock moves. No new dependency is expected in any of this

## Offline acceptance

Tests over the path run in both arms (duplex and loopback, `arms!`), and both `h1` and `h2` (`BOTH`), through `tls::intercept`'s rig with `opts.hook = ContentHook`. Each name must exist and pass. Red first where marked (S9): temporarily disable the rule under test and say so in the report.

**Wiring (`http/tests.rs`, `inject/content.rs`)**
- [ ] `content_off_leaves_every_byte_and_header_alone` (real hook, switch off, HTML page with `Content-Length`: length stands, body identical, `Accept-Encoding` unchanged at the origin) (red first)
- [ ] `content_on_injects_before_the_meta_csp_for_each_encoding` (identity, gzip, deflate, br, zstd: style and script first, CSP header holds the nonce, no `Content-Encoding` or `Content-Length`)
- [ ] `global_switch_off_rewrites_nothing`, `content_needs_a_document_rule_to_rewrite` (no rules for the page: unchanged, not decoded)
- [ ] `an_iframe_response_is_injected`, `a_script_response_is_not` (D4) (red first)
- [ ] `a_server_sent_stream_is_not_held` (`text/event-stream` head arrives before any body byte: `wants` false)
- [ ] `a_cap_breach_resets_the_stream` (gzip bomb: RST_STREAM on h2, close on h1; the next h2 stream works)
- [ ] `a_truncated_gzip_page_resets_rather_than_ending_clean`
- [ ] `switching_content_off_applies_to_the_next_response` (snapshot swap mid-connection)
- [ ] `the_hook_is_what_build_interception_wires` (source-level law or a constructor test: production is not `NoRewrite`)
- [ ] `meters_count_rewrites_and_resets`, `status_json_content_holds_no_host`

**Gaps**
- [ ] `content_gzip_tail_does_not_reset_the_page` (D9, F1)
- [ ] `sieve-filter`: `document_with_a_hide_option_keeps_its_network_exception` (table: `$document,elemhide`, `$doc,ehide`, `$document,generichide`, `$document,specifichide`; on `check_host` and on `check_request` by initiator; `$important` still beats them) (red first: F2 is the repro)
- [ ] `a_hide_option_with_a_type_keeps_that_type_only` (`$elemhide,script` opens scripts, not images)
- [ ] `a_hide_exception_alone_opens_no_network`, `network_halves_keep_their_list_and_their_written_text`, `network_halves_do_not_shift_a_later_lists_provenance`, `page_exception_lines_count_once`

**User and lists (`cosmetic.rs`)**
- [ ] `a_users_hide_rule_reaches_the_page`, `a_users_document_exception_empties_the_page`, `a_users_elemhide_cuts_the_lists_css_and_keeps_scriptlets`
- [ ] `a_users_unhide_cuts_a_lists_selector_generic_and_specific`, `a_lists_document_exception_keeps_the_users_rules`
- [ ] `a_users_scriptlet_exception_drops_the_lists_scriptlets_there_only` (red first)
- [ ] `a_users_own_scriptlet_stays_inert_for_now` (pins the deferral)
- [ ] `no_user_rules_shares_the_lists_stylesheet` (`Arc::ptr_eq`)

**Request and head**
- [ ] `readable_accept_encoding_table` (`gzip, deflate, br, zstd, dcb, dcz`; `*`; `identity;q=0`; `br;q=1.0, gzip;q=0.8`; empty)
- [ ] `accept_encoding_is_narrowed_for_pages_only` (origin echoes it: document and iframe narrowed; script unchanged; content off unchanged)
- [ ] `a_rewrite_removes_exactly_the_headers_it_falsifies`, now with `etag` and `last-modified` gone (D6)
- [ ] `a_304_passes_through_untouched`

**Switch and laws**
- [ ] `the_policy_without_content_loads_and_serializes_without_it`, `sieve-ipc` round trip with `content: true`
- [ ] Law 11: both switches unavailable; law 4: `filtering.content` defaults off, names `live_content_injects_into_test_page`, which is an ignored Rust test, and requires `filtering.https`
- [ ] Controller: `wantedPolicy` sends `content: false`, and a status without the field reads the same (`engine-controller.test.ts`); settings search, export and reset ignore it (`unavailable.test.ts` mechanism, real key)
- [ ] `engine/tests/no_site_names.rs`: `engine_source_names_no_site`, `every_declared_exception_still_occurs`, `the_scanner_catches_a_site_and_skips_reserved_names_and_field_access` (red first: remove one exception row)
- [ ] `catalogue`: `arms_differ_exactly_by_the_gated_lists`, `defaults_follow_the_plan_table` unchanged and green

**Script**
- [ ] `tests/laws/youtube-live.test.ts`: importing the module starts nothing (spawn recorders record zero); `armLists` against the fixture gives the catalogue's rows in each arm; `videoVerdict` table (advancing and clean: pass; ad state seen: fail; time stuck: fail; never played: unplayed); `runVerdict` (10 passes: pass; 9 played: inconclusive; wrong issuer: inconclusive; `h3`: inconclusive; no payload: inconclusive); `parseArgs` refuses unknown browser or arm; the file holds no engine path but `status.json`
- [ ] `node --check scripts/live/youtube.mjs` exits 0
- [ ] `engine-content.ps1` parses: `[System.Management.Automation.Language.Parser]::ParseFile` reports no errors. It is not run. Law 8 stays green

**Budget, evidence not gate:** `cargo run --release -p sieve-engine --example inject_bench` after the call change. Numbers go in the report, labelled in-process.

**Commands** (from the worktree; `pnpm install --frozen-lockfile --offline` first):
```
$env:CARGO_BUILD_JOBS='8'
cd engine
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --features relay-experiments,attribution-diagnostics -- -D warnings
cd ..
pnpm typecheck; pnpm lint; pnpm test
pnpm rust:test; pnpm rust:lint
node --check scripts/live/youtube.mjs
```
The feature clippy runs because `stack/` changes. `pnpm rust:*` runs because `sieve-ipc` changes. No browser e2e: no key becomes visible and no component changes; if one does, that is a finding, and the e2e goes through the lease as the stream rules say.

## UNVERIFIED: needs the user, live

None of these is run by this stream.

Under `live_content_injects_into_test_page`, `docs/live/engine-slice-9.md` (needs slice 6's check first, and Q1 for the scriptlet rows):
- **U1.** A user rule hides an element on `example.com` in Edge, Chrome and Firefox; the page source starts with the nonce'd elements; `status.json.content.rewritten` grew.
- **U2.** Real pages with a strict header CSP, a meta CSP and Trusted Types: the browser accepts the rewritten policy and our elements run and apply; no CSP violation is reported against the site's own scripts.
- **U3.** Which real scriptlets work under Trusted Types (plan 5.6 item 6), and uBO `world: 'ISOLATED'` entries in the main world.
- **U4.** Budgets on 20 fixed sites: page load, generic stylesheet size, main-thread p50 (over 5 ms triggers the token-filter step in 5.6), time to first byte 1 ms or less, 100 MB/s.
- **U5.** Real-list facts: skip counts, zero skipped exceptions in the default lists, how many lines F2's fix touches.
- **U6.** Firefox's reading of gzip tails (from memory of its source, unrun; content task). Browsers with `dcb`/`dcz` after narrowing.
- **U7.** Kill, reboot and uninstall tests (conventions section 0) with content on. Pages cached while it was on, after it is off (O3).
- **U8.** Service-worker-served pages are not injected (D4): how many, and what they lose. Plain `http://` pages are not injected either; slice 6 only intercepts TLS.

Under `docs/live/engine-slice-10.md` (needs slice 8, U1 and U2, a real bundle): `youtube.mjs` in both arms in Chrome, Edge and Firefox; the 5.7 day-one items; the video ids reviewed; the WebDriver BiDi driver against a real Firefox; results recorded in the plan; only then the default flip.

Static-only by construction: `engine-content.ps1` and `youtube.mjs`' drivers have never run.

## Ordered steps

Commit at each green point on `wf2-content-wire`, explicit paths, each message ending with the attribution line.

0. **Base.** `git merge main` in the worktree (O1), resolve `engine/crates/sieve-engine/src/control/mod.rs`, keep both sides. `pnpm install --frozen-lockfile --offline`. `cargo test --workspace` green before touching anything. Confirm `the_verdict_does_not_depend_on_the_chunk_size` is present.
1. **F2.** Failing test first, then `network_half`, `written`, list-text append. `cargo test -p sieve-filter`.
2. **`RuleSet::page_cosmetics`.** `UserGates`, `page_cosmetics_under`, `no_scriptlets`; existing `cosmetic::tests` unchanged and green.
3. **`inject`.** `begin(&RuleSet)` with test helpers, D6, `readable_accept_encoding`.
4. **`http`.** `is_page`, `prepare_request`, the serve call.
5. **Switch.** `Policy.content`, `DomainFilter.content`, `ContentMeters`, `list_hits`, `status.json.content`.
6. **`ContentHook`.** With the wiring tests, D9's test, `build_interception`.
7. **App side.** Registry, `CONTENT_SWITCH`, protocol, controller, laws 4 and 11. `pnpm typecheck; pnpm lint; pnpm test`.
8. **Live check.** `live_content_injects_into_test_page`, `engine-content.ps1`, `docs/live/engine-slice-9.md`.
9. **Site-name law.** Write it, fix what it finds, declare the rest. Do not widen the exception list without a reason in its row.
10. **Catalogue.** `ListArm`, `arm_lists`, `UBO_SLICE` wording.
11. **Script.** `youtube.mjs`, videos file, `youtube-live.test.ts`, `node --check`, `docs/live/engine-slice-10.md`.
12. **Docs.** Comments list above, conventions, plan status notes, results table. Bench. Full suites. Kill anything started.
13. **Report.** Evidence per checkbox, red-first notes, bench numbers, UNVERIFIED unchanged, every deviation named.

## Open questions

Decisions for the user:

**Q1. Where the real scriptlet bundle comes from** (content task Q1, still open; F8). Until it is answered no scriptlet runs on a real machine and slice 10 cannot pass. Default: option (a) there: the user runs `assemble-ubo.mjs` at a reviewed uBO tag and pins the hash. For the live run only, the runbook says edit `RESOURCE_PIN` on a local build and place the JSON as `lists\resources.json`. This stream adds no mechanism for it and does not choose a tag.

**Q2. Does the allowlist stop cosmetics?** `allowRule` is `@@||host^`, and its text promises only that connections go through, so an allowlisted site's pages still get hidden elements and scriptlets once content is on, as in uBO. AdGuard's allowlist turns everything off for that site. Default: keep it, text unchanged; the way to leave a site alone stays "Sites not decrypted" or a `$document` rule. Changing it means `@@||host^$document`, which also changes the network decision on what such pages load, so it should be decided before `filtering.content` is unlocked.

**Q3 (O3). A rewritten page cached by the browser outlives Sieve off.** With a `max-age`, the page still carries its injected style and scriptlets after Sieve is off, until it expires. The network is normal, so the top rule holds as written, but the page is not what the site sent. Default: leave `Cache-Control` alone, as AdGuard does, and read it in U7. The strict alternative is `no-store` on every rewritten document, which costs back-forward cache and repeat loads on every site.

For the orchestrator:

**O1. Merging main into this stream.** The brief branches from `wf2-tls`, which lacks main's a869fd6 (F6). Default: step 0 merges main, because wiring without it ships a reset on real pages. `git merge-tree` shows one conflict, `control/mod.rs`, that the eventual merge of `wf2-tls` hits anyway. If the orchestrator would rather merge `wf2-tls` into main first, step 0 becomes a plain `git merge main` with no conflict left. Tell the executor if neither is wanted; then at least a869fd6 must be cherry-picked.

**O2. `PROTOCOL` stays 3** (D1), following the wave's own precedent. Other wf2 streams adding policy fields should do the same, or one bump covers all at merge.

**Other streams:** `http/hook.rs` gains a defaulted method, `RequestFacts` gains `is_page`, `FlowBook` gains `list_hits`, `Meters` gains `content`. `wf2-quic` is a prerequisite of slice 10's live run only. `D13` may touch `flow/sni.rs` and `dns/` test strings: small, one-line, and any stream adding a real name there will fail the law at merge, which is its purpose.
