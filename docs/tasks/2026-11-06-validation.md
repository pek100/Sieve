# Task: slice 11, validation parity (CT, CRLite, upstream ECH)

Spec: `docs/plans/2026-10-17-https-filtering.md` 2.6, 2.9, slice 11, and the user's decision table at the top of that plan. Branch `wf2-validation`, worktree `F:\Projects\Code\Sieve\.claude\worktrees\wf2-validation`, based on `wf2-tls` 400f3ce. Read `docs/tasks/2026-11-06-tls.md` first: D2, D4, D5, D9 and D18 are what this builds on.

## Goal

With `filtering.https` on, an upstream chain must also pass two local checks before it is decrypted: Certificate Transparency under Chrome's policy against Chrome's signed log list, and CRLite as a hard-fail revocation source. The engine's own upstream hello uses ECH when the name's HTTPS record carries a config. Every failure of any of the three ends as a pass-through or a plain handshake, so the client judges the real server and no site breaks because of them.

Done means: the offline acceptance below passes, the runbook `docs/live/engine-slice-11.md` and its ignored `live_*` tests are handed over unrun, and missing data leaves the engine behaving as slice 6 does. No new switch (plan: "part of `filtering.https`"). `filtering.https` stays unavailable.

## Rules that bind this task

- No test reaches the internet. Tests use the recorded fixtures named below, in-memory data and loopback. Nothing in this stream downloads a log list or a filter: both arrive through `update::data_path`.
- No elevation, service, route, adapter, DNS setting, firewall, certificate store, Firefox policy, `E:\Sieve`, `ProgramData\Sieve` or AdGuard. Do not change `ENGINE_SLICE_6`, `unavailableUntil` or law 11. Do not change `flow::relay::relay_tcp`.
- Forwarded flows are never decrypted: nothing here runs before `decrypt` said Intercept with `upstream: None`.
- Offline tests never call `rustls-platform-verifier` (task D3 of slice 6).
- No hardcoded site names in engine source: the ignored `live_*` tests read their host from an environment variable, and the runbook names hosts.
- PowerShell for shell commands. `$env:CARGO_BUILD_JOBS='8'` before cargo. A paused cargo may just be the watchdog: rerun, do not kill.
- Nothing under `docs/` may hold an em dash (law 2).

## Findings, each observed while planning on 2026-11-06

Each changes the design, so each is stated before it is used. The planner made ordinary outbound HTTPS reads to get them (crates.io, Chrome's log list, Mozilla's settings server and one filter delta, one TLS handshake to read a certificate). No network setting was touched and no test does this.

| # | Finding | Evidence | Consequence |
|---|---|---|---|
| F1 | **Mozilla no longer publishes filter cascades, so the crate the spec names cannot read the published data.** `rust_cascade` 1.5.0 (last release 2023) refused a real published delta with `Parse("unknown version")`. `clubcard-crlite` 0.6.2 (2026-08, MPL-2.0) parsed the same file: 81 logs in coverage, 1019 issuers. Its source notes cascades use versions 0 to 2; the file starts with 3. | Spike, `20261030-1-default.filter.delta`, 203061 bytes | D6, Q1 |
| F2 | The collection `security-state/cert-revocations` holds, per channel, one full filter and about 39 deltas: `default` 6.0 MB plus 9.8 MB, `compat` 1.6 MB plus 5.4 MB. Deltas come every 12 h. | Settings server records, 2026-11-06 | D7, Q2 |
| F3 | A clubcard query needs the issuer's SPKI hash, the leaf's raw serial and the log id and timestamp of its SCTs. `NotCovered` and `NotEnrolled` mean no answer. | `clubcard-crlite` `query.rs`, `examples/query.rs` | D5, D6 |
| F4 | **rustls never asks for or exposes TLS-delivered SCTs.** The only trace in rustls 0.23.46 is the `ExtensionType::SCT` enum value. The verifier sees embedded SCTs (in the leaf) and the OCSP staple. | grep of `rustls-0.23.46/src` | D3: a site whose SCTs come only by TLS extension fails CT and passes through, which is safe |
| F5 | Chrome's policy as published: an embedded set needs SCTs from 2 distinct logs when the lifetime is at most 180 days and 3 above it; a non-embedded set needs 2; both need 2 distinct operators (entries of `operators`) and at least one SCT from a log `qualified`, `usable` or `readonly` at the check; a retired log counts only when the earliest SCT presented is before its `retired` timestamp. CT stops being enforced when `log_list_timestamp` is older than 70 days. | `googlechrome.github.io/CertificateTransparency/ct_policy.html` | D4 |
| F6 | Log list v3: top keys `version`, `log_list_timestamp`, `operators`; each operator has `logs` and `tiled_logs`; each log `log_id`, `key`, `state`, `temporal_interval`. Recorded list: states usable, qualified, readonly and retired all occur. `log_list.sig` is RSA-4096 PKCS#1 v1.5 with SHA-256 over the JSON bytes (verified; PSS refused). | Python witness on the recorded files | D2, D3 |
| F7 | The SCT signature recipe is right for a real certificate: 2 of 2 SCTs of the recorded leaf verified against the recorded list over `version 0, type 0, timestamp, entry type 1, SHA-256(issuer SPKI), u24 len, TBS without the SCT extension, u16 len, extensions`. The stripped TBS is 704 bytes, the full one 968. | Python witness with `cryptography`'s own `tbs_precertificate_bytes` | D3 and the recorded test |
| F8 | rustls has the client half of ECH only. Its server has none, so no local server can accept ECH. A rustls server simply ignores the extension, which the client reads as rejected. | `rustls-0.23.46/src/client/ech.rs`, no server module | Accepted ECH is live only (U3). Everything else is tested offline |
| F9 | On rejection rustls fails the connection with `PeerIncompatible::ServerRejectedEncryptedClientHello`. Today `handshake` maps any rustls error to `Protocol`, which is cached for 24 h as a fact about the server. | `ech.rs` 863, `tls/upstream.rs` 162 | D10: must not reach that arm |
| F10 | With ECH rejected, the certificate is for the public name, and `CapturingVerifier` asserts everything. So retry configs from that server are unauthenticated, and the captured chain is not the host's. | `tls/upstream.rs` 74 | D10: retry configs are not used, and the chain is dropped |
| F11 | `dns::parse` keeps addresses and CNAMEs only. Nothing reads HTTPS records. The branch `wf2-dns-extras`, started at the same commit, is expected to own ECH stripping and may add a reader. | `dns.rs` 309, slice 6 F9 | D9 and the cross-stream note |
| F12 | `RootCertStore` trust anchors hold the SPKI **without** its outer SEQUENCE, while the hash CT and CRLite use is over the full SPKI. A leaf issued directly by a root would hash wrongly unless rewrapped. | `rustls-pki-types` `TrustAnchor` | D5 and test `issuer_hash_of_an_anchor_is_over_the_full_spki` |

## Recorded fixtures, committed with this plan

The executor cannot be assumed to have network, so these were recorded once and are committed. Tests inject `now`, so they do not rot. `.gitattributes` marks them `-text`: a line-ending change in the JSON would break its signature.

| File (under `engine/crates/sieve-engine/`) | What | SHA-256 |
|---|---|---|
| `fixtures/validation/log_list.json` | Chrome's list, `log_list_timestamp` 2026-11-05T13:36:08Z | `e7930ddd50db8f2f99ad43a331fef94cd76234b1dde6a589b77a446d9783fa17` |
| `fixtures/validation/log_list.sig` | Its signature | `12aa99a486bc5751e519ae03e086ecc49a9bd5e05217e160e515c2b94ff833f6` |
| `fixtures/validation/leaf.der` | A public leaf, lifetime 89 days, 2 embedded SCTs from 2 operators, both logs usable | `bf23019b282d3c79eaf5f0688479ec4561d390a827b61b44ce6d5dcb5b7d10f3` |
| `fixtures/validation/issuer.der` | Its issuer | `97658de8c68dfa98ace1e5028a63d54a1aae911b3e21471076c6850cd08cbab4` |
| `data/ct-log-list-pubkey.der` | Chrome's log list key, SPKI DER, compiled in with `include_bytes!` | `f1d8b68e50210d8e73d9a3e97f571773c52d7f28c0b1a71beee81d8562e6fd85` |

## Design decisions

**D1. The stack gains one local step, between eligibility and trust.** `Verifier::verify` becomes:
1. eligibility, as today;
2. `Validation::check(chain, now_ms)`: CRLite, then CT, both local and inline;
3. trust, unless the same leaf is already known.

Reasons: a private root never reaches CT, which is plan 2.6's "chains to public roots only" by order, with no second test. Revoked comes first so a revoked and non-compliant chain still closes open flows. Steps 2 run **even for a known leaf**: they cost microseconds, and a filter that arrived an hour ago must reach a host visited all day. A `Revoked` on a known leaf takes the existing path in `intercept.rs` (`put`, then `close_host`), which needs no change.

`Verifier::new` gains a required `Arc<ValidationSlot>` and `verify` a required `now_ms` from `Interception.clock` (S15). They are required arguments, not optional ones (S47): a missed caller fails to compile. Existing tests pass `ValidationSlot::default()`, which holds no data.

**D2. One envelope, two signatures, for the log list.** `Kind::List("ct-logs")` at `update::data_path` is `u32 LE signature length, signature, JSON`. The minisign signature was checked by the update cycle before the file got there. The Google signature is checked here at load, against the compiled-in key. Reasons: the spec asks for the signed list; the timestamp that decides staleness is then signed by Chrome's key, and a leak of Sieve's update key cannot add a log. Anything refused means no list. No download path exists in this stream.

**D3. `tls/ct.rs`, pure, no clock, no I/O.**
- `LogList::from_envelope(bytes, key)` then `LogList::parse(json)`: a map from log id to operator index, key and state, over both `logs` and `tiled_logs`. A state this build does not know makes the log count for nothing. Unknown JSON fields are ignored, since Google adds them. A list with no usable log is refused.
- `precert_tbs(leaf_der)`: the TBS with the SCT extension removed and every enclosing DER length rewritten, order kept. Two small functions over raw DER, bounded by the input, no panic on hostile bytes.
- `sct_message(...)`: the signed bytes of F7, entry type 1 for embedded and 0 (the full certificate) for stapled.
- `scts_of(leaf)` through x509-parser's `ParsedExtension::SCT`. `stapled_scts(ocsp)`: a DER walk from the OCSP response to `1.3.6.1.4.1.11129.2.4.5` in the single response, then `parse_ct_signed_certificate_timestamp_list`. The staple's own signature is not checked, because each SCT signs the certificate itself. x509-parser has no OCSP reader and one extension does not justify a new crate.
- Signature check: `aws_lc_rs::signature::UnparsedPublicKey` with `ECDSA_P256_SHA256_ASN1` or `RSA_PKCS1_2048_8192_SHA256`, chosen by the SCT's algorithm bytes, the one crypto provider (plan 2.7). A bad signature, an unknown log, a wrong version or a timestamp after `now` means that SCT does not count; nothing else follows from it.
- `policy(verified, lifetime, list, now) -> CtAnswer`, in the shape of F5, as one pure function over verified `(log, timestamp, delivery)`.

```rust
pub enum CtAnswer { Compliant, Violates, Skipped(CtSkip) }
pub enum CtSkip { NoList, StaleList }
```

Declared and annotated: `MAX_LIST_AGE_MS` (70 days, Chrome's), `SHORT_LIFETIME_DAYS` (180), `SCTS_SHORT` (2), `SCTS_LONG` (3), `SCTS_STAPLED` (2), `MIN_OPERATORS` (2). No threshold for "the certificate predates CT" as AdGuard has (E7): no certificate issued before Chrome's 2018 date is still in date, so it could not fire (S52). `temporal_interval` is not checked: the published policy does not ask for it and a log would not have issued outside it. The `previous_operators` wording of F5 is not built: the recorded list has no such field on any log; a log that gains one is judged by its present operator, and the failure mode is a pass-through.

**D4. A stale or absent list is refused, and CT is then skipped.** Plan 2.6 and Chrome agree: past 70 days Chrome stops enforcing too, so the skip is not weaker than the browser. A list dated in the future is fresh: it is signed, and a wrong local clock already makes other things fail in the safe direction. A `Violates` becomes a new verdict with its own word, so the log says why:

`UpstreamVerdict::NoTransparency` maps to `Floor::UpstreamTransparency`, slug `floor:upstream-ct`, added to `Floor::ALL` and the reachability law in `sieve-filter/src/exclusions.rs`. It is cached like `Invalid` (D5 of slice 6). `reasonWords` shows an unknown slug with spaces, so no TS change and no protocol change.

**D5. The issuer comes from the path eligibility accepts.** `Validation::check` needs the issuer SPKI hash for both checks. It calls `webpki::EndEntityCert::verify_for_usage` through a direct dependency on `rustls-webpki` (already in the lock at 0.103.16), with the same roots and `provider().signature_verification_algorithms.all`, and reads `VerifiedPath::intermediate_certificates().next()`, else `anchor()`, rewrapping the anchor's SPKI (F12). TENSION (S51, recorded at the code): the path is built twice per new connection, because `WebPkiServerVerifier` does not hand it over. Rebuilding eligibility on `webpki` directly would remove the second build and rewrite slice 6's tested error mapping; not worth it without a measured cost. `bench_validation_local_checks` reports it. If no path is built here though eligibility passed (it cannot happen by construction), the answer is `Skipped`, and the trust call still runs.

**D6. `tls/crlite.rs` over `clubcard-crlite`, not `rust_cascade`.** F1 settles it: the named crate would produce a check that can never load real data, and the plan's own reason for CRLite is parity with Firefox. See Q1. Default features (`bincode` for V3, `sha2`). `builder` in dev-dependencies only, so tests make real filters. Resolver 3 keeps it out of the production build.

`Crlite::from_bundle(bytes)`, then `Crlite::is_revoked(issuer_hash, raw_serial, embedded_scts) -> bool`: true when any filter says `Revoked`, the rule for a full filter plus deltas, since a revocation stays revoked. `Good`, `NotCovered` and `NotEnrolled` all mean false, and the stack carries on to the OS. Embedded SCTs only, as Firefox and the crate's example do.

**No age limit on the filter.** CRLite here only ever adds "revoked". A certificate issued after the filter was built has SCT timestamps outside coverage, so the answer is `NotCovered`, not a guess. An old filter misses new revocations, and CryptoAPI is still asked. So an age dial would guard nothing (S52). A positive `Good` does not skip the OS call in this stream; that saving belongs after Q3 of slice 6 is decided live.

**D7. The bundle, `Kind::List("crlite")`:** repeated `u32 LE length, clubcard bytes`, full filter first, then deltas in order, from the `default` channel (Firefox's default; assumption, F2). One broken filter refuses the whole bundle at load: one normalizer per boundary. The file is capped at `MAX_BUNDLE_BYTES` 64 MiB when read; the signed index's `size` already caps the download.

**D8. `tls/validation.rs`: the slot.** `ValidationSlot(RwLock<Arc<ValidationData>>)`, in the form of `FilterSlot`, holding `Option<LogList>`, `Option<Crlite>` and the two files' modified times.
- `reload(engine_dir)` reads a file only when its time changed, parses off the runtime (`spawn_blocking`), and swaps. A refused new file keeps what was loaded: signed data that was good stays good, and the refusal is counted.
- Called from `sync_https` when interception is built and from the hourly wake in `refresh_exclusions` (`control/routing.rs`). No new task and no new timer.
- `check` reads one snapshot and returns a `Checked { verdict: Option<UpstreamVerdict>, ct: CtAnswer }`. It holds no lock across anything.

Nothing here can fail a flow: no data, broken data or a panic-free parse failure all reach step 3 as today. This is the top rule for this stream: **validation can only move a flow from intercept to pass-through**, and a pass-through is the client's own connection to the real server.

**D9. `tls/ech.rs`: an active lookup behind a cache.**
- `Message` in `dns.rs` gains one additive field, `https: Vec<HttpsRecord { priority, ech: Option<Vec<u8>>, ttl }>`, read in `parse`'s existing answer loop for `TYPE_HTTPS` (65), with `ech` param key 5 read from the SvcParams, bounded. It uses the same owner-and-CNAME walk as addresses: only the question's chain counts. AliasMode (priority 0) gives no config and is not followed. Lowest priority with a config wins.
- `Service::https_records(name)`: builds a query and goes through the existing `resolve`, so it is encrypted, or LAN for a matched suffix, and never plain beyond that.
- `EchCache`: `Lru` keyed by host (`crate::lru`, capacity `ca::LEAF_CACHE_SIZE`), with one lookup per host in flight, run on its own task so a waiter that gives up still fills the cache. A found config lives for its TTL, clamped to `[MIN_TTL 60 s, MAX_TTL 1 h]`; no config for `NEGATIVE_TTL` 5 min; a failed lookup for `FAILED_TTL` 30 s.
- A flow waits at most `ECH_LOOKUP_WAIT` 300 ms, then goes on without ECH. Port 443 only: another port's record lives under `_port._https`, which is not built (S35).
- The source behind the cache is a trait, `EchLookup`, so tests inject one; production holds the engine's `Service`. `Interception` gains the required field `ech: Arc<EchCache>`.

No tap on the browser's own HTTPS queries. It would make a first connection cheaper but it is an optimisation with no measurement behind it, and it sits exactly where the stripping stream will edit. U5 measures the cost, and the tap is the follow-up if it matters.

**D10. The handshake with ECH.** `handshake` gains `ech: Option<&EchConfig>`. `client_config` uses `.with_ech(EchMode::Enable(..))` in place of `with_safe_default_protocol_versions` (TLS 1.3 only, which any server publishing a config speaks), with `aws_lc_rs::hpke::ALL_SUPPORTED_SUITES`. A config list rustls cannot use (`EchConfig::new` errs) counts as no config.

An attempt with ECH that ends in anything but `Done` returns the new `HandshakeEnd::EchFailed`, under `ECH_HANDSHAKE_TIMEOUT` 3 s. That includes a rejection, a reset, a timeout and a certificate request. Then:
- the captured chain is dropped, never judged (F10), and no verdict is cached (F9);
- the cache marks the host `NEGATIVE_TTL`;
- `intercept.rs` step 4 dials a fresh socket through `Dial` and runs the plain handshake once. The rest of the path is unchanged. A failed dial is `Unavailable`, which ends in `fresh_splice`.

Retry configs are not used (F10). The cost: an active attacker can force the real SNI onto the wire. The hello it forces is the one the browser would have sent with ECH stripped (plan 2.9), and a pass-through would show it too. Forgoing a retry keeps the rule "a failure never breaks a site" over a stronger privacy property we cannot authenticate with a capturing verifier. No GREASE when there is no config: plan 2.9 asks only for use, and it would change the fingerprint with nothing gained.

**D11. Evidence without a disk log, as slice 6's D18.** `HttpsMeters` gains counts only: `ct_compliant`, `ct_violating`, `ct_skipped_no_list`, `ct_skipped_stale`, `crlite_revoked`, `validation_refused` (files), `ech_offered`, `ech_accepted`, `ech_failed`. `status.json.https` also reports `ct_list_timestamp` and `crlite_filters`. No host. No IPC field, no protocol bump, no UI, no browser e2e.

**D12. The offline tool that makes the two artefacts.** `engine/crates/sieve-engine/examples/validation_bundle.rs`: from local files only, writes the envelope and the bundle using the crate's own `encode` functions (one owner of each format, round-tripped in tests), and checks the log list signature before writing. No network. The user signs the output with the procedure of `docs/live/updates.md`, which gets a short section with `kind=list:ct-logs` and `kind=list:crlite`.

### Design gate (S48 to S52)

- Instances of existing laws: a verdict in the existing verifier stack; a floor reason in `decrypt`; signed data at `update::data_path`, as `lists::resources` reads it; counts on `HttpsMeters`.
- New primitives: the two chain checks and the ECH lookup. The basis cannot express them, and the plan names them.
- New dials are all declared with a reason above. Rejected as inert: filter age, CT predates-threshold, `temporal_interval`, a new switch, a `rust_cascade` path.
- Made redundant: nothing retires. Q3 of slice 6 weakens: if the engine's OCSP fetches turn out refused by the loop guard, CRLite still catches revocations. U4 records this.

## Files

New:
- `engine/crates/sieve-engine/src/tls/{ct,crlite,ech,validation}.rs`
- `engine/crates/sieve-engine/examples/validation_bundle.rs`
- `engine/crates/sieve-engine/fixtures/validation/*`, `engine/crates/sieve-engine/data/ct-log-list-pubkey.der` (committed with this plan)
- `docs/live/engine-slice-11.md`

Changed, small and additive:
- `engine/crates/sieve-engine/src/tls/mod.rs` (modules, header), `tls/upstream.rs` (`Verifier`, `handshake`, `client_config`, `HandshakeEnd`), `tls/intercept.rs` (field, step 4, the two `verify` calls)
- `engine/crates/sieve-engine/src/tls/tests.rs` (harness fields; new scenarios appended)
- `engine/crates/sieve-engine/src/dns.rs` (`Message.https`, `TYPE_HTTPS`), `dns/service.rs` (`https_records`)
- `engine/crates/sieve-engine/src/stack/mod.rs` (`HttpsMeters`)
- `engine/crates/sieve-engine/src/control/routing.rs` (`build_interception`, `sync_https`, `refresh_exclusions`), `control/mod.rs` (the test's `Interception`)
- `engine/crates/sieve-filter/src/exclusions.rs` (D4)
- `engine/crates/sieve-engine/Cargo.toml` (`clubcard-crlite = "0.6"`, `rustls-webpki = "0.103"`, dev `clubcard-crlite` with `builder`), `engine/Cargo.lock`
- `docs/conventions.md` (seam row), `docs/live/updates.md`, `docs/live/engine-slice-6.md` ("Not here" line), `docs/plans/2026-10-17-https-filtering.md` (dated notes on 2.6, 2.9 and slice 11, including the rust_cascade finding)

## Offline acceptance

Every test name below must exist and pass. Scenarios through `tls::intercept::run` use the `arms!` macro (duplex and loopback), as slice 6 does.

**CT, recorded**
- [ ] `recorded_list_signature_verifies`, `a_tampered_list_is_refused` (one byte), `a_wrong_key_is_refused`
- [ ] `recorded_leaf_scts_verify_against_recorded_list`: the real positive, both SCTs counted
- [ ] `recorded_leaf_is_compliant`, with `now` = list timestamp + 1 day
- [ ] `precert_tbs_of_the_recorded_leaf_is_704_bytes_and_lacks_the_extension` (F7's witness), `precert_tbs_refuses_hostile_der` (proptest: arbitrary bytes and every truncation of the leaf; no panic)
- [ ] `a_changed_byte_in_the_leaf_stops_its_scts_counting`: the control, without which the positive could be vacuous
- [ ] `recorded_list_at_exactly_70_days_is_used_and_one_ms_later_is_skipped`
- [ ] `no_list_is_skipped`

**CT, policy table** (pure `policy`, one row per case, list built in the test)
- [ ] `policy_table`: 2 embedded from 2 operators, 180 days: compliant; 2 at 181 days: violates; 3 at 181 days: compliant; 2 from one operator: violates; the same log twice counts once; 1 usable plus 1 retired with earliest SCT before retirement: compliant; earliest after it: violates; 2 retired only: violates; `rejected`, `pending` and an unknown state count for nothing; a timestamp in the future counts for nothing; `tiled_logs` count as logs; 2 stapled: compliant at any lifetime; 1 stapled plus 1 embedded where neither set alone suffices: violates
- [ ] `unknown_log_and_bad_signature_do_not_count`, `unknown_state_and_unknown_fields_do_not_refuse_the_list`, `a_list_with_no_usable_log_is_refused`
- [ ] `stapled_scts_are_read_from_a_built_ocsp_response`, `stapled_walk_refuses_hostile_der` (proptest)

**CRLite** (filters made with the crate's `builder`, in the shape of its own tests, MPL header kept on anything copied)
- [ ] `a_revoked_serial_is_revoked_and_a_good_one_is_not`
- [ ] `not_covered_and_not_enrolled_are_no_answer` (a timestamp outside coverage, an issuer not in the filter)
- [ ] `no_embedded_scts_is_no_answer`
- [ ] `a_delta_can_revoke_what_the_full_filter_calls_good`
- [ ] `the_bundle_round_trips_v3`, `one_broken_filter_refuses_the_bundle`, `an_oversized_length_refuses_the_bundle` (no large allocation), `an_empty_bundle_is_no_filter`
- [ ] `a_cascade_file_is_refused_not_misread`: version byte 2

**The stack, through `Verifier`**
- [ ] `unknown_root_never_reaches_validation` (a chain with no SCTs, the data loaded: `NonPublicRoot`)
- [ ] `revoked_beats_ct_violation`, `ct_violation_gives_no_transparency_and_never_asks_trust`
- [ ] `compliant_chain_asks_trust_once`, `known_leaf_still_runs_local_checks_and_skips_trust`
- [ ] `no_data_behaves_as_slice_6` (fake trust called; verdict `Eligible`)
- [ ] `issuer_hash_of_an_intermediate_matches_the_recorded_issuer`, `issuer_hash_of_an_anchor_is_over_the_full_spki` (F12), `issuer_is_found_when_the_server_sends_the_chain_out_of_order`

**The slot**
- [ ] `reload_reads_through_data_path`, `a_refused_new_file_keeps_what_was_loaded`, `an_unchanged_file_is_not_parsed_again`, `missing_files_mean_no_data_and_no_error`
- [ ] `the_tool_output_loads` (`validation_bundle`'s encoders into `from_envelope` and `from_bundle`)

**End to end through `tls::intercept::run`** (a helper makes an rcgen leaf with SCTs from an in-memory log: a first pass gives the TBS, a second carries the SCT extension, and `precert_tbs` of the second must equal the first's TBS)
- [ ] `ct_violation_passes_through_with_client_hello_intact`, log row `floor:upstream-ct`
- [ ] `ct_compliant_chain_is_intercepted`, the control
- [ ] `stale_list_intercepts_and_counts_skipped`
- [ ] `crlite_revoked_passes_through_and_closes_open_flows_to_that_host`
- [ ] `crlite_revocation_arriving_later_reaches_a_known_leaf`: reload between two connects
- [ ] `ct_violation_is_cached_and_skips_the_next_handshake`
- [ ] `forwarded_flow_runs_no_validation_and_no_ech_lookup`, `pass_through_by_floor_runs_no_ech_lookup`

**`decrypt`** (`sieve-filter`)
- [ ] `every_pass_reason_is_reachable_and_has_a_slug` still green with the new reason; `no_list_input_yields_intercept_for_a_floor_fact` covers it

**ECH**
- [ ] `https_record_table` in `dns.rs`: a service record with `ech`; lowest priority with a config wins; AliasMode gives none; a record on the CNAME chain counts; a record on an unrelated owner does not; other params around key 5; an error reply and a truncated reply give none
- [ ] `https_record_parse_refuses_hostile_bytes` (proptest; no panic; the existing address tests unchanged)
- [ ] `lookup_goes_through_the_encrypted_upstream` (`dns::testing` loopback server; the plain path untouched)
- [ ] `cache_holds_for_the_clamped_ttl`, `no_config_is_remembered_negative`, `failed_lookup_is_remembered_briefly`, `one_lookup_per_host_in_flight`, `a_slow_lookup_lets_the_flow_go_and_still_fills_the_cache`, `port_other_than_443_does_not_look_up`
- [ ] `ech_hello_hides_the_real_name`: the bytes a recording stream saw decode through `flow::sni` to the public name with `ech` set, and the real name appears nowhere in them. The config list is built in the test with a real X25519 key
- [ ] `rejected_ech_retries_plain_on_a_fresh_socket_and_intercepts`: a rustls server ignoring the extension (F8); the first connection's chain is for the public name and is not judged; the second connection gets the real name; verdict `Eligible`, not `Protocol`
- [ ] `rejected_ech_caches_no_verdict_and_marks_the_host_negative`
- [ ] `ech_reset_and_ech_timeout_retry_plain`
- [ ] `failed_retry_dial_closes_the_app_side_and_the_book_says_failed`
- [ ] `no_config_offers_no_ech` (the hello has no extension: no GREASE)
- [ ] `a_config_rustls_cannot_use_is_no_config`
- [ ] `ech_changes_nothing_about_the_key_exchange_order`: with ECH offered the outer hello still lists X25519MLKEM768 first

**Offline evidence, not gates**
- [ ] `#[ignore] bench_validation_local_checks`: time of `Validation::check` per connection, on the recorded leaf with a builder-made filter. Numbers in the report, labelled in-memory.

**Commands** (from the worktree; `pnpm install --frozen-lockfile --offline` first):
```
cd engine
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p sieve-filter exclusions
cargo test -p sieve-engine tls::
cargo test -p sieve-engine dns::
cd ..
pnpm typecheck; pnpm lint; pnpm test
pnpm rust:test; pnpm rust:lint
node scripts/check-relay-experiments.mjs 4328141e068a6e776e699196eb62802f9c8508f2
```
`pnpm rust:*` runs because `sieve-filter` changes and src-tauri compiles against it. The feature-flag clippy is not needed unless `stack/relay.rs` changes; it should not. `pnpm e2e` is not needed: no UI changes. Law 11 stays green with `filtering.https` hidden.

## UNVERIFIED: needs the user, live, under `docs/live/engine-slice-11.md`

None of these is run by this stream. They follow slice 6's route (`scripts/live/engine-ca.ps1`, app closed), need slice 6's own live check to have passed first, and need the two artefacts on disk, signed (Q2). Ignored tests: `live_ct_violating_endpoint_passes_through`, `live_crlite_revoked_passes_through`, `live_upstream_ech_used`, host from `SIEVE_LIVE_HOST`.

- **U1.** A CT-violating endpoint (badssl.com's `no-sct`) shows its real issuer, with the log row `floor:upstream-ct`. A normal public site still shows Sieve's issuer, and `ct_compliant` grew.
- **U2.** A CRLite-revoked certificate passes through with `crlite_revoked` grown. Run the artefact's filters through the crate's `query` example first to pick an endpoint actually in them.
- **U3.** Accepted ECH (F8): Cloudflare's trace page, `https://crypto.cloudflare.com/cdn-cgi/trace`, reports `sni=encrypted` through Sieve, and `ech_accepted` grew. No local test can show this.
- **U4.** Revocation without the OS: repeat slice 6's U5 and note whether a CRLite hit stands when `own_refused` shows the OCSP fetch refused.
- **U5.** Cost: added time on a first connection to a new host (the lookup and the second path build) and on a repeat one, against the 2 ms budget of plan section 6. Decides the DNS tap of D9. `ECH_LOOKUP_WAIT` and `ECH_HANDSHAKE_TIMEOUT` are tuned here.
- **U6.** How many hosts fall to `floor:upstream-ct` on the fixed 20-site set of U11 of slice 6. A large number means a policy reading is wrong or SCT-by-TLS (F4) is commoner than assumed.
- **U7.** Memory and load time with the real 16 MB bundle, against the 300 MB budget. Whether `compat` would be enough.
- **U8.** A real ECH server rejecting a stale config: the site still loads.
- **U9.** Whether a real full filter in the `default` channel is V3 or V4 on the day: the crate reads both; the delta seen today was V3.
- **U10.** Kill, reboot and uninstall tests of `docs/conventions.md` section 0 with all three active. Nothing here adds system state, so they should match slice 6's result; they are still the user's to run.
- **U11.** The real update cycle delivers `list:ct-logs` and `list:crlite` end to end, and the engine picks them up within the hourly wake.

## Ordered steps

Commit at each green point on `wf2-validation`, each message ending with the attribution line.

1. **Dependencies and probes.** Add the crates, resolve the lock. Write `recorded_list_signature_verifies` and `recorded_leaf_scts_verify_against_recorded_list` against aws-lc-rs first: whether `UnparsedPublicKey` takes SPKI DER or needs the inner key is settled here. Run the F1 refusal once as `a_cascade_file_is_refused_not_misread`. If a finding is false, stop and update the D-numbers.
2. **`ct.rs`.** `precert_tbs`, `sct_message`, `LogList`, `policy`, stapled walk, with the recorded and table tests.
3. **`crlite.rs`.** Bundle codec, query, builder-made tests.
4. **`validation.rs`, `Floor`, `UpstreamVerdict`.** Slot, reload, issuer path, `sieve-filter` change and its laws.
5. **`Verifier`.** The step in `verify`, the required arguments, meters. All existing `tls::` tests green unchanged apart from the new arguments, which shows off is slice 6.
6. **Wiring.** `build_interception`, `sync_https`, `refresh_exclusions`. The end-to-end CT and CRLite tests, with the SCT-bearing rcgen helper.
7. **`dns.rs` and `service.rs`.** `HttpsRecord`, `https_records`. Before writing it, read `wf2-dns-extras`' current state (see the note below).
8. **`ech.rs` and the handshake.** Cache, `EchLookup`, `EchFailed`, step 4 and the retry. The ECH tests.
9. **Tool, runbook, ignored tests, docs.** `validation_bundle`, `docs/live/engine-slice-11.md`, `docs/live/updates.md`, plan notes, conventions row, S53 sweep (`tls/mod.rs` header, `upstream.rs` header, slice 6 runbook's "Not here").
10. **Bench and full suites.** All commands above.
11. **Report.** Evidence per checkbox, bench numbers, UNVERIFIED unchanged, every deviation named.

## As built (2026-11-06)

Every D-number holds. What the build settled or added:

- Step 1: `UnparsedPublicKey` takes SPKI DER for both `RSA_PKCS1_2048_8192_SHA256` and `ECDSA_P256_SHA256_ASN1`, so keys are passed as the list holds them. F1, F7 and F12 held when rerun as tests.
- `CtSkip` has a third value, `NoIssuer`, for D5's "cannot happen by construction" case, which had no honest word among the two. It has no meter.
- With no usable data the path is not built at all, so no data costs what slice 6 costs (`missing_files_mean_no_data_and_no_error`).
- A missing file means no data, also after a good one was loaded, so deleting a file takes a bad artefact back. Only a refused file keeps what was loaded. An empty bundle is zero filters.
- `issuer_hash_of_an_intermediate_matches_the_recorded_issuer`: the recorded issuer has no recorded root, so no path through it as an intermediate can be built. The test shows the leaf's direct issuer on a built path, and webpki's rewrap of the recorded issuer against x509-parser's bytes. Its SCTs verifying under that hash is the `ct` test.
- Meters live behind `ValidationSlot`, which holds the engine's `Arc<Meters>`; `Engine.validation` outlives the switch, so data loaded once stays across an off and on.
- Step 7: `wf2-dns-extras` held no SvcParams reader on 2026-11-06 (commit 3cf9784 and its worktree), so `Message.https` and `https_rdata` land here. Whichever merges second makes one reader of the two.

## Cross-stream note

`wf2-dns-extras` is expected to strip `ech` from answers (plan 1.4, 2.9) and so to read SvcParams too. Two readers of one format would break S29. Step 7 reads that branch first. If its reader exists, use its shape and add only what is missing; if not, `Message.https` lands here and the orchestrator tells that stream. Whichever merges second makes one reader of the two. This stream's lookup does not depend on stripping, and stripping does not depend on this: the engine's own query never passes through the strip, which acts on what goes back to a client.

## Open questions for the user

**Q1. `clubcard-crlite` in place of the named filter-cascade crate.** The brief and plan 2.6 say Mozilla's filter cascade. Mozilla has moved on: a real published file is refused by `rust_cascade` and read by `clubcard-crlite`, the crate from the same team and the one Firefox uses (F1). Default: `clubcard-crlite`, MPL-2.0 like `adblock-rust`, and the plan gets a dated note. The alternative of building cascades ourselves would mean running Mozilla's whole pipeline.

**Q2. Who publishes the two artefacts, and how often?** This is the real decision here. The brief routes data through `update::data_path`, so each file carries a minisign signature from your offline key (decision of 2026-10-18), but upstream changes constantly: the log list daily with a 70-day limit, CRLite every 12 h.
- Default: you run `validation_bundle` and sign by hand at a cadence you pick. CT is fine monthly. A CRLite signed weekly can be up to a week behind Firefox. That lag is safe, because the OS revocation check still runs.
- Consequence to accept: **until you publish, CT and CRLite are skipped on every connection**, and `status.json` says so (`ct_skipped_no_list`). `filtering.https` then behaves as slice 6 does, which is weaker on CT than Chrome. The stream does not block the switch on this; say if you want the unlock to require a list.
- Alternatives, not built: an online data-only signing key, which weakens the offline-key decision; or the engine fetching from Google and Mozilla directly, as plan 2.6 first said, verifying Google's signature and Mozilla's content signature, which is more code and more outbound requests from the engine.
