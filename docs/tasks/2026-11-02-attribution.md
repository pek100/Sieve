# Task: exact attribution (A1, A2, A3) and the "Virtual machines and WSL" group

Stream `attribution`, branch `wf-attribution`. Spec: `docs/plans/2026-10-18-slice-3-attribution-and-cpu.md` section 2 (A1, A2, A3) and section 6 decisions 1 and 2. Base: main at f0fe2cb. Sibling plan read: `docs/tasks/2026-11-02-domain-policy.md` on `wf-domain-policy` (D4, D14, D17, line 166).

## Goal

The live run scored 0.7955 against a gate of 0.95 of ALL new flows. The gate does not move. Every flow gets the most exact origin the machine can prove, and nothing is ever guessed.

Done means:

- A second exact PID source (ETW) names host sockets the owner tables cannot see. If the two sources disagree, the flow is unknown.
- A flow that matches a NAT session exactly on its whole tuple is reported as forwarded, never as a host app. It counts as attributed only when that match names its VM.
- The engine counts all-flows and host-only attribution, and every report shows both.
- Apps shows a "Virtual machines and WSL" group at the top once forwarded traffic has been seen. It has one row per named VM and one "Unidentified virtual machine traffic" row, each with a Sieve/Off switch and the note "Filtered by domain only".
- A diagnostic build (feature `attribution-diagnostics`) puts every flow in one of four categories and keeps the evidence for each unknown flow.

Sieve off, killed or uninstalled stays a normal network. Everything added here reads the system. Nothing is persisted, and a failed read costs attribution only, never routing.

## Evidence this plan rests on

Read on this machine, unelevated, 2026-11-05:

| Fact | Source | Consequence |
|---|---|---|
| `Microsoft-Windows-Kernel-Network`, GUID `7DD42A49-5329-4832-8DFD-43D979153A88`. Keywords IPV4 `0x10`, IPV6 `0x20`. | local manifest (`wevtutil gp`) | Pinned as constants. |
| Event 12 TCPv4 "Connection attempted", 28 TCPv6, 42 UDPv4 send, 58 UDPv6 send. All at version 0, all starting `PID u32, size u32, daddr, saddr, dport u16, sport u16`. `daddr`/`saddr` are `u32` on v4 and `Binary` on v6. Ports are `win:Port`. | `Get-WinEvent -ListProvider` templates | One decoder over the shared prefix, whatever follows it. |
| `MSFT_NetNatSession` has `Protocol`, `ExternalSourceAddress/Port`, `ExternalDestinationAddress/Port`, `InternalSourceAddress/Port`, `NatName`, `CreationTime`. | `Get-CimClass` | These are the exact fields of the match. |
| A real WSL NTP session: internal `172.17.83.30:36099`, external `198.18.0.1:62049`, destination `185.125.190.57:123`, protocol 17. | Codex `work\diagnostic-20261018-210112\matching-nat-sessions.json` | The flow's `local` on the TUN is the NAT's EXTERNAL source. The key is (protocol, external source, external destination). |
| `Microsoft-Windows-WinNat` (`66C07ECD-6667-43FC-93F8-05CF07F446EC`) has event 1001 "session created" and 1005 "session deleted", in two template versions, with internal and external socket addresses. | local manifest | A documented candidate for NAT state that `Get-NetNatSession` does not list (D7). |
| `Get-HnsNetwork`, `Get-HnsEndpoint` and `hnsdiag list all` answer Access denied without elevation. `Get-NetNatSession` gives 0 rows unelevated. | run here | HNS shapes and naming cannot be read offline: UNVERIFIED. |
| `net_snapshot` drops flows with no pid; `visible_to` hides `session: None`; the app has no Flows screen; `Policy` is `{revision, engine}`; the relay decides nothing yet. | code | D9 to D12. |

The Kernel-Network and WinNat fixtures are hand-built from these manifests, because recording needs an elevated session. Each fixture says so in its first field. L1 records real ones, and the tests must then pass on those too.

## Design decisions

**D1. Four categories, defined by exact evidence only.** A pure function in diagnostics:

| Category | Evidence |
|---|---|
| host attributed | a PID from the owner tables or ETW |
| forwarded exact NAT | a NAT session equal on protocol, external source and external destination |
| host unknown | no owner, but a row with this exact local tuple exists with PID 0 or several PIDs, or ETW and the tables disagree, or a table owner and a NAT match both answered. A host socket is proven; its owner is not. |
| unexplained | none of the above |

The four sum to `flows`, and a law checks it.

*Reason:* the spec names the four but not the line between the last two. This line needs no TTL.

**D2. TTL and TCP fingerprints are recorded and never read by any decision.** The spec says the TTL "only selects which exact check to run next". The NAT check is cheap enough to run on every miss, so no selector is needed. That removes the one path by which a spoofable field could steer attribution (S24, S52). Fingerprints exist only behind the feature, as raw values (S4), with no "decremented" verdict computed.

**D3. NAT matching is production code; only its evidence recording is feature-gated.** A3 needs it in the shipped build, so the feature keeps its meaning: "never changes an attribution decision". A1's gated part is the fingerprints, the category report, the samples and the raw event capture.

**D4. NAT is consulted on an owner miss, not on every flow.**

- After `Owner::Unknown` (the existing 250 ms give-up), the relay asks for a fresh read, rate limited to one per `NAT_REFRESH_MIN_MS` (250) and bounded by `NAT_READ_TIMEOUT_MS` (1000; a timeout adds no new match, the flow gets what the last finished read holds, and it is counted).
- All reads run on one dedicated thread, which owns its COM apartment. Flow tasks wait on a reply channel and never block a runtime worker.
- Flows share reads: a flow joins the last read asked for if that read started no earlier than its own first lookup, otherwise it asks for a new one, and a read queued but not started serves every flow behind it. The timeout covers a flow's whole wait, so a slow read costs a counted timeout per flow and never a growing queue.
- A machine with no VMs issues a WMI query only for its rare unknown flows, so no timer is added and idle CPU is unaffected.
- A source that fails, a WMI `Next` outlasting its own wait included (`WBEM_S_TIMEDOUT`; only `WBEM_S_FALSE` ends a read), counts in `read_errors` and keeps its last finished answer. Another source's answer never retires its sessions. With no TTL, a source that stays failed keeps its sessions until it next answers, and a later flow on that exact tuple reads as forwarded, or as unknown when a host owner also answers (D5).

**D5. Precedence: both answering is a conflict, and a conflict is unknown.**

| Owner tables / ETW | NAT | Result |
|---|---|---|
| PID | none | host, that PID |
| none | exact match | forwarded |
| PID | exact match | unknown (no PID, not forwarded), counted `host unknown` |
| tables and ETW disagree | not asked | unknown, counted `host unknown` |
| none | none | unknown |

A forwarded UDP flow whose external port equals a host wildcard-bound port would match `match_owner`'s wildcard fallback and borrow that app's exemption. So UDP owner answers are checked against the NAT snapshot already held, without a fresh read.

The loop guard comes before this table. It asks the raw owner answer (`stack::attribution::is_own`), so the engine's own flow is refused even where the table above would leave it unknown with no PID.

*Stated limit (TENSION, S24):* a NAT session newer than the last snapshot can slip past this check. A fresh read on every UDP flow would add a WMI round trip to every host DNS lookup, which is not acceptable. On a machine with an active VM, its own misses keep the snapshot fresh. L3 counts collisions live. If WinNAT avoids host-bound ports, the limit is moot. A code comment at the check must record this (S53).

**D6. ETW rules (A2).**

- Session name `SieveEngineAttribution`. Provider enabled with keywords `0x30` and an `EVENT_FILTER_TYPE_EVENT_ID` filter for exactly 12, 28, 42, 58. Without the filter, every TCP send is an event, on a path already over its CPU budget.
- Real-time mode only, no log file. Fixed small buffers.
- The session lives exactly as long as routes are up: started in `bring_up`, stopped in `take_down` after the routes are deleted, so a hang there cannot hold a route. Routing off means no session.
- A failed start is not a Setup blocker. It goes to `last_error` and routing continues with the tables alone (fail-open).
- A stale session of that name is stopped at every service start and end, and by the `restore` and `uninstall` verbs (a real-time session outlives a killed controller).
- A stop is bounded: it waits at most `TASKS_BOUND`, then detaches the consumer thread.

**D7. The ring holds unique tuples, not raw events.** Keyed by (proto, local, remote), it stores pid and last-seen time, with FIFO eviction at `ETW_RING_CAP` (4096).

- A repeat from the same PID refreshes the entry and takes no slot. A UDP-heavy socket would otherwise churn a raw ring and read as constant loss.
- The engine's own PID is dropped at ingestion: every upstream UDP send would otherwise be an event. PID 0 is dropped too and means no answer, as it does in the owner tables (D1).
- A different PID on a tuple seen within `ETW_MATCH_WINDOW_MS` (2000) marks it conflicted, and a conflicted tuple answers unknown. An older entry is simply replaced (port reuse).
- `Counters.etw_dropped` is evictions plus the session's `EventsLost`.
- Addresses compare as ip and port with scope ignored. A v4-mapped IPv6 address is normalised to IPv4 in the decoder. The Codex measurement says dual-mode sockets show in the IPv4 tables, so without this the same socket could never match.

*The window:* 2000 ms is the 1 s minimum `FlushTimer` plus margin. It is a declared constant (S25), and L2 measures the real latency.

**D8. Delivery latency is the main risk to A2, and it has a fix.** Real-time ETW delivers when a buffer fills or at `FlushTimer` (1 s minimum), which is far past the 250 ms give-up. For a low-rate one-shot UDP socket, the ETW answer would arrive after the decision. So while a flow is pending, the attributor nudges its witness, which calls `ControlTraceW(EVENT_TRACE_CONTROL_FLUSH)` at most every `ETW_FLUSH_MIN_MS` (50). `GIVE_UP_MS` stays 250. Agreement is checked with what the ring holds at decision time, because waiting for ETW on a table hit would add latency to every flow. A later contradiction is not re-judged. The diagnostics count it.

**D9. Wire shape: one nullable field, no redundant enum.**

- `FlowEvent.forwarded: Option<Forwarded>`, where `Forwarded { vm: Option<String> }`. `pid` Some means host; `forwarded` Some means guest; both None means unknown. The illegal fourth state has one constructor, `Attribution::event_fields`, with a test.
- `visible_to` admits `forwarded.is_some()`. A VM belongs to the machine, as services do. The pipe's DACL already limits clients to the owner and admins. Host-unknown flows stay hidden, as today.
- `snapshot_flow` still drops them, so Home's chart and history keep their measurand (S20) and no synthetic PID is invented (S21).

**D10. The group reads the Status, not the flow stream.** `EngineStatus.guests: Vec<Guest>`, where `Guest { key, vm: Option<String>, seen: u64, open: u32 }`, sorted with named VMs first and the unidentified row last.

- `FlowBook` owns it, updated in `open` and `close`, because it already owns the flows.
- The 2 s probe already carries Status to the store, so there is no new command, poll or store slice, and no host name crosses this path.
- "Seen" means since the engine started. An Off choice survives in `apps.levels` and applies as soon as the row returns.
- Capped at `MAX_GUESTS` (32); past that a new name folds into the unidentified row and the status stays bounded. `VM_NAME_MAX` is 64.

**D11. Keys align with domain-policy D4.** `sieve_ipc::vm_key(vm: Option<&str>)` is the one owner: `vm:<lower-cased name>` or `vm:unidentified`. A VM literally named "unidentified" is treated as unnamed, so two rows can never share a key. `:` cannot occur in a Windows file name, so no exe stem collides.

**D12. Policy is not built here.** Domain-policy owns `domain::Owner`, `off_apps`, "never inherits", and `may_decrypt`, with its tests `forwarded_flow_never_inherits_a_host_apps_off` and `forwarded_flow_is_domain_filtered_and_never_decryptable`. This stream supplies the classification, and the merge constructs `Owner::Forwarded` from `Attribution` in `stack/relay.rs`. No parallel owner type, no policy function, and no decision on the relay path in this branch. `apps.levels` is already the source of `off_apps`, so VM keys flow through it with no extra wiring.

**D13. Counters, appended.** `forwarded`, `forwarded_named`, `etw_found` (a PID only ETW gave), `etw_disagreed`, `etw_dropped`. `attributed` becomes host PID found OR forwarded named. Both rates derive from counters in one place each, never stored (S23):

- all flows: `attributed / flows`
- host only: `(attributed - forwarded_named) / (flows - forwarded)`

`LIVE_CHECKS` and the 0.95 check do not change. The host-only figure goes in the check's detail text.

**D14. VM naming goes through an injected `VmDirectory`.** It maps an internal IP to `Option<String>`.

- The real chain: HCN endpoints by IP, then the endpoint's VM id, then HCS's compute system (`Owner`), then for Hyper-V `Msvm_ComputerSystem.ElementName`. The name always comes from the system, never from a list in source (S49).
- If any link fails, the name is None and the flow takes the unidentified row. That row counts as a gate miss, per decision 1.
- WSL distros share one utility VM and one IP, so WSL is one row.
- `computenetwork.dll` and `computecore.dll` load at run time with `LoadLibraryExW(LOAD_LIBRARY_SEARCH_SYSTEM32)` and `GetProcAddress`. A static import of an optional component would stop the service from starting on a machine without it, breaking fail-open.

**D15. NAT sources are a list behind one trait.** `NatSource::read` returns sessions.

- `WmiNat` reads `MSFT_NetNatSession` with `ExecQuery` only (proven live for WSL).
- `WinNatEvents` builds a table from WinNat events 1001 and 1005, enabled on the same ETW session: the candidate for the HNS Default Switch, whose sessions `Get-NetNatSession` does not list.
- I found no documented API for HNS session state, and whether HNS NAT emits these events is unverified. If L1 shows it does not, Default Switch flows stay unexplained and count as misses. That is the honest result, so nothing else may stand in for it.
- After L1, if one source covers everything, retire the other (S52).

**D16. No new crates.** The `windows` crate gains features only: `Win32_System_Diagnostics_Etw`, `Win32_System_Com`, `Win32_System_Wmi`, `Win32_System_Variant`, plus `Win32_System_Ole` if the WMI calls need it. `ferrisetw` would add a dependency for about 100 lines of `StartTraceW`, `EnableTraceEx2`, `OpenTraceW` and `ProcessTrace`, and `decode` is ours and tested regardless.

**D17. UI, flat.**

- A section label, then rows, with no card, badge or divider. It sits above Mine.
- The section header is extracted from `AppSectionView` and reused (S33).
- A row is icon-less text: name, "Filtered by domain only" as its caption, the open count, then `AppToggle`, so toggles stay on the header actions' line. No detail sheet: there is no exe or PID to show.
- The switch's tooltip uses a `VM_OFF_MEANS` string, because `APP_OFF_MEANS` ("stops tracking and charting") is false for a row that is never charted.
- Search filters the rows by name. "Off for every app" includes the visible VM rows, since its notice says every app. "Sieve all" already clears them.
- `sievedCount` and Home are unchanged: they count apps, and VMs are not apps there.

**D18. Merge with the protocol wave.** `PROTOCOL` 3 is one version for this wave (domain-policy line 165; app-log D2). The bump is its own commit, dropped at merge if v3 already landed; everything else appends. No fixture rename in this stream.

## Exact files

New:

- `engine/crates/sieve-engine/src/flow/etw.rs`: `decode`, `EtwRing`, the `PidWitness` trait, `Unwitnessed`, and `pub mod os` (`#[cfg(windows)]`: session start, stop, `stop_stale`, flush, consumer thread).
- `engine/crates/sieve-engine/src/flow/nat.rs`: `NatSession`, `NatSource`, `VmDirectory`, `NatTable`, `exact_match`, `session_from_fields`, `decode_winnat`.
- `engine/crates/sieve-engine/src/flow/nat/os.rs` (`#[cfg(windows)]`): the WMI reader thread, `WinNatEvents`, the HCN/HCS directory.
- `engine/crates/sieve-engine/src/stack/attribution.rs`: `Attribution`, `decide`, counting, event fields.
- `engine/crates/sieve-engine/testdata/kernel-network-events.json`, `testdata/winnat-session-events.json`: hand-built from the manifests, and labelled so.
- `engine/crates/sieve-engine/fixtures/nat-sessions.json`: the real session shape from the evidence table.
- `engine/crates/sieve-engine/examples/wmi_system32.rs`: reads `Win32_OperatingSystem` under `SetDefaultDllDirectories(SYSTEM32)`.
- `src/core/guests.ts`, `src/core/guests.test.ts`: `guestRows`, labels, `VM_OFF_MEANS`, `hostAttribution`.
- `src/components/sieve/apps/vm-group.tsx`.
- `docs/live/attribution.md`: the steps of L1 to L4.

Edited, engine:

- `engine/crates/sieve-engine/Cargo.toml`: `windows` features only.
- `src/flow/mod.rs`: the two modules.
- `src/flow/flows.rs`: `Attributor::new(source, witness)`, new `Owner` variants `WitnessOnly(u32)` and `Disagreed`, `combine`, stats.
- `src/stack/mod.rs`: new `Meters` and `counters()`.
- `src/stack/book.rs`: guests; `visible_to`.
- `src/stack/relay.rs`: `attribute()`, `admit`.
- `src/stack/diagnostics.rs`: categories, `Evidence`, fingerprints, raw events.
- `src/flow/packet.rs`: `syn_fingerprint`, behind the feature.
- `src/tun/device.rs` and `src/tun/batch.rs`: the feature-gated fingerprint hook. Both reader paths need it.
- `src/control/mod.rs`: `status()`.
- `src/control/routing.rs`: `Up` owns the session and `NatTable`; `bring_up`, `take_down`.
- `src/service/runner.rs`: `stop_stale` at start and end.
- The verbs' step lists for `restore` and `uninstall`, found with `clear_stale`.
- `src/service/mod.rs`: the `REQUIRED_PRIVILEGES` comment (see L2).
- `src/bin/probe/main.rs`: `Attributor::new(IpHelper, Unwitnessed)`.

Edited, shared (append only):

- `engine/crates/sieve-ipc/src/lib.rs`: `Forwarded`, `Guest`, `vm_key`, `MAX_GUESTS`, `VM_NAME_MAX`, fields; the worst-case frame test.
- `src/data/fixtures/engine-ipc-v2.json`: `forwarded: null` on existing flows, one named and one unidentified flow, `guests`, counters.
- `tests/laws/engine-ipc.test.ts`: the `vm_key` agreement; fix its stale v1 comment.

Edited, app:

- `src-tauri/src/engine.rs`: test expectations only (forwarded flows are still left out).
- `src/data/fixtures/engine-probe-v2.json`: counters and `guests` on every example.
- `src/data/protocol.ts`: `COUNTER_KEYS`, `parseEngineStatus`, the guests normalizer.
- `src/core/engine.ts`: `hostAttribution`.
- `src/components/sieve/settings/engine-card.tsx` and its test: both rates when `forwarded > 0`. The sentence is unchanged at 0.
- `src/components/sieve/apps/use-apps.ts`, `apps-screen.tsx`, `app-list.tsx`, `app-toggle.tsx`, `apps.test.tsx`.
- `src/core/apps-actions.ts`: `matchesQuery` reuse; bulk keys.
- `tests/e2e/apps.spec.ts`.
- `tests/laws/engine-network.test.ts`: the new test below.
- `scripts/live/engine-route.ps1`, `scripts/live/run-slice-3-auto.ps1`: host-only in the detail text.
- `docs/conventions.md`: rows for Engine IPC, Engine routing and Apps.

Not touched: `src/core/settings/*` (`apps.levels` is a free map, so no new key and no schema step), `src/core/routes.ts`, `src-tauri/src/netstat/*`, `Cargo.lock` beyond what features require.

## Offline acceptance

Before every cargo command: `$env:CARGO_BUILD_JOBS='8'`. The worktree has no `node_modules`: run `pnpm install --frozen-lockfile --offline`, then fall back to `--frozen-lockfile`.

**ETW (`flow::etw`)**

- [ ] `decodes_all_four_events_from_the_manifest_templates`: fixture bytes give the exact pid, tuple and proto, for v4 and v6, with network-order ports.
- [ ] `a_truncated_or_unknown_event_decodes_to_none`; proptest `decode_never_panics`.
- [ ] `v4_mapped_addresses_normalise_to_ipv4`
- [ ] `exact_means_all_four_fields`: changing any one of local ip, local port, remote ip, remote port, or proto gives no answer.
- [ ] `an_event_outside_the_window_does_not_answer`
- [ ] `two_pids_on_one_tuple_within_the_window_answer_conflict`; `an_old_entry_is_replaced_not_conflicted`
- [ ] `a_busy_socket_takes_one_slot`; `the_ring_is_bounded_and_counts_every_eviction`
- [ ] `the_engines_own_events_are_not_stored`

**Combining (`flow::flows`)**

- [ ] `combine_matches_the_table`: one assertion per row of table+ETW: agree; ETW only; table only; disagree; ETW conflict; neither pending; neither past give-up.
- [ ] `a_disagreement_clears_first_miss`
- [ ] `a_pending_flow_nudges_the_witness_at_most_every_flush_interval`
- [ ] All existing `flows::tests` pass with `Unwitnessed`.

**NAT (`flow::nat`)**

- [ ] `the_recorded_session_shape_matches_its_flow`, using `fixtures/nat-sessions.json`.
- [ ] `exact_match_requires_protocol_and_both_external_ends`: each field changed gives no match. An internal-side-only match gives no match.
- [ ] `two_sessions_on_one_external_tuple_are_forwarded_but_unnamed`
- [ ] `a_read_error_is_no_match_and_counted`; `reads_are_rate_limited`; `a_slow_read_times_out_to_no_match` (fake source, `tokio::time::pause`).
- [ ] `every_source_is_asked`: a match in the second source counts.
- [ ] `decode_winnat_reads_both_template_versions`; `a_deleted_session_leaves_the_table`; `the_session_table_is_bounded`.
- [ ] `vm_names_are_trimmed_capped_and_control_free`; `no_alphanumeric_name_is_unnamed`; `the_name_unidentified_is_unnamed`.

**Attribution and book (`stack::*`)**

- [ ] `decide_matches_the_table_of_d5`, one row each; `a_forwarded_flow_has_no_pid_exe_or_session`.
- [ ] `a_udp_owner_with_a_held_nat_match_is_unknown`, with no read issued.
- [ ] `counters_give_both_rates`, including `forwarded_unnamed_is_a_miss`: 100 flows, 90 host, 5 named, 5 unnamed give all-flows 0.95 and host-only 1.0.
- [ ] `guests_appear_on_first_sight_and_stay_after_close`; `open_counts_follow_open_and_close_all`; `guests_are_capped_into_the_unidentified_row`.
- [ ] `a_client_sees_forwarded_flows_but_not_unknown_ones`.

**Diagnostics** (`cargo test -p sieve-engine --features attribution-diagnostics`)

- [ ] `every_flow_lands_in_exactly_one_category`: the four sum to `flows`.
- [ ] `host_unknown_needs_a_row_or_a_disagreement`, table-driven.
- [ ] `fingerprints_never_reach_a_decision`: the same flow with TTL 128 and TTL 63 gets the same category and the same `Attribution`.
- [ ] `syn_fingerprint_reads_ttl_hop_window_and_option_order`, v4 and v6; a non-SYN gives none.
- [ ] The fingerprint table and raw events are bounded; the JSON stays under the existing size bound; it contains no host name, path or payload.

**IPC and app**

- [ ] `cargo test -p sieve-ipc`: every fixture message round trips; `a_full_flows_frame_stays_under_the_frame_limit` with `forwarded` at `VM_NAME_MAX`; `a_status_with_max_guests_fits`; the `vm_key` cases.
- [ ] `pnpm rust:test`: `engine_flows_become_snapshot_rows_with_the_tables_meaning` still gives 4 rows and leaves out both forwarded flows; every probe example round trips.
- [ ] `guests.test.ts`: `guestRows` over named, unidentified and both; `hostAttribution` null at 0 flows and when every flow is forwarded (no division by zero).
- [ ] `parseEngineStatus` degraded: `guests` missing gives `[]`, `guests` not an array gives `[]`, a broken entry is dropped and the good ones kept, and a missing new counter is a `ProtocolError` like the others.
- [ ] `apps.test.tsx`: the group is hidden with no guests, no status, or a null probe. It sits above Mine. Each row has the name, the note and a switch that writes `vm:<name>` into `apps.levels`. Unidentified uses the exact label. Search narrows it. Bulk Off includes it.
- [ ] `engine-card.test.tsx`: the existing sentence is unchanged at `forwarded: 0`; both rates show when above 0.
- [ ] Law (append to `engine-network.test.ts`): `StartTraceW`, `ControlTraceW`, `EnableTraceEx2` appear only in `flow/etw.rs`. The engine never names `Autologger`, a file logging mode, `ExecMethod`, `PutInstance`, `New-NetNat`, `Add-NetNat` or `Remove-NetNat`. The test proves its patterns catch these. `ExecQuery` appears only in `flow/nat/os.rs`.
- [ ] No hardcoded VM names: a law greps the new engine files for `wsl`, `ubuntu`, `cowork`, `hyper-v` as string literals (case-insensitive) and finds none.
- [ ] `cargo run -p sieve-engine --example wmi_system32` exits 0 unelevated. This proves COM and WMI load under the service's System32-only DLL search.

**Whole suites**

```powershell
# engine/
cargo test --workspace
cargo test -p sieve-engine --features attribution-diagnostics
cargo test -p sieve-engine --features relay-experiments,attribution-diagnostics
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p sieve-engine --all-targets --features relay-experiments,attribution-diagnostics -- -D warnings
# repo root
pnpm typecheck; pnpm lint; pnpm test; pnpm rust:test; pnpm rust:lint
powershell -NoProfile -File scripts/live/test-slice-3-auto.ps1   # the contract test, no live path
# Read nvidia-smi first; if another project holds over half the card, wait.
powershell -NoProfile -File <tools>\procs\with-gpu.ps1 -Label sieve-e2e-attribution -- pnpm e2e
```

- [ ] e2e, `?engine=filtering`: the group is at the top of Apps, its toggle ends on the header actions' line, and the switch persists across a reload. Default mock (`missing`): no group.

## UNVERIFIED: live proofs for Michael

No agent runs these: they need elevation, the installed service or real routes. Steps go in `docs/live/attribution.md`, one at a time under the runner lease, with AdGuard and the engine restored and audited afterwards.

- **L1, the A1 run.** A 10-minute run of the diagnostic build, with a window where Cowork is idle and one where it is active, and with WSL traffic. Done when every unknown flow is an exact NAT match or listed as unexplained with its evidence. It also answers:
  - Does the HNS Default Switch appear in `MSFT_NetNatSession`, in WinNat events, or neither (D15)?
  - What do `Get-HnsEndpoint` and HCS really return, and does the D14 chain name a VM?
  - What origin do the 12 IPv6 flows to `[2607:6bc0::10]:443` have? That is still a hypothesis.
  - Do the recorded raw events decode the same as the hand-built fixtures? Copy them into `testdata/` and rerun.
- **L2, ETW.**
  - The session starts under the trimmed `REQUIRED_PRIVILEGES` token. If not, `last_error` says so and a privilege decision follows.
  - Real delivery latency with the flush nudge, against the 2000 ms window.
  - `etw_found` is above 0 and `etw_disagreed` is 0 or explained.
  - `logman query -ets` shows no session after a stop, a kill plus restart, `restore`, and `uninstall`.
  - A kill recovers the network as before.
- **L3, NAT.** WMI query latency and CPU under `LocalSystem`; how often a forwarded UDP flow collides with a host wildcard port (the D5 limit); forwarded flows in the Apps group with real names.
- **L4, acceptance.** The new 30-minute run. The gate stays 0.95 of all flows, and the relay CPU gate must still pass with ETW on: a UDP-heavy case measures what event 42 costs. This stream may not reach 0.95 alone. Unnamed forwarded and unexplained flows are misses by decision 1.
- **Not provable offline:** that a guest's traffic is actually filtered and never decrypted. That needs domain-policy merged, and its own live run.

## Dependencies on other streams

- **`wf-domain-policy`:** D12. The note "Filtered by domain only" and `VM_OFF_MEANS` are true only once its filtering is in main. Until then the engine blocks nothing, and repo copy rules forbid claiming otherwise (`engineDetail`: "Nothing is blocked yet"). **Merge this after it, or in the same release.** At merge: construct `Owner::Forwarded` from `Attribution`, and use `sieve_ipc::vm_key` in its key check. Its plan writes `vm:<name>`; this plan lower-cases the name, as `apps.levels` keys are.
- **Fixture rename:** domain-policy line 165 renames to `engine-ipc-v3.json`, while app-log D2 keeps the path. The orchestrator settles this once; this stream does not rename.
- **`wf-coexist`** adds an `adguard_paused` probe example. It needs the new counters and `guests` at merge, or the round trip fails.
- **`wf-app-log`** reads `FlowEvent`. `forwarded` is the Flows-view label the spec asks for: the app has no Flows screen in this branch, so the label ships as the wire field, and the log renders "Virtual machines and WSL" from it.

## Open questions for Michael

1. **What goes in "Unidentified virtual machine traffic"?** Your decision says "unmatched forwarded flows", but a flow can only be called forwarded on evidence.
   - **Default in this plan:** a flow with an exact NAT match whose VM cannot be named. A flow with no NAT match at all stays host-unknown or unexplained, with the default policy, outside the group.
   - **The alternative:** also put flows with a lowered TTL in that row. It would show more, but TTL is settable by any host program, so with that row Off a host program could exempt itself. I recommend the default. It affects only what is shown and exempted: both choices count these flows as gate misses.
2. **Should a VM row's name be the system's own?** WSL would show whatever HCS reports as its owner (likely `WSL`), and a Hyper-V VM its `ElementName`. No friendly-name mapping is planned, because any such list would be a hardcoded enumeration. Say if you want one.

Assumed unless you say otherwise: VMs do not appear in Home's chart or history, only in Apps and the counters, since the spec names only those.

## Implementation order

Each step is one commit, with failing tests first (S9) and the suites touched green before the next.

1. **Protocol bump, alone.** `PROTOCOL` 3 and `SUPPORTED`, fixture constants. Droppable at merge (D18).
2. **IPC shapes.** `Forwarded`, `Guest`, `vm_key`, caps, counters, fixtures (both), `protocol.ts` parser with degraded tests, the law. Update `src-tauri` expectations.
3. **ETW, pure.** Fixture, `decode`, `EtwRing`, `PidWitness`, `Unwitnessed`.
4. **Attributor.** `combine`, new `Owner` variants, nudge, probe call site; all existing tests green.
5. **NAT, pure.** `NatSession`, `exact_match`, `NatTable` with rate limit and timeout, WinNat decoder, name normalizer.
6. **`stack::attribution` and the book.** `decide`, counters, guests, `visible_to`, status.
7. **Relay wiring.** `attribute()`, `admit`. Feature off and on both compile and pass.
8. **Windows code.** ETW session and `stop_stale`; WMI thread and `wmi_system32`; WinNat events; HCN/HCS directory with run-time loading. `bring_up`, `take_down`, runner, verbs. Stop and report if any of this cannot compile against the `windows` crate as planned; do not stub it silently.
9. **Diagnostics (A1).** Categories, `Evidence`, `syn_fingerprint` and both reader hooks, raw capture.
10. **Reports.** The two scripts' detail text, the contract test, `hostAttribution`, engine card.
11. **Apps.** `guests.ts`, `vm-group.tsx`, the shared section header, `use-apps`, `app-toggle`, bulk and search, unit tests, then e2e under the lease.
12. **Laws and docs.** Engine-network additions, the no-hardcoded-names law, `docs/conventions.md`, `docs/live/attribution.md`.
13. **Full suites**, then a `git diff main --stat` review against "Exact files". Kill every process started, by tree.
