# Slice 3 fixes: attribution and relay CPU

2026-10-18. Status: plan. Slice 3 (`docs/plans/2026-10-17-https-filtering.md`, section 8) is NOT accepted. The 30-minute live run on Michael's PC failed two of its gates and passed the rest:

| Gate | Result | Evidence |
|---|---|---|
| Attribution of at least 0.95 of new flows | **FAIL** 2,174 / 2,733 = 0.7955 | `auto-20261018T202539-…` (Codex handoff) |
| Relay CPU, 100 Mbit/s single download | **FAIL** 0.222 cores per 100 Mbit/s (budget 0.15) | `budget-20261018-210831\normal-budget.json` |
| Engine memory | pass, 31.7 MiB | same |
| Kill recovery | pass, network back in 3.67 s | live run |
| Watchdog trip | pass, routes gone after a 5.1 s stall | live run |

This plan fixes the two failures without moving either gate. The 0.95 threshold and the 0.15 budget stay. Anything that changes what is counted is listed under "Decisions for Michael" and waits for his answer.

Evidence sources: the Codex handoff (`%USERPROFILE%\Documents\Codex\2026-10-18\here-s-the-whole-picture-from\outputs\claude-handoff.txt`), its `work\` folders, and the merges into main on 2026-10-18 (3e3a26a lazy ipstack logging, 5168709 attribution diagnostics, 6006391 slice 4 groundwork with stricter owner matching).

## 1. What we know

### Attribution

The attribution path (`engine/crates/sieve-engine/src/flow/flows.rs`) reads the owner-pid TCP and UDP tables and matches the flow's local and remote ends. It retries for 250 ms, then gives up.

The four-minute diagnostic run (feature `attribution-diagnostics`, 314 flows, 22 unknown) showed:

- **No timing misses.** Every table read succeeded. A re-read after the give-up found no late match. Waits were 250 to 342 ms. Raising the give-up time would not help.
- **Forwarded traffic (proven).** Two controlled WSL requests and four WSL NTP flows (`ntp.ubuntu.com`) matched Windows NAT session records exactly. NAT'd guest traffic has no Windows socket, so no owner-table row can ever match it. Equivalent requests from Windows apps were attributed.
- **Unexplained IPv6 TCP (12 of 22).** All go to `[2607:6bc0::10]:443`, the AAAA address of `api.anthropic.com`. No row exists on those ports in either table, even at the first lookup, which comes milliseconds after the SYN. Claude processes on the host are attributed for the same API. A guest origin (the Cowork VM) is a hypothesis, not established. Codex measured that dual-stack sockets are NOT the cause: a dual-mode UDP socket also appears in the IPv4 table, and a dual-mode TCP connection to IPv4 appears in the IPv4 table.
- **Counting was slightly generous.** Before 6006391, a TIME_WAIT row (PID 0) or another app's row on a reused port could count as attributed. Main now requires a unique, nonzero PID, so the next baseline may be lower. It will also be honest.

### CPU

- 300 MB over one connection took 5.33 CPU-seconds, about 26 us per 1500-byte packet. The design estimated 1 to 3 us. Slice 6 will need 500 Mbit/s through the same path, so this is structural, not a tuning detail.
- Throughput fell from about 97 Mbit/s with Sieve off to 81 Mbit/s with it on.
- The profile was 58% unresolved `ntoskrnl` and 13% unresolved `ntdll`, because symbol download failed. Kernel-heavy time points at work per packet or per syscall: ring signalling, socket calls and wakeups. It does not point at Rust computation, but nothing is proven yet.
- The lazy-logging candidate (3e3a26a) is merged, but its live effect is unknown. Its one comparison run hit HTTP 429 from Cloudflare after 150 MB and is invalid. The 16% partial figure is not evidence.

## 2. Attribution work

Order: measure what is really there, then add exact evidence sources. No heuristic may name an app.

### A1. Name the origin of every unknown flow (offline code, then one live run)

Extend the diagnostics, still behind the feature flag and still metadata only:

1. The SYN's IPv4 TTL or IPv6 hop limit, plus the TCP option order and window size. A host socket arrives undecremented; a forwarded packet arrives one hop lower. This only selects which exact check to run next. It never assigns an owner.
2. An exact match of the flow's tuple against NAT session state, for both WinNAT (`MSFT_NetNatSession`) and the HNS-managed Default Switch, which `Get-NetNatSession` does not list.
3. A per-category count: host attributed, host unknown, forwarded (exact NAT match), unexplained.

Live step (Codex or Michael, under the runner lease): one 10-minute diagnostic run, with a window where Cowork is idle and a window where it is active. Done when every unknown flow is either an exact NAT match or listed as unexplained with its evidence.

### A2. ETW as a second exact source for host sockets

Owner tables only show sockets that still exist. A host socket that sends and closes before the lookup (one-shot UDP) is invisible to them. The `Microsoft-Windows-Kernel-Network` ETW provider reports the PID with the exact local and remote address and port on TCP connect and on UDP send. The engine runs as LocalSystem and can hold a real-time session. Rules:

- The ETW match must be exact on all four tuple fields, within a short window, and agree with the owner tables whenever both answer. A disagreement makes the flow unknown.
- It must stay bounded: a fixed-size ring of recent events, dropped when full and counted.
- Starting a real-time ETW session changes no system setting and persists nothing. It must still be stopped on service stop and on a crash (named session, cleaned up at the next start).

This is offline work, with unit tests over recorded event fixtures. Live proof comes in the next acceptance run.

### A3. Report forwarded traffic as its own category

If A1 confirms forwarded flows, the engine reports them as "Virtual machines and WSL" (a counter plus a Flows-view label). They get the default app policy. They never inherit a host app's exemption. Whether they count toward the 0.95 gate is Michael's decision (below). Until he decides, every report shows the rate both ways.

## 3. CPU work

Order: see where the time goes, then change one thing at a time, measuring each change on its own.

### C0. A workload that can be repeated

Cloudflare rate-limited the second run (HTTP 429). Pick one large-file endpoint that tolerates repeated downloads, record it in `scripts/live/budget-transfer.ps1`, and space runs at least 5 minutes apart. The validity checks stay: response count, bytes, status, one reused connection, deadline. Every comparison runs the baseline and the candidate back to back, three times each. The median decides.

### C1. Resolved kernel stacks

Fetch the Microsoft symbols while Sieve is off (the earlier download failed on DNS during the trace), then re-read the existing `cpu.etl` and take one new trace. Done when the top kernel frames have names: for example Wintun ring events, AFD send and receive, IOCP waits. That list decides the order of C2.

### C2. Experiments, each kept only if it wins

| # | Change | Where | Expected effect | Regression check |
|---|---|---|---|---|
| E1 | lazy ipstack logging (merged) | vendor ipstack | fewer allocations per packet | none needed, behaviour identical |
| E2 | TUN MTU 9000 for TUN and stack | `tun/mod.rs`, `control/routing.rs` | about 6x fewer packets per byte; TCP ends at ipstack, so the real path never sees the TUN MTU | QUIC page load, large UDP datagram relay, path-MTU probes |
| E3 | 64 to 256 KiB copy buffers (`copy_buf`) | `flow/relay.rs` | fewer upstream syscalls and wakeups | relay unit tests |
| E4 | batch TUN reads; pooled buffers in place of `to_vec` | `tun/device.rs` | fewer wakeups and allocations | watchdog heartbeat still trips on a stall |
| E5 | `lto = "thin"`, `codegen-units = 1`, keep `debug = 1` | `engine/Cargo.toml` | 5 to 15 percent across the board | build time only |
| E6 | runtime shape: worker count, dedicated relay thread | `control/` | fewer cross-thread wakeups | kill and watchdog tests |

Done: three valid runs at 0.15 cores per 100 Mbit/s or less, with throughput within 10 percent of Sieve off. If E1 to E6 together cannot reach the budget, the finding goes to Michael with the measured gap. The candidate then is a different capture design (redirecting TCP to a local socket in place of a userspace TCP stack), not a weaker budget.

## 4. Other slice 3 items still open

- **Route-delete codes.** The watchdog reported 51 failed deletions while the journal replay succeeded and no routes remained. Log the real `DeleteIpForwardEntry2` return codes, and treat `ERROR_NOT_FOUND` (already gone) as success. Offline, with a unit test.
- **Ordinary AdGuard pause.** `sc stop` leaves AdGuard in StopPending by design (`LeaveServiceRunning`). The coexistence check must judge whether AdGuard is intercepting by behaviour (does a test flow get redirected into AdguardSvc?), not by service state. Until then the product cannot pause AdGuard by itself. The test runner's disable-and-kill path is a test workaround only.
- **Reboot and uninstall checks** for slices 2 and 3, at a restart that suits Michael.

## 5. Who does what

- Offline code: Codex executor tasks (CPU-only, `run-task.ps1`), one per experiment or attribution step. Claude verifies each with numbers and merges it, and Codex gives a second review.
- Live runs: only the Codex desktop session or Michael, one at a time under `runner.lock`, with AdGuard and the engine restored and audited afterwards. Claude stays read-only on services, routing and the UI.
- Acceptance: one new 30-minute run with A1 to A3 and the chosen CPU changes, against the unchanged gates.

## 6. Decisions for Michael

1. **Forwarded traffic and the 0.95 gate.** Traffic NAT'd from WSL or a VM has no Windows socket, so Sieve can name the VM but never the app inside it. Options:
   - (a) the gate covers host flows only, and forwarded flows get their own counter and their own policy row;
   - (b) forwarded flows stay in the denominator, so 0.95 holds only on a machine where VMs are quiet.

   Either way, both rates are reported.
2. **Whether WSL and VM traffic should be filtered at all,** or passed like an Off app until a guest-aware design exists.
3. **The capture fallback.** If the CPU budget is out of reach with ipstack, should a WFP-redirect design (closer to how AdGuard works) be explored? It needs a signed driver or an existing signed one, which is the question already settled once for WinDivert.
