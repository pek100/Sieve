# Task: P0, the relay floor through kernel sockets (no install)

## Why

`docs/research/2026-10-18-wfp-redirect.md` ("Prototype, if approved", P0) asks one question before any driver work: how much CPU does the engine's relay cost when the kernel's own TCP stack carries both sides, the way a WFP redirect design would? Michael approved P0 on 2026-10-18. Signing and drivers are on hold until P0 and the Wintun experiments report. P0 installs nothing: a local HTTP CONNECT proxy, built from the engine's own relay code, measured with curl on the slice 3 budget workload.

## Read first

docs/research/2026-10-18-wfp-redirect.md (sections 5 and "Prototype"); docs/plans/2026-10-18-slice-3-attribution-and-cpu.md (C0); engine/crates/sieve-engine/src/flow/relay.rs (`relay_tcp`); engine/crates/sieve-engine/examples/owner_tables.rs (the example pattern in this crate); scripts/live/budget-transfer.ps1 and its test scripts/live/test-budget-transfer.ps1; scripts/live/run-slice-3-auto.ps1, the "budget" step (how CPU per 100 Mbit/s is computed); scripts/live/live-lease.ps1.

## Build

1. `engine/crates/sieve-engine/examples/connect_relay.rs`: an HTTP/1.1 CONNECT proxy on `127.0.0.1:<port>` (`--port`, default 0, printing the chosen port on its first stdout line).
   - It accepts only `CONNECT host:port` and answers `200 Connection established`, then relays with `sieve_engine`'s `relay_tcp`, with the same buffer sizes the engine uses. Refuse anything else with 405. Refuse non-loopback clients. Cap concurrent tunnels at 16.
   - It exits after `--seconds` (required, 1 to 600), or when stdin closes.
   - On exit it prints one JSON line: its own process CPU time (user and kernel separately, from `GetProcessTimes`), bytes relayed in each direction, and tunnel count.
   - It must not set a system proxy or touch any setting. The proxy is used only by an explicit `curl -x`.
2. Generalise `scripts/live/budget-transfer.ps1` without changing its default behaviour:
   - optional `-Url`, `-Count` and `-Size`, defaulting to today's Cloudflare 12 x 25 MB;
   - optional `-Proxy` (passes `-x` and drops `--noproxy`).
   The validator derives the expected response count, size and total from those parameters, not from new constants. Extend scripts/live/test-budget-transfer.ps1 to cover a non-default count and size, and the proxy argument.
3. `scripts/live/p0-relay-floor.ps1`, which runs UNELEVATED:
   - **Before measuring:** take the live lease; refuse if Sieve routes are up (any route on the Sieve adapter) or if the engine reports routing on (read what an unelevated user can; if unreadable, require `-AssumeRoutingOff` and record it).
   - **Measure:** run the baseline (curl direct) and the candidate (curl through connect_relay, built in release) alternately, `-Runs` times each (default 3), with `-PauseSeconds` between runs (default 300, because the server rate-limits: HTTP 429 seen 2026-10-18).
   - **Validate:** each run must pass the workload validator. An invalid run is reported as invalid, never scored.
   - **Score:** the relay's CPU cores per 100 Mbit/s (its own CPU time over the run's bytes and wall time) and throughput against the baseline's median. Pass mark from the research note: 0.05 cores per 100 Mbit/s or less, with throughput within 10 percent of direct.
   - **Record AdGuard:** record its service state at start and end. Do not change it. The live controller decides whether AdGuard is paused for the run.
   - **Output:** write JSON evidence to a timestamped folder under `C:\Users\Public\sieve-engine-live\`, plus a short summary. Support `-DryRun`, which prints the plan and touches nothing.
4. Tests: a Rust unit test for the CONNECT request parser (accepts `CONNECT example.com:443 HTTP/1.1`, refuses other methods, missing port, port 0, an over-long line, and a non-loopback peer) and for the end-of-run JSON shape. Write a PowerShell contract test, `scripts/live/test-p0-relay-floor.ps1`, that mocks curl and the relay and checks:
   - invalid runs are not scored;
   - the median is computed correctly;
   - the refusal when routes are up;
   - `-DryRun` touches nothing.
5. Add a short "P0" paragraph to docs/live/ (a new file `docs/live/p0-relay-floor.md`) with the exact commands the live controller runs.

## UNVERIFIED (list in your report; the Claude verifier runs these)

- `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` from `engine/`.
- `cargo build --release -p sieve-engine --example connect_relay`.
- The real measurement: network, AdGuard state and timings. The live controller runs it.

## Limits

No em dash U+2014 anywhere. Do not run curl against the network, start the relay, install, elevate, or touch E:\Sieve, any service, AdGuard, routes, proxy settings or network settings. Running `scripts/live/test-*.ps1` with mocks and `-DryRun` is allowed. Do not change engine production code (flow/relay.rs may gain a `pub` only if the example needs it).

## Sieve, not another project: read this before the standards above

The preamble was written for another project. In THIS repo:
- Ignore the WebGPU, FrameGraph, two-clocks, `?flag`, metres-per-wu and Vite-port rules. Standards 1, 6 and 8 apply in full.
- There is no `tooling\procs` here. You start no GPU process, no browser and no dev server.
- cargo lives under `%USERPROFILE%`, which your sandbox cannot read, so do not try. Write the Rust carefully: the verifier compiles it. List every Rust change under UNVERIFIED with the exact cargo commands.
