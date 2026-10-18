# P0 relay floor

P0 measures the engine's existing TCP relay through kernel sockets using an explicit loopback CONNECT proxy. It installs nothing. From the worktree root, the live controller runs the following in an **unelevated** PowerShell with Cargo and curl available. The controller owns the decision to pause AdGuard and must arrange routing off before measuring; this script only reads their state. The defaults and acceptance limits come from the approved P0 in `docs/research/2026-10-18-wfp-redirect.md` and C0 in `docs/plans/2026-10-18-slice-3-attribution-and-cpu.md`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/live/p0-relay-floor.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/live/p0-relay-floor.ps1 -Runs 3 -PauseSeconds 300
```

If engine status is unreadable, the script refuses. Only after independently confirming routing is off, the controller can record that assumption explicitly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/live/p0-relay-floor.ps1 -Runs 3 -PauseSeconds 300 -AssumeRoutingOff
```

The assumption never overrides an observed Sieve route, unreadable route table, or engine status reporting routing on. The runner takes the shared live lease, builds `connect_relay` in release, alternates direct and proxied downloads, and pauses between every download. `-Url`, `-Count`, `-Size` and `-Seconds` select another HTTPS workload and its validation bounds. With no URL override, the Cloudflare request size follows `-Size`; with a URL override, that exact URL must serve the specified size. The candidate uses `curl -x` only; inherited proxy bypass lists are cleared for that child. No system proxy is set. The relay prints its chosen port first and exits on stdin EOF or its bounded lifetime. The runner closes stdin after curl and disposes its child processes.

Each timestamped `C:\Users\Public\sieve-engine-live\p0-relay-floor-*\evidence.json` records the workload, raw curl results, routing observations and assumptions, AdGuard state at start/end, and relay JSON. The relay counts successful payload writes in both directions, excluding CONNECT setup, and obtains its own user/kernel CPU time with `GetProcessTimes`. Its CPU includes process startup and shutdown; the throughput clock is the curl workload wall time. Scoring uses validated HTTP body bytes, matching the slice budget, rather than the larger TLS/socket byte count. The normalization is `(CPU seconds / wall seconds) / (body bytes * 8 / wall seconds / 1e6 / 100)`. Invalid workloads, cancelled connections and missing or inconsistent relay records remain unscored. Medians use valid runs only; an incomplete requested set has no pass verdict. A complete set passes at CPU median at most `0.05` cores per `100 Mbit/s` and candidate throughput median within `10 percent` of direct, in either direction. Results with AdGuard running describe that environment, not an isolated redirect floor.

Offline verification commands (the PowerShell tests use mocks, not live measurements):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/live/test-budget-transfer.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/live/test-p0-relay-floor.ps1
Set-Location engine
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p sieve-engine --example connect_relay
```

Rust compilation and real measurements require the verifier/live controller. Mock throughput and CPU fixtures are not evidence of the relay's live cost.
