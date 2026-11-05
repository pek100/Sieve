# Live proofs: exact attribution (L1 to L4)

Task: `docs/tasks/2026-11-02-attribution.md`. No agent runs these, because they need elevation, the installed service or real routes. Run them one at a time, under the runner lease, at an admin prompt. Afterwards restore AdGuard and the engine and audit both.

The offline suites prove the logic against hand-built fixtures. Everything below is still UNVERIFIED.

## Before you start

- Build the diagnostic engine: `cargo build --release -p sieve-engine --features attribution-diagnostics`. Never bundle this build. L4 uses the normal one.
- Results go to `ProgramData\Sieve\engine\`: `status.json` and `attribution-diagnostics.json`, both admin-only.
- Sieve off, killed or uninstalled must always leave a normal network. If it does not, stop and run `sieve-engine.exe restore`.

## L1: the A1 run

Run the diagnostic build for 10 minutes with routing on: one window with Cowork idle, one with it active, and some WSL traffic in both.

Done when every flow in `attribution-diagnostics.json` is in a category and every unknown flow is either an exact NAT match or listed as `unexplained` with its evidence.

The run also answers these questions:

1. Does the HNS Default Switch appear in `MSFT_NetNatSession`, in WinNat events (`raw_events` with ids 1001 and 1005), or neither? If it appears in neither, those flows stay `unexplained` and count as misses, and nothing else may stand in for it. If one source covers everything, retire the other.
2. What do `Get-HnsEndpoint` and HCS really return? `flow::nat::parse_endpoint` and `parse_compute_systems` read documented field names that have never been seen on this machine. Does the chain name a VM, and what does WSL show as its owner?
3. What origin do the 12 IPv6 flows to `[2607:6bc0::10]:443` have? A guest origin is still a hypothesis.
4. Do real events decode like the hand-built fixtures? Copy `raw_events` entries into `testdata/kernel-network-events.json` and `testdata/winnat-session-events.json`, then rerun `cargo test -p sieve-engine flow::`. A raw entry holds at most 112 bytes, which covers every field the decoders read.

## L2: ETW

1. Does the session start under the trimmed `REQUIRED_PRIVILEGES` token? If it does not, `last_error` says `attribution without ETW`, routing continues, and a privilege decision follows.
2. Measure real delivery latency with the flush nudge, against the 2000 ms `ETW_MATCH_WINDOW_MS`. Do one-shot UDP sockets now get a PID before the 250 ms give-up?
3. `etw_found` is above 0, and `etw_disagreed` is 0 or explained. Do PIDs for svchost-hosted DNS agree with the owner tables?
4. `logman query -ets` shows no `SieveEngineAttribution` after each of: a stop, a kill plus restart, `restore`, `uninstall`.
5. A kill recovers the network as before.

## L3: NAT

1. WMI query latency and CPU under `LocalSystem`. Are reads under `NAT_READ_TIMEOUT_MS`?
2. How often does a forwarded UDP flow collide with a host wildcard-bound port? This measures the limit recorded at `Relay::attribute`: a session newer than the last read can slip past the held check. If WinNAT avoids host-bound ports, the limit is moot.
3. Forwarded flows appear in Apps under "Virtual machines and WSL" with real names.

## L4: acceptance

The new 30-minute run. The gate stays 0.95 of all flows, and the relay CPU gate must still pass with ETW on. A UDP-heavy case measures what event 42 costs.

This stream may not reach 0.95 alone: unnamed forwarded and unexplained flows are misses by decision 1. Both rates show in the check's detail.

## Not provable here

That a guest's traffic is actually filtered and never decrypted. That needs domain-policy merged and its own live run.
