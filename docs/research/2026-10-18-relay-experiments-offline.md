# Relay experiments: executor evidence

This is an offline implementation, not CPU, throughput, MTU or watchdog live evidence. No engine, probe, installer, service, browser or network-setting command was run. Rust compilation and tests remain for the verifier.

## Commands observed

Node commands below used this PowerShell prefix in this worktree:

```powershell
$env:PATH = "C:\Program Files\cursor\resources\app\resources\helpers;" + $env:PATH
```

`node scripts/gate.mjs` failed with `MODULE_NOT_FOUND`: this Sieve checkout has no such script. There was no TypeScript/build pass from that command.

`node node_modules/vitest/vitest.mjs run tests/laws/engine-network.test.ts tests/laws/em-dash.test.ts` failed before tests with `EPERM` when Vite attempted to write its bundled config under the shared `node_modules` junction. Adding `--configLoader runner --no-cache --no-fsModuleCache` avoided that write, but jsdom startup failed with `ERR_REQUIRE_ESM`. Adding `--environment node` then failed in the repository's browser-only setup with `ReferenceError: window is not defined`.

The laws themselves do not use a DOM. A temporary config, removed before handoff, selected Node and no browser setup, with caches disabled and any Vite cache confined to the worktree. Exact successful setup and command:

```powershell
@'
const fs = require('fs');
fs.writeFileSync('.relay-vitest.config.mjs', 'export default { cacheDir: ".relay-vitest-cache", test: { environment: "node", setupFiles: [], cache: false, fsModuleCache: false } };\n');
'@ | node
node node_modules/vitest/vitest.mjs run tests/laws/engine-network.test.ts tests/laws/em-dash.test.ts --config .relay-vitest.config.mjs --configLoader runner
```

Observed: `Test Files 2 passed (2)`, `Tests 6 passed (6)`. This verifies the selected source laws only, not the Rust implementation.

`node scripts/check-relay-experiments.mjs 4328141e068a6e776e699196eb62802f9c8508f2` printed:

```text
PASS: original relay_tcp source unchanged
PASS: original TUN reader loop unchanged
PASS: release profile unchanged
PASS: attribution and DNS sources unchanged
PASS: ipstack packet buffer follows MTU; existing datagram and ring sizing retained
```

`git diff --check` reported no whitespace errors. The source audit normalizes CRLF before comparison; it does not compare executable bytes or claim runtime equivalence.

## Dependency inspection

Read commands included `Get-Content engine/vendor/ipstack/src/lib.rs`, `Get-Content engine/vendor/ipstack/src/stream/udp.rs`, and `Get-Content engine/crates/sieve-engine/src/stack/relay.rs`. The packet buffer uses `config.mtu as usize + offset`; the UDP datagram buffer retains its existing maximum IP length. The UDP writer uses MTU minus header lengths and can consume only part of a datagram; this existing behavior is not changed here.

The accessible published [Wintun session source](https://docs.rs/wintun-bindings/0.7.40/src/wintun_bindings/session.rs.html) provides `try_receive`, `receive_blocking`, `shutdown` and a packet length bounded by `u16`. The [adapter API](https://docs.rs/wintun-bindings/0.7.40/wintun_bindings/struct.Adapter.html) requires a power-of-two ring within its exported limits. The [Tokio copy documentation](https://docs.rs/tokio/1.53.3/tokio/io/fn.copy.html) supplies the default copy-buffer size used in status reporting. A Rust test probes that size against the dependency; that test has not run here. Published source inspection does not verify the local Windows dependency build or adapter behavior.

## Verifier work, not run

Run from `engine/`:

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -p sieve-engine --features relay-experiments
cargo clippy --workspace -p sieve-engine --features relay-experiments --all-targets -- -D warnings
cargo build --profile release-lto -p sieve-engine --features relay-experiments
```

All changed Rust and Cargo code is uncompiled in this executor session: settings and refusal reasons, status serialization, worker selection, adapter/stack MTU wiring, pooled batching and shutdown, heartbeat behavior, buffered relay and classifier-tail preservation, deletion classification/counts/reporting, and the inherited LTO profile. Added unit tests cover parser boundaries and malformed inputs, status snapshots, MTU dependency bounds, packet ordering and slab reuse, short drains and filtering, watchdog timing under backpressure, duplex copy integrity at both capacity bounds, and fake route-delete codes. Their presence is not a passing result.

Live measurements are wholly unverified: adapter MTU in both address families, CPU, throughput, QUIC, large UDP replies, path MTU, watchdog/kill recovery and memory under sustained load. The controller must compare each experiment independently on the same workload. No performance improvement is claimed. Production behavior equivalence is also unmeasured beyond the source-preservation checks above. The diagnostic relay deliberately retains a separate feature-gated implementation to leave the original relay intact; future changes to shared relay semantics need corresponding changes and tests in both paths.
