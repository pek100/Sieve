# Task: switchable relay CPU experiments (E2 to E5) and route-delete codes

## Why

Slice 3 failed its relay CPU gate: 0.222 cores per 100 Mbit/s against 0.15 (about 26 us per 1500-byte packet, 58% of samples in the kernel). The plan, `docs/plans/2026-10-18-slice-3-attribution-and-cpu.md` section 3, lists experiments E2 to E6. Each must be measured on its own against the same workload. Every engine binary swap needs an elevated reinstall, so the live controller should be able to A/B the experiments with ONE diagnostic binary, by stopping the service, editing a file and starting it again. Production behaviour must not change.

## Read first

docs/conventions.md (engine sections); docs/plans/2026-10-18-slice-3-attribution-and-cpu.md; engine/crates/sieve-engine/src/tun/mod.rs and tun/device.rs; src/control/routing.rs (stack config, `config.mtu`); src/flow/relay.rs (`relay_tcp`, the 16 KiB client buffer and the `tokio::io::copy` calls); src/stack/relay.rs; src/control/mod.rs (how status.json is written, how policy.json is read at start, the engine dir); src/stack/diagnostics.rs and the `attribution-diagnostics` feature (the pattern to copy: a cargo feature, off by default, compiled out entirely); src/route/mod.rs:65 and src/route/apply.rs:93 (`DeleteIpForwardEntry2`); engine/Cargo.toml `[profile.release]`.

## Build

1. A cargo feature `relay-experiments` on `sieve-engine`, off by default. With the feature off, the code compiles out entirely and behaviour is byte-for-byte today's.
2. With the feature on, the engine reads `experiments.json` once at start, from the engine's existing admin-only ProgramData directory (the same directory as policy.json). The file is optional. Missing or invalid means today's values, and the reason is recorded. Every field is optional, with the default in brackets:
   - `tun_mtu` (1500): the Wintun adapter MTU AND the ipstack MTU together. Accept 1280 to 65535 only, otherwise refuse the whole file. Check `wintun-bindings` and ipstack for limits and buffer sizes that assume 1500 (packet buffers, `DATAGRAM`, ring size), and size them from the MTU, not from new constants.
   - `copy_buffer_bytes` (today's sizes): the relay's upstream-to-app and app-to-upstream copy buffers. Use `tokio::io::copy_buf` over a `BufReader` with this capacity. Accept 8 KiB to 1 MiB.
   - `tun_batch` (1, meaning today's one packet per wake): the most packets the TUN reader thread drains per `receive_blocking` wake, sent as one batch through the channel, with pooled buffers in place of the per-packet `to_vec`. The watchdog heartbeat must still begin and end around each batch, so a stalled stack still trips it. Accept 1 to 256.
   - `worker_threads` (tokio's default): the runtime's worker count. Accept 1 to 64.
3. Under the feature, status.json gets an `experiments` object: the values in force, plus the file's read result (absent, ok, refused with the reason).
4. E5: add a cargo profile `release-lto` that inherits `release` with `lto = "thin"` and `codegen-units = 1`, keeping `debug = 1`. Do not change `[profile.release]`.
5. Route-delete codes (production code, no feature): where `DeleteIpForwardEntry2` is called (route/mod.rs and route/apply.rs), treat `ERROR_NOT_FOUND` as already deleted, not as failed. Count it separately (`already_gone`). For any other nonzero code, keep the actual code: count per code and include the codes in the existing log and report line. The live watchdog reported "51 failed / 119 deleted" while the journal showed 112 already gone and 0 failed. This change must make the two agree.
6. Tests (Rust unit tests; you cannot run them, see below):
   - the experiments file parser: defaults, every bound accepted and refused at each edge, unknown fields refused, a malformed file refused with its reason;
   - `tun_batch`: a fake packet source delivers N packets, they arrive in order across batches, and none is lost or duplicated at batch edges;
   - the heartbeat still brackets each batch (follow the existing watchdog test pattern);
   - the copy buffer: a relay over `tokio::io::duplex` moves a multi-megabyte payload intact at the smallest and largest buffer;
   - route deletion: a fake delete function that returns NO_ERROR, ERROR_NOT_FOUND and one other code yields the right deleted, already-gone and failed counts and keeps the code.
7. Update docs/conventions.md (engine section): the feature, the file, the profile, the code classification.

## UNVERIFIED (list in your report; the Claude verifier runs these)

- `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, and the same two with `-p sieve-engine --features relay-experiments`, from `engine/`.
- `cargo build --profile release-lto -p sieve-engine --features relay-experiments`.
- Every live measurement (MTU behaviour on a real Wintun adapter, CPU, QUIC). The live controller does these, not you.

## Limits

No em dash U+2014 anywhere. Do not install, elevate, run the engine or the probe, or touch E:\Sieve, any service, AdGuard, routes or network settings. Do not change production defaults. Do not change the attribution code (flows.rs) or the DNS code: another task owns them.

## Sieve, not another project: read this before the standards above

The preamble was written for another project. In THIS repo:
- Ignore the WebGPU, FrameGraph, two-clocks, `?flag`, metres-per-wu and Vite-port rules. Standards 1, 6 and 8 apply in full.
- There is no `tooling\procs` here. You start no GPU process, no browser and no dev server.
- cargo lives under `%USERPROFILE%`, which your sandbox cannot read, so do not try. Write the Rust carefully: the verifier compiles it. List every Rust change under UNVERIFIED with the exact cargo commands.
