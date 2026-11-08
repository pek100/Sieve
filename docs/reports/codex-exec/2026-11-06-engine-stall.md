# Codex exec - `engine-stall`

- tag: `engine-stall`
- base: `main` = `14a17c1a15b9d029f02e42a343f9c9102584ec80`
- branch: `codex-engine-stall`
- worktree: `F:\Projects\Code\Sieve\.claude\worktrees\codex-engine-stall`
- executor: codex-cli 0.166.0 (gpt-6-astra), sandbox `workspace-write`, extra writable: none, node for the sandbox: `C:\Program Files\cursor\resources\app\resources\helpers` (v20.18.2)
- exit: 0, duration: 856s, run: 2026-11-06
- prompt: `F:\Projects\Code\Sieve\docs\tasks\2026-11-07-codex-engine-stall.md` (plus the standing executor preamble in `tooling\codex-exec\run-task.ps1`)
- commit on Codex's behalf (`commit-on-behalf.ps1`): **d7ca774b0f174d9874561f8b853aaa4e822ed1b7**

## Commits on `codex-engine-stall` (`git log --oneline 14a17c1..HEAD`)

```
d7ca774 Detect packet-path stalls and terminate failed adapter readers
```

## Worktree state after the commit step (`git status --short`)

```
(clean)
```

<details><summary>commit-on-behalf output</summary>

```
[codex-exec] commit-on-behalf: staging 12 path(s), committing (the gate runs now)
[codex-exec] commit-on-behalf: committed d7ca774
d7ca774b0f174d9874561f8b853aaa4e822ed1b7
```
</details>

## Codex's last message, verbatim

## FILES

CODEX-COMMIT.txt prepared for the driver. First line:

`Detect packet-path stalls and terminate failed adapter readers`

Final `git status --short --untracked-files=all` paths:

```text
CODEX-COMMIT.txt
docs/live/engine-slice-3.md
docs/live/engine-stall-offline.md
engine/crates/sieve-engine/src/control/mod.rs
engine/crates/sieve-engine/src/control/routing.rs
engine/crates/sieve-engine/src/stack/mod.rs
engine/crates/sieve-engine/src/tun/batch.rs
engine/crates/sieve-engine/src/tun/device.rs
engine/crates/sieve-engine/src/watchdog.rs
engine/crates/sieve-engine/src/watchdog/path.rs
engine/crates/sieve-engine/src/watchdog/path_tests.rs
engine/vendor/ipstack/src/lib.rs
engine/vendor/ipstack/src/progress.rs
```

## VERIFIED

Fixed EOF spinning and read errors silently disabling input. Added packet-stage watchdog timers, status reporting, and reproduction documentation.

| Exact command | Observed result |
|---|---|
| `cargo test --offline --manifest-path engine/Cargo.toml -p sieve-engine --lib watchdog::path_tests::adapter_ -- --nocapture` | Before fix: 2 failed, reproducing both read defects. |
| `cargo test --offline --manifest-path engine/Cargo.toml -p sieve-engine --lib watchdog:: -- --nocapture` | After fix: 12 passed. Covers stalls, idle/slow progress, stage names and mocked routes-before-exit order. |
| `cargo test --offline --manifest-path engine/Cargo.toml -p sieve-engine --lib control::tests::packet_path_status -- --nocapture` | 1 passed. |
| `cargo test --offline --manifest-path engine/Cargo.toml -p sieve-engine --features relay-experiments --lib tun::batch:: -- --nocapture` | 3 passed. |
| `cargo test --offline --manifest-path engine/Cargo.toml --workspace -- --quiet` | 1220 passed, 2 failed, 12 ignored. Failures were existing ACL tests reporting Access Denied. Cargo stopped before subsequent targets. |
| `$env:PATH = "C:\Program Files\cursor\resources\app\resources\helpers;" + $env:PATH; node scripts/gate.mjs` | `MODULE_NOT_FOUND`; script absent. |
| `git diff --check` | No output. |

## UNVERIFIED

The VM cause remains unknown. Candidates ranked by fit, with detailed falsifiers in [the investigation](F:/Projects/Code/Sieve/.claude/worktrees/codex-engine-stall/docs/live/engine-stall-offline.md):

1. Device-write error terminating ipstack, `engine/vendor/ipstack/src/lib.rs:360`.
2. Reader termination mishandling, `engine/vendor/ipstack/src/lib.rs:335`.
3. Dispatch/output stall before the input queue fills, `engine/vendor/ipstack/src/lib.rs:461`.
4. Shared locks or blocking TCP destruction, `engine/vendor/ipstack/src/stream/tcp.rs:455`.
5. Session/task/queue accumulation, `engine/vendor/ipstack/src/lib.rs:324`.
6. DNS upstream exhaustion, `engine/crates/sieve-engine/src/dns/service.rs:251`.

Live browser reproduction, Wintun behavior, actual route removal, restart/connectivity recovery, timing and performance remain unverified. A relay can still hang while ipstack continues dispatching; these counters do not prove application-level success.

Remaining workspace targets, unrestricted ACL checks and the driver-created commit are pending.

<details><summary>run log tail (last 40 lines)</summary>

```
engine/crates/sieve-engine/src/control/mod.rs
engine/crates/sieve-engine/src/control/routing.rs
engine/crates/sieve-engine/src/stack/mod.rs
engine/crates/sieve-engine/src/tun/batch.rs
engine/crates/sieve-engine/src/tun/device.rs
engine/crates/sieve-engine/src/watchdog.rs
engine/crates/sieve-engine/src/watchdog/path.rs
engine/crates/sieve-engine/src/watchdog/path_tests.rs
engine/vendor/ipstack/src/lib.rs
engine/vendor/ipstack/src/progress.rs
```

## VERIFIED

Fixed EOF spinning and read errors silently disabling input. Added packet-stage watchdog timers, status reporting, and reproduction documentation.

| Exact command | Observed result |
|---|---|
| `cargo test --offline --manifest-path engine/Cargo.toml -p sieve-engine --lib watchdog::path_tests::adapter_ -- --nocapture` | Before fix: 2 failed, reproducing both read defects. |
| `cargo test --offline --manifest-path engine/Cargo.toml -p sieve-engine --lib watchdog:: -- --nocapture` | After fix: 12 passed. Covers stalls, idle/slow progress, stage names and mocked routes-before-exit order. |
| `cargo test --offline --manifest-path engine/Cargo.toml -p sieve-engine --lib control::tests::packet_path_status -- --nocapture` | 1 passed. |
| `cargo test --offline --manifest-path engine/Cargo.toml -p sieve-engine --features relay-experiments --lib tun::batch:: -- --nocapture` | 3 passed. |
| `cargo test --offline --manifest-path engine/Cargo.toml --workspace -- --quiet` | 1220 passed, 2 failed, 12 ignored. Failures were existing ACL tests reporting Access Denied. Cargo stopped before subsequent targets. |
| `$env:PATH = "C:\Program Files\cursor\resources\app\resources\helpers;" + $env:PATH; node scripts/gate.mjs` | `MODULE_NOT_FOUND`; script absent. |
| `git diff --check` | No output. |

## UNVERIFIED

The VM cause remains unknown. Candidates ranked by fit, with detailed falsifiers in [the investigation](F:/Projects/Code/Sieve/.claude/worktrees/codex-engine-stall/docs/live/engine-stall-offline.md):

1. Device-write error terminating ipstack, `engine/vendor/ipstack/src/lib.rs:360`.
2. Reader termination mishandling, `engine/vendor/ipstack/src/lib.rs:335`.
3. Dispatch/output stall before the input queue fills, `engine/vendor/ipstack/src/lib.rs:461`.
4. Shared locks or blocking TCP destruction, `engine/vendor/ipstack/src/stream/tcp.rs:455`.
5. Session/task/queue accumulation, `engine/vendor/ipstack/src/lib.rs:324`.
6. DNS upstream exhaustion, `engine/crates/sieve-engine/src/dns/service.rs:251`.

Live browser reproduction, Wintun behavior, actual route removal, restart/connectivity recovery, timing and performance remain unverified. A relay can still hang while ipstack continues dispatching; these counters do not prove application-level success.

Remaining workspace targets, unrestricted ACL checks and the driver-created commit are pending.
```
</details>

---

NOT MERGED. The worktree is left in place on purpose: a Claude agent verifies these claims against
evidence, then the orchestrator merges `codex-engine-stall` and deletes the worktree.