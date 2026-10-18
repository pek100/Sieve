# Task: an unattended slice 3 live check (one elevated command, no prompts)

## Why

The user runs Sieve's engine slice 3 live check from an elevated PowerShell. The current flow
(`scripts/live/run-slice-3.ps1` wrapping `scripts/live/engine-route.ps1`) keeps stopping for clicks in the
Sieve app and for y/n questions, and the user is the bottleneck. They want ONE command they start and walk
away from: one UAC approval, then nothing until a summary.

You WRITE and dry-run the script. You never run it elevated. The user runs it.

## Read first

`scripts/live/engine-route.ps1`, `scripts/live/run-slice-3.ps1`, `scripts/live/engine-install.ps1` (its
trap pattern and the GetNamedSecurityInfo pipe read), `docs/live/engine-slice-3.md`, and how the engine
persists and reads its policy: `engine/crates/sieve-engine/src` (policy.json in
`C:\ProgramData\Sieve\engine`, status.json, runs.json, the crash-loop rule, how policy changes reach the
running service). Also `src/data/engine-controller.ts`: the app sends its `filtering.engine` value to the
engine whenever they differ, so the Sieve app MUST be closed during an unattended run, or it fights the
script.

## Build `scripts/live/run-slice-3-auto.ps1`

No `Read-Host` anywhere.

- **Preflight.**
  - Assert admin.
  - If any `sieve.exe` UI process runs, ask it to close and wait up to 60 s; then refuse with a clear
    message.
  - The installed engine service `sieve-engine` must exist and run.
- **Routing on and off without the app.**
  - Use the engine's own mechanism exactly as the engine code expects (revision increasing, exact format).
  - If the engine reads policy.json only at start, write it, then restart the service. If there is no
    safe file path, add a minimal elevated-only verb `sieve-engine.exe policy on|off` (admin-only through
    the install folder's ACL; logged), with a unit test, and say why.
  - Track every state you change, and ALWAYS restore it in a `finally`: routing OFF, and AdGuard's service
    RUNNING again if it was running at the start.
- **AdGuard.**
  - While "Adguard Service" runs, check the refusal from status.json's `blocker`.
  - Then `sc.exe stop "Adguard Service"` (starting this script is the user's approval), check the engine
    routes, and at the end `sc.exe start "Adguard Service"`.
- **UI questions.** Each y/n question becomes an automatic check of engine facts. UI-only questions ("the
  app shows X") are recorded as `SKIP (UI, covered by e2e: <spec>)`, never PASS.
- **Steps, in order:**
  - before (routing off);
  - adguard (refusal, then pause);
  - on;
  - soak: default 30 minutes, `-SoakMinutes`; a countdown plus the engine's counters every minute; the user
    just uses the PC;
  - kill;
  - stall: the build at `engine\target\stall\release\sieve-engine.exe`; skip with a reason if missing;
  - budget: if the user is active, the idle-CPU figure is advisory, so record the value and say why;
  - adguard-back.
  The reboot test stays separate: print its two commands at the end.
- **Kill timing.** Measure from the kill to the FIRST successful lookup plus HTTPS, polling every 250 ms
  from t=0. Use a fast target with a short timeout (for example `curl -I https://www.cloudflare.com -m 3`)
  and record the target. The last live run measured 5.3 to 5.6 s, because a single curl to example.com
  after a 1 s sleep itself took about 4.5 s.
- **Attribution.** Measure since routing came on in THIS run: take a counter baseline at "on".
- **Results and output.**
  - Append to `C:\Users\Public\sieve-engine-live\results-route.txt` under a run header marked AUTO.
  - Use a never-silent `trap` (as in engine-install.ps1).
  - End with a summary table; the exit code is the number of failed checks.
- **`-DryRun`.** Prints every planned action and changes nothing. Use it to self-test unelevated.

## Run

- PowerShell parser: 0 errors.
- `-DryRun` end to end, unelevated, with its output pasted into your report.
- If you add an engine verb: `cargo test` and `cargo clippy --all-targets -D warnings` in `engine/`.
- Update `docs/live/engine-slice-3.md` with the one-command flow and the exact command.

## UNVERIFIED (list in your report)

The real elevated run, all of it: the user runs it.

## Limits

No em dash U+2014. Never run anything elevated, stop or start services, touch `E:\Sieve`, its
ProgramData, AdGuard or network settings. Never commit `features = []` churn.
