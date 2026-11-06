# Live check: engine slice 5 (root CA, Firefox, removal)

For the user, with a verifier reading the evidence. Agents never run any of this: no key, store or registry write has run on a real system yet. Script: `scripts/live/engine-ca.ps1`. Every step prints PASS or FAIL per check and appends to `C:\Users\Public\sieve-engine-live\results-ca.txt`; `cargo test -p sieve-engine live_root_ca_trust_and_removal -- --ignored` reads it back. Send that folder to the verifier.

What slice 5 changes: while `policy.https` is on, one CNG key (`Sieve root <16 hex>`, machine scope, SYSTEM only), one root in `LocalMachine\Root`, the Firefox policy value when Firefox is installed and the value is absent, and `ProgramData\Sieve\engine\ca.json` (names, thumbprints and dates only). Nothing decrypts: `decrypting` stays false, and no traffic changes, so the kill, reboot and uninstall network listings apply at slice 6.

## Why the script drives the switch

`filtering.https` stays hidden until slice 6 builds interception (decision 17 of `docs/tasks/2026-11-02-root-ca.md`), so the app reads it as off and sends `https: false` whenever it runs. The script therefore works with the app closed: elevated, it stops the service, writes `policy.json` with `https: true` and a higher revision, and starts it. No new verb, build or production surface. Opening the app while the root is installed removes it, which is check 4 by another path.

## Before you start

- Build and install the current branch (`pnpm tauri build`, then the installer). Close the app.
- AdGuard may stay on: slice 5 does not touch traffic.
- Open Terminal (Admin) and `cd` to the worktree. Run each step with
  `powershell -ExecutionPolicy Bypass -File scripts\live\engine-ca.ps1 -Step <step>`.

## Steps

1. **`-Step before`**. Saves the root store, the key listing and the Firefox value.
2. **`-Step on`**. Turns the switch on through `policy.json`, waits for `ca.json` to record a root, then checks items 1 to 3 of plan 7.2:
   - the root is in the store under its recorded thumbprint, CA true, path length 0, Server Authentication only, and the store's property is Server Authentication only;
   - the key is a machine key of the Microsoft Software Key Storage Provider, not exportable, DACL SYSTEM only. Read `key-detail.txt`: decision 11 assumes an elevated admin is refused this key, and that is a claim only this run can settle. Say what you saw;
   - no file under `ProgramData\Sieve` holds key material;
   - the Firefox value matches what `ca.json` says Sieve did.
3. **Firefox, by hand, if it is installed.** Open `about:certificate` or Settings > Certificates > View Certificates > Authorities: the root is listed. Say whether Firefox showed it before the policy value too (whether current Firefox honours enterprise roots by default, plan 2.3, is open). A per-user Firefox install may not be seen by SYSTEM's detection; say which kind you have.
4. **`-Step restart`**. The same thumbprint after a service restart, and the key opens as SYSTEM.
5. **Reboot (by hand), then look.** After sign-in, `Get-Content C:\ProgramData\Sieve\engine\ca.json` names the same thumbprint, `certutil -store Root <thumbprint>` still shows it, and `withdrawn` in `ca.json` is still false (a key that would not open sets it).
6. **`-Step off`**. Writes `https: false`: root, policy (if Sieve set it) and key go. Item 4 of plan 7.2.
7. **The update path, by hand.** Run `-Step on` again, then `sieve-engine.exe restore`, then `sieve-engine.exe install` from the install folder. The root and `ca.json` are still there: an update must not strand them.
8. **Reinstall in the real window.** A store add and remove pair otherwise happens only at a real rotation, a year away, so Reinstall is the live stand-in. This needs a build with `filtering.https` shown, so it waits for slice 6 unless you want the switch shown now (open question 1 of the task). The fake-clock tests prove rotation's timing only.
9. **`-Step uninstall`** (after `-Step on`). The real verb: routes, stop, trust, ca keys (the service starts once with `purge-ca-keys`), delete service, program data. Root, key, policy, service and `ProgramData\Sieve` are all gone. If anything was left, the verb reports FAILED; `ca.json` and the service stay (the service set to start on demand, because a rerun reaches the keys only through it), and rerunning `sieve-engine.exe uninstall` finishes the job once the cause is gone. Run from the installer, a failed verb also leaves the engine's files in the install folder and shows that command; after the rerun, delete that folder by hand, or instead install and uninstall Sieve again, which removes them. A failed uninstall is not forced here, so this recovery has only run against fakes. If you do see it, say what the rerun printed. Item 4 of plan 7.2.
10. **The Certificate group** (Settings > Filtering, needs a running engine): state, valid until, thumbprint (press to copy), Firefox, last rotation, in the real Tauri window, and the two new commands over the real pipe.

## Not here

Interception by browsers is slice 6, and the empty-subject leaf is first seen by real clients there. Its check is `live_https_intercepts_public_and_passes_floor`, with the runbook in `docs/live/engine-slice-6.md`.
