# Live check: engine slice 2 (service, pipe, install, uninstall)

For the user, with a verifier reading the evidence. Agents never run any of this (plan section 9: no installer, no service, no elevation). Script: `scripts/live/engine-install.ps1`. Every step prints PASS or FAIL per check and appends to `C:\Users\Public\sieve-engine-live\results.txt`; the listings, `sc` outputs and ACLs it read sit beside it. Send that folder to the verifier.

What slice 2 installs: `C:\Program Files\Sieve\` (the app and `sieve-engine.exe`), the `sieve-engine` service (LocalSystem, automatic start), `C:\ProgramData\Sieve\engine\state.json`. The engine changes nothing about traffic: no adapter, no route, no DNS, proxy or firewall change. So every network listing must match the before-listing at every step.

## Before you start

- Build the installer (already built on the branch; rebuild after any change): `pnpm tauri build` in the worktree. The installer is `src-tauri\target\release\bundle\nsis\Sieve_0.1.0_x64-setup.exe`.
- Uninstall any earlier Sieve. Close `pnpm tauri dev`.
- AdGuard may stay on: slice 2 does not touch traffic.
- For the second-user step you need another local Windows account that is a standard user (Settings > Accounts > Other users > Add account, "I don't have this person's sign-in information", "Add a user without a Microsoft account"). Give it a password.

Open Terminal (Admin) and `cd` to the worktree. Run each step with
`powershell -ExecutionPolicy Bypass -File scripts\live\engine-install.ps1 -Step <step>`.

## Steps

1. **`-Step before`** (admin). Saves the before-listings (`Get-NetRoute`, `Get-DnsClientServerAddress`, `netsh winhttp show proxy`, the active firewall rules, `route print`) and checks that lookups and HTTPS work and that no `sieve-engine` service exists.
2. **`-Step install`** (admin). Runs the installer; approve UAC and click through. Then checks:
   - `sc qc sieve-engine`: `SERVICE_START_NAME : LocalSystem`, `START_TYPE : 2 AUTO_START`, binary in `C:\Program Files\Sieve`;
   - `sc queryex`: RUNNING; `sc qfailure`: two restarts after 5000 ms, reset after 3600 s; `sc qprivs`: SeChangeNotifyPrivilege only;
   - `icacls C:\ProgramData\Sieve`: SYSTEM and Administrators only, inherited;
   - `state.json` records your SID; the pipe's DACL has exactly three entries (SYSTEM, Administrators, you);
   - every listing matches the before-listing; lookups and HTTPS work.
3. **`-Step app`** (any). Open Sieve from the Start menu, Settings > Filtering: the Engine block must say **Installed, not filtering** and **Engine version 0.1.0**. Optionally start `pnpm tauri dev` too: that copy is not in Program Files, so the engine refuses it and the block says **Installed** with "This copy of Sieve is not the installed one".
4. **`-Step pipe-open`** as the second, standard user. From your admin terminal:
   `runas /user:<other user> "powershell -ExecutionPolicy Bypass -File <worktree>\scripts\live\engine-install.ps1 -Step pipe-open"`
   (if that account cannot read the worktree, copy the script to `C:\Users\Public` and point at the copy). Expected: **ACCESS DENIED**: Windows refuses the open because that account is not in the pipe's DACL. If you have no second account, the same denial is shown offline by the test `ipc::server::tests::an_account_not_in_the_dacl_cannot_open_the_pipe` (`cargo test -p sieve-engine` in `engine/`), which opens a real pipe with this DACL minus the owner entry from an unelevated account.
5. **`-Step kill`** (admin). `taskkill /F` on the engine's process. Within 5 s lookups and HTTPS work and every listing matches the before-listing; 10 s later the service manager has restarted the engine (recovery: restart after 5 s).
6. **`-Step reboot-prep`** (admin), then reboot. It sets the service to manual start, as the rule's reboot test asks.
7. **`-Step after-reboot`** (admin), after signing in. Lookups and HTTPS work, the listings match, the engine did not start. The step then sets automatic start again and starts it.
8. **`-Step uninstall`** (admin). Runs `sieve-engine.exe uninstall` twice (both must succeed: the verb is idempotent), then the Sieve uninstaller (approve UAC; its hook runs the verb a third time). Expected: no `sieve-engine` service (`sc query` says 1060), no `C:\ProgramData\Sieve`, nothing at `HKLM\SYSTEM\CurrentControlSet\Services\sieve-engine`, no `sieve-engine.exe` left, the listings match the before-listing, lookups and HTTPS work.

The emergency off, at any time from an admin prompt: `"C:\Program Files\Sieve\sieve-engine.exe" restore` deletes every route on an interface named "Sieve" (none exist in slice 2) and stops the service.

## What the verifier reads

- `results.txt`: every PASS and FAIL with the step and the user that ran it.
- `install-sc-*.txt`, `install-programdata-acl.txt`, `install-pipe-acl.txt`, `pipe-open-<user>.txt`.
- `<step>-routes.txt`, `<step>-dns.txt`, `<step>-proxy.txt`, `<step>-firewall.txt`, `<step>-route-print.txt`, and a `-diff.txt` for any listing that changed. A firewall diff can come from other software updating its rules; the verifier checks that no rule names Sieve.
