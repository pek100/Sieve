# Live check: engine slice 2 (service, pipe, install, uninstall)

For the user, with a verifier reading the evidence. Agents never run any of this (plan section 9: no installer, no service, no elevation). Script: `scripts/live/engine-install.ps1`. Every step prints PASS or FAIL per check and appends to `C:\Users\Public\sieve-engine-live\results.txt`; the listings, `sc` outputs and ACLs it read sit beside it. Send that folder to the verifier.

What slice 2 installs: the install folder you pick (default `C:\Program Files\Sieve\`; the app, `sieve-engine.exe` and `sieve-install.marker`), the `sieve-engine` service (LocalSystem, automatic start), `C:\ProgramData\Sieve\engine\state.json`. The engine changes nothing about traffic: no adapter, no route, no DNS, proxy or firewall change. So every network listing must match the before-listing at every step.

The install folder (finding of the first run, 2026-10-18). The installer still lets you choose the folder. The first run installed to `E:\Sieve`, which inherited "Authenticated Users: Modify" from `E:\`, so any user could have replaced the SYSTEM service's exe. Now the installer locks whatever folder you choose before it copies anything into it: owner Administrators, inheritance off, SYSTEM and Administrators full control, Users read and execute. A new or empty folder is accepted (it gets `sieve-install.marker`), and so is a folder an earlier Sieve install marked. A folder that already holds other files is refused on the folder page and again during the install, because locking it could break those files. The engine itself refuses to register its service (exit code 3, "binary folder: FAILED, refused: ...") and refuses to start (service exit code 3, reason in `last-error.txt`) when anyone other than SYSTEM, Administrators or TrustedInstaller can change its exe, a file beside it, its folder or a folder above it. The 0.1.0 build from the first run left `E:\Sieve` without a marker: uninstall it first (Settings > Apps, or let the new installer's "uninstall first" choice do it), or the new installer refuses that folder while files remain in it.

## Before you start

- Build the installer (already built on the branch; rebuild after any change): `pnpm tauri build` in the worktree. The installer is `src-tauri\target\release\bundle\nsis\Sieve_0.1.0_x64-setup.exe`.
- Uninstall any earlier Sieve. Close `pnpm tauri dev`.
- AdGuard may stay on: slice 2 does not touch traffic.
- For the second-user step you need another local Windows account that is a standard user (Settings > Accounts > Other users > Add account, "I don't have this person's sign-in information", "Add a user without a Microsoft account"). Give it a password.

Open Terminal (Admin) and `cd` to the worktree. Run each step with
`powershell -ExecutionPolicy Bypass -File scripts\live\engine-install.ps1 -Step <step>`.

## Steps

1. **`-Step before`** (admin). Saves the before-listings (`Get-NetRoute`, `Get-DnsClientServerAddress`, `netsh winhttp show proxy`, the active firewall rules, `route print`) and checks that lookups and HTTPS work and that no `sieve-engine` service exists.
2. **`-Step install`** (admin). Runs the installer; approve UAC and click through. Any folder is fine, `E:\Sieve` included, as long as it is new or empty. The script waits for the service (the installer relaunches itself elevated, so the first process returns early), finds the folder from the service's registered path, then checks:
   - `sc qc sieve-engine`: `SERVICE_START_NAME : LocalSystem`, `START_TYPE : 2 AUTO_START`, binary is `sieve-engine.exe` in the folder you chose;
   - `sc queryex`: RUNNING, and the exit code is not 3 (the engine did not refuse its folder); `sc qfailure`: two restarts after 5000 ms, reset after 3600 s; `sc qprivs`: the engine's required privileges only (slice 3: SeChangeNotifyPrivilege, SeLoadDriverPrivilege, SeBackupPrivilege, SeRestorePrivilege);
   - the install folder's DACL is protected (no inherited ACEs) and grants write only to SYSTEM and Administrators; the binary folder grants no write to non-admins: no file in it (the engine included) is owned by, or writable by, anyone else (read by SID with `Get-Acl`; `icacls` output saved as `install-folder-acl.txt` and `install-engine-acl.txt`); `sieve-install.marker` is there; no `last-error.txt`;
   - `icacls C:\ProgramData\Sieve`: SYSTEM and Administrators only, inherited;
   - `state.json` records your SID; the pipe's DACL has exactly three entries (SYSTEM, Administrators, you);
   - every listing matches the before-listing; lookups and HTTPS work.
   **`-Step verify`** (admin) runs the same checks against an existing install without running the installer again, for example when the install step stopped early.
3. **`-Step app`** (any). Open Sieve from the Start menu, Settings > Filtering: the Engine block must say **Installed, not filtering** and **Engine version 0.1.0**. Optionally start `pnpm tauri dev` too: that copy is not in Program Files, so the engine refuses it and the block says **Installed** with "This copy of Sieve is not the installed one".
4. **`-Step pipe-open`** as the second, standard user. From your admin terminal:
   `runas /user:<other user> "powershell -ExecutionPolicy Bypass -File <worktree>\scripts\live\engine-install.ps1 -Step pipe-open"`
   (if that account cannot read the worktree, copy the script to `C:\Users\Public` and point at the copy). Expected: **ACCESS DENIED**: Windows refuses the open because that account is not in the pipe's DACL. If you have no second account, the same denial is shown offline by the test `ipc::server::tests::an_account_not_in_the_dacl_cannot_open_the_pipe` (`cargo test -p sieve-engine` in `engine/`), which opens a real pipe with this DACL minus the owner entry from an unelevated account.
5. **`-Step kill`** (admin). `taskkill /F` on the engine's process. Within 5 s lookups and HTTPS work and every listing matches the before-listing; 10 s later the service manager has restarted the engine (recovery: restart after 5 s).
6. **`-Step reboot-prep`** (admin), then reboot. It sets the service to manual start, as the rule's reboot test asks.
7. **`-Step after-reboot`** (admin), after signing in. Lookups and HTTPS work, the listings match, the engine did not start. The step then sets automatic start again and starts it.
8. **`-Step uninstall`** (admin). Runs `sieve-engine.exe uninstall` twice (both must succeed: the verb is idempotent), then the Sieve uninstaller (approve UAC; its hook runs the verb a third time, through the engine the service is registered with). Expected: no `sieve-engine` service (`sc query` says 1060), no `C:\ProgramData\Sieve`, nothing at `HKLM\SYSTEM\CurrentControlSet\Services\sieve-engine`, no `sieve-engine.exe` and no install folder left, the listings match the before-listing, lookups and HTTPS work.

Optional, the refusal (no script step, nothing is installed): make a folder with one file in it, for example `C:\Users\Public\not-sieve\note.txt`, run the installer and pick that folder. Expected: on Next, a message that the folder already holds files Sieve's installer did not put there, and the installer stays on the folder page. Cancel, then delete the folder.

If the engine stops by itself, why is in `C:\ProgramData\Sieve\engine\last-error.txt` (readable from an admin prompt).

The emergency off, at any time from an admin prompt: `"<install folder>\sieve-engine.exe" restore` deletes every route on an interface named "Sieve" (none exist in slice 2) and stops the service.

## What the verifier reads

- `results.txt`: every PASS and FAIL with the step and the user that ran it.
- `install-sc-*.txt`, `install-folder-acl.txt`, `install-engine-acl.txt`, `install-programdata-acl.txt`, `install-pipe-acl.txt`, `pipe-open-<user>.txt`.
- `<step>-routes.txt`, `<step>-dns.txt`, `<step>-proxy.txt`, `<step>-firewall.txt`, `<step>-route-print.txt`, and a `-diff.txt` for any listing that changed. A firewall diff can come from other software updating its rules; the verifier checks that no rule names Sieve.
