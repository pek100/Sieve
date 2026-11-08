# Live check: engine slice 3 (full route, relay, DNS on the TUN, crash safety, coexistence)

`live_engine_full_route_relays_and_restores`, the live check of the `filtering.engine` switch. For the user, with a verifier reading the evidence. Agents run only the unelevated dry-run and contract checks below, never the live path (plan section 9: no installer, no service, no routes, no elevation).

Script: `scripts/live/engine-route.ps1`. Every step prints PASS or FAIL per check and appends to `C:\Users\Public\sieve-engine-live\results-route.txt`; the listings, the engine's `status.json` copies and the budget numbers sit beside it. Send that folder to the verifier. Afterwards, in the worktree, `cargo test --manifest-path engine\Cargo.toml -p sieve-engine -- --ignored live_engine_full_route_relays_and_restores` reads `results-route.txt` and passes only when every required check passed (the list is `control::LIVE_CHECKS`).

What slice 3 does when you turn routing on: the engine creates its Wintun adapter "Sieve" and routes this computer's traffic into it, except private and local ranges, every LAN you are on and any split-tunnel VPN's prefixes (those keep their normal routes). Every flow is relayed to where it was going, nothing is blocked. DNS lookups to your router (or whatever DNS server Windows uses) enter the adapter through a host route and are forwarded to that same server; Windows' DNS settings are never changed. Every route sits on the Sieve adapter in the active store only, so a stop, a kill, a crash or a reboot removes all of them. While AdGuard intercepts (one test connection tells, whatever its service's state), or a VPN that carries all traffic is connected, the engine routes nothing and says why.

Not relayed in slice 3: ICMP (ping and traceroute to the internet fail while routing is on; local pings work). UNVERIFIED until this check: the four service privileges are enough to create the adapter (if not, the Engine block shows "Could not start" with the reason and the network is untouched; send `status.json`).

## Unattended run (existing install)

Open Terminal (Admin), approve UAC, and change to this worktree. With the current normal engine already installed and its service running, run this command and leave the terminal open:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\live\run-slice-3-auto.ps1
```

There are no installer dialogs or questions in this runner. Starting it authorizes pausing `Adguard Service` for the test. It requests any `sieve.exe` window to close and refuses if the process remains after the close grace. Keep Sieve closed until the summary: `src/data/engine-controller.ts` sends the app's stored `filtering.engine` value whenever it differs from the engine policy. A tray window that hides instead of exiting must be quit before retrying. If Sieve reopens during the check, the runner aborts and cleans up; if it is still open at cleanup, the engine stays stopped with policy OFF so the UI cannot undo the cleanup.

The order is before, AdGuard refusal and pause, on, soak, kill, stall, budget, AdGuard back, then cleanup. The default soak is the existing acceptance interval; override its duration with `-SoakMinutes <minutes>`. A short override is a diagnostic run, not the full soak acceptance. The countdown prints engine counters every minute while you use the PC. The runner checks sampled routing, process identity, status freshness and HTTPS; it cannot certify that a video call or game launcher worked throughout. Attribution uses the difference from the saved on-step counter baseline, and a process restart or counter reset invalidates the measurement.

The runner uses the engine's existing admin-only file path. `service/runner.rs` loads `policy.json` at service startup, while the running engine receives changes through its authenticated pipe. The runner stops the service, writes exactly `{"revision":<successor>,"engine":<boolean>}` as atomic UTF-8 without BOM, then starts it and verifies the loaded revision in `status.json`. The successor exceeds both the persisted and last reported revisions. No new engine verb is needed. `runs.json` is read for evidence and never edited: file-based policy changes do not call `set_policy` and do not forgive a crash loop. A crash-loop blocker fails the run and requires the existing app off/on recovery separately, followed by closing the app before retrying.

Prepare the optional Stall build unelevated in this worktree, separately from the normal installer:

```powershell
cargo build --release --manifest-path engine\Cargo.toml -p sieve-engine --bin sieve-engine --features stall --target-dir engine\target\stall
```

The runner looks only at `engine\target\stall\release\sieve-engine.exe`, recording SKIP with the path if absent. It keeps the normal executable backup beside the installed executable, restores and hashes it in `finally`, and retains the backup if restoration fails. The outer cleanup independently attempts routing OFF, normal binary restoration, and AdGuard RUNNING if it was running initially. AdGuard that was absent or stopped stays that way, with its coexistence checks marked SKIP. No service startup type or recovery configuration is changed. Cleanup failures are visible failed checks, not successful restoration claims; inspect the summary before reopening Sieve.

The kill measurement launches direct lookup plus HTTPS attempts immediately after the kill, polls at the requested cadence, and records the first observed successful response from `https://www.cloudflare.com`. Each new curl resolves that hostname itself, bypasses HTTP proxies, verifies TLS and requires a successful HTTP status. Slow attempts overlap rather than delaying the next probe; all probe processes are reaped. The reported interval conservatively includes the kill call and completion polling, with the target and response metadata recorded. Idle CPU is always ADVISORY because unattended user activity and background traffic are uncontrolled; the relay CPU, completed download and memory checks remain checks of measured values.

`C:\Users\Public\sieve-engine-live\results-route.txt` is appended under an AUTO run header. Detailed evidence goes into the run's unique `auto-...` directory. The final table distinguishes PASS, FAIL, SKIP and ADVISORY; the process exit code is the failed-check count. UI questions are SKIP with the applicable `tests/e2e` spec path, never live PASS. Those specs use fixtures and do not establish live UI behavior. The existing ignored Rust acceptance test still requires the manual UI, idle, normal-use and reboot checks; an AUTO summary alone is not a complete slice acceptance.

The summary prints the separate reboot commands with this run's evidence directory. First turn routing on in the installed app and close it, because AUTO deliberately ends OFF. The existing reboot steps remain interactive and their crash-loop assertion depends on the preserved crash history (including whether the Stall step ran).

Unelevated validation, with no machine-state access or changes:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\live\run-slice-3-auto.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\live\test-slice-3-auto.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\live\test-live-lease.ps1
```

The local contract tests use temporary files inside the worktree and mocked service/network operations. See [the validation transcript](engine-slice-3-auto-validation.txt) for the commands and observed output. The real elevated workflow, including service recovery and timings, remains unverified until the user runs it.

The performance workload transfers 300 MB as twelve 25 MB HTTPS responses in one curl process, verifies that exactly one TCP connection was used, and enforces a single 60-second deadline. A single 300 MB request returned HTTP 403 even with Sieve OFF on 2026-10-18. A rejected, short, timed-out or multi-connection transfer fails workload validation and cannot produce a CPU-budget pass. Raw transfer evidence is saved in `route-budget-transfer.json`.

## Filtered browser stall reproduction (still unverified live)

Use a disposable test VM with a separate management channel. Follow this runbook's existing installation, authorization and cleanup procedure. This is a diagnostic workload, not a replacement for the full acceptance soak. The offline investigation and ranked candidates are in [engine-stall-offline.md](engine-stall-offline.md).

- Record the engine executable hash, source revision, policy, enabled default lists and list versions. Keep routing and sieving ON. Record HTTPS filtering separately, and use the same setting for every comparison.
- Run normal browser traffic (including headless Edge, as in the reported failure) alongside repeated curl DNS/HTTPS requests for **15 minutes**. Save the URLs, navigation sequence, browser version, command lines, timestamps, curl exit codes and timeouts so another run can repeat the workload. Run the same workload with sieving OFF as the control. The duration is the requested reproduction interval, not an observed success in this change.
- Copy timestamped `status.json` and `dns-status.json` snapshots at the watchdog's sampling cadence (`CHECK_EVERY_MS` in `watchdog.rs`). Save the engine PID/start time, private bytes, handle/thread counts, route table, adapter state, policy and `last-error.txt`. Keep snapshots from before a failure, rather than overwriting them with the service's restart state.
- `status.json.packet_path` follows admitted input (`offered`: unicast arrivals less oversized drops) through `received`, `dispatched`, `writes_started` and `writes_finished`. Every count belongs to this routing run: `offered` is counted by this run's own TUN reader, so a previous run's reader still draining its ring cannot add to it. `waiting_stage` is the watchdog's last sample, not proof of a cause; `worker_exited` records a terminated packet worker and `exit_reason` its device error (no flow addresses). The normal scheduler/reader heartbeats remain enabled. On a trip, `last-error.txt` names the stage through the existing service trip path, with the worker's error in parentheses when it exited with one. `status.json.counters.tun_write_dropped` counts packets to the adapter dropped because Wintun's send ring was full; a full ring no longer ends the packet worker.
- Arrange dump capture before starting: preserve a full process dump and thread stacks on the first observed stall, with a packet trace and the last counter samples. The watchdog now deliberately ends a stuck engine, so do not rely on starting a dump manually after noticing a timeout. Keep dumps and traces in the private evidence folder, never in the repository; they can contain traffic and credentials.
- If it stalls, retain evidence of whether adapter arrivals continued, which stage stopped, whether routes were removed before process exit, the service restart history, and the first successful independent DNS/HTTPS request afterwards. Preserve `last-error.txt` before a later failure overwrites it. If automatic recovery fails, use the existing cleanup procedure and record that failure rather than extending a network outage for the sake of the soak.
- Separately check an idle machine, a quiet link with multicast chatter, slow but progressing traffic, and routing OFF/ON. Successful browse or curl alone does not establish idle false-positive safety or route cleanup timing.

The local watchdog uses the existing `STALL_MS` budget; a pending local stage that completes work resets its timer. It does not use a minimum packet rate or expect a reply to every packet. Remote silence and intentionally swallowed traffic are not evidence that the packet loop stopped. Live recovery, scheduler delays, Wintun failures and compatibility with the browser workload remain unverified until captured here.

Two stall kinds are invisible to this watchdog. A reader stuck inside Wintun's receive call while packets sit in the ring looks like an idle link: nothing is counted as offered until the reader returns a packet, and the TUN heartbeat is pending only after an arrival. Flow tasks blocked on something other than the runtime (a lock, a blocking call, a peer that never answers) while ipstack keeps reading, dispatching and writing look healthy too: every stage keeps completing work and runtime pings are answered. A capture of either needs the dump and packet trace above, not `packet_path`.

## Before you start (manual flow)

The interactive wrapper, unattended runner, individual routing steps and mutating install-check steps share `C:\Users\Public\sieve-engine-live\runner.lock`. A second runner refuses before changing the app, policy or services. The wrapper holds the lock across its prompts; only its verified child processes inherit it. Each child retains a handle, so it continues to exclude a second runner if the wrapper exits. The OS releases the lease after the last participating process exits or is killed; leftover files need no manual deletion. Older script copies do not participate: close those runners before using this version.

- Build the installer from this branch: `pnpm tauri build` in the worktree (it needs Wintun 0.14.1 at `E:\ml-tools\wintun`, or `SIEVE_WINTUN_DLL` pointing at its `bin\amd64\wintun.dll`; the build refuses any other file). The installer is `src-tauri\target\release\bundle\nsis\Sieve_0.1.0_x64-setup.exe`.
- Install it over the slice 2 install (`E:\Sieve` is fine; it holds Sieve's marker): `powershell -ExecutionPolicy Bypass -File scripts\live\engine-install.ps1 -Step install`, then `-Step verify`. The verify step now expects the engine's four privileges.
- For the Stall step, build the Stall engine now, in a normal (unelevated) terminal in the worktree: `cargo build --release --manifest-path engine\Cargo.toml -p sieve-engine --bin sieve-engine --features stall`. Do this AFTER `pnpm tauri build` (the installer must carry the normal build), or build it to a different target dir and pass `-StallBuild <path>`.
- Close `pnpm tauri dev`; use the installed Sieve from the Start menu (the engine answers only the installed app).
- AdGuard stays running for now: step 2 checks the refusal and pauses it from Sieve.

Open Terminal (Admin) and `cd` to the worktree. Run each step with
`powershell -ExecutionPolicy Bypass -File scripts\live\engine-route.ps1 -Step <step>`.

## Steps

1. **`-Step before`**. Saves the before-listings (routes without the Sieve adapter, persistent routes, DNS servers, WinHTTP proxy, firewall rules, `route print`), checks lookups and HTTPS work, the engine service runs, and no Sieve adapter or route exists. It records your default gateway for the LAN check.
2. **`-Step adguard`** (AdGuard running). Turning on filtering: in the installed Sieve, Settings > Filtering, turn on **Route traffic through the engine**. The step checks that the engine refuses (`status.json` blocker `adguard`, no Sieve route), asks you whether the Engine block says **Waiting for AdGuard** with the reason and shows **Pause AdGuard** with the text "Pausing AdGuard asks its Windows service (Adguard Service) to stop. Windows asks you to approve it. ...". Click **Pause AdGuard** and approve the Windows prompt (it runs `sc.exe stop "Adguard Service"`). Expected: no error, AdGuard's service sits in StopPending (it does not reach Stopped), and within about 5 s the engine's blocker clears and it routes; the block says **AdGuard is paused** and how to turn it back on, with no button.
3. **`-Step on`**. Routes on the Sieve adapter; none in the persistent store; every listing except the Sieve adapter's own rows matches the before-listing (no DNS server, proxy or firewall change); no DNS server on the Sieve adapter; lookups and HTTPS work; the LAN router's web UI answers on TCP 80 and loads in a browser (you confirm); `status.json` says routes up; the app says **Routing traffic** in the Engine block and on Home's Engine tile (you confirm).
4. **30 minutes of normal use**, then **`-Step soak`**. Browse, make a video call, open a game launcher, as you normally would, for 30 minutes with routing on. Then the step asks whether everything worked and reads the engine's own counters from `status.json`: **attribution of at least 0.95** (`attributed / flows`), no flow of the engine's own refused, DNS answers relayed. You confirm Home and Apps show the apps you used. DNS, proxy and persistent-route listings must still match.
5. **`-Step kill`**. `taskkill /F` on the engine. At +1 s it checks lookups and HTTPS, timed at the network test itself: **within 5 s**. No route on an interface named "Sieve", no Sieve adapter, the listings match. Then the service manager restarts the engine (5 s) and, the switch being on, it routes again.
6. **`-Step stall`**. Swaps in the Stall build (the installed exe is kept as `sieve-engine.exe.normal` and put back at the end, whatever happens), starts it, waits for its routes. 30 s after they came up, the Stall build's relay stops answering the watchdog; within 5 s plus 1 s the watchdog deletes the routes and exits (`last-error.txt` says "the watchdog stopped the engine"). Network checked. The normal engine is restored and started.
7. **`-Step reboot-prep`**, then reboot. It sets the service to manual start and kills the engine while it routes.
8. **`-Step after-reboot`**, after signing in. Lookups and HTTPS work, no Sieve route, no Sieve adapter, the listings match. The service is set back to automatic and started. The kill (step 5), the watchdog's exit (step 6) and the kill before the reboot (step 7) are three runs that did not end cleanly within an hour, so the engine now starts in the crash-loop stop (plan 1.6.4): the step checks `status.json` says `crash_loop` and nothing is routed; the Engine block says **Stopped after repeated failures** and Home shows the banner. When the step asks, turn **Route traffic through the engine** off and on again: the engine routes again within 30 s.
9. **`-Step budget`**, with routing on. Idle CPU over 60 s with the computer idle: **under 1 percent** of one core (plan 6: blocking reads only). A 300 MB download from `speed.cloudflare.com` through the engine: engine CPU **at most 15 percent of one core per 100 Mbit/s**; working set **at most 300 MB**. Numbers in `route-budget.txt`.
10. **`-Step adguard-back`**. After a pause, turn protection on in AdGuard's own window; only if its service is really Stopped, click **Start AdGuard again** in the Engine block and approve the Windows prompt (`sc.exe start "Adguard Service"`). Expected: the engine's blocker says `adguard`, it takes its routes down and waits, the network works. The service state that follows is written to `route-adguard-back-service.txt` (proof L3).

Optional, a crash loop: with the Stall build installed, let the watchdog trip three times within an hour (the service manager restarts it twice, then start it once more by hand: `sc start sieve-engine`). Expected: the Engine block says **Stopped after repeated failures**, Home shows the banner, nothing is routed; turning **Route traffic through the engine** off and on again clears it.

## AdGuard's pause: live proofs L1 to L6 (added 2026-11-05, nobody has run them)

The engine now judges AdGuard by one test connection instead of by its service state (`engine/crates/sieve-engine/src/coexist.rs`, `docs/tasks/2026-11-02-coexist.md`). Everything offline uses rows constructed from a model, so these decide whether it is right. **L1 must pass before this ships as the default**: if AdGuard skips documentation addresses, Sieve would route while AdGuard intercepts, and the probe falls back to loopback.

- **L1. The probe against the real AdGuard, and the row shape.** Unelevated, in the worktree: `cargo run --manifest-path engine\Cargo.toml -p sieve-engine --example adguard_probe -- --send`. It opens one TCP socket to a documentation address, writes nothing, prints the service state, pid, observation and verdict as one JSON line, and changes nothing. (Without `--send` it only prints its usage.) Run it three ways, and keep each line:
  1. protection on: `verdict` true; note which of `connect_witness` and `row_witness` fired;
  2. after `sc stop "Adguard Service"`, in StopPending: `verdict` false;
  3. protection off from AdGuard's window while the service is Running: `verdict` false.

  The lines replace the constructed rows in `engine/crates/sieve-engine/fixtures/adguard-probe.json`.
- **L2. The same verdict from the service.** The LocalSystem engine must be captured as the example process is (probe run 2 proved capture for an elevated process, not a service). With AdGuard on and the switch on, read `blocker` from `status.json`.
- **L3. The whole flow in the app.** Pause AdGuard, approve the prompt: no error, routing within about 5 s, the paused text. Then turn protection on from AdGuard's window from that StopPending state: does it resume, what service state follows, does the engine step aside within about 5 s? (Read from the 2026-10-18 log, never tried through the app.)
- **L4. A reboot from a pause.** With Sieve routing and AdGuard paused, reboot with the engine's service set to manual: AdGuard filters again, the engine stays down, the network is normal.
- **L5. `sc.exe` through the Windows prompt.** Unchanged by this work; still unproven.
- **L6. No loop.** Routing with AdGuard paused for a few minutes, with the probe running every 5 s: no probe flow in the engine's counters, no route change, `sc start` not needed.

Also unmeasured: a network that answers documentation addresses (the engine would keep waiting on a computer with AdGuard), and an AdGuard rule exempting `sieve-engine.exe` (the probe reads clear while apps are still redirected, so Sieve is blind but does not loop).

## A row's Off: live proof (added 2026-11-06, nobody has run it)

The engine keys a process hidden from the app by the name the app shows for it (`AppKeys::of_pid` in `engine/crates/sieve-engine/src/flow/flows.rs`). Offline tests use a constructed machine. Whether a process is hidden is asked of Windows, as the console's user (`console_user_can_open`), because the account a process runs as does not settle it: a read-only probe on 2026-11-06 at medium integrity found `remoting_host.exe` (SYSTEM, Chrome Remote Desktop) and AnyDesk readable. The account rule stands in only while no user can be asked. That impersonation needs SYSTEM, so nobody has run it. Two facts only a real machine can settle: that the answer matches what the unelevated app can read, and that the service list reads the same as SYSTEM and as the user.

With the switch on and the rule `||example.com^` under Filters:

1. Turn **Microsoft Windows Operating System** off under Apps. From a program the row covers, such as a Windows tool in your own session, `example.com` loads. A service host keeps its row reading sieved, and its connections to a blocked host are still closed.
2. Turn that row on again and turn off a row named after services, such as **DHCP Client and 3 more**. In the log, the flows of that host read as exempt.

3. If a remote desktop tool is installed (Chrome Remote Desktop, AnyDesk), turn its row off. In the log its flows read as exempt.

If step 2 or 3 does not exempt, the app and the engine disagree on that row's name: a service the user may not query, or a process the two judge differently. That row then stays sieved, the safe side, and its Off does not do what the setting's help says. Record which row.

## Emergency: getting the network back by hand

Whatever state the engine is in, routing it added can always be removed from an admin prompt:

- Start menu > **Sieve - restore network** (it asks for admin and opens a window that stays open), or
- `"<install folder>\sieve-engine.exe" restore` in Terminal (Admin).

Both delete every route on an interface named "Sieve" and every route in the engine's journal, then stop the service. Certificates and settings are left alone. Rebooting also removes everything (nothing Sieve adds is persistent); a service set to start automatically would route again only if **Route traffic through the engine** is still on, so turn it off in the app, or set the service to manual (`sc config sieve-engine start= demand`) before rebooting.

## What the verifier reads

- `results-route.txt`: every PASS, FAIL and ERROR with the step and the user.
- `route-<step>-*.txt` listings and any `-diff.txt`; `route-on-sieve-routes.txt` (the routes the engine added: none may be a private or LAN range; DNS servers appear as /32 or /128).
- `route-adguard-status.json`, `route-soak-status.json` (the engine's counters), `route-stall-last-error.txt`, `route-stall-build.txt`, `route-budget.txt`.
