# Live check: engine slice 3 (full route, relay, DNS on the TUN, crash safety, coexistence)

`live_engine_full_route_relays_and_restores`, the live check of the `filtering.engine` switch. For the user, with a verifier reading the evidence. Agents never run any of this (plan section 9: no installer, no service, no routes, no elevation).

Script: `scripts/live/engine-route.ps1`. Every step prints PASS or FAIL per check and appends to `C:\Users\Public\sieve-engine-live\results-route.txt`; the listings, the engine's `status.json` copies and the budget numbers sit beside it. Send that folder to the verifier. Afterwards, in the worktree, `cargo test --manifest-path engine\Cargo.toml -p sieve-engine -- --ignored live_engine_full_route_relays_and_restores` reads `results-route.txt` and passes only when every required check passed (the list is `control::LIVE_CHECKS`).

What slice 3 does when you turn routing on: the engine creates its Wintun adapter "Sieve" and routes this computer's traffic into it, except private and local ranges, every LAN you are on and any split-tunnel VPN's prefixes (those keep their normal routes). Every flow is relayed to where it was going, nothing is blocked. DNS lookups to your router (or whatever DNS server Windows uses) enter the adapter through a host route and are forwarded to that same server; Windows' DNS settings are never changed. Every route sits on the Sieve adapter in the active store only, so a stop, a kill, a crash or a reboot removes all of them. While AdGuard's service runs, or a VPN that carries all traffic is connected, the engine routes nothing and says why.

Not relayed in slice 3: ICMP (ping and traceroute to the internet fail while routing is on; local pings work). UNVERIFIED until this check: the four service privileges are enough to create the adapter (if not, the Engine block shows "Could not start" with the reason and the network is untouched; send `status.json`).

## Before you start

- Build the installer from this branch: `pnpm tauri build` in the worktree (it needs Wintun 0.14.1 at `E:\ml-tools\wintun`, or `SIEVE_WINTUN_DLL` pointing at its `bin\amd64\wintun.dll`; the build refuses any other file). The installer is `src-tauri\target\release\bundle\nsis\Sieve_0.1.0_x64-setup.exe`.
- Install it over the slice 2 install (`E:\Sieve` is fine; it holds Sieve's marker): `powershell -ExecutionPolicy Bypass -File scripts\live\engine-install.ps1 -Step install`, then `-Step verify`. The verify step now expects the engine's four privileges.
- For the Stall step, build the Stall engine now, in a normal (unelevated) terminal in the worktree: `cargo build --release --manifest-path engine\Cargo.toml -p sieve-engine --bin sieve-engine --features stall`. Do this AFTER `pnpm tauri build` (the installer must carry the normal build), or build it to a different target dir and pass `-StallBuild <path>`.
- Close `pnpm tauri dev`; use the installed Sieve from the Start menu (the engine answers only the installed app).
- AdGuard stays running for now: step 2 checks the refusal and pauses it from Sieve.

Open Terminal (Admin) and `cd` to the worktree. Run each step with
`powershell -ExecutionPolicy Bypass -File scripts\live\engine-route.ps1 -Step <step>`.

## Steps

1. **`-Step before`**. Saves the before-listings (routes without the Sieve adapter, persistent routes, DNS servers, WinHTTP proxy, firewall rules, `route print`), checks lookups and HTTPS work, the engine service runs, and no Sieve adapter or route exists. It records your default gateway for the LAN check.
2. **`-Step adguard`** (AdGuard running). Turning on filtering: in the installed Sieve, Settings > Filtering, turn on **Route traffic through the engine**. The step checks that the engine refuses (`status.json` blocker `adguard`, no Sieve route), asks you whether the Engine block says **Waiting for AdGuard** with the reason and shows **Pause AdGuard** with the text "Pausing AdGuard stops its Windows service (Adguard Service). Windows asks you to approve it. ...". Click **Pause AdGuard** and approve the Windows prompt (it runs `sc.exe stop "Adguard Service"`). Expected: AdGuard's service stops and, within 5 s, the engine routes.
3. **`-Step on`**. Routes on the Sieve adapter; none in the persistent store; every listing except the Sieve adapter's own rows matches the before-listing (no DNS server, proxy or firewall change); no DNS server on the Sieve adapter; lookups and HTTPS work; the LAN router's web UI answers on TCP 80 and loads in a browser (you confirm); `status.json` says routes up; the app says **Routing traffic** in the Engine block and on Home's Engine tile (you confirm).
4. **30 minutes of normal use**, then **`-Step soak`**. Browse, make a video call, open a game launcher, as you normally would, for 30 minutes with routing on. Then the step asks whether everything worked and reads the engine's own counters from `status.json`: **attribution of at least 0.95** (`attributed / flows`), no flow of the engine's own refused, DNS answers relayed. You confirm Home and Apps show the apps you used. DNS, proxy and persistent-route listings must still match.
5. **`-Step kill`**. `taskkill /F` on the engine. At +1 s it checks lookups and HTTPS, timed at the network test itself: **within 5 s**. No route on an interface named "Sieve", no Sieve adapter, the listings match. Then the service manager restarts the engine (5 s) and, the switch being on, it routes again.
6. **`-Step stall`**. Swaps in the Stall build (the installed exe is kept as `sieve-engine.exe.normal` and put back at the end, whatever happens), starts it, waits for its routes. 30 s after they came up, the Stall build's relay stops answering the watchdog; within 5 s plus 1 s the watchdog deletes the routes and exits (`last-error.txt` says "the watchdog stopped the engine"). Network checked. The normal engine is restored and started.
7. **`-Step reboot-prep`**, then reboot. It sets the service to manual start and kills the engine while it routes.
8. **`-Step after-reboot`**, after signing in. Lookups and HTTPS work, no Sieve route, no Sieve adapter, the listings match. The service is set back to automatic and started. The kill (step 5), the watchdog's exit (step 6) and the kill before the reboot (step 7) are three runs that did not end cleanly within an hour, so the engine now starts in the crash-loop stop (plan 1.6.4): the step checks `status.json` says `crash_loop` and nothing is routed; the Engine block says **Stopped after repeated failures** and Home shows the banner. When the step asks, turn **Route traffic through the engine** off and on again: the engine routes again within 30 s.
9. **`-Step budget`**, with routing on. Idle CPU over 60 s with the computer idle: **under 1 percent** of one core (plan 6: blocking reads only). A 300 MB download from `speed.cloudflare.com` through the engine: engine CPU **at most 15 percent of one core per 100 Mbit/s**; working set **at most 300 MB**. Numbers in `route-budget.txt`.
10. **`-Step adguard-back`**. Click **Start AdGuard again** in the Engine block and approve the Windows prompt (`sc.exe start "Adguard Service"`). Expected: AdGuard's service runs, the engine takes its routes down and waits, the network works.

Optional, a crash loop: with the Stall build installed, let the watchdog trip three times within an hour (the service manager restarts it twice, then start it once more by hand: `sc start sieve-engine`). Expected: the Engine block says **Stopped after repeated failures**, Home shows the banner, nothing is routed; turning **Route traffic through the engine** off and on again clears it.

## Emergency: getting the network back by hand

Whatever state the engine is in, routing it added can always be removed from an admin prompt:

- Start menu > **Sieve - restore network** (it asks for admin and opens a window that stays open), or
- `"<install folder>\sieve-engine.exe" restore` in Terminal (Admin).

Both delete every route on an interface named "Sieve" and every route in the engine's journal, then stop the service. Certificates and settings are left alone. Rebooting also removes everything (nothing Sieve adds is persistent); a service set to start automatically would route again only if **Route traffic through the engine** is still on, so turn it off in the app, or set the service to manual (`sc config sieve-engine start= demand`) before rebooting.

## What the verifier reads

- `results-route.txt`: every PASS, FAIL and ERROR with the step and the user.
- `route-<step>-*.txt` listings and any `-diff.txt`; `route-on-sieve-routes.txt` (the routes the engine added: none may be a private or LAN range; DNS servers appear as /32 or /128).
- `route-adguard-status.json`, `route-soak-status.json` (the engine's counters), `route-stall-last-error.txt`, `route-stall-build.txt`, `route-budget.txt`.
