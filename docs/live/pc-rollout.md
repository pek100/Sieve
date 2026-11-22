# Plan: Sieve on the owner's PC (not started)

Written 2026-11-20. The owner asked for this plan and said not to start it yet. Nothing here runs until the owner says go, one stage at a time.

Everything so far ran on a data-centre test VM. This plan moves Sieve onto the owner's own PC, where other web-reliant work runs, so every stage is small, can be undone by switching Sieve off, and ends with a check that the network is exactly as before.

## Before stage 1

- **AdGuard uninstalled by the owner**, then a reboot. Check afterwards, by hand: no AdGuard adapter in `Get-NetAdapter`, DNS servers back to automatic on every adapter, no AdGuard root certificate under Trusted Root Certification Authorities, browsing normal. Sieve never touches AdGuard itself.
- **A baseline**, recorded with Sieve off: `Get-NetAdapter`, `Get-NetIPConfiguration`, `Get-NetRoute`, `Get-DnsClientServerAddress`, `Get-DnsClientNrptRule`, the WFP filter count, and speed and latency to two fixed hosts. Every later stage compares against it.
- **A rollback card** printed in the runbook's first page: switch Sieve off in the app; if the app does not open, stop the `sieve-engine` service; if that fails, uninstall. Each leaves the network as the baseline (the fail-open law, proven on the VM by kill, reboot and uninstall).
- **The current build** of app and engine from main, installed over the old one, with its version checked.
- **The stages stay manual, and this PC's install keeps routing off.** Since 2026-11-22 a new install has routing, HTTPS decryption and page filtering on by default (`docs/tasks/2026-11-06-open-decisions.md` decision 10). An install over the old one is not new: its settings file (schema 5 or older) keeps all three off unless the owner turned one on, and the engine keeps what its `policy.json` holds, so the upgrade changes nothing and each stage below is still the owner's own click in Settings. Check after the upgrade, before stage 1: Settings > Filtering shows "Route traffic through the engine", "Decrypt HTTPS traffic" and "Filter inside pages" off. If only the settings file is missing (deleted by hand, or Sieve opened from another Windows account), the engine is not new: the app then stores the engine's own switches as it holds them. An install with neither (a clean machine, or an uninstall that removed both the app's data and the engine's `ProgramData` folder) starts with the three on; on this PC, turn them off at once in the welcome guide's switches step or in Settings before stage 1.

## Stages

Each stage runs for a stated time while the owner works normally, then the checks in its row, then the baseline comparison with Sieve off.

| Stage | What is on | How long | What to check |
|---|---|---|---|
| 1. Watch only | App installed, engine routing off | 1 day | Home and Apps charts look right; no network change at all (baseline equal with the app running) |
| 2. Routing | Engine routing, filtering off, DNS encryption on | 1 to 2 days | Every app works as with Sieve off; attribution of flows to the right apps, WSL and Hyper-V/VirtualBox VMs in their own group; LAN (printers, NAS, casting) untouched; speed and latency within the slice 3 gates; no System log errors from Wintun, tcpip, NDIS, WFP |
| 3. Domain filtering | Stage 2 plus filtering by name, default lists | 2 to 3 days | Ads and trackers blocked by name; nothing the owner uses breaks; per-app issue detection quiet or right about what it reports; the compatibility runbook's PC-only items (updaters, games, torrents, VPN apps) |
| 4. HTTPS filtering | Stage 3 plus the root certificate and HTTPS filtering, browsers only | 3 to 7 days | YouTube: no ads, no added stalls, mid-roll markers handled; in-page ads gone on the owner's usual sites; banking, health and other sensitive sites never decrypted; pinning apps self-heal; turning it off and removing the certificate leaves nothing |
| 5. Daily use | Everything on, the owner's choice of settings | ongoing | Sieve replaces AdGuard; the owner reports anything odd through the log's report button |

Gate before stage 4 (decided 2026-11-20, `docs/tasks/2026-11-06-open-decisions.md` item 5): slice 6's live checks U1 to U4 (`docs/live/engine-slice-6.md`) and slice 9's (`docs/live/engine-slice-9.md`) have passed on the VM, run through the owner's home connection. HTTPS filtering is available in the app before then; this PC does not turn it on until they pass.

Gate met 2026-11-22 (Runs 9 and 9b in `docs/tasks/2026-11-08-vm-slices-7-11-status.md`): slice 6 U1, U2 and U4 passed in Chrome, Edge and Firefox, U3 in Chrome; slice 9 U1 in all three and U2 in Chrome and Edge (Firefox's driver reads no console, so its U2 is not checked); YouTube 15-minute views with the default lists clean in all three browsers, also after autoplay.

## What only this PC can check

- Attribution with WSL, local VMs and real daily apps (the slice 3 gate of 0.95 of all flows).
- LAN devices: printers, NAS, casting, the router's admin page.
- Real residential traffic: YouTube and sites that treat the VM's address as a bot.
- Long uptime: sleep and resume, Wi-Fi changes, a week without restarting.

## What this plan does not do

- It does not run a link hub on this PC. That is the separate live run in `docs/live/link-exit.md`, which also needs the owner's yes.
- It does not change anything on the PC outside Sieve's own install, adapter and session-only routes and filters.
