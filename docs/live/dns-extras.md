# Live check: ECH stripping, the Firefox canary, private reverse lookups, the upstream editor

Run by the user, on a machine where the engine is installed and `filtering.engine` is on. Nothing here was run by the implementing stream: every automated test binds loopback only. The ignored test `live_dns_extras_on_the_real_path` points here. Commands are for an admin PowerShell prompt; the engine folder is `C:\ProgramData\Sieve\engine`.

`dns-status.json` beside `status.json` now holds `answers` next to `upstreams`, rewritten every 30 s while routes are up: `ech_stripped`, `ech_left`, `canary`, `reverse_lan`, `reverse_local`. They are counts, never a name. Task: `docs/tasks/2026-11-06-dns-extras.md`.

```powershell
Get-Content C:\ProgramData\Sieve\engine\dns-status.json | ConvertFrom-Json | Select-Object -ExpandProperty answers
```

## Before anything

Take the before-listing of `docs/conventions.md` section 0 (`route print`, `Get-DnsClientServerAddress`, `netsh winhttp show proxy`, the firewall rule list).

## Checks

Replace `<ech name>` with a name you know publishes ECH today, and `<router ip>` with your gateway.

| # | Do | Pass |
|---|---|---|
| 1 | With `filtering.https` off: `Resolve-DnsName <ech name> -Type HTTPS`. | The answer shows `ech`. `ech_stripped` stays; `ech_left` rises. |
| 2 | After the check of `docs/live/engine-slice-6.md` passed, with `filtering.https` on: the same query. Then load the name in Chrome and Edge with Secure DNS off. | No `ech` in the answer. `ech_stripped` rises. The page shows Sieve's issuer. |
| 3 | With `filtering.https` on, the same query for a name under a restricted suffix or in your "not decrypted" list. | `ech` is still there (`ech_left` rises). |
| 4 | Which clients ask where: with Secure DNS off, the port 53 capture of `encrypted-dns.md` while Chrome and Edge load a page. In Firefox, the same. | Say what you saw: do Chrome's and Edge's HTTPS queries reach port 53 on the TUN? Does Firefox ask the OS for HTTPS records at all? Does the DNS Client set DO? A DO query keeps its `ech` by design, so if it does set DO, nothing is ever stripped and the design has to change. |
| 5 | Address hints: browse with Chrome for a while, then read the log for `floor:ech`. | How often a flow connects from an `ipv4hint` or `ipv6hint` with no A query (it reads as "not resolved here" and passes through). Safe; the share is the fact wanted. |
| 6 | `Resolve-DnsName use-application-dns.net`. | NXDOMAIN; `canary` rises. |
| 7 | Firefox in its default mode, `about:networking`, DNS tab. | System DNS, not TRR. Max Protection stays on its own DoH by Firefox's design. |
| 8 | Turn `filtering.engine` off, wait, repeat 7. | Firefox goes back to its own default on its next check. Note how long that took. |
| 9 | `Resolve-DnsName <router ip> -Type PTR`. | The router's answer, or its own NXDOMAIN; `reverse_lan` rises. |
| 10 | On a network whose DNS is a public resolver (or set one on the adapter), the same query. | NXDOMAIN at once; `reverse_local` rises. |
| 11 | During 9 and 10, the port 53 capture and a look at the upstreams' `answers`. | Nothing new leaves but the query to the router. `nslookup` starts with no visible delay; Windows' dynamic-update SOA probes delay nothing. |
| 12 | WSL with DNS tunnelling: `dig <ech name> HTTPS` inside it. | Say whether `ech` is gone. Its flows are never decrypted; tunnelling may reach the resolver as a host process, which costs the guest ECH and breaks nothing. |
| 13 | Settings, Upstream DNS servers: add a DoT server, move it first, reload. Read `dns.json` and `dns-status.json`. | Both list it first, in that order, and the row says "The engine uses this list." Point the first entry at an address that does not answer: lookups keep working within 2 s, from the next one. |
| 14 | The kill, reboot and uninstall tests of `docs/conventions.md` section 0, with all of this active. | Lookups and HTTPS work, and the listings match the before-listing. A stripped answer in the DNS Client's cache lasts its TTL after the engine stops and only means no ECH until then. |

## Decision for you to review

Private reverse lookups: a reverse lookup for a private range goes to the LAN server when one is known, else gets NXDOMAIN here, and never reaches the public upstream. "Private" is every range the engine already never routes (`route::plan::EXCLUDED`). "Known" is the DNS server of the adapter covering the address, then any adapter with a private DNS server. The cost: where the network's DNS is a public resolver, `Resolve-DnsName 192.168.1.5` says "no such name" even if some other server could know. The alternative tells your upstream your private addressing. Task Q1; say if you want them forwarded on such networks.

## Not here

Interception itself is `engine-slice-6.md`, and `filtering.https` stays locked until that check passes: this page unlocks nothing. Other special-use names (`home.arpa`, `.local`, single labels) still go to the encrypted upstream unless a suffix claims them (task Q6).
