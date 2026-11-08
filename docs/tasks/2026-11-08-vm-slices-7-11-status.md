# VM live run 2026-11-08: status at the stop

## Run 2 (second session, same day)

Branch `live-vm-2026-11-08` with main 8d1d873 merged. VM started 2026-11-08 20:10 local. Slice 7 skipped (self-healing is being fixed elsewhere). Scripts in the session scratchpad: `d-s8b.ps1`, `d-s9.ps1`, `d-s10.ps1`, `d-s11.ps1`, `d-real2.ps1`, `k-*.ps1`, `content.mjs`, `text.mjs`.

Engines: `engine-cur-pin.exe` (C26FD6DE) is this branch with Version Negotiation as `REFUSAL` and a VM-only pin of the TEST scriptlet bundle (uBO 3762a26, sha256 9527a0b5...a385, placed as `lists\resources.json`). The pin is never committed. The slice 8 arms ran on the earlier pin builds (c4f9e87), whose QUIC code is the same.

### Slice 8: refusal arms (decided)

| Check | Result | Evidence |
|---|---|---|
| VN arm unit test | PASS | `version_negotiation_answers_each_initial_through_the_stream` (91ceb55), `a_sealed_initial_through_ipstack_is_answered_by_version_negotiation` (5a6d8af) |
| U2 fallback time, Edge and Chrome | PASS for VN | 3 rounds per arm, alternating order. VN median 1 ms in both browsers, 89 % (Edge) and 80 % (Chrome) within 100 ms, 0 samples at the 300 ms TCP delay. PU: Edge median 301 ms, 34 of 77 samples at 295 to 310 ms. Drop: 23 of 159 there. Table in `docs/live/engine-slice-8.md` |
| U1 ICMP reached the app | PASS in part | `replies` +270 to +300 per run with PU; Chrome moved to TCP early (81 % within 100 ms), Edge did not (44 %) |
| U2 Firefox | SKIP | playwright-core 1.48 cannot drive the installed Firefox 159 |
| U9 refused per load | Reported | 35 to 51 refused flows per 16 loads (8 sites twice) per browser and arm |

Decision: `REFUSAL = Refusal::VersionNegotiation` (5a6d8af). The Chrome VN tail is longer than ICMP's (p90 705 ms against 368 ms; 5 of 60 over 1 s), most likely later TCP flows inside the 10 s window, which this run did not tell apart.

### Slice 9: content injection

Engine 709C9CAA (this branch at 3850222 with the TEST bundle pinned: uBO 3762a26 assembled, then trusted-prevent-xhr.js marked trusted by the fixed rule of 6dc6a8d, sha256 88bc3ecc...582a). User rules: one hiding rule and `+js(set-constant, sieveProbe, 42)` per test site. Probe `content.mjs`: the delivered body, the DOM, console CSP and Trusted Types reports, page errors.

| Check | Result | Evidence |
|---|---|---|
| U1 example.com, Edge and Chrome | PASS | `<style nonce=...>` right after `<head>`; `example.com##p` hid 6 of 6 `p`; `rewritten` +1 per load in each. Today's example.com has no `h1`, so the runbook's `example.com##h1` matches nothing (runbook to update) |
| U1 Firefox 159 | PASS in part | headless Firefox took Sieve's certificate (`intercepted` +3) and `rewritten` +1; the screenshot is on the VM (`C:\sieve\logs\s9\ff-example2.png`), not read here |
| U1 user scriptlet | FAIL, then fixed | Before 3850222 a user's `+js()` rule injected nothing (`with_scriptlets` +0 on example.com): only the lists' engine had the bundle. After: `with_scriptlets` +1 per load. The probe global still read `undefined` on example.com, github.com, MDN, accounts.google.com and web.dev, and 42 on www.youtube.com: not explained yet (see "Open") |
| Bundle | FAIL, then fixed | The assembled uBO 3762a26 bundle was refused whole: "resource trusted-prevent-xhr.js is named trusted but any list could inject it" (uBO registers it without `requiresTrust`). Fixed in the bundle script (6dc6a8d) |
| U2 header CSP, Trusted Types | PASS | github.com, www.google.com search, www.youtube.com (TT), developer.mozilla.org, accounts.google.com (TT), web.dev: 0 CSP or Trusted Types reports, and each site's hiding rule applied (footer 1/1, textarea 1/1, ytd-masthead 1/1, accounts h1 1/1). Google's results page threw `solveSimpleChallenge is not defined`: its bot challenge for this IP; not compared with Sieve off |
| U2 meta CSP | SKIP | none of the six pages had one |
| U3 scriptlet with Trusted Types | PASS on YouTube | `sieveProbe` = 42 on www.youtube.com (TT enforced); `undefined` on accounts.google.com (TT) as on the non-TT pages, so TT is not the cause |
| U4 budgets | Reported | the generic stylesheet adds about 540 KB to every page (example.com: 557,840 bytes delivered); load times in "Real use" |
| U5 skip counts | Reported | default lists: adguard-base 74,227 applied / 3,712 skipped, adguard-tracking 437,184 / 14, adguard-url-tracking 2,528 / 208, adguard-dns 190,790 / 7, ubo-badware 4,675 / 65 |
| U6 | SKIP | no site with trailing gzip bytes or a shared dictionary was found |
| U7 cached page after off | SKIP | the reload after content off failed with `ERR_NAME_NOT_RESOLVED` (see "DNS just after a start") |
| U8 plain http, service worker | PASS | http://neverssl.com/ not injected (twice); squoosh.app injected on the network load and not on the service worker's (`fromServiceWorker` true) |

**Found and fixed: no uBO scriptlet ever ran.** uBO's scriptlets read `scriptletGlobals`, which uBO's own injector declares; adblock-rust does not, and Sieve's payload did not. Each scriptlet threw a ReferenceError inside its own `try` and did nothing, silently (`with_scriptlets` still counted the page). Seen with a user `+js(set-attr, html, data-sieve-probe, 1)`: the attribute appeared only on www.youtube.com (not explained), not on example.com, github.com, accounts.google.com, MDN or web.dev; the same scriptlet under jsdom and node read the undeclared name. Fixed in 8726598 (`var scriptletGlobals={};` first in the scriptlets' scope); test `scriptlets_run_in_a_scope_that_declares_scriptlet_globals`, failing before the fix. The slice 10 content arms below ran before it and are rerun after it.

### DNS just after a start

`d-dnsstart.ps1`, three engine restarts, `nslookup` every 150 ms: for about 3 s after `routes_up` lookups through the TUN got no address (rounds: 2.4 to 5.6 s, 0.5 to 3.8 s, 0.3 to 3.9 s after the start), then answered. A browser opened right after a policy restart fails its first names (`ERR_NAME_NOT_RESOLVED`). Not investigated further yet.

### Real use

Engine 709C9CAA (before the scriptletGlobals fix, so no scriptlet ran), default lists, `https`, `content` and encrypted DNS on. 20 sites, Edge 157 and Chrome 157, a fresh profile per load, rounds off, on, on, off. Medians of two loads, ms (`load` event):

| Site | Edge off | Edge on | Chrome off | Chrome on |
|---|---|---|---|---|
| wikipedia.org | 567 | 839 | 566 | 698 |
| google.com search | 1206 | 1259 | 1117 | 1198 |
| youtube.com | 1826 | 2113 | 1825 | 1934 |
| bbc.com/news | 1903 | 1711 | 1661 | 1550 |
| nytimes.com (403 to this IP) | 491 | 718 | 442 | 668 |
| amazon.com | 332 | 406 | 402 | 334 |
| ebay.com (403) | 289 | 315 | 257 | 277 |
| github.com | 1384 | 1944 | 1339 | 1426 |
| stackoverflow.com (403) | 531 | 528 | 393 | 478 |
| microsoft.com | 3527 | 4321 | 3499 | 3598 |
| apple.com (EV, passed through) | 795 | 797 | 895 | 729 |
| twitch.tv | 1684 | 1797 | 1610 | 1640 |
| imdb.com (403) | 143 | 176 | 121 | 152 |
| espn.com | 307 | 425 | 275 | 450 |
| reddit.com (403) | 107 | 169 | 115 | 152 |
| linkedin.com | 561 | 1416 | 511 | 666 |
| netflix.com | 3598 | 3464 | 3577 | 3380 |
| accounts.google.com | 1088 | 1350 | 326 | 337 |
| login.microsoftonline.com | 656 | 815 | 414 | 529 |
| instagram.com | 669 | 858 | 655 | 972 |

The median of the per-site differences is about +115 ms in Edge and +85 ms in Chrome. Broken pages: none seen. Every page had the same status off and on, its visible text within a few percent except linkedin.com (2,114 and 2,137 characters on against 2,839 off in Edge, one of two loads in Chrome; not checked against the screenshots), and the extra failed requests on are blocked ad and tracker requests (microsoft.com 22, netflix 16, twitch 11). A screenshot of each load of round 1 is on the VM (`C:\sieve\logs\real2\shots-*`). The 403s are this data-centre IP, off and on alike.

30-minute browsing soak, same switches, Edge and Chrome alternating (21 passes, 420 loads, 1 without a load event), sampled every minute: engine CPU 7.1 to 9.6 % of one core (average 8.12 %), working set 131 MB at the start, 184 to 223 MB after the first minute and flat (217 MB at the end), private 195 to 202 MB, handles 650 to 770, threads 16 to 31. `intercepted` +5429, `rewritten` +669, `resets` 0, `blocked` +2592, no `last_error`.

**Heal false positives, large (slice 7, fixed on main 0ea3303 meanwhile):** after these runs `exclusions.json` held 32 `auto:pinning` rows for msedge and chrome on hosts that do not pin (www.google.com, www.facebook.com, github.githubassets.com, static.cdninstagram.com, bbci, espncdn, twitch, licdn, microsoft CDNs). This build has the old heal rule; slice 7 is checked with main's build below.

### Kill, reboot, uninstall (section 0) with interception, content and encrypted DNS on

| Check | Result | Evidence |
|---|---|---|
| Kill (`taskkill /F`), slice 6 U12, encrypted-dns 9, dns-extras 14 | PASS | after the kill: Resolve-DnsName 0.38 s, nslookup 0.07 s, curl https 0.18 s; routes on Sieve 0, adapter gone; route, DNS, proxy, firewall and adapter listings 0 lines different from the before-listing. The service's own recovery restarted the engine within 70 s with routes up. The download in flight was not measured cleanly (the curl arguments broke) |

### Slice 11: CT, CRLite, upstream ECH

Artefacts placed by hand in `ProgramData\Sieve\engine\updates\` (unsigned: the owner's key is not on the VM). Engine C26FD6DE then F17B34C7, Chrome 157, a fresh profile per load, `status.json.https` read around each load.

| Check | Result | Evidence |
|---|---|---|
| Artefacts loaded | PASS | `ct_list_timestamp` 1794145453000, `crlite_filters` 45, `validation_refused` 0 |
| U1 no-sct.badssl.com | SKIP | Chrome showed `ERR_CERT_AUTHORITY_INVALID`: the host's chain is not publicly trusted any more, so it cannot exercise CT. The engine passed it through (`passed` +1), `ct_violating` +0 |
| U1 normal site | PASS | www.wikipedia.org: Sieve's issuer, `ct_compliant` +9, `intercepted` +5 |
| U2 CRLite revoked | PASS | revoked-rsa-dv.ssl.com, revoked-ecc-dv.ssl.com and revoked.badssl.com: each `crlite_revoked` +1 and the real issuer in Chrome (SSL.com TLS Issuing RSA CA R1, ECC CA R2, YE2); www.wikipedia.org `crlite_revoked` +0 |
| U3 upstream ECH | PASS | crypto.cloudflare.com/cdn-cgi/trace through Sieve (Sieve's issuer): `sni=encrypted`, `tls=TLSv1.3`, `kex=X25519MLKEM768`; `ech_offered` +1, `ech_accepted` +1, `ech_failed` +0 |
| U5 first and repeat connection | Reported | the trace page loaded in 198 ms the first time and 141 ms the next (whole page, fresh browser each); the 2 ms handshake budget needs the bench, not a page load |
| U7 memory | PASS | engine working set 131 MB after load with the CRLite bundle, 142 MB after the loads, private 124 MB: under 300 MB |
| U4, U6, U8, U9, U12 | SKIP | U6 is read from the real-use run below; no ECH server rejecting a stale config is known (U8); U9 and U12 not run for time |
| U10 | see kill, reboot, uninstall below | |
| U11 signed update cycle | SKIP | needs the owner's signing key |

Heal false positives seen again (slice 7, not fixed here): `auto:pinning` for msedge on cdn.discordapp.com and static.cdninstagram.com, chrome on static.cdninstagram.com, during these runs. Each run cleared `exclusions.json` first.

The run stopped early because the owner's PC was restarting. Branch `live-vm-2026-11-08`. VM: `sieve-test-vm`, 1.4 h used (started 18:39, stopped 20:03), stopped at the end. The evidence logs are on the VM under `C:\sieve\logs\` (`dnsa`, `dnsb`, `dnsc`, `extras`, `yt1`, `ytp`, `s8`, `g`). The scripts are in the session scratchpad (`d-*.ps1`, `lib.ps1`, `browse.mjs`, `yt.mjs`, `dnsbench.mjs`).

Engine under test: main c4f9e87. For slices 9 and 10 a VM-only build pinned a TEST scriptlet bundle (uBO 3762a26, sha256 9527a0b5...a385). That pin was never committed.

## Done

### DNS (encrypted-dns.md, dns-extras.md)

**Found: the DNS Client service bypasses the TUN.** `Dnscache` (svchost pid 1584) sends its queries from the Ethernet address 10.128.0.2 straight out of the Ethernet adapter to the adapter's server 10.128.0.1. It does this although a /32 route to 10.128.0.1 runs over Sieve, because it binds its source address and Windows sends by the strong-host rule. So the queries of every getaddrinfo user (Resolve-DnsName, curl, PowerShell, Firefox, system services) leave in plain text and never reach the engine. Only clients with their own socket go through the engine: Chrome's and Edge's built-in resolver, and nslookup.
- Capture `p53`: Resolve-DnsName and GetHostAddresses went out on eth; nslookup went over the TUN. Check 13: with every resolver blocked, Windows still got an answer in plain text.
- Experiment: WeakHostSend Enabled on Ethernet (ActiveStore, reverted) sent Dnscache's query over the TUN. That is a system setting, so it breaks the fail-open rule.
- This needs an owner decision. Options: a WFP dynamic session (removed when the process dies), weak host send (a persistent change, against the conventions), or a DNS server on the Sieve adapter (banned by law 12). Not fixed.

Results:
- **Check 1:** FAIL in intent, for the reason above. Every port 53 packet went to the private address 10.128.0.1, so it passes by the letter of the runbook.
- **Check 2:** PASS. The first lookup took 1064 ms, the next ones about 20 ms, and the dead resolver was retried after 30 s (1027 ms).
- **Check 3:** PASS. Cloudflare used X25519MLKEM768; Quad9 used X25519, which is recorded.
- **Check 4:** IPv4 PASS (connected). IPv6 SKIP: the VM has no IPv6.
- **Check 5:** PASS.
  - DoT to 1.1.1.1 connected with alpn null; DoT to dns.quad9.net with alpn dot.
  - DoQ to dns.adguard-dns.com and unfiltered.adguard-dns.com connected with doq.
  - The named custom upstream dns.google answered.
- **Check 6:** PASS. own_refused stayed 0, and internal names resolved.
- **Check 7:** PASS. The suffix `us-central1-a.c.sieve-live-test.internal` went to 10.128.0.1.
- **Check 8:** TXT and TC PASS (61 TXT records in 66 ms). SERVFAIL PASS (rcode 2 with every resolver blocked). The Wi-Fi to Ethernet switch is SKIP.
- **Check 10:** PASS. Idle CPU was 0.13 % of a core over 120 s; working set 108 MB.
- **Check 12:** PASS. Mode went to `plain` within a probe; port 53 went only to 10.128.0.1; the encrypted upstreams answered 0; turning it back gave `encrypted` with no restart.
- **Check 13:** PASS for the engine. Lookups got rcode 2 at once; `dns_unreachable` was true; the mode stayed encrypted with plain_dns unset; after the rule was removed, answers came back and `dns_unreachable` cleared. The leak above still applies.
- **Check 9 and dns-extras 14 (kill, reboot, uninstall):** not run.
- **dns-extras 1:** PASS. Three ECH names, `ech_left` +3.
- **dns-extras 4:** Edge's and Chrome's type 65 queries reach port 53 on the TUN, with no EDNS and so no DO bit.
- **dns-extras 6:** PASS on the TUN (NXDOMAIN, canary +1). It FAILS through the DNS Client, which got an answer, so Firefox never sees the canary.
- **dns-extras 9:** PASS. reverse_lan +4.
- **dns-extras 10:** PASS. NXDOMAIN in 129 ms, reverse_local +2.
- **dns-extras 11:** partly FAIL. One Dnscache packet went in plain text to 8.8.8.8 because of the bypass.

DNS speed in ms, measured with an unbound UDP client over the TUN, 40 names per set:

| Path | Cold median | Cold p99 | Warm median | Warm p99 | Burst of 200 at once |
|---|---|---|---|---|---|
| Sieve off (GCP resolver) | 15.4 | 45.5 | 0.4 | 13.7 | cold: 168 of 200 timed out (the resolver drops bursts); warm: 6 of 200 timed out |
| Encrypted, DoH Cloudflare | 18.3 | 71.5 | 15.5 | 42.4 | median 149, p99 179, wall time 185 ms |
| DoT, 1.1.1.1 | 16.4 | 55.2 | 30.4 | 43.5 | median 31, p99 51 |
| DoQ, AdGuard | 32.0 | 195 | 29.9 | 41.6 | median 373, p99 737 |
| Plain mode | 17.3 | 42.5 | 19.4 | 31.8 | cold: every query about 2027 ms (GCP drops the burst; the engine's retry answers all 200) |

The DoH burst is 5 times slower than DoT. Not investigated yet.

### Slice 8 (QUIC refusal), first pass

Port-unreachable and silent-drop arms, Edge 157 and Chrome 157, with a warmed profile on 8 sites:
- `fallback_ms` median: about 301 ms in both arms and both browsers. Chrome on the drop arm: 127.
- port_unreachable made `replies` grow (Edge +285), yet it was not faster than the drop.
- So ICMP brings no gain, and the 100 ms budget is missed in both arms. The 300 ms looks like Chrome's own delay before its TCP job.

**The VN arm needs a rerun.** The first VN binary was built with the wrong constant (a relative path in `[IO.File]`), so its run was a second port_unreachable run. A correct VN build (5D2F3CC5) was uploaded, and its run had just started when the VM stopped.

Code: `Refusal::VersionNegotiation` on this branch (WIP, REFUSAL unchanged), with `refuse` taking AsyncWrite. Quic unit tests pass, 65 of them. It needs its own unit test and the live numbers before REFUSAL changes.

### Slice 7 (heal), found by accident

**Found: heal false positives.** During normal Edge and Chrome loads, `exclusions.json` gained `auto:pinning` entries:
- for msedge: www.google.com, static.cdninstagram.com, cdn.discordapp.com;
- for chrome: static.cdninstagram.com.

None of these hosts pins. The likely cause: a close within `SILENT_CLOSE_MS` (2 s) of a handshake with no request counts as a rejection. Unused preconnects or coalesced connections closed at page or browser close look the same.

Effect: www.google.com is then never decrypted in Edge, and its QUIC is relayed, not refused. Not fixed. Next: reproduce with long-lived browsing, then tell browser-exit and preconnect closes apart from real rejections.

### YouTube

From this data-centre IP, YouTube blocks playback:
- **One profile across videos:** the first video plays and every later one gets "Sign in to confirm you're not a bot", with Sieve off and on.
- **A fresh profile per video** (FRESH=1): videos start (first frame 2.3 to 3.0 s), then the player says "Something went wrong" after about 45 s.
- **Ad requests:** the player JSON had adPlacements 1 and no mid-roll offsets.

These walls come from the IP and not from Sieve: they happen with Sieve off too. Mid-roll and long-play checks cannot run here; they need a residential IP.

Off and route arms on dQw4w9WgXcQ, Edge:

| Arm | First frame | Pre-roll | Content starts | Stalls | Seek resume |
|---|---|---|---|---|---|
| Off | 2265 ms | 1 ad | 32.7 s | 0 | 832 ms |
| Route | 2648 ms | 1 ad | 18.3 s | 0 | 902 ms |

## Fixed

- `4632809`: the bundle script now takes uBO dependencies declared as a class or an async function. Current uBO broke the assembler. Test: `tests/laws/injected.test.ts`, "takes dependencies declared as a class or an async function", with fixture `tests/fixtures/ubo-tree-declarations`. Checked failing on the old script and passing after.

## Not run (next, in order)

1. Slice 8 VN arm: rerun `d-s8vn.ps1`. The VN binary is on the VM at `C:\sieve\drop\engine-pin-VersionNegotiation.exe`. Choose the arm by the numbers.
2. The heal false-positive repro and fix (slice 7 U5).
3. YouTube content arms (`d-yt2.ps1`: content-adguard, content-ubo, Edge and Chrome). The bundle is at `C:\sieve\dl\resources.json` and the pinned binary at `C:\sieve\drop\engine-pin.exe`.
4. Slice 9 U1 to U8.
5. Slice 10 `youtube.mjs`. It is limited by the bot wall.
6. Slice 11. The artefacts are made and unsigned, on the VM at `C:\sieve\drop\list-ct-logs` and `C:\sieve\drop\list-crlite` (45 filters, log list 1794145453000). Put them in `ProgramData\Sieve\engine\updates\`; U11 (the signed update cycle) is SKIP.
7. Real use (`d-real.ps1`: 22 sites, off, route and content, then a 30-minute soak).
8. Slice 7 U1 to U3 with the live-scope build (`C:\sieve\drop\engine-livescope.exe`).
9. Kill, reboot and uninstall tests.

## VM state left behind

- The engine is `engine-pin-SilentDrop` or `engine-pin-VersionNegotiation`, with https on.
- The pipe test client replaces `C:\Program Files\Sieve\sieve.exe`. The real app is at `C:\sieve\bin\sieve-real.exe`: put it back before any uninstall check.
- Chrome 157 and Firefox 159 are installed.
