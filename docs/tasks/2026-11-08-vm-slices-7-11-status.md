# VM live run 2026-11-08: status at the stop

The run stopped early because the owner's PC was restarting. Branch `live-vm-2026-11-08`. VM: `sieve-test-vm`, about 4.5 h used, stopped at the end. The evidence logs are on the VM under `C:\sieve\logs\` (`dnsa`, `dnsb`, `dnsc`, `extras`, `yt1`, `ytp`, `s8`, `g`). The scripts are in the session scratchpad (`d-*.ps1`, `lib.ps1`, `browse.mjs`, `yt.mjs`, `dnsbench.mjs`).

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
