# VM live run 2026-11-08: status at the stop

## Run 6 (2026-11-09): the capture's compatibility fixes

Branch `worktree-agent-a380fcbceca411e90` on main 3502855, fixes 9f07f15 (signed exchanges) and e2f5c53 (capability gate, backoff, neutral probe, full undo). Engine under test CB1D5B77 (release of e2f5c53); "before" is main 3502855 (4DC7B275). sieve-test-vm ran at n2-standard-2 beside a throwaway domain controller `sieve-test-dc` (e2-standard-2, Windows Server 2025, forest `sievead.test`, zone AD-integrated with secure-only updates, 10.128.0.3), with a temporary VPC rule letting 10.128.0.0/20 in. Runtime switches went through a VM-only pipe client in place of `sieve.exe` (Hello with or without capabilities, `set <field> <bool>`).

Found first: Ethernet's IPv4 metric was 1 with the automatic metric off again, so the capture refused itself (tie). Set back to automatic, it was 1 again after each restart of the VM, the persistent store set to automatic too, so something on this VM image (not Sieve, which writes no other adapter) puts it back at boot; it was set to automatic after each restart before the checks.

| Check | Result | Evidence |
|---|---|---|
| Old app, new engine (item 2) | PASS | Status to a bare Hello: `dns_capture` absent; to a Hello naming `dns_capture`: `{"state":"working"}` |
| Switch on, off, on at runtime (item 7) | PASS | on: 1 filter, server fd53::53, 10/10 lookups median 35 ms, **0** plain port-53 packets; off (status answered in 132 ms): 0 filters, server gone, IPv6 metric back to automatic (5), fd53:6965:7665:1::1 removed, link-local `SkipAsSource` false, 10/10 at 17 ms, 20 plain packets (as without the capture); on again: filter back in 1.6 s, working, 10/10 median 35 ms p90 253 ms, **0** plain packets |
| Close undoes the adapter (item 5) | PASS | the off row above |
| Does `SetIpInterfaceEntry` persist the metric? (item 5) | No | the NSI persistent store holds an IPv6 interface entry for Sieve's LUID from the moment the adapter comes up with routes, capture off (Windows' defaults: only zero bytes, no metric); opening the capture (metric 1 live) and closing it leave it byte for byte the same; a clean stop removes it. Tcpip6 key under Sieve's GUID: `NameServer` only, no metric. Nothing added to the cleanup |
| Kill with the capture on | PASS, one leftover noted | 0 filters after the kill; Tcpip6 key with `NameServer=fd53:...::53` until the next start (as run 5); DNS 0.02 s, https 0.28 s. After kill, restart and clean stop, the NSI interface entries of Sieve's LUID (IPv4 and IPv6, Windows' defaults) stayed, where a clean stop alone removes them |
| Three kills in an hour | as designed | the crash-loop blocker held routes down until the switch went off and on through the pipe |
| Secure registration, Sieve off | registered | NIC: unsigned UPDATE Refused, TKEY over TCP answered (473 bytes), signed UPDATE (`[1au]`) NOERROR; no DNS Client error event |
| Secure registration, main 3502855 | **FAILS** | the DNS Client sends its registration unbound, so it enters Sieve's adapter (the DC has a host route there): the unsigned UPDATE reached the DC through the engine and came back Refused, but the TKEY never reached the DC; the DNS Client got FormErr and ServFail back over TCP (the public resolver's answers); event 8016 "failed to register host (A or AAAA) records" |
| Secure registration, the fix | registered | the same exchange as off, each message relayed by the engine from 10.128.0.2 to the DC: UPDATE Refused, TKEY over TCP answered (473 bytes) and relayed, signed UPDATE NOERROR and relayed; no DNS Client error event |
| `DisabledComponents` 0xFF (reboot, report only) | not caught, network as without it | status `not_caught`, `ipv6_off` ("IPv6 is off on Sieve's adapter, and its DNS server is IPv6"), 0 filters; Sieve has IPv4 only; 10/10 fresh names (median 18 ms), 10/10 real names, curl https 0.53 s; 20 plain port-53 packets, as without the capture |
| `DisabledComponents` 0x10 (reboot, report only) | the same | `ipv6_off`, 0 filters, 10/10 (median 18 ms), 10/10 real names, curl 0.38 s, 20 plain packets |
| Capture on a domain-joined PC | not caught (fail-open) | with the DC as Ethernet's server the probe arrives but `DnsQuery_W` does not return within 1000 ms, every try; status `not_caught`, `failed`, lookups 5/5 at 24 ms as without the capture. Cause not looked into; the retries now back off from 15 s |

The record-polling half of the registration script (deleting the A record on the DC and polling `Get-DnsServerResourceRecord` every 2 s for 7 minutes) saw no record in any arm, Sieve off included, while the wire showed the signed UPDATE answered NOERROR and the record was there when read later: that measurement is not used.

VM time: sieve-test-vm 10:52 to 12:09 local (1.3 h), the DC 10:51 to 12:00 (1.2 h). State at the stop: the DC VM and its disk deleted, the temporary VPC rule deleted; sieve-test-vm left the domain (WORKGROUP), Ethernet's DNS reset to DHCP (10.128.0.1), TrustedHosts empty, the password file deleted, `DisabledComponents` removed, Ethernet's metric automatic (until the image puts it back at boot), the engine it had before (8BFE89A7) and the real `sieve.exe` (2D5046ED) back, policy `engine` false, no Sieve key in the registry, the run's scheduled tasks removed, machine type back to n2-standard-4, stopped. RSAT-DNS-Server stays installed.

Open from this run: a corporate DNS server that is not on an adapter's on-link prefix is no LAN server by `upstream::is_lan_server` (private and inside a hole), so a TKEY or signed UPDATE to one is REFUSED, and its names get no split-horizon either; the probe failing on a domain-joined PC.

## Run 5 (2026-11-09): own-name answers and the LLMNR delay

VM 02:46 to 03:47 local (1.0 h), stopped at the end. "Before" is 27141dd (67666092), "after" is the IPv6-server build (24DF3567). Run 4's metric-1 check had left Ethernet's persistent IPv4 metric at 1 with the automatic metric off, so after the VM restarted the capture refused itself until that was reverted (`Set-NetIPInterface -AutomaticMetric Enabled -PolicyStore PersistentStore`).

**Own name.** With Sieve on, Windows answers the machine's own name with every source-capable address, ordered by interface metric. At metric 1 that put Sieve's addresses first. Fix: the adapter's DNS server is now IPv6, `TUN_DNS` = `fd53:6965:7665:1::53`, beside its ULA `TUN_V6`. Sieve is the DNS Client's first network by its IPv6 metric alone, and IPv4 keeps its automatic metric. Sieve's link-local addresses are skipped as a source. The capture adds and removes the server's host route itself. Measured on the way, not shippable:
- `SkipAsSource` on 198.18.0.1 removes it from the answer, but then no source exists for anything routed into Sieve (`Find-NetRoute` empty, curl 000).
- A link-local IPv4 source beside it shows up in the answer instead.
- Weak-host send and receive on Sieve's adapter: curl 000, lookups 0/5.
- `SkipAsSource` on `TUN_V6`: the DNS Client has no source for the server, and the probe never arrives.

| Name (.NET) | Off | Before | After |
|---|---|---|---|
| `sieve-test-vm` | fe80 (Ethernet), 10.128.0.2 | Sieve's fe80, Ethernet's fe80, **198.18.0.1**, 10.128.0.2 | fe80 (Ethernet), 10.128.0.2, then 198.18.0.1, fd53:6965:7665:1::1 |
| `sieve-test-vm.<suffix>` | 10.128.0.2 | 10.128.0.2 | 10.128.0.2 |
| `sieve-test-vm.local` | as the short name | as the short name | as the short name |

So the FQDN is identical. The short and `.local` names keep Ethernet's addresses first and in the same order as off, with Sieve's two after them; no adapter-only setting removes them, for the reasons above.

| Row | Off | Before | After |
|---|---|---|---|
| Plain port-53 packets, 10 lookups | 20 | 0 | 0 |
| 10 lookups, median | 19 ms | 30 ms | 39 ms |
| NXDOMAIN, .NET, `nx-*.com` | 2 to 27 ms | 19 to 25 ms | 20 to 25 ms (12 rewrites) |
| `metadata` (only under Ethernet's suffix) | 2 ms | 2 ms | 1 to 2 ms |
| LLMNR-only `sieveonly1` | 2.8 s | 9.8 s | 9.8 s |
| Nonexistent single label | 2.8 s | 9.8 s | 9.8 s |
| curl https | 200 | 200 | 200 |
| Kill, then the next start | | | Tcpip6 key with `NameServer=fd53:...::53` after the kill, absent after the recovery start; DNS 0.01 s after the kill |

**The LLMNR delay: cause found, not fixed.** DNS Client ETW (3009, 3010) shows what happens to a single-label name. The DNS Client sends it with each adapter's own connection-specific suffixes, and only to that adapter's servers. On Ethernet that means `sieveonly1.us-central1-a.c.sieve-live-test.internal` and the other two suffixes, all to 10.128.0.1. Off, they get an NXDOMAIN in 6 to 8 ms. With the capture, the block drops them, and the DNS Client resends after 1 s and more. It sends LLMNR at 0.4 s in both cases, but returns its answer only when the blocked network's queries time out: 9.8 s against 2.8 s. Sieve's network is never asked those names. Tried:
- Sieve's adapter given Ethernet's suffix, rewrite off: Sieve answers NXDOMAIN, and the DNS Client still waits for Ethernet (9.8 s; the FQDN under the suffix takes 12 s).
- The same with the rewrite on: 2.35 s, but the LLMNR-only name **fails**, because NODATA is final.
- NetBIOS off on Sieve's adapter: 9.8 s.

The rewrite plays no part (9.8 s with it on and off). What stalls is the DNS Client waiting on the queries the block drops. Any user-mode fix means letting the DNS Client's queries to the adapter's own servers through, and with them the parallel public-name leak, or answering them in place, which needs a WFP connect-redirect callout (a kernel driver).

## Run 4 (2026-11-09): the capture's second review

Branch `worktree-agent-acd57d2c31e644f62`, main merged (a3c5a24), fixes fc6e72f and 27141dd. VM 02:03 to 02:44 local (0.7 h), stopped at the end. Engines: A958B1C9 (rewrite on) and EF74955B (rewrite off, the one switch `dns::service::NXDOMAIN_AS_NODATA` flipped), then 67666092 (27141dd, rewrite on) for the key and probe checks. "Off" is policy `engine` false. Helpers on the VM: a DNS server on 127.0.0.2 (zones `split.test`, `corp.test`) and an LLMNR responder on Ethernet for `sieveonly1` (scratchpad `r-resp.ps1`).

Found on the VM and fixed in 27141dd:
- The rewrite never acted at first (NXDOMAIN 12 s): the loopback pseudo-interface lists `fec0:0:0:ffff::1-3`, so not every network looked blocked. Those servers and the loopback are no network now; after, NXDOMAIN 25 ms and `dns-status.json` counts each rewrite (`nodata`).
- With metric 1 Sieve's adapter held `224.0.0.0/4`, `255.255.255.255/32` and `ff00::/8` at 256 + 1 against Ethernet's 256 + 5, so multicast and broadcast sends naming no interface went into the engine. They are deleted from Sieve's adapter; after, only Ethernet and loopback hold them.
- After a kill Windows still converts Sieve's GUID to a LUID (a non-present interface), so the leftover key was never deleted. Presence is now the adapter list's.
- A firewall rule against 198.18.0.53 closed the capture 48 s later (60 s probe); every lookup timed out (12 s) meanwhile. Probe every 15 s: closed in 16 s, reopened 13.6 s after the rule went.

| Check | Off | On, rewrite on | On, rewrite off |
|---|---|---|---|
| Plain port-53 packets out of the NIC, 30 fresh names | (40 for 20, run 3) | **0** from the DNS Client; 1 SRV and 2 A/AAAA of the internal suffix, the engine's own split-horizon sends to the LAN server | not run |
| 20 uncached lookups, median / p90 | 18 / 19 ms | 23 / 26 ms | 24 / 32 ms |
| NXDOMAIN, Resolve-DnsName, median of 6 | 18 ms | 25 ms | **12 018 ms** |
| NXDOMAIN, .NET getaddrinfo / curl, median of 6 | 26 / 89 ms | 21 / 99 ms | **12 015 / 12 111 ms** |
| Search list `sieve-nope-4711.com,wikipedia.org` (set and settled 20 s), `www` and `en`, .NET and curl, 6 each | 24/24, 4 to 160 ms | 24/24, 16 to 136 ms (42 rewrites counted) | 24/24, 5 to 151 ms |
| The same list set 1 s before each trial (.NET `www`) | 1 of 5 resolved (4 failed at 2.8 s) | 3 of 5 (2 failed at 9.7 s) | 5 of 5 |
| Search list `nope.test,corp.test`, `host1` only under the second (NRPT to 127.0.0.2), .NET | 24 ms | 61 ms | 14 ms |
| Single label only LLMNR answers (`sieveonly1`), .NET | 2.8 s | **9.7 s** | **9.8 s** |
| `.local` own name (mDNS) | 15 ms, Ethernet's link-local | 15 ms, Sieve's link-local first | 1 ms, the same |
| Split DNS `a.split.test`, NRPT to 127.0.0.2 | 17 ms | 16 ms | 2 ms |
| Own host name, single label | 10.128.0.2 | 198.18.0.1 first | not run |

Does NODATA change the suffix search or LLMNR? Not measurably: with a settled search list the name under the second suffix resolved 24 of 24 times with 42 rewrites behind it, as without the rewrite. The failures in the second-to-last row came with a search list changed a second earlier, and Sieve off failed more of those than the rewrite did. LLMNR fallback works in every arm; Sieve on costs it 7 s whatever the rewrite (NetBIOS off on Sieve's adapter: still 9.8 s; cause not found). Without the rewrite every NXDOMAIN costs 12 s, in every program that resolves through Windows.

| Check | Result | Evidence |
|---|---|---|
| Ethernet at metric 1 | PASS | capture refused, `last_error`: "Ethernet" has interface metric 1 for IPv4, which ties with Sieve's DNS server...; 0 filters, no server on Sieve; lookups 10/10 at 25 ms, NXDOMAIN 17 ms; the old leak (44 plain packets), as without the capture |
| Firewall drops 53 to 198.18.0.53 | PASS after the fix | closed 16 s after the rule; lookups then 55 ms; at a restart with the rule the probe refuses it ("a probe through the DNS Client did not reach Sieve's DNS server within 1000 ms"), lookups 10/10 |
| Kill, then the next start | PASS after the fix | key with `NameServer=198.18.0.53` after the kill; absent after the recovery start; DNS 0.01 s, https 0.26 s after the kill |
| Uninstall after a kill | PASS | key present before, absent after; service absent, no adapter; DNS 0.02 s |
| Dynamic registration (primary suffix `corp.test`, `ipconfig /registerdns`) | INCONCLUSIVE | the VM's server is no authority for `corp.test`, so registration fails off and on alike (event 8016 in both). On: 8 queries reached 198.18.0.53, 2 reached the engine addressed to 10.128.0.1 through the adapter (sent unbound, so the block did not stop them), and 29 port-53 packets left the NIC to 10.128.0.1 (the engine's split-horizon sends for `corp.test`, now a machine suffix, and any forwarded update: pktmon does not tell them apart). No server on the VM accepts an update; forwarding is proven by unit test only |
| Two-adapter split DNS, a VPN | SKIP | one NIC and no VPN on the VM; NRPT to a loopback server instead (above), the rest by unit tests |

VM state at the stop: `setup-cur.exe` reinstalled (engine 8BFE89A7), policy `engine` false, no NRPT rule, no test firewall rule, search list and primary suffix empty, Ethernet metric automatic, responders stopped, no Sieve key in the registry.

## Run 3 (2026-11-09): the DNS gap after a start, the DNS Client leak

Branch `worktree-agent-acd57d2c31e644f62` on main 8abf3bf. VM 23:57 to 01:21 local (1.4 h), stopped at the end. Engine under test 1B5C3A1A (release); "before" is main 0ea3303 (3940237E), whose bring-up and DNS code are the same as 8abf3bf's.

**The gap after a start: Sieve's address was still tentative.** Sampled every 100 to 300 ms after `Start-Service`: the engine added its routes at 0.27 to 0.39 s while 198.18.0.1 was `Tentative` (duplicate address detection, `DAD Transmits: 3` on the adapter). Until it turned `Preferred` at 3.3 to 3.4 s, every send through those routes failed at once with `HostUnreachable` (own socket to 10.128.0.1 and to 1.1.1.1), so lookups got no answer for 3.0 s each round. Fix: the addresses go on right after the adapter is created, and no route is added before every address is `Preferred` (bounded at 10 s, then a Setup blocker; `routing::route_adapter`, tests in `routing_tests.rs` that fail without the wait). After: 3 rounds, 0 failed probes of 75 to 120 per round through the own socket and the DNS Client; the routes go in at 3.4 to 4.8 s, and until then traffic takes the normal path. One 300 ms probe to 1.1.1.1 timed out in two of six rounds while only Windows' own routes were on the adapter (the probe went out of the NIC), not explained.

**The DNS Client leak.** DNS Client ETW (events 3009, 3010, 3020): it asks every network's servers at once, binding each query to that adapter's address, and Sieve's adapter had no server (its query returned 1460 at once). Server 2025 never asks `fec0:0:0:ffff::1-3`. Measured on the VM with temporary settings, then built:

| Setup | Plain queries out of the NIC | Lookup |
|---|---|---|
| main, no server on Sieve | 40 for 20 lookups (all) | 17 to 36 ms |
| a server on Sieve (198.18.0.53), metric 5 or 1, no block | 40 for 20 lookups | 38 ms |
| server, metric 5, Dnscache's port 53 on Ethernet blocked | 2 | 12 s (it waits out the blocked first network) |
| server, metric 1, blocked | 0 | 44 to 143 ms; an NXDOMAIN 12 s (it waits for the blocked network after a negative) |
| blocking Dnscache's binds to 10.128.0.2 instead | 0 | every lookup fails at once (WSAEACCES) |
| **built: server, metric 1, block, NXDOMAIN to the DNS Client as NODATA** | **0 for 30 fresh names** | 38 ms median; NXDOMAIN 39 ms, NODATA 46, real 31 (off: 16, 18, 2) |

Built (`route::capture`, `route::wfp`, `apply::set_adapter_dns`, `apply::put_first_for_dns`): the adapter names `TUN_DNS` 198.18.0.53 (host route in the plan), interface metric 1, and a dynamic WFP session blocks port 53 from the DNS Client's service SID only, leaving the default-route adapters, to what the engine routes. The DNS service answers the DNS Client's NXDOMAIN as NODATA (same records, rcode 0) so it does not wait 12 s; that is a change of what the DNS Client sees, and needs the owner's yes.

| Check | Result | Evidence |
|---|---|---|
| Leak, 30 fresh names (Resolve-DnsName, .NET, curl) | PASS | pktmon on the NIC: 0 plain port-53 packets; 51 queries to 198.18.0.53. In other runs the only ones were the internal suffix's names (`_ldap._tcp.dc._msdcs.<suffix>` SRV, `<host>.<suffix>`), which the engine itself sends to the LAN server by its split-horizon rule |
| Lookups | PASS | 10 real names over three resolvers 10/10; the internal suffix name resolved to 10.128.0.2; 20 uncached lookups median 38 ms, p90 53 (Sieve off 18 / 20) |
| NRPT `.example.org` to 8.8.8.8 | PASS | www.example.org resolved; rule removed |
| `plain_dns` | PASS | lookups 10/10, NXDOMAIN 22 ms; encrypted upstream answers 311 -> 0 during plain mode; queries left to 10.128.0.1 in plain text, as the user chose |
| Kill (`taskkill /F`) | PASS | capture filters 0 right after; Resolve-DnsName 0.02 s, curl https 0.24 s; route, DNS, proxy, firewall, adapter listings 0 lines different; metrics as before |
| `sc stop` | PASS | filters 0; listings 0 lines different; Sieve's Tcpip interface key gone |
| Reboot after a kill | PASS, one residue | DNS 0.82 s after boot, listings 0 lines different. The kill leaves `Tcpip\Parameters\Interfaces\{5e7e5e7e-...0003}` with `NameServer=198.18.0.53`; it survives the reboot, no adapter reads it, and the next clean stop deletes it (seen) |
| IPv6 disabled (`DisabledComponents` 0xFF, reboot) | PASS | routes up, 198.18.0.1 Preferred, capture on, lookups 10/10, real names 10/10, curl 200, 0 public names leaked; reverted and rebooted |
| Uninstall (`uninstall.exe /S`, exit 0 in 3.4 s, capture on) | PASS | filters 0, service absent, no adapter, no Sieve key in the registry, listings 0 lines different; lookups 0.02 s |
| Dnscache restart | SKIP | Windows refuses to stop it |
| IPv6 block | SKIP | the VM has no IPv6 default route, so only the IPv4 filter was made |
| VPN, Wi-Fi to Ethernet switch | SKIP | none on the VM |

VM state at the stop: `setup-cur.exe` reinstalled, engine main 0ea3303 (3940237E) put back, policy `engine` false, `DisabledComponents` absent, no NRPT rule, no test firewall rule.

## Run 2 (second session, same day)

Branch `live-vm-2026-11-08` with main 8d1d873 merged. VM 20:10 to 23:50 local (3.7 h; 5.1 h today with run 1), stopped at the end.

Fixes on this branch, each with a test that fails without it: 5a6d8af (Version Negotiation is the QUIC refusal), 6dc6a8d (bundle script marks `trusted-*` resources trusted), 3850222 (a user's `+js()` rules get the bundle), 8726598 (`scriptletGlobals` declared for uBO scriptlets).

Still open, in order: the DNS Client leak and the 3 s gap after a start (both fixed in run 3 above, not merged); slice 7 U1 (curl with its own CA bundle is never healed); the uBO list arm of slice 10; slice 9 U6 and the meta-CSP row; slice 11 U9 and U12; video playback (needs a residential IP); the runbooks' `example.com##h1` (the page has no h1 now).

VM state at the stop: Sieve installed from `setup-cur.exe`, engine main 0ea3303 release (3940237E), the real app in place, policy `engine` false, no `live-scope.json`, IPv6 enabled again, no test firewall rule or NRPT rule left. Scripts in the session scratchpad: `d-s8b.ps1`, `d-s9.ps1`, `d-s10.ps1`, `d-s11.ps1`, `d-real2.ps1`, `k-*.ps1`, `content.mjs`, `text.mjs`.

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
| U1 user scriptlet | FAIL, then fixed | Before 3850222 a user's `+js()` rule injected nothing (`with_scriptlets` +0 on example.com): only the lists' engine had the bundle. After: `with_scriptlets` +1 per load. The page still showed nothing: the scriptletGlobals defect below. After 8726598: `data-sieve-probe` = 1 on all six pages in Edge and Chrome, 0 CSP or Trusted Types reports |
| Bundle | FAIL, then fixed | The assembled uBO 3762a26 bundle was refused whole: "resource trusted-prevent-xhr.js is named trusted but any list could inject it" (uBO registers it without `requiresTrust`). Fixed in the bundle script (6dc6a8d) |
| U2 header CSP, Trusted Types | PASS | github.com, www.google.com search, www.youtube.com (TT), developer.mozilla.org, accounts.google.com (TT), web.dev: 0 CSP or Trusted Types reports, and each site's hiding rule applied (footer 1/1, textarea 1/1, ytd-masthead 1/1, accounts h1 1/1). Google's results page threw `solveSimpleChallenge is not defined`: its bot challenge for this IP; not compared with Sieve off |
| U2 meta CSP | SKIP | none of the six pages had one |
| U3 scriptlet with Trusted Types | PASS | after 8726598 a user `set-attr` scriptlet ran on www.youtube.com and accounts.google.com (both enforce Trusted Types) and on the four pages without; the uBO `world: 'ISOLATED'` question was not run |
| U4 budgets | Reported | the generic stylesheet adds about 540 KB to every page (example.com: 557,840 bytes delivered); load times in "Real use" |
| U5 skip counts | Reported | default lists: adguard-base 74,227 applied / 3,712 skipped, adguard-tracking 437,184 / 14, adguard-url-tracking 2,528 / 208, adguard-dns 190,790 / 7, ubo-badware 4,675 / 65 |
| U6 | SKIP | no site with trailing gzip bytes or a shared dictionary was found |
| U7 cached page after off | SKIP | the reload after content off failed with `ERR_NAME_NOT_RESOLVED` (see "DNS just after a start") |
| U8 plain http, service worker | PASS | http://neverssl.com/ not injected (twice); squoosh.app injected on the network load and not on the service worker's (`fromServiceWorker` true) |

**Found and fixed: no uBO scriptlet ever ran.** uBO's scriptlets read `scriptletGlobals`, which uBO's own injector declares; adblock-rust does not, and Sieve's payload did not. Each scriptlet threw a ReferenceError inside its own `try` and did nothing, silently (`with_scriptlets` still counted the page). Seen with a user `+js(set-attr, html, data-sieve-probe, 1)`: the attribute appeared only on www.youtube.com (not explained), not on example.com, github.com, accounts.google.com, MDN or web.dev; the same scriptlet under jsdom and node read the undeclared name. Fixed in 8726598 (`var scriptletGlobals={};` first in the scriptlets' scope); test `scriptlets_run_in_a_scope_that_declares_scriptlet_globals`, failing before the fix. The slice 10 content arms below ran before it and are rerun after it.

### DNS just after a start

`d-dnsstart.ps1`, three engine restarts, `nslookup` every 150 ms: for about 3 s after `routes_up` lookups through the TUN got no answer (rounds: 2.4 to 5.6 s, 0.5 to 3.8 s, 0.3 to 3.9 s after the start; a second run 0.3 to 4.1 s and 0.6 to 3.7 s), then answered. nslookup (2 s timeout, one retry) said "No response from server": the engine took the queries and answered none in time, most likely while its encrypted upstream connected. A browser opened right after a policy restart fails its first names (`ERR_NAME_NOT_RESOLVED`). Not investigated further yet.

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
| Reboot, engine set not to start | PASS | engine 82DD52A8 on with everything, start type Manual, reboot: after sign-in the service was stopped, 0 routes on Sieve, no Sieve adapter; Resolve-DnsName 1.0 s, nslookup 1.15 s, curl https 1.34 s after the check began. Listing differences: only the Ethernet interface index (7 before, 6 after the boot) and one firewall rule's display name resolved from its resource string; nothing of Sieve's. Start type restored, engine started by hand: routes up |
| Uninstall | PASS | `setup-cur.exe` (this branch at 73b413b, `pnpm tauri build`) installed over the old one silently (exit 0), everything on (`decrypting` true), then `uninstall.exe /S` (exit 0 in 0.9 s): service gone, 0 routes, no adapter, 0 Sieve roots in LocalMachine\Root, `Program Files\Sieve` empty, `ProgramData\Sieve` gone; lookups 0.64 s, nslookup 0.76 s, curl 0.92 s; listings as after the reboot (interface index only) |

### DNS Client capture (branch `worktree-agent-ac848fb4eb311e301` at 89e216c, not merged)

Engine CDD4A717 built from that worktree, installed in place of this run's engine, encryption on. Checks of its `docs/plans/2026-11-08-dns-client-capture.md`:

| # | Result | Evidence |
|---|---|---|
| 1 | PASS | `dns_capture` `waiting` with routes up; Sieve's adapter lists fec0:0:0:ffff::1..3, three /128 routes, address fd53:6965:7665:1::1/128 |
| 2 | FAIL | after `Clear-DnsClientCache; Resolve-DnsName example.com` the capture stayed `waiting` for the whole run: Server 2025's DNS Client never sent a query to the fec0 servers. Even with its usual server (10.128.0.1) blocked by a temporary firewall rule, the lookup failed in 32 ms and no query reached fec0 |
| 3 | not reached | no "Sieve DNS capture" object, since the session never opened (3 dynamic sessions in `netsh wfp show state`, none Sieve's) |
| 4 | FAIL | pktmon on the NIC: 137 plain port-53 packets leaving 10.128.0.2 for 10.128.0.1, all 30 fresh names from PowerShell, curl and Firefox among them, also after a Dnscache restart |
| 5 | Reported | uncached lookups, median / p90: Sieve off 17 / 20 ms; capture build 17 / 23 ms; Sieve's adapter metric 1 17 / 19 ms; metric 500 17 / 20 ms. No extra delay, because nothing is captured |
| 6 | PASS in part | plain mode: lookups answer, the queries leave to 10.128.0.1; failover SKIP (one server) |
| 7 | PASS | the `.internal` name resolved to 10.128.0.2; `nslookup example.com 8.8.8.8` answered |
| 8 | SKIP | no VPN on the VM |
| 9 | PASS | DisabledComponents 0xFF, reboot: routes up, wikipedia.org and github.com loaded in Edge, `dns_capture` `failed`: "no path through Sieve's adapter: CreateUnicastIpAddressEntry fd53:6965:7665:1::1 failed: Win32 error 1168"; reverted |
| 10 | PASS | removing fec0:0:0:ffff::1/128 gave `failed` "Sieve's adapter lacks the route fec0:0:0:ffff::1/128"; DNS kept working |
| 11 | not reached | BFE restarted; the capture was never open, so stayed `waiting`; DNS worked after |
| 12 | PASS | AAAA answers came back; `Test-NetConnection example.com -Port 443` went over IPv4 (104.20.23.154, source 198.18.0.1) |
| 13 | SKIP | junction install not tried |
| 14 | PASS | an NRPT rule for .example.org to 8.8.8.8: www.example.org resolved; rule removed |
| 15 | PASS for what it can show | after `taskkill /F`, `sc stop` and an uninstall: 0 "Sieve DNS capture" objects and DNS working (Resolve-DnsName 0.01 s, curl 0.2 s). The session had never opened, so this does not prove the session's objects go away |
| 16 | PASS | rebooted with Sieve installed and off: 0 capture objects, lookups and HTTPS normal |

So on this Windows Server 2025 VM the design's premise does not hold: the DNS Client does not use the fec0 well-known servers of an adapter with no DNS server, even when its own server fails. The leak found in run 1 stays. The normal engine was put back afterwards (the slice 7 checks below install main's build).

### Slice 7 with main's fixes (0ea3303)

Main built here (release 3940237E; `live-scope` build B0DBE09A), installed over a fresh install, `https` on, `content` off.

| Check | Result | Evidence |
|---|---|---|
| U5 ordinary browsing | PASS | 20 sites, 20 minutes, 17 passes alternating Edge and Chrome, fresh profiles and a kept profile per browser (closed after each pass): 340 loads, 4847 intercepted; `https.healed` +0, 0 `auto:pinning` rows. `exclusions.json` before: empty; after: one row, www.apple.com reason `ev` (not heal's). The old build in this run had made 32 browser `auto:pinning` rows in the same kind of browsing |
| U1 a pinning client | FAIL | live-scope build, `{"scope":"all"}`: curl 8.21.0 (Schannel) with `--cacert` holding the machine's 32 public roots (Sieve's left out), www.wikipedia.org, six attempts 2 s apart: each failed with "untrusted root" (Sieve's certificate, 0.07 to 0.14 s). No exclusion was made, `https.healed` stayed 0, and the log rows for curl read `passed (no_rule)`. A capture shows each connection ended by FIN, no RST. So curl was never excluded and never worked on retry |
| U2 | SKIP | Discord and Steam are not installed |
| U3 | SKIP | "Try decrypting again" is an app action; not driven here |
| U4 | Reported | curl over Schannel closes with FIN after the certificate (no RST); the alert byte was not decoded |

On the first try the three curls ran about 1 s after the restart and all failed with "Could not resolve host": the same DNS gap just after a start as above.

Afterwards: live-scope file removed, main's release engine 3940237E back, the real app back in place of the pipe client, policy `engine` false.

### Slice 10 without the video site

12 ad-heavy news sites, Edge and Chrome, a fresh profile per load, 6 s watched. `ads` counts visible ad elements, `adRequests` requests to ad hosts. Off and route ran on 709C9CAA, the content arms on 82DD52A8 (scriptletGlobals fixed, TEST bundle).

| Arm | Edge ads | Edge ad requests | Chrome ads | Chrome ad requests | Loaded |
|---|---|---|---|---|---|
| Sieve off | 134 | 4761 | 137 | 4104 | 11/12, 12/12 |
| Route only (DNS and connection filtering, no decryption) | 50 | 201 | 50 | 199 | 12/12 |
| Content, default lists (`blocked` +626, `rewritten` +23 and +20, `with_scriptlets` +19 and +16) | 0 | 64 | 0 | 64 | 12/12 |
| Content, default plus uBO lists | 0 | 57 | 0 | 57 | 12/12 |

- Default list set: PASS on these sites, 0 visible ad elements in both browsers with content filtering, against 134 and 137 with Sieve off.
- uBO arm: inconclusive. The three uBO lists were downloaded during the arm (20:55 UTC) but `status.filter.lists` still showed only the five default lists when the 300 s wait ended, so the run cannot say they were compiled. It changes nothing here: the default arm already showed 0 ads.
- A first content run before the scriptletGlobals fix gave the same 0 ads (scriptlets did not run then), so on these sites the hiding and blocking rules alone remove what the probe counts.
- Video playback: SKIP, YouTube blocks this data-centre IP (run 1).
- Real use again with 82DD52A8: the same 20 sites loaded, no page broken (same status and text as off), `with_scriptlets` +13 (Edge) and +6 (Chrome); load times single samples, in the same range as above.

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
