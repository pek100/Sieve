# Spike: per-app filtering through a Wintun TUN (2026-10-17)

> **Moved 2026-10-18 (engine slice 1).** `spikes/wintun/` no longer exists. Its decoders and their tests are in `engine/crates/sieve-engine/src/flow/`, the probe in `engine/crates/sieve-engine/src/bin/probe/` (`support.rs` was `probe_support.rs`), the bench in `engine/crates/sieve-engine/examples/`. `rules.rs` was retired: verdicts ask `sieve_filter::rules::RuleEngine`. Open issue 5 (ipstack's `build.rs`) is resolved by `engine/vendor/ipstack`. Paths below are the spike's as it was. Build the probe now with `cargo build --release --bin probe` in `engine/`; the exe is `engine\target\release\probe.exe`.

Question: can Sieve drop a blocked domain for one app and not for another, which its DNS filter cannot do (the Windows DNS Client service makes every lookup, so DNS has no per-app identity)?

Approach under test: Sieve creates a Wintun adapter (WireGuard's signed layer-3 TUN), routes traffic into it, reads IP packets in user mode, terminates them in a userspace TCP/IP stack, attributes each flow to its process, reads the domain from the flow's first bytes (TLS SNI, HTTP Host, QUIC Initial), decides pass or drop per (app, domain), and forwards passed flows to the real network through sockets pinned to the physical interface.

Code: `spikes/wintun/` (standalone crate, own workspace and target dir, not a member of `src-tauri`). Nothing in `src/` or `src-tauri/` changed.

History: this spike started on WinDivert. Microsoft Defender flagged the official WinDivert 2.2.2 release zip (`Misleading:Win32/Malgent!AMTB`) on download, and the user chose to pivot to Wintun. No WinDivert code or binary is in this crate or in git. The quarantined zip is still listed by Defender under `E:\ml-tools\windivert`; it was left to Defender.

## Verdict so far

| Part | Status | Evidence |
|---|---|---|
| Domain from TLS, HTTP, QUIC v1 and v2 | Proven offline | 95 unit and property tests, RFC 9001 and RFC 9369 vectors byte for byte |
| Per-app decision | Proven offline | pure `verdict()` tests, enforce-test policy tests |
| Flow to pid (owner tables, lag retry) | Logic proven offline; live UNVERIFIED | decoder and attributor tests with a lagging fake table |
| Wintun adapter, routes, forwarding, cleanup | Builds; UNVERIFIED until the user runs the probe | `cargo build --release` ok |
| Decode cost | Measured | 0.2 to 4 microseconds once per flow |
| Userspace stack cost | Measured in memory | about 17 microseconds per packet in a pessimistic one-packet-at-a-time test |

## 1. What was proven offline

`cargo test` in `spikes/wintun`: **95 passed, 0 failed** (lib). `cargo clippy --all-targets -D warnings`: clean in debug and release. `cargo build --release --bin probe`: ok.

| Module | What it does | Tests |
|---|---|---|
| `sni.rs` | TLS records over a TCP stream to ClientHello: SNI (first `host_name`, lower case, validated), ALPN, ECH flag (reports the outer name only). Records split anywhere, GREASE skipped, missing SNI is `Done(None)`, two `server_name` extensions or a bad name is `Invalid` (never guessed), 16 KiB cap. | 21 (4 property tests: arbitrary bytes, handshake-shaped garbage, mutated valid hellos, round trip of any name over any record split) |
| `quic.rs` | QUIC Initial: keys from the client DCID (HKDF, v1 and v2 labels and salts), header protection removal, AES-128-GCM open, frame walk (PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE; anything else is `Invalid`), coalesced packets (skips 0-RTT and Handshake, stops at a short header or a Retry), CRYPTO reassembly in any order across packets and datagrams, 16 KiB cap. | 16, including: RFC 9001 A.1 keys and A.2 header-protection mask; the RFC 9001 and RFC 9369 A.2 client Initials decrypt to the expected ClientHello (`example.com`, ALPN `alpn`); sealing the RFC payload reproduces both RFC packets byte for byte; a ClientHello split over two Initials (both versions, either order, with a retransmit); 4 property tests (arbitrary datagrams, long-header garbage, mutated RFC packet, shuffled fragments) |
| `http.rs` | HTTP/1 request head to Host (case-insensitive header, port and brackets stripped, absolute-form and CONNECT fallbacks, two Host headers refused, 8 KiB cap) | 6 (1 property) |
| `stream.rs` | Per-flow TCP payload reassembly by sequence number: retransmits, overlaps, out-of-order with a 16-segment pending cap, wraparound, byte cap | 6 (1 property: any segmentation and order rebuilds the stream) |
| `packet.rs` | IPv4/IPv6 (hop-by-hop, routing, destination options walked; fragments skipped) to TCP/UDP payload | 4 (1 property) |
| `rules.rs` | The DNS filter's rule syntax and suffix-set matcher, copied from `src-tauri/src/dns/rules.rs` at 949dbf5. Copied rather than linked so the spike builds while `src-tauri` is being edited and does not pull in Tauri; integration moves it into one shared crate. | 5 (the parity subset) |
| `flows.rs` | Owner-pid table decoding (TCP/UDP, v4/v6, network-order ports, count clamped to the buffer), matching (exact 5-tuple, then local end, then wildcard UDP), `Attributor` (snapshot cache, refresh on a miss at most every 15 ms, `Pending` until 250 ms, then `Unknown`), pid to exe cache (10 s, never asks for pids 0 and 4), and the pure `verdict(domain, exe, rules, policy)`. | 17 (2 property: table decoding never panics, off and watch never drop) |
| `classify.rs` | One decision per flow: TCP on the in-order client stream, UDP on datagrams. Stops inspecting after deciding. Caps: 16 reads or the stream byte cap for TCP, 8 datagrams for UDP. | 9 (1 property: at most one decision, buffer within the cap) |
| `probe_support.rs` | Probe arguments, the enforce-test domain guard (reserved TLDs only), route-target guard, flow record, summary, admin command text | 8 |
| `lib.rs` | Reader, varint (RFC 9000 A.1 examples), hex | 3 |

Decision rules (`flows::verdict`), all tested:
- No domain (no SNI, ECH with no usable outer name, no Host, not TLS/QUIC/HTTP, cap hit): **pass**, reason "unknown domain".
- App level below `sieve` (Sieve's `off < watch < sieve`): **pass**, reason names the level.
- Allow rule: pass. Block rule for a sieved app: **drop**. No rule: pass.
- Unknown app (pid not found or exe unreadable): the policy default applies (sieve in observe mode, off in the enforce test).

## 2. Stack and binding choices

**Userspace stack: `ipstack` 1.0.1** (Apache-2.0, github.com/narrowlink/ipstack, updated 2026-07). Candidates (crates.io, 2026-10-17):

| Crate | Version, updated | License | Fit |
|---|---|---|---|
| ipstack | 1.0.1, 2026-07 | Apache-2.0 | TCP and UDP terminate into tokio `AsyncRead`/`AsyncWrite` streams with `local_addr`/`peer_addr`; takes any packet device; used by tun2proxy on Windows with Wintun. Chosen. |
| netstack-smoltcp | 0.2.4, 2026-07 | MIT or Apache-2.0 | Also good (smoltcp underneath, used by clash-rs); a sink/stream split API; would work. Second choice. |
| smoltcp directly | 0.14.0, 2026-08 | 0BSD | Most mature engine, but we would write the socket-per-flow plumbing, the any-destination accept and the UDP flow table ourselves. |
| lwip bindings | 0.4.0 | MIT/Apache | C stack, small community on crates.io, FFI build on Windows. Not chosen. |

Why ipstack: least glue for "accept every flow to any destination" (the TUN case), UDP flows included (needed for QUIC), maintained, Windows-tested by tun2proxy, permissive license. Watch-outs found in its source:
- Its `build.rs` runs on every Windows build, also as a dependency: it shells out to `cargo metadata` and copies the `wintun.dll` bundled in the `wintun` crate (its dev-dependency) into `target/<profile>/examples/`. The copied DLL hashes `E5DA8447...DAFCE`, the same as the official 0.14.1 amd64 DLL verified below. It is under `target/` (git-ignored) and the probe never loads it (it loads the DLL from `--wintun-dll`). For the product, vendor or patch this out.
- UDP reads clamp oversized datagrams (the tail is dropped); the forwarder uses 64 KiB buffers so this does not happen.

**Wintun loader: `wintun-bindings` 0.7.40** (MIT, tun2proxy fork of the `wintun` crate, updated 2026-08; the original `wintun` crate was last updated 2025-01). It loads `wintun.dll` at run time (libloading), so the build needs no binary. Its `verify_binary_signature` feature is on: the probe refuses a DLL whose Authenticode signer is not "WireGuard LLC". Its `set_address`/`set_netmask` shell out to `netsh`; the probe does not use them and sets its address and routes through the IP Helper API (`CreateUnicastIpAddressEntry`, `CreateIpForwardEntry2`), which it can undo exactly.

## 3. Getting Wintun

- Source: `https://www.wintun.net/builds/wintun-0.14.1.zip` (latest), into `E:\ml-tools\wintun` (outside the repo).
- Zip SHA-256: `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` (750,540 bytes).
- `wintun\bin\amd64\wintun.dll` SHA-256: `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` (427,552 bytes).
- `Get-AuthenticodeSignature`: **Valid** ("Signature verified."). Signer: CN=WireGuard LLC, Boulder, Colorado, US. Issuer: DigiCert EV Code Signing CA (SHA2). Certificate valid 2018-12-10 to 2021-12-14, with a DigiCert timestamp (2021), so the signature stays valid after expiry.
- Microsoft Defender: no detection for the Wintun zip or its files (the only recent detection is the earlier WinDivert zip).

## 4. Flow attribution from the TUN side

When ipstack hands over a new flow, its `local_addr` is the app's socket (source address is the TUN's address, because the route sent the packet there) and `peer_addr` is the destination. `flows::Attributor` looks that up in the owner-pid rows of `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` or `GetExtendedUdpTable(UDP_TABLE_OWNER_PID)`, the same read-only tables Sieve's netstat module reads. The table can lag the first packet, so a miss refreshes the snapshot (at most every 15 ms) and retries until 250 ms, then gives up as "unattributed". The pid goes to `QueryFullProcessImageNameW` (cached 10 s). Attribution runs in parallel with the upstream connect and the first-bytes wait, so it adds no latency unless the table is slower than the ClientHello.

## 5. Forwarder and DNS

- TCP: connect upstream at once (pinned to the physical interface) and relay server to app at once, so server-speaks-first protocols are not stalled. Client bytes are held until the classifier decides (or 5 s pass with nothing to decide on). Pass forwards the held bytes and relays the rest; drop closes both sides.
- UDP: datagrams are held until decided (a QUIC ClientHello can span two Initials), then relayed both ways; drop discards the flow. QUIC is decoded, never blocked wholesale; a blocked domain's Initials are dropped like a blocked TLS hello, and the app falls back to TCP, where the same domain is dropped again.
- Loop prevention: every upstream socket gets `IP_UNICAST_IF` (IPv4, index in network byte order) or `IPV6_UNICAST_IF` (index in host order) set to the physical interface Windows chose for that address before the test route existed. A lookup that answers the TUN's own index is refused ("would loop").
- DNS (port 53): in the probe's test mode only one public host is routed, so the system's DNS traffic never enters the TUN. When a port 53 flow does enter it (full-route mode later), it is counted as `dns` and forwarded to `--dns-via` (for example Sieve's DNS filter at `127.0.0.1:53`; a loopback target is not pinned) or else to its original destination through the physical interface. For the product: send TUN DNS to Sieve's own DNS filter, so DNS blocking and per-app blocking share one rule set, and keep the filter's upstreams pinned to the physical interface.

## 6. The live probe (the user runs it; it was NOT run here)

Build (already done, no admin): `cargo build --release --bin probe` in `spikes\wintun`. It creates an adapter and routes only when run elevated; unelevated it prints the command below and changes nothing.

Safety by construction:
- It routes only the /32 and /128 addresses of one host you name (at most 8), never the default route. It refuses loopback, private, link-local, CGNAT, multicast, documentation and benchmark ranges.
- Adapter "Sieve Spike", tunnel type "Sieve", fixed GUID `5e7e5e7e-51e7-4e00-8a11-5e7e00000001`, address `198.18.211.1` (benchmark range), plus `fd53:6965:7665::1` when an IPv6 address is routed.
- On time up, Ctrl+C or panic, it deletes exactly the routes and address it created, then closes the adapter (Wintun removes an adapter when its creator closes it). If the process is killed, Windows closes the handle, the adapter disappears, and routes bound to that interface go with it.
- Enforce test: drops only a name under `.example`, `.test`, `.invalid` or `.localhost`, and only for the one exe given. Everything else is forwarded.

### Observe run (one admin command)

In Terminal (Admin):

```
& "F:\Projects\Code\Sieve\.claude\worktrees\agent-a025d1b361c8851d3\spikes\wintun\target\release\probe.exe" --route-host example.com --seconds 60 --out $env:TEMP
```

(After merge the exe is at `<repo>\spikes\wintun\target\release\probe.exe`. The default `--wintun-dll` is `E:\ml-tools\wintun\wintun\bin\amd64\wintun.dll`.)

While it runs, in a normal terminal: `curl.exe -s -o NUL https://example.com/` and `curl.exe -s -o NUL http://example.com/`, and open https://example.com in Edge or Chrome (Cloudflare serves HTTP/3, so after the first visit the browser may use QUIC). This machine's built-in curl 8.21 has no HTTP/3, so the QUIC check needs the browser.

Expected: a banner listing the routed addresses, then one line per flow, for example

```
[  3.214s] tcp  pid=12345  exe=curl.exe               kind=tls  domain=example.com                      ech=false verdict=pass (would) (no rule)
[  9.870s] udp  pid=6789   exe=msedge.exe             kind=quic domain=example.com                      ech=false verdict=pass (would) (no rule)
```

then a summary (flows, attributed, decoded by kind, ECH, failures, forwarder errors, TUN packets in and out), "routes and address removed", and the paths of `probe-report-<time>.json` and `.txt`. Add `--rules <list file>` to see the verdict Sieve would give with a real list, and `--exempt <exe>` to see an off app pass.

How to read it:
- `attributed` close to `flows` means owner-table attribution works from the TUN. Many `unattributed` means the table lags more than 250 ms or the local address differs: open issue.
- `decoded` with `tls`, `http` and `quic` entries proves each decoder on real traffic. `quic` appearing proves the Initial decoding on a live browser.
- `forwarder errors` at 0 and pages loading prove the IP_UNICAST_IF forwarder does not loop.
- After it exits, `route print 104.20.23.154` (or the address it routed) must show no route through "Sieve Spike", and `Get-NetAdapter -Name "Sieve Spike"` must find nothing.

### One-app blocking test

In Terminal (Admin):

```
& "F:\Projects\Code\Sieve\.claude\worktrees\agent-a025d1b361c8851d3\spikes\wintun\target\release\probe.exe" --route-host example.com --seconds 120 --out $env:TEMP --enforce-test --block-domain sieve-spike-test.example --block-exe curl.exe
```

The banner prints the exact commands with the routed address filled in. In a second, normal PowerShell (`<ip>` is the IPv4 the banner shows, today 104.20.23.154 or 172.66.147.243):

```
Copy-Item C:\Windows\System32\curl.exe $env:TEMP\curl-other.exe
curl.exe -s -m 8 -o NUL -w "%{http_code}`n" --resolve sieve-spike-test.example:80:<ip> http://sieve-spike-test.example/
& $env:TEMP\curl-other.exe -s -m 8 -o NUL -w "%{http_code}`n" --resolve sieve-spike-test.example:80:<ip> http://sieve-spike-test.example/
```

Expected: `curl.exe` prints `000` (connection closed, no response) and the probe logs `verdict=drop (block rule)`. `curl-other.exe` (a different exe path, same binary) prints the server's status code, likely a 4xx error page from Cloudflare for an unknown host, and the probe logs `verdict=pass (app level off ...)`. That is one domain blocked for one app and not for another.

TLS check (same pattern on port 443 with `-vk`): both may end without an HTTP code, because the server rejects the test name. The difference is where: the blocked one never receives a server hello (connection closed right after the client hello), the passed one gets the server's TLS alert or certificate. The probe's log lines are the authoritative evidence.

### Live run 1 (observe, `--route-host example.com`, AdGuard and AdGuard VPN running): findings and fixes

What happened: 20,827 flows, all UDP, almost all owned by `probe.exe`, 790,887 packets in and 18 out. The curls took 20 s and failed, then 2 s and succeeded, then succeeded quickly. Routes and adapter were removed at exit, as designed.

1. **Self-loop: multicast, not byte order.** Every flow's destination was multicast: 239.255.255.250 (SSDP) 8,864, ff02::1:3 (LLMNR) 4,388, 224.0.0.252 (LLMNR) 3,933, ff02::c 1,996, ff02::1 886, 224.0.0.251 and ff02::fb (mDNS). The first was Steam's LAN discovery to `ff02::1:27036`, sent on every interface, including the new TUN's auto-assigned link-local address. The forwarder re-sent each datagram from a new socket. `IP_UNICAST_IF` / `IPV6_UNICAST_IF` do not apply to multicast, so Windows sent it out of the TUN again. A new source port each time made a "new flow" owned by `probe.exe` every 31 ms, which then multiplied. The byte order was already correct (IPv4 in network order, IPv6 in host order); it now lives in a tested helper (`unicast_if_value`). Fixes:
   - The TUN reader hands the stack only packets whose destination is a routed test address. Multicast, broadcast and link-local traffic is counted as "not unicast", anything else as "not a routed address", and both are discarded before any per-flow work. This is tested on every destination class the run looped on.
   - Loop guard: a flow owned by the probe's own pid is refused, logged once and then counted (`own-process flows refused`).
2. **TCP did reach the stack; the count missed it.** Four IPv6 TCP flows from curl to `2606:4700:10::ac42:93f3` (ports 80 and 443) arrived and were accepted. The upstream connect failed with 10049 ("address not valid in its context"), and the handler returned before logging, so the summary said `tcp 0`.
   - Cause: with a /128 route to the TUN, Windows picks the TUN's ULA (`fd53:...::1`) as the source address for the destination, while `IPV6_UNICAST_IF` forces the packet out of Wi-Fi, where that source does not exist.
   - Fix: before adding any route, the probe asks Windows for the source address it would use for each test address (UDP connect, nothing sent) and binds every forwarder socket to it, plus the interface pin. An address with no usable source is not routed at all.
   - Failed connects are now logged and counted as flows (`upstream connect failed`).
   - The app side is closed with a FIN on any drop or failure. An ipstack stream that is only dropped sends nothing, so curl waited for its own timeout. That explains the 20 s failure: curl tried IPv6 first, which hung in the forwarder.
   - No IPv4 TCP and no UDP 443 to the routed addresses arrived during the whole run. The later 200s were most likely IPv4 connections that AdGuard's driver redirected to its local proxy before routing; AdGuard then connected out itself without passing through the TUN. That would also explain why the browser showed no QUIC, since AdGuard may block or proxy HTTP/3. Unconfirmed: the new counters `to routed addresses: TCP SYN v4/v6, UDP v4/v6` answer it on the next run. Then repeat with AdGuard protection paused.
3. **Test host.** example.com is a shared Cloudflare anycast front, so its addresses carry many unrelated sites. (Steam itself was multicast, not routed traffic.) The default is now `quic.nginx.org`: nginx's own HTTP/3 test site on dedicated AWS addresses (3.125.64.247 and 18.193.151.235 on 2026-10-17, IPv4 only), serving HTTP, HTTPS and HTTP/3. `--route-ip` takes explicit public addresses; the public-only guard is unchanged.
4. **Logging.** The console prints the first 200 flow lines, then a note; the reports keep the first 2,000 records; every flow is still counted in the summary.

Tests added: destination admission (all multicast and link-local destinations from the run), own-pid refusal, the byte-order helper, the log cap, the default host and the destination helper. 100 tests pass.

### Live runs 2 to 4 (after the fixes)

- **probe2, AdGuard protection ON:** all 3,570 flows were `AdguardSvc.exe`. AdGuard's driver redirects apps to its proxy before routing, and then re-captures the forwarder's own outbound connections, so they loop; curl timed out. Conclusion: the per-app engine must refuse to run while AdGuard protection is on (detect and say so).
- **probe3, AdGuard paused, observe:** 6 flows, all attributed (curl.exe TLS and HTTP, claude.exe TLS, plus QUIC decoded live with `ech=true`). No loop, no forwarder errors, cleanup OK. HTTPS through the TUN returned 200 (1.1 s first, then 0.27 s). Counters: TCP SYN v4 5, UDP v4 72, 261 multicast packets discarded.
- **probe4, enforce test:** curl.exe was dropped and curl-other.exe passed, as designed.
- **Plain HTTP "empty reply" (curl exit 52) on `http://quic.nginx.org/`: not a probe bug.** The same curl from this machine with no TUN at all gives exit 52 too ("Request completely sent off", then "Empty reply from server"): quic.nginx.org accepts port 80, reads the request and closes without answering. `http://nginx.org/` returns 200 from the same machine. The probe did its job: it decoded the Host (`kind=http`), passed the flow, replayed the request and relayed the server's close.
  - **Regression tests:** the TCP relay moved into `spike::relay::relay_tcp`, generic over the stream types, and the probe calls it for every TCP flow, so TLS and HTTP share one path. Eight tests drive it with an in-memory app stream and a real loopback upstream: an HTTP request is replayed exactly once and the 200 response reaches the app; a request in 7-byte pieces arrives whole; reply-then-close delivers the whole reply; close-without-reply gives the app EOF with 0 bytes, not a hang (the quic.nginx.org case); TLS in two writes is replayed, then both directions flow; drop sends nothing upstream; a server-first banner reaches the app before any client byte; client EOF before any byte stops without deciding.
  - **Enforce test clarity:** a made-up test name gets rejected by any real server, so its pass case is not a clean signal. `--block-domain` may now also be the routed host itself (only flows to its routed addresses can reach the stack, so nothing else can be dropped). The banner then prints plain HTTPS commands: blocked prints 000, passed prints 200.

- **Run 2 never exited** (it printed the summary and wrote both reports, but the process was still alive 25 minutes later and had to be killed). Root cause: `run()` let the tokio runtime drop while thousands of stuck flow tasks were still live. Each task owned an ipstack TCP stream, whose `Drop` waits synchronously (`block_in_place` + `block_on`) for the stream's own session task. A runtime that is shutting down no longer drives that task, so the drop waited forever. Runs 3 and 4 had no live streams at the end, so they exited. Fix:
  - All flow tasks live in `spike::tasks::FlowTasks` (a `JoinSet`).
  - At stop, the probe arms a 30 s exit watchdog, closes the Wintun session (the blocking read returns), and aborts and drains every flow task within 5 s while the runtime still runs.
  - It then removes routes, closes the adapter, writes the reports, and ends the runtime with `shutdown_timeout(3 s)` instead of a drop.
  - If anything still hangs, the watchdog removes the routes (idempotent) and calls `std::process::exit(6)`.
  - Tests: 40 relays stuck on a loopback upstream that never answers, plus 40 forwarder connects that never complete, each holding a guard whose `Drop` blocks exactly like ipstack's. All are cancelled and the runtime is shut down within the bound (well under a second here). A second test covers reaping finished flows and an immediate shutdown of an empty set.

### Next live run (observe)

In Terminal (Admin):

```
& "F:\Projects\Code\Sieve\.claude\worktrees\agent-a025d1b361c8851d3\spikes\wintun\target\release\probe.exe" --seconds 90 --out $env:TEMP
```

(Default host quic.nginx.org; its plain HTTP gives curl exit 52 with or without the TUN, see above.) Enforce test with a clean pass signal (AdGuard protection paused):

```
& "F:\Projects\Code\Sieve\.claude\worktrees\agent-a025d1b361c8851d3\spikes\wintun\target\release\probe.exe" --seconds 90 --out $env:TEMP --enforce-test --block-domain quic.nginx.org --block-exe curl.exe
```

Expected: `curl.exe https://quic.nginx.org/` prints 000, the copied `curl-other.exe` prints 200, and the log shows `verdict=drop` and `verdict=pass`. The banner prints the curl commands. In a normal PowerShell run them twice each, then open https://quic.nginx.org/ in a browser and reload twice. Then, if AdGuard allows it, pause AdGuard protection and run all of it once more within the same 90 s, or in a second run.

What to look for in the summary:
- `TUN packets discarded before the stack: not unicast N`: OS chatter, now harmless. `own-process flows refused` must be 0.
- `to routed addresses: TCP SYN v4 N`: IPv4 connects reached the TUN. 0 with AdGuard on and above 0 with AdGuard paused means AdGuard's redirect takes TCP before routing.
- `UDP v4 N` and `decoded domains by kind: quic=N` mean the browser used HTTP/3 through the TUN and the QUIC decoder read its SNI live.
- `tls`, `http` entries and `attributed` equal to `flows`, with `curl.exe` and the browser named as the exe.
- `forwarder errors: none`, and curl prints 200 (or a redirect code) in well under a second.

## 7. Performance (measured, CPU only)

`cargo run --release --example bench` on this machine:

| Path | Cost |
|---|---|
| TLS ClientHello (1.5 KB) to SNI and ALPN | 245 ns per flow |
| HTTP request head to Host | 354 ns per flow |
| QUIC v1 Initial (1200 B) decrypt and SNI | 4.1 us per flow (0.8 us of it is key derivation) |
| IPv4+TCP header parse | 6 ns |
| Owner match, 500-row table | 176 ns |
| Verdict against 100k rules | 171 to 231 ns |
| ipstack: UDP datagram TUN to stream read | 16.5 us per packet |
| ipstack: TCP 1400 B segment TUN to stream read | 17.8 us per packet (about 630 Mbit/s for one flow at that cost) |

Reading: the per-flow decode and decision cost a few microseconds once and do not matter. The userspace stack dominates: every packet of a routed flow pays it, in both directions. The ipstack number comes from a deliberately pessimistic test (one packet in flight, a cross-thread wakeup per packet); batched real traffic should do better. Expect roughly 1 to 3 CPU-microseconds per packet under load plus the relay copy. A 100 Mbit/s download is about 9,000 packets per second, around 2 to 15 percent of one core. Fine for the test route; for full-route mode, measure on the probe (the summary reports TUN packets in and out; time a large download through a routed host).

Battery and CPU: an idle TUN costs nothing (the reader thread blocks on Wintun's event). Under load the cost scales with packets. Full-route mode keeps a core partly busy during large downloads; a "filter only these apps" route policy (later) would avoid sending everything through it.

## 8. Risks

- **AdGuard and AdGuard VPN on this machine.** AdGuard's WFP driver redirects app connections to its local proxy; AdGuard VPN is itself a TUN with its own routes. With AdGuard filtering on, packets to a routed host may be redirected before they reach Sieve's route (then the probe sees nothing, or sees AdGuard's process as the owner), and the forwarder's own outbound sockets may be intercepted by AdGuard too. AdGuard VPN, if connected, has the most specific or lowest-metric routes for everything; our /32 is more specific and wins, but the forwarder's physical-interface pin then bypasses the VPN for that host. The probe does not touch either. Unknown until the user runs it, ideally once with AdGuard filtering and the VPN off, once with them on.
- **Route conflicts and metrics.** A /32 always beats a default route by prefix length; full-route mode (two /1 routes) competes with VPN clients that do the same. Excluded ranges (LAN, DNS servers, the VPN's own server address) must be carved out.
- **IPv6.** The probe routes the /128s and assigns a ULA address when the host has AAAA records. A machine without IPv6 connectivity will see IPv6 flows fail at the forwarder (counted). Not exercised offline.
- **MTU.** The adapter and ipstack use 1500. Paths with a smaller MTU rely on PMTU discovery across two TCP connections (app to stack, stack to server), which is generally fine. QUIC sets its own sizes (1200-byte minimum).
- **ECH.** With ECH, only the outer (public) name is visible, for example Cloudflare's shared name. Those flows can only be decided by IP or by the DNS filter. Counted as `ech` in the summary.
- **QUIC.** v1 and v2 decode; draft versions and unknown versions are reported as not QUIC and pass. 0-RTT packets carry no new name. Coalesced packets are handled. Packet-number reconstruction uses the truncated number, exact for a client's first Initials.
- **Attribution lag.** If the owner table is slower than 250 ms, the flow is decided as unknown app (policy default). The probe measures it (`attributed after a table retry`).
- **ipstack build script.** It runs `cargo metadata` and copies a bundled DLL into `target/` on every Windows build. Patch it out for the product.
- **Panic semantics.** A panic in any flow task runs the panic hook, which removes the routes while the probe keeps running. That fails safe: traffic returns to normal routing.

## 9. Licensing

- **Wintun** prebuilt DLL ("Prebuilt Binaries License", in the zip): use for lawful purposes; no modification or reverse engineering; redistribution is allowed only when the DLL is distributed alongside software that uses it only through the `wintun.h` API (Sieve would); no use of the WireGuard or Wintun names to endorse or promote Sieve. So Sieve may ship `wintun.dll` unmodified next to its helper. Ship the license text with it.
- ipstack: Apache-2.0. wintun-bindings: MIT. aes, aes-gcm, hkdf, sha2 (RustCrypto): MIT or Apache-2.0. etherparse (benchmark only): MIT or Apache-2.0.

## 10. Integration design for Sieve (if the probe passes)

- **Elevated helper owns the adapter.** A small Windows service (or a helper started once per session elevated) owns Wintun, the routes, ipstack and the forwarder. The Tauri app stays unelevated. The helper loads `wintun.dll` with the signer check, from Sieve's install folder only.
- **IPC.** A named pipe with an ACL for the logged-in user. App to helper: rule set (shared crate, same matcher as the DNS filter), per-app levels, mode. Helper to app: flow events (pid, exe, kind, domain, verdict) feeding the live per-app chart, counters and health. Config changes apply to new flows; existing flows keep their verdict (decide once).
- **Per-app levels map to verdicts.** `sieve`: blocked domains are dropped for that app. `off` and `watch`: never dropped (watch still logs). Unknown app: the "filter unknown apps" setting picks the default. This unlocks the `filtering.perApp` live check (`live_per_app_filter_blocks_one_app`) that `LEVEL_REQUIRES.sieve` is waiting on.
- **DNS filter afterwards.** Keep it. It still blocks system-wide for names, is cheap, and covers ECH and IP-only cases the TUN cannot name. TUN port 53 goes to it. The per-app layer then only needs to decide flows whose app is not sieved: an app set to off must also bypass DNS blocking. Since DNS lookups have no app identity, the clean form is that, with per-app filtering on, the DNS filter stops blocking (only logs and resolves) and the TUN layer drops by (app, domain). Otherwise an off app still gets blocked answers.
- **Full-route mode later.** Two /1 routes (and ::/1, 8000::/1) into the TUN, with exclusions for LAN subnets, the DNS upstreams and VPN server endpoints; forwarder sockets pinned with IP_UNICAST_IF as here.
- **Crash safety.**
  - A dead helper takes the adapter with it (Wintun removes it when its handle closes), so routes never point at a dead TUN.
  - A hung helper is the real risk. Add an internal watchdog: if the packet loop stops servicing the ring for N seconds, the helper deletes its routes first, then exits.
  - The app pings the helper over IPC and shows "per-app filtering stopped" when the pings fail.
  - On start, the helper deletes any route on an interface named "Sieve" left from an unclean OS shutdown.

## 11. Open issues

1. Run the probe (observe, then enforce test) and paste the summary; every live claim above is UNVERIFIED until then.
2. Run it with AdGuard filtering and AdGuard VPN off, then on, to see the stacking behaviour.
3. Measure throughput and CPU through a routed host on the live adapter.
4. Decide the DNS filter's role with per-app filtering on (section 10).
5. Patch or vendor ipstack's `build.rs` before product use.
