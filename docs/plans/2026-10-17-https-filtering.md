# Sieve: AdGuard-grade traffic filtering (design)

Date: 2026-10-17. Status: design only, no product code. Gate: the Wintun live probe (slice 0).

The user's decision, verbatim: "not chosen sites, everything. our filtering should be at least as bulletproof as adguard's".

So Sieve filters all traffic by default, the way AdGuard for Windows does: HTTPS decryption with a local root certificate, full-URL network rules, cosmetic CSS and scriptlet injection (this is what removes YouTube video ads), QUIC covered. It also carries everything that makes AdGuard safe to run that way: automatic exclusions, self-healing exclusion, strict upstream validation, and the per-app Sieve/Off switch as a real exemption.

Inputs: `docs/research/2026-10-17-parity/*` (the survey of AdGuard 8.0.5584 at `E:\AdGuard`), `docs/plans/2026-10-17-parity.md`, `docs/conventions.md`, the Wintun spike (branch `worktree-agent-a025d1b361c8851d3`: `spikes/wintun/`, `docs/research/2026-10-17-wintun-spike.md`), and `src-tauri/src/dns/` and `sysdns/` on main at f5775c6 (`sysdns` was removed on 2026-10-18, see the rule below). New read-only facts from `E:\AdGuard` are in section 0, paraphrased in my own words.

## Decisions by the user (2026-10-17), these override anything below

| Question | Decision |
|---|---|
| AdGuard protection running | Detect it and OFFER TO PAUSE it from Sieve. First find a supported way AdGuard exposes to pause protection (read-only inspection of `E:\AdGuard`); if none exists, the offer stops the AdGuard service with the user's own UAC approval, and the UI says exactly that. Sieve never filters while AdGuard intercepts (probe run 2: every flow became AdguardSvc.exe and Sieve's connections looped). |
| Sensitive never-decrypt list | WRITE OUR OWN: categories (banking, payments, health, government and military TLDs, password managers, OS update endpoints) plus a curated domain list Sieve owns and ships. AdGuard's unlicensed exclusions list is NOT used. |
| Sieve's licence | GPL-3.0. |
| Decryption scope on day one | BROWSERS FIRST (Chrome, Edge, Firefox, Brave, Opera, Vivaldi and other Chromium/Gecko builds, detected from the exe, not a hardcoded list where avoidable). Every other app gets domain-level blocking. Widen to all apps after self-healing exclusions are proven live. |
| Firefox | YES: set the machine policy so Firefox trusts the Windows store (ImportEnterpriseRoots); remove it on uninstall. |
| Shared PC | One machine-wide engine; the account that enabled filtering (and admins) owns the log and settings. |
| Root certificate | 1-year lifetime, SILENT ROTATION a month before expiry; the old root is removed after the switch; status in Settings > Filtering. |
| Scriptlet resources | SEPARATE SIGNED UPDATE checked daily and verified against a published hash, independent of app releases. |
| Health sites | Covered by our own list's health category. |
| Encrypted DNS upstream (2026-10-18) | When the engine answers DNS on its adapter (slice 4), every lookup it does not block goes to the resolver ENCRYPTED: DNS over HTTPS by default (Cloudflare and Quad9 templates); DNS over TLS and DNS over QUIC are optional upstream kinds the user picks in settings. Never plain DNS while the engine runs. Fail open still holds: when the engine stops, Windows' own DNS settings apply untouched (1.4). |
| Post-quantum key exchange (2026-10-18) | The hybrid X25519MLKEM768 through rustls with aws-lc-rs, preferred first on ALL TLS: the client-facing side of interception, the upstream side, and the DoH, DoT and DoQ upstream. AdGuard does the same (E12), and "never weaker than the browser" requires it: Chrome already offers X25519MLKEM768, so interception must not strip it (2.7). |
| Network safety (2026-10-18) | "remove the Point Windows at Sieve feature; the engine will replace it with something that can't break the network." Removed the same day. The rule below binds every slice. |
| Install folder (2026-10-18) | The user KEEPS CHOOSING the install folder (they use `E:\Sieve`). The installer makes any chosen folder as safe as Program Files: it locks a new or empty folder to administrators before copying anything, keeps a marker in it, and refuses a non-empty folder it did not create. The engine refuses to install and to start when its files can be changed by non-admins (1.5, 7.4). |
| Signed updates (2026-10-18) | EVERY UPDATE ARTEFACT IS SIGNED with Ed25519 in the minisign format Tauri's updater uses: app and engine releases, the scriptlet resource bundle, and Sieve-owned lists such as the sensitive never-decrypt list. The private key is generated and kept offline by the user, never in the repo or CI; the public key is compiled into the engine. The engine service downloads, verifies the signature and a version that must increase, and only then replaces files in the locked install folder; anything unsigned, tampered or older is refused and nothing is written. The unelevated app can only request an update. Design in 7.5, slice 13. |

## The rule: Sieve off means a normal network

Sieve off means a normal network. Sieve never writes persistent system network state (DNS servers, persistent routes, proxy settings, firewall rules that outlive the process). Everything Sieve changes disappears by itself when Sieve stops, crashes, is uninstalled or the PC reboots.

Why: "Point Windows at Sieve" set every adapter's DNS to 127.0.0.1 and ::1. After a reboot with Sieve not running, nothing answered DNS and the PC could not connect until the user reset DNS by hand. A recovery that runs when Sieve starts cannot help when Sieve does not start.

What it means for this design:
- The engine's routes and addresses live on the Wintun adapter and in the active store only (`CreateIpForwardEntry2` and `CreateUnicastIpAddressEntry` without a persistent store), so they go with the adapter when the engine's handle closes, and are not there after a reboot (1.6).
- DNS is caught on the TUN (1.4). Windows adapter DNS settings are never written, by the engine or the app.
- No system proxy, no WinHTTP proxy, no firewall or WFP rule that outlives the engine process.
- Trust state is not network state, but it is held to the same exits: the root certificate and the Firefox policy (2.3) change nothing while the engine is stopped, and they go when HTTPS filtering turns off and on uninstall (2.4). The service registration (1.5) starts the engine; it changes no network state by itself.

Acceptance checks every slice that changes traffic must pass (slices 3 to 11), run by the user with a verifier reading the evidence; each records the before and after listings of `route print`, `Get-DnsClientServerAddress`, `netsh winhttp show proxy` and the firewall rules:
- **Kill test.** With the slice's feature on and working, `taskkill /F` the engine. Within 5 s, `Resolve-DnsName example.com` answers and `curl -I https://example.com` succeeds, and every listing matches the before-listing.
- **Reboot test.** With the feature on, set the engine not to start (service start type manual) and reboot. After sign-in, lookups and HTTPS work and every listing matches the before-listing.
- **Uninstall test.** With the feature on, uninstall Sieve. Lookups and HTTPS work, every listing matches the before-listing, and no Sieve route, adapter, DNS server, proxy or firewall rule is left.

Live probe results (slice 0, done): runs 3 and 4 with AdGuard paused proved per-flow app attribution, live QUIC SNI decoding, per-app blocking (one domain dropped for curl.exe, passed for a copy) and clean teardown. The spike's fixes (multicast filter, source-address pinning, bounded shutdown) are on branch `worktree-agent-a025d1b361c8851d3`.

How to read this: every section states decisions and the reason for each. "UNVERIFIED" marks claims that only a live run can settle. "PROBE" marks the ones the Wintun probe settles.

## 0. Evidence from the installed AdGuard (new, read only)

Sources: `default.adg` (the shipped factory zip: `settings.json`, `FLM/agflm_standard.db`) and log and format strings in `x64\AdguardCore.dll`. Nothing was launched and the service was not touched. Short identifiers are quoted; everything else is paraphrased.

| # | Fact | Where | What it decides here |
|---|---|---|---|
| E1 | HTTPS filtering is off in the factory state (`IsFilterHttpsEnabled` false), and `FilterEvCertificates` is true. The wizard's matching option reads as "do not filter sites with EV certificates". | `settings.json` NetworkSettings; survey row 71 | EV pass-through on by default (4.2) |
| E2 | The HTTPS exclusion list ships inside the settings as `DomainsLists["3"]` with 4,289 entries (top TLDs: de 1442, com 776, ru 628). The EV exclusion list (`["4"]`) is empty and enabled. | `settings.json` | The list is large and mostly banks; it is AdGuard's public HttpsExclusions repo compiled in (E10) |
| E3 | Apps come in four lists. Browsers: 79, all decrypted except Tor and Tor Browser. Known-problem apps: 5 + 37, all with HTTPS decryption off, 39 of them linked to a public issue (for example Discord, Steam, Battle.net, iTunes, NVIDIA App, Visual Studio, Riot Vanguard, GitHub Desktop). Other known apps: 26, decrypted. `FilterUnknownAppsByDefault` is true. | `settings.json` ApplicationsLists | Non-browser apps break under decryption often enough that AdGuard keeps a hand list. Sieve replaces the hand list with self-healing plus the public `$app=` exclusions (4.3) |
| E4 | Default excluded IP ranges: 10/8, 172.16/12, 192.168/16, 224/3, 255.255.255.255/32, fc00::/7, ff00::/8. `FilterLocalhost` is true. | `settings.json` WindowsAdvancedSettings | Route exclusions (1.4) |
| E5 | QUIC handling, from the core's log strings: when a connection should be filtered but HTTP/3 filtering is off, AdGuard blocks QUIC. It bypasses QUIC when the filter action is bypass, when the QUIC connection is not HTTP/3, and for 0-RTT packets. It blocks non-QUIC or old-QUIC UDP on that path. HTTP/3 filtering, when on, terminates QUIC itself (ngtcp2 and nghttp3 are linked in) and uses Retry packets. | `AdguardCore.dll` strings | QUIC decision (section 3) |
| E6 | AdGuard's own release note for HTTP/3 filtering says Chrome does not work with it: Chrome checks QUIC certificates its own way and rejects AdGuard's. Firefox and Safari work. | adguard.com blog, v7.15 for Windows | Terminating QUIC buys nothing for Chrome and Edge (section 3) |
| E7 | Upstream certificate checking in the core: OCSP with response verification, OCSP stapling, CRLite (Mozilla's) and CRLSets (Chrome's) as revocation sources, Certificate Transparency (SCTs from the certificate, TLS or OCSP; checked only when the chain validates against the Mozilla store; skipped when the log list is too old or the certificate predates a threshold), the Windows chain engine (`wcrypt_validate_cert`), a pinning test that is skipped for non-standard CAs, and active connections dropped when a certificate turns out revoked. | `AdguardCore.dll` strings | Upstream validation (2.6) |
| E8 | Bypass rules in the core: a client-certificate request makes the connection bypass; a weak DH prime means "do not filter"; a connection upgraded from HTTP (WebSocket) is bypassed; an app-and-address pair on the allowlist bypasses the session; non-TLS traffic is bypassed. EV hosts are cached in an `evhosts` table. Minted certificates are cached in a `certs` table with expiry pruning. | `AdguardCore.dll` strings; survey (native tables) | Pass-through set (4.1), caches (2.5) |
| E9 | Per-app model: route, filter, filter HTTPS. The HTTPS switch also depends on the global HTTPS switch. Advanced HTTPS options: enforce CT, OCSP check, ECH. DNS options include "block ECH". | survey rows 59, 66 to 68, 75, 77 | Mapped to Sieve's one switch (4.4) |
| E10 | AdGuard publishes the exclusions at `github.com/AdguardTeam/HttpsExclusions`, files `exclusions/{banks,sensitive,issues,windows,firefox,mac,android}.txt`. Syntax: one domain per line (with subdomains), a quoted domain means exact, `*` wildcards, `$app=` limits a line to executables, `//` comments. The repo declares **no licence** (GitHub reports none, the README has no terms). AdGuard compiles the lists into each app release. | GitHub, fetched 2026-10-17 | Runtime fetch only, never vendored; licence is an open question (section 10) |
| E11 | Licences: AdguardFilters GPL-3.0; AdGuard Scriptlets GPL-3.0; AdGuard ExtendedCss GPL-3.0; uBlock Origin and uAssets GPL-3.0; brave/adblock-rust MPL-2.0. AdGuard builds each filter per platform, including a uBO-dialect build (`filters.adtidy.org/extension/ublock/filters/2.txt` is "AdGuard Base filter + EasyList", about 6.5 MB, updated today). | GitHub API; filters.adtidy.org | Engine and list choices (section 5) |
| E12 | Post-quantum key exchange: `AdguardCore.dll` and `AdguardDns.dll` (x64) contain the strings `X25519Kyber` and `MLKEM`; `Adguard.Dns.dll` and `Adguard.DnsApi.dll` contain a `PostQuantum` setting. | read-only string search of `E:\AdGuard`, 2026-10-18 | PQ key exchange on all TLS (2.7) |

## 1. Architecture

### 1.1 Shape in five lines

1. `sieve-engine`, an elevated Windows service (LocalSystem), owns the Wintun adapter, the routes, the userspace TCP/IP stack (ipstack), flow attribution, DNS, TLS interception and filtering.
2. Every packet to a routed destination enters the TUN. The stack terminates it, the flow is attributed to a process, and its first bytes are decoded (SNI, Host, QUIC Initial). The policy then picks one of three actions: relay, refuse, or intercept.
3. Intercepted TLS is decrypted with a leaf minted from the per-install root. HTTP/1.1 and HTTP/2 run through hyper, full-URL network rules apply per request, and HTML responses are rewritten while streaming to carry cosmetic CSS and scriptlets.
4. Upstream sockets are pinned to the interface Windows would use without Sieve (`IP_UNICAST_IF`), so they never loop. Upstream TLS is validated at least as strictly as a browser, and any reason not to decrypt becomes a transparent pass-through.
5. The unelevated Tauri app is a client over a versioned named pipe: it shows status, the per-app chart, the filtering log and exclusions, and it edits policy. The engine keeps filtering when the app is closed.

### 1.2 Process and code layout

Decision: a separate Cargo workspace `engine/` with three crates, and src-tauri depends on two of them by path.

| Crate | Kind | Owns |
|---|---|---|
| `engine/crates/sieve-ipc` | lib, no Windows calls | The pipe protocol: message types, version, framing, fixtures. Used by the engine and src-tauri (one shape, one owner: S29, S14). |
| `engine/crates/sieve-filter` | lib, pure | The list manager (catalogue, download metadata, `Expires` parsing, trust flags), the rule engine wrapper (5.3), the exclusion matcher (4.1), the resource library loader (5.5). Used by the engine. The app uses it only to validate a user rule before sending it. |
| `engine/crates/sieve-engine` | bin, Windows | Service, TUN, stack, attribution, DNS, TLS, HTTP, injection, CA, IPC server, watchdog. |

Why a separate workspace: the engine must build and be tested while src-tauri is being edited by other builders, its target dir stays apart, and it never links Tauri. The spike's parsers (`sni.rs`, `quic.rs`, `http.rs`, `stream.rs`, `packet.rs`, `flows.rs`, `classify.rs`) move into `sieve-engine/src/flow/` with their tests unchanged. The spike's copied `rules.rs` is retired, not moved (5.3 replaces it).

### 1.3 IPC

Decision: one named pipe, `\\.\pipe\sieve-engine`, carrying length-prefixed JSON frames (u32 little-endian length, at most 1 MiB), protocol version 1.

- **Versioning.** The first frame from the client is `Hello {protocol: 1, app_version}`. The engine answers `Welcome {protocol, engine_version, session_id}` or `Incompatible {supported: [min, max]}`. Changing any message shape bumps `protocol` and the fixture in one commit, the same rule as `protocol.ts` v1 (law test in `sieve-ipc` plus a TS law against `src/data/fixtures/engine-ipc-v1.json`).
- **ACL.** The DACL grants full control to SYSTEM and Administrators and read/write to the SID of the user who enabled filtering (recorded at install). Everyone else is denied. `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first instance stops another process from squatting the name. `PIPE_REJECT_REMOTE_CLIENTS` is set.
- **Client check.** Per connection, the engine reads `GetNamedPipeClientProcessId` and the client's image path. It accepts only Sieve's own app executable from the install directory, which only admins can write. Same-user malware can still talk to the engine by injecting into Sieve; the operations it could reach are bounded by 7.2.
- **Session scoping.** Every flow carries the Windows session id of its process. A client receives flow events and log rows only from its own session. Another logged-in user's browsing never reaches this user's log.
- **Operations.** Requests: `Status`, `SetPolicy {revision, ...}` (switches, off apps, user rules, user exclusions, list selection), `RemoveExclusion`, `RetryDecryption {host, app}`, `CertStatus`, `InstallRoot`, `RemoveRoot`, `ListsRefresh`, `LogTail {since}`, `BuildReport {flow_id}`. Events: `Flows` (batched every 250 ms: pid, exe, session, kind, host, action, reason, bytes), `Log` rows, `Health`. There is no operation that signs anything, exports a key, or names a certificate to mint.

### 1.4 Routing and DNS

- **Full route.** `0.0.0.0/1` and `128.0.0.0/1`, plus `::/1` and `8000::/1` when the machine has IPv6, all on the Wintun interface "Sieve" (fixed GUID, address from 198.18.0.0/15 and an fd00::/8 ULA, as in the spike). Routes and addresses go through the IP Helper API (`CreateIpForwardEntry2`, `CreateUnicastIpAddressEntry`), never netsh.
- **Exclusions from routing.** These ranges are not routed: AdGuard's defaults (E4) plus loopback, link-local (169.254/16, fe80::/10), CGNAT 100.64/10, and the server endpoints of any VPN that is up. LAN traffic never enters the stack. The exclusions are route entries with more specific prefixes on the original interface, derived at start from the adapter table, not a hardcoded per-network list.
- **DNS is folded in.** Port 53 (UDP and TCP) to any address enters the TUN, including the DNS server addresses when they sit in an excluded LAN range: each configured DNS server gets a /32 or /128 route into the TUN. The engine answers DNS itself:
  - From slice 4 it forwards each query it does not block ENCRYPTED (the user's decision): DNS over HTTPS by default, to the Cloudflare and Quad9 templates (`https://cloudflare-dns.com/dns-query`, `https://dns.quad9.net/dns-query`), tried in order, with DNS over TLS (`tls://host`) and DNS over QUIC (`quic://host`) as upstream kinds the user can pick. `filtering.upstreams` holds the list; its element shape grows from an address to these three forms. Upstream connections go through the pinned interface (loop prevention below), use the same TLS stack and key exchange as interception (2.7), and are kept open between queries. A failing upstream (no answer within its timeout, or a TLS or HTTP error) falls over to the next one within 2 s. The engine never sends plain DNS to the internet while it runs.
  - Split-horizon names: a query for the adapter's own connection-specific suffixes and search list (`router.lan`, corporate zones) goes to that adapter's DNS server only when that server is in a LAN range that is excluded from routing (E4), so it never leaves the LAN. Anything else goes to the encrypted upstream. UNVERIFIED that every corporate zone is covered by the suffix list; a missing one fails to resolve, never leaks.
  - Fail open: when the engine stops, nothing of this remains. Windows' own adapter DNS settings were never touched, so they apply as they were.
  - **It does not block in DNS.** It resolves, logs, and records every answer in an IP-to-names map with TTL. Blocking happens per flow (section 5), because DNS lookups come from the DNS Client service and carry no app identity. Blocking in DNS would make the per-app Off switch a lie. A flow with no name of its own (no SNI, no Host, not QUIC) is decided by the names its destination IP was resolved for: it is blocked for a sieved app only when every live name for that IP is blocked.
  - It strips the `ech` parameter from HTTPS and SVCB answers for names that would be intercepted (2.9), and answers the Firefox canary `use-application-dns.net` with NXDOMAIN so Firefox does not switch itself to DoH.
- **What retires.** `sysdns` (pointing Windows DNS at loopback, backup, restore) was already removed on 2026-10-18 (the rule above); the app only reads adapter DNS now, for a safety notice. The app-hosted DNS proxy on 127.0.0.1:53 is no longer needed once slice 4 passes, because DNS is caught on the TUN without touching adapter settings. Retire it in slice 4 (S52).
- **Loop prevention.** Every upstream socket (TCP, UDP, DNS, list downloads) gets `IP_UNICAST_IF` or `IPV6_UNICAST_IF` set to the interface Windows would choose for that destination with Sieve's routes ignored. That interface is computed from the forwarding table, skipping Sieve's own. A lookup that resolves to Sieve's interface is refused ("would loop"), as in the spike.

### 1.5 Lifecycle

- **Install.** The Tauri bundle is a per-machine NSIS install. The user picks the folder (default `C:\Program Files\Sieve\`; the user's own is `E:\Sieve`). A service binary in a user-writable folder is a local privilege escalation, and the live check of 2026-10-18 found exactly that (7.4), so whatever folder is chosen is made as safe as Program Files:
  - **The installer locks it.** Tauri's NSIS config has no switch for the folder page (only a full custom template could drop it), so the pre-install hook does the work, after Tauri creates the folder and before it copies the first file. It sets the owner to Administrators, turns inheritance off, removes broad grants and grants SYSTEM and Administrators full control and Users read and execute, inherited by everything inside (`acl::INSTALL_DIR_SDDL`). It writes `sieve-install.marker` into a folder it found empty and checked empty again after locking (nothing slipped in while it was open). A folder holding the marker is locked again on update. A folder that holds other files and no marker is refused, on the folder page's Next and again during the install, because locking it could break someone else's files.
  - **The engine proves the lock held** (`service::image`, one pure rule over parsed DACLs). Before `install` registers anything, and again at every service start, it checks that only SYSTEM, Administrators and TrustedInstaller own or can change the exe, every file beside it (the marker must be one; a planted DLL loads from the exe's folder first), the folder (inheritable grants too) and every folder above it (rename, delete-child and ACL rights). A refusal registers nothing (`install` exits 3) or keeps the service stopped (service exit code 3, reason in `last-error.txt`). Nothing in the engine re-ACLs a folder.
  - **Uninstall and update find the engine through the service's registered ImagePath**, so an older build in another folder is still stopped and removed.

  `wintun.dll` 0.14.1 (signed, hash pinned in code) and its licence text sit beside the engine. The NSIS post-install hook runs `sieve-engine.exe install`: create the service (`sieve-engine`, LocalSystem, automatic start, recovery: restart after 5 s twice, then stay stopped), set the required privileges to the measured minimum, and create `C:\ProgramData\Sieve\engine\` with a DACL of SYSTEM and Administrators only. Installing does not turn on filtering and does not install the root certificate.
- **Turning on.** The first run asks once, with one button "Filter all traffic". It explains in one paragraph that Sieve will decrypt HTTPS with its own certificate and what is never decrypted. That act turns on `filtering.engine`, `filtering.https` and `filtering.content`, each still gated by its passed live check (section 9). The registry law keeps every data switch default `false`, so the defaults stay off, and the first-run consent is the user's flip.
- **Autostart.** The service starts at boot and filters as soon as its persisted policy says so, without the app. The app's "Launch at login" stays its own setting. Quitting the app never stops filtering. The tray gets "Stop filtering", which sends `SetPolicy` with the engine switch off.
- **Uninstall.** The NSIS uninstall hook runs `sieve-engine.exe uninstall`. The steps are idempotent and safe to rerun: stop filtering (routes removed, adapter closed), remove every root Sieve installed (by recorded thumbprint, never by name), remove the Firefox policy value only if Sieve set it, delete the CNG key, delete the service, delete `ProgramData\Sieve`. A failed step is reported and the rest still run.
- **Updates (design, slice 13; decision of 2026-10-18).** The engine service is the only updater. It downloads app and engine releases, the scriptlet resource bundle and Sieve's own lists, checks each one's Ed25519 (minisign) signature against the public key compiled into it and checks that the signed version is higher than the one installed, and only then replaces its files in the locked install folder (or in admin-only ProgramData for data). The old version stays until the new one starts. The app can only ask for an update over the pipe; it never writes into the install folder. Threats and acceptance tests: 7.5.
- **Kill switch.** "Stop filtering" (tray and app) is the everyday off. The emergency off for a person at an admin prompt is `sieve-engine.exe restore`, also a Start menu shortcut "Sieve: restore network": it deletes every route on any interface named "Sieve", stops the service, and leaves certificates alone. Sieve always fails open (normal routing). It never fails closed.

### 1.6 Crash safety

A dead or hung engine must never leave the machine without network.

1. **Dead process.** Wintun removes the adapter when its creator's handle closes, and routes bound to that interface go with it, so a killed engine leaves normal routing behind. PROBE and slice 3 verify it with `taskkill /F`.
2. **Hung engine.** A watchdog thread outside the tokio runtime reads two heartbeat counters: the TUN reader's and the relay scheduler's. If either stops advancing for `watchdog.stallMs` (declared, 5000), the watchdog deletes Sieve's routes first, then exits the process. SCM restarts it.
3. **Unclean shutdown.** Before adding a route, the engine appends it to a journal (`routes.journal`, fsync'd). On start, it first deletes any route on an interface named "Sieve" and every route in the journal, then truncates the journal. A crashed boot therefore never carries stale routes into the next one.
4. **Crash loop.** After the third restart within an hour the service stays stopped. The app shows a banner, "Filtering stopped after repeated failures", with Start and a link to the log.
5. **App-side liveness.** The app pings over the pipe every 2 s. On failure it shows "Filtering is not running", which comes from facts, never assumed.
6. **Panic.** Panics in flow tasks are caught per task: that flow closes and the engine keeps running. A panic hook in the main thread runs the route cleanup before abort.

### 1.7 Coexistence with AdGuard, AdGuard VPN and other TUN/VPN adapters

Decision: detect and refuse. The detection is read only.

| Detected | How (read only) | Action |
|---|---|---|
| AdGuard for Windows service running | Service status of AdGuard's service and its process | **Refuse to start the engine.** Two interceptors would stack: AdGuard's WFP driver redirects the engine's own upstream sockets, and the engine would end up validating AdGuard's certificates, which fails the "never weaker" rule. The app says: "AdGuard is filtering this computer. Stop AdGuard's protection to use Sieve's filtering." |
| AdGuard VPN, WireGuard, OpenVPN (TAP or DCO), Tailscale, ZeroTier or any other up adapter that holds a default or /1 route and is a tunnel or virtual interface (`IF_TYPE_PROP_VIRTUAL`, `IF_TYPE_TUNNEL`, or a Wintun adapter that is not Sieve's) | `GetAdaptersAddresses` plus the forwarding table | **Refuse while a full-tunnel VPN is up**, naming the adapter. A split-tunnel VPN (no default or /1 route) is allowed. Its routed prefixes are more specific than Sieve's /1s, so its traffic bypasses Sieve. That is stated in the UI, never hidden. |
| A VPN that comes up after Sieve | `NotifyRouteChange2` | Sieve steps aside: removes its routes, keeps its policy, and shows "Paused while <adapter> is connected". It resumes when the VPN's routes go. |
| Another root CA that intercepts (for example AdGuard Personal CA) in the machine store | Root store scan for non-public roots that a running filtering product uses | A warning only. Sieve's upstream trust ignores non-public roots for interception decisions (2.6). |

"Sieve in front of a VPN" is not built until someone asks. If it is, it is a later slice with its own live check. It would pin upstream sockets to the VPN interface, which is what the "interface Windows would choose" rule already computes.

## 2. TLS interception

### 2.1 Root CA, one per install

- **Algorithm.** ECDSA P-256 with SHA-256. Every TLS client in use accepts it, and signing a leaf costs about 30 to 60 us, against milliseconds for RSA-2048.
- **Subject.** "Sieve local filtering CA (<machine name>, <install date>)". The install date in the name makes every install distinguishable in the store.
- **Extensions.** `basicConstraints CA:true, pathLen:0` (cannot sign intermediates). `keyUsage keyCertSign, cRLSign`. `extendedKeyUsage serverAuth` on the root itself. CryptoAPI and NSS both treat an EKU on a CA as a constraint on everything under it, so a stolen key cannot sign code or e-mail certificates that Windows trusts. In addition, the Windows store property `CERT_ENHKEY_USAGE_PROP_ID` is set to Server Authentication only.
- **Name constraints: not used.** The CA must sign for any public host, so permitted subtrees cannot be set. Excluded subtrees would only hide a fraction of the risk and some clients reject critical name constraints. The EKU and pathLen limits are the viable form of constraint.
- **Lifetime.** One year. The engine rotates silently 30 days before expiry: it makes a new root, installs it, mints new leaves from it, and removes the old root once its last leaf has expired. Leaves live at most 7 days, so the overlap is short. The service can install roots without a prompt (machine store as SYSTEM), and the user's original consent covers rotation. Rotation is logged and shown under certificate status.

### 2.2 Private key protection

- The root key is a CNG persisted key in the Microsoft Software Key Storage Provider, machine scope (DPAPI machine protection underneath), **non-exportable**, with a key DACL granting SYSTEM only. The engine signs through `NCryptSignHash`. rcgen takes a remote signer (`RemoteKeyPair`), so the key never enters process memory as bytes.
- The leaf key is one P-256 key generated in memory at each engine start, never written anywhere. All leaves of that run share it. The root is the security boundary; per-leaf keys would add CPU cost and no protection.
- Admin-level code on the machine can always reach SYSTEM's keys. That is outside what any local MITM product can defend against, and the threat model says so (7.1).

### 2.3 Installing the root

- **Windows.** `LocalMachine\Root` through `CertAddCertificateContextToStore` from the service, then the EKU property set. Windows Firefox, Chrome, Edge and every schannel or CryptoAPI client read it from there. The thumbprint is recorded in `engine/state.json` and appears under certificate status.
- **Firefox.** Firefox on Windows can read the Windows root store when `security.enterprise_roots.enabled` is effective. Decision: if Firefox is installed (App Paths or the Mozilla registry key) and the machine policy `HKLM\SOFTWARE\Policies\Mozilla\Firefox\Certificates\ImportEnterpriseRoots` is not already set, the engine sets it to 1 and records that it did. The value is removed on uninstall or when HTTPS filtering turns off, only if Sieve set it. Why this route: it is Mozilla's documented enterprise policy, it covers every profile, and it needs no NSS tooling or profile writes. Whether a Firefox version on the machine already honours enterprise roots by default is UNVERIFIED; the slice 5 live check opens Firefox and loads an intercepted page.
- **Other own-store clients** (Java, Node, Python certifi, Electron apps that bundle roots) are not touched. They reject the leaf, and that is exactly the case self-healing handles (4.3).

### 2.4 Removing the root

Turning `filtering.https` off removes the root from the store and drops the Firefox policy if Sieve set it. Turning it back on makes a new root (a new key, never the old one). Uninstall removes it in every case. A root left on a machine with no Sieve to guard its key is the worst failure in this design, so removal comes first in every off path.

### 2.5 Leaf minting and caching

- The leaf is minted after the upstream handshake (2.6) for the client's SNI.
- **SAN = the SNI host only.** Upstream SANs are never copied. Browsers pool HTTP/2 connections across hosts that one certificate covers. A leaf naming only the SNI host stops the browser from sending, say, `bank.example.com` requests down a connection made for `www.example.com`, where the exclusion check never ran. A request whose `:authority` differs from the SNI gets `421 Misdirected Request`, and the browser opens a new connection.
- **Validity.** notBefore is now minus 1 hour (clock skew). notAfter is the earliest of the upstream certificate's notAfter, now plus 7 days, and the root's notAfter.
- Serial: random 128 bits. Key usage: digitalSignature. EKU: serverAuth. SKI and AKI are set. No AIA and no CRL DP: the root is local.
- **Cache.** In-memory LRU keyed by host, capacity `tls.leafCacheSize` (declared, 4096). Nothing is cached on disk, because the leaf key changes per run. This is the native form of AdGuard's `certs` table (E8), without the disk.

### 2.6 Upstream first, and strict upstream validation

**Order of a TLS flow (the key property).** The client's ClientHello arrives at the stack. The engine does not answer it yet. It opens the upstream connection with the client's SNI and the client's ALPN list (2.7) and completes the upstream handshake. Only then does it decide:

- **Intercept:** answer the client with the minted leaf.
- **Pass through:** open a fresh upstream TCP connection, replay the client's original ClientHello bytes, and splice the two byte streams. The client then completes its own handshake with the real server and judges the real certificate itself.

Because nothing has been sent to the client before the decision, every "do not decrypt" outcome found during the upstream handshake becomes a clean pass-through: validation failure, client-certificate request, EV, non-public root, unsupported protocol. The client never sees a broken connection, and the upstream verdict cache (keyed by host and port, valid for the certificate's lifetime and capped at 24 h) makes the second connect a one-time cost per host.

**Validation. Never weaker than the browser. Any failure means pass-through, never an override.**

| Check | Decision | Why |
|---|---|---|
| Chain, path building, name, time, key usage | `rustls-platform-verifier` (Windows CryptoAPI chain engine with AIA fetching, the same engine Edge used and Windows apps use) | Accepts what Windows accepts, including enterprise roots for *trust*. |
| Eligibility to intercept | The chain must anchor in the public root set (the Mozilla/CCADB roots shipped as `webpki-roots`, updated with Sieve releases), and must not anchor in Sieve's own root. | A chain to a private or enterprise root (corporate proxies, routers, other interceptors) passes through. Sieve then never decrypts something whose trust is local, and never stacks on another MITM. |
| Revocation | CryptoAPI end-entity revocation (OCSP or CRL) with the stapled OCSP response handed to the verifier. Soft-fail on network errors (browser behaviour), hard-fail on "revoked". **Then, slice 11:** CRLite (Mozilla's filter cascade, fetched at runtime) as a hard-fail source, the same as Firefox. | AdGuard uses OCSP, stapling, CRLite and CRLSets (E7). OCSP plus stapling is already stronger than Chrome's CRLSets. CRLite brings parity with Firefox's hard-fail. |
| Certificate Transparency (slice 11) | For chains to public roots only: require SCTs (embedded, TLS extension or stapled OCSP) that satisfy Chrome's CT policy against Chrome's published log list (fetched at runtime with its signature, refused when older than 70 days, in which case CT is skipped, as AdGuard does). | Chrome enforces CT, so the rule "never weaker" needs it. |
| Protocol | rustls: TLS 1.2 and 1.3 only, AEAD suites only, no RSA key exchange, no SHA-1 signatures, no FFDHE. A server that needs less fails the upstream handshake, and the flow passes through. | Weak protocols are refused by construction. Pass-through lets the client apply its own (browsers also refuse TLS 1.0). |
| EV | If the leaf carries the CA/B EV policy OID (2.23.140.1.1) and `https.skipEv` is on (default on, E1), pass through and record the host in the EV cache. | Browsers no longer show EV, so EV is not a validation property. It is a strong signal of banks and payment sites, and AdGuard defaults to skipping them. |
| Revoked while connected | When a staple or OCSP answer later says revoked, active intercepted connections to that host are closed (E7). | Parity. |

### 2.7 TLS stack: rustls with aws-lc-rs

Decision: rustls 0.23 with the aws-lc-rs provider, on both sides.

- **Memory safety.** The engine parses hostile input from every server and every app as SYSTEM. A C TLS library (OpenSSL, BoringSSL, schannel through FFI wrappers) adds a memory-unsafe parser at the most exposed point of the system.
- **Weak options cannot exist.** rustls has no TLS 1.0/1.1, no RSA key exchange and no CBC suites, so "weak protocols refused" holds by construction, not by configuration.
- **What it needs is there.** `ResolvesServerCert` for per-SNI leaves, ALPN on both sides, control over early data, a client-certificate hook (to detect the request), and ECH on the client side (HPKE comes from aws-lc-rs; ring has no HPKE).
- **Fit.** hyper, tokio and ipstack already speak tokio-rustls.
- **Post-quantum key exchange (the user's decision).** The key exchange groups are, in order of preference, X25519MLKEM768 (the standardized hybrid of X25519 and ML-KEM-768), then X25519, then secp256r1, on every TLS session the engine makes or answers: the client-facing side of interception, the upstream side, and the DoH, DoT and DoQ upstream (1.4). On the client side the engine picks X25519MLKEM768 whenever the client offers it, so a browser that offers it (Chrome does) keeps it through Sieve; anything else would be weaker than the browser. rustls with aws-lc-rs supports the group (the ring provider does not, another reason for aws-lc-rs). This protects the key exchange against record-now-decrypt-later; certificates and signatures stay classical (7.1).
- **Known cost: the TLS fingerprint.** The upstream ClientHello looks like rustls, not like the user's browser. Sites with fingerprint-based bot scoring (some Cloudflare and Akamai configurations) may challenge more often. AdGuard's own `issues.txt` lists a bot-detector false positive. Measured in slice 6 on a fixed site set (challenge pages seen with and without Sieve). Risk R5.
- **Build cost.** aws-lc-sys needs CMake and NASM on Windows, or its prebuilt NASM objects. The slice 6 build notes must say which.

Schannel is rejected because it cannot mint a per-SNI server identity cheaply, its validation and protocol limits follow OS policy, and it is hard to test.

### 2.8 ALPN and HTTP/2

- The upstream offer is the client's ALPN list filtered to `h2` and `http/1.1`, in the client's order. The client's choice of `h3` never applies to TCP. Whatever the server selects is the ALPN given to the client, so both sides speak the same protocol.
- If the client offers ALPN values and none is `h2` or `http/1.1` (for example `acme-tls/1`, `imap`, or custom protocols), the flow passes through. With no ALPN at all, the flow is intercepted only when its destination port is 443 or 8443, and after decryption the first bytes must parse as HTTP. Otherwise the two TLS sessions are relayed as plain bytes, with no filtering.
- hyper 1.x serves the client side (`http1` or `http2` per ALPN). On the upstream side, one upstream connection is paired to each client connection. There is no shared pool, so coalescing, connection-level settings and errors stay one-to-one.
- WebSockets (HTTP/1.1 `Upgrade` and HTTP/2 extended CONNECT) are spliced after the upgrade without filtering inside, as AdGuard does (E8). gRPC and trailers pass through hyper unchanged.

### 2.9 ECH

- **Default path: ECH is not offered to the browser for names Sieve would intercept.** The engine is the DNS resolver on the TUN and strips `ech` from HTTPS/SVCB answers for those names (1.4), so the browser sends a ClientHello with the real SNI.
- **Upstream, the engine itself uses ECH** when the name's HTTPS record carries an ECHConfigList (looked up by the engine; the outer name is the server's public name). Privacy on the wire then stays where the browser had it. This lands in slice 11 with CT and CRLite; until then the upstream hello carries the real SNI, which is what the browser would have sent with ECH stripped.
- **When a ClientHello still carries ECH** (the browser uses its own DoH and learned the config itself): the spike's decoder reports the outer name only. Network rules apply to the outer name and the IP-to-names map. The flow **passes through**. Sieve cannot decrypt ECH without the server's key, and refusing ECH would break sites. It is logged as "encrypted hello, not decrypted". The log shows how often this happens per app, so the cost is visible, not guessed.

### 2.10 TLS 1.3 0-RTT

- **Client side:** the rustls server config sets `max_early_data_size = 0`. The client's 0-RTT data is rejected and resent after the handshake. That is standard TLS 1.3 behaviour and costs one round trip on the local hop only.
- **Upstream:** early data is never sent. 0-RTT is replayable, and a proxy that forwards it widens the replay window of requests the user never chose to make idempotent.
- **QUIC 0-RTT** packets on pass-through flows are relayed untouched (E5).

### 2.11 Client-certificate sites

The upstream client config installs a client-certificate resolver that records "the server asked" and returns no certificate. On that signal the upstream handshake is abandoned, the host and port go into the exclusion store with reason "client certificate" (no expiry), and this flow passes through by replaying the ClientHello (2.6). The client then presents its own certificate to the real server. Post-handshake authentication (TLS 1.3) on an intercepted connection fails the request. The connection closes with the reason logged, and the host is excluded the same way.

## 3. QUIC and HTTP/3

**Decision: do not terminate QUIC. For flows that will be content-filtered, refuse that QUIC flow with an ICMP port-unreachable so the browser falls back to TCP at once. Every other QUIC flow is decoded and relayed.**

Evidence:
- AdGuard does exactly this in its default configuration. The core logs "connection should be filtered but HTTP/3 filtering is not enabled, blocking QUIC" and bypasses QUIC when the action is bypass (E5). Its HTTP/3 filtering is an opt-in advanced setting.
- Terminating QUIC does not work for Chrome and Edge, which carry most traffic. Chromium refuses QUIC certificates that chain to a locally installed root (`ERR_QUIC_CERT_ROOT_NOT_KNOWN`), and AdGuard's own release note says Chrome does not work with its HTTP/3 filtering (E6). A quinn termination would cost a QUIC stack, Retry handling, HTTP/3 framing and QPACK, and then Chrome would fall back to TCP anyway, after a timeout instead of at once.
- For Firefox, termination would work, but HTTP/3 over TCP fallback gives the same filtering at the price of one transport. That trade does not justify a second HTTP stack now (S35). If Firefox QUIC ever matters, the decision can be revisited with a measured reason.

Against the user's "decode it, don't block" intent: QUIC is never blocked wholesale. Every Initial is decoded (SNI, ALPN, attribution) before anything is decided. A flow is refused only when it is the specific (app, host) that the same policy would decrypt over TCP. Refusing it is the only way to keep its content filtered, so the refusal follows from the filtering decision, not from QUIC.

Exactly when QUIC is refused:
1. The (app, host) would be intercepted over TCP: app on Sieve, host not excluded, `filtering.https` on, not a session-0 process, no auto-exclusion. The datagram is answered with an ICMP or ICMPv6 port-unreachable synthesized into the TUN, and the flow is remembered for its lifetime.
2. The domain is blocked by a network rule for that app. The Initial is dropped, as a blocked TLS ClientHello would be (spike behaviour).

QUIC is relayed in every other case: app Off, excluded host (sensitive list, EV cache, client certificate, pinning, user), HTTPS filtering off, not HTTP/3 (E5), unknown or draft QUIC versions (spike), or an ECH outer name.

Why ICMP and not a silent drop: a silent drop makes the browser wait for its QUIC-to-TCP race timer, while an unreachable error fails the QUIC attempt straight away. UNVERIFIED: whether Chromium on Windows treats the ICMP error (`WSAECONNRESET` on the UDP socket) as an immediate QUIC failure. Slice 8 measures the time from the first Initial to the first TCP SYN for the same host in Chrome, Edge and Firefox. If ICMP is not faster than a drop, the drop is used and the decision is recorded with the numbers.

## 4. Exclusions: what makes it bulletproof

### 4.1 One store, one function

Every "do not decrypt" fact is an entry in one exclusion store, and one pure function decides:

`decrypt(flow facts, store, switches) -> Intercept | PassThrough(reason)`

- **Facts:** app exe, session id, host (SNI), port, ALPN offer, ECH flag, the upstream verdict when known.
- **Entry:** `{pattern (host, *.host, exact "host", or IP), app (exe path or name, optional), reason, source, created, note}`.

| reason | source | expires |
|---|---|---|
| `user` | the user | never |
| `list:<file>` | HttpsExclusions file name (4.2) | replaced at each list refresh |
| `auto:pinning` | self-healing (4.3) | never; the user can "try again" |
| `auto:client-cert` | 2.11 | never |
| `auto:ev` | 2.6 | with the upstream verdict cache |

**Floor (not stored, part of the function):**
- `floor:service`: a process in session 0 (Windows services) is never decrypted. Services pin, update and license themselves. This is derived from the session id, not a list. Their flows still get host-level network rules, as the DNS filter applies to them today.
- `floor:non-public-root`, `floor:upstream-invalid`, `floor:protocol` (2.6, 2.7).
- `floor:ech`, `floor:no-sni` (no SNI, so no meaningful leaf).
- `floor:alpn` (2.8).
- `floor:restricted-suffix`: registrable suffixes reserved for vetted institutions are never decrypted: `.gov`, `.mil`, `.bank`, `.insurance`, and public-suffix entries whose label before the TLD is one of the government labels in the declared table `exclusions.governmentLabels` (`gov, gouv, gob, govt, go, gv`). The table lives in config with a comment on what it covers (S25, S49), not in code.
- `floor:no-exclusion-list`: until the HttpsExclusions lists have been fetched once, nothing is decrypted.

Order of evaluation: floor, then store, then app Off (4.4), then intercept. Every pass-through carries its reason to the log and the UI. One function, one owner (S29): the QUIC refusal (section 3) calls the same function, so TCP and QUIC can never disagree about a host.

Safety asymmetry (S24): an exclusion list can only add pass-through. No input, list or rule can cause decryption that the floor forbids, and a tampered or missing exclusion list can at worst turn decryption off.

### 4.2 Sensitive categories: HttpsExclusions, fetched at runtime

- **Source.** `raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/{banks,sensitive,issues,windows,firefox}.txt` (mac and android are for other platforms and are not fetched). The files are downloaded by the engine over its own validated TLS, every 24 h with `If-None-Match`, and cached in `ProgramData\Sieve\engine\lists\`. Never vendored, never in git, never in the installer.
- **Parsing.** AdGuard's syntax as described in E10: with subdomains by default, quoted means exact, `*` wildcards, `$app=a.exe|b.exe` limits the line to those executables, `//` comments. A line that does not parse is skipped and counted, never guessed.
- **Licence.** The repo declares none (E10). Fetching it at runtime keeps it out of Sieve's distribution, but the user must decide whether that is acceptable (Q2). If not, Sieve's own list (the same categories, written from scratch) is the fallback, with self-healing carrying more of the load until it matures.
- **Health.** Health is not a named category in these files. `sensitive.txt` covers sensitive personal-data services and government. Health coverage is UNKNOWN (Q9).

### 4.3 Pinning detection and self-healing

A client that rejects the leaf shows a recognisable pattern right after Sieve's server Finished: a TLS alert, or a close with no application data. The engine reads it as evidence about the pair (app, host), not about the host alone, because browsers accept the root while an Electron or Java app may not.

- **Strong evidence: a fatal alert** from the client during or right after the handshake (`bad_certificate`, `unsupported_certificate`, `certificate_unknown`, `unknown_ca`, `decrypt_error`, `access_denied`). One is enough. The entry is `auto:pinning` for (exe, host). The client's retry then passes through.
- **Weak evidence: a silent close.** The client closes after the handshake completes, without sending a single application byte, within `heal.silentCloseMs` (declared, 2000 ms). This also happens innocently (speculative connections, preconnects), so it is weighed:
  - Every silent close of (exe, host) adds 1 to a score that halves every `heal.halfLifeMin` (declared, 30 min).
  - Every intercepted connection of that pair that carries a request subtracts 1.
  - The pair is excluded when the score reaches `heal.excludeAt` (declared, 2).

  Two quick failed attempts with no success in between exclude the pair. A browser's preconnects that are later used never accumulate. This is one quantity with one threshold, not a ladder (S50), and the threshold is a declared, annotated policy dial.
- **Notice.** Each new auto-exclusion sends one notice: "<App> rejected Sieve's certificate for <host>. Sieve stopped decrypting it." Notices for the same app within 10 minutes are grouped. The action opens the exclusion.
- **Retry.** "Try decrypting again" removes the entry. If the app still pins, the entry comes back with its history.
- **Proactive part:** the `$app=` lines of `issues.txt` and `windows.txt` (4.2). There is no Sieve-maintained app list (S49): the hand list AdGuard ships (E3) is exactly what self-healing derives.

### 4.4 Per-app exemption: the existing Sieve/Off switch

`apps.levels` Off becomes a real exemption. An Off app's flows are relayed through the stack untouched: no decryption, no network rules, no QUIC refusal. They are still counted and charted unless the app is also hidden by the existing tracking rule. Routes are per destination, so an Off app's packets still cross the userspace stack. The cost is the relay only, and slice 3 measures it. The copy changes from "Off cannot exempt an app from DNS blocking" to "Off: Sieve passes this app's traffic through untouched". That copy becomes true once slice 4 retires DNS-level blocking.

### 4.5 Per-domain user exclusions

The user adds host patterns, optionally limited to one app, from Settings or from a log row ("Do not decrypt this site"). These are B6 domain-list entries (`kind: exclude, scope: https`), edited through IPC. Import and export reuse B6.

### 4.6 What the floor guarantees

Banks, sensitive services, government and restricted TLDs, EV sites, client-certificate sites, Windows services, anything on a private root, anything whose certificate fails validation, and anything that rejected Sieve's certificate once are never decrypted. The verifier checks this list item by item (section 7).

## 5. Filtering engine

### 5.1 One dialect, one engine

Decision: **uBlock Origin's rule dialect, matched by brave/adblock-rust (MPL-2.0), as a dependency.**

- **Reuse before re-implementing (S33).** adblock-rust is the production engine of the Brave browser: uBO-compatible network rules with modifiers, cosmetic filters including procedural ones, scriptlet and redirect resources, and a serialized compiled form. A Sieve-written matcher would re-derive years of edge cases.
- **One dialect covers the lists.** uBO's own lists are written in it. AdGuard publishes uBO-dialect builds of its filters (E11). The brief's scriptlet syntax, `+js()`, is uBO's.
- **No raw JavaScript rules.** The dialect has no rule that injects arbitrary JavaScript. The only JavaScript a list can cause is a scriptlet from the pinned resource library, with arguments. That is a security property AdGuard's dialect does not have (AdGuard's `#%#` runs raw JS from trusted lists).
- **One engine for every decision.** The current DNS rules (`src-tauri/src/dns/rules.rs`) and the spike's copy retire. Host-level decisions (SNI-only flows, QUIC, plain TCP) ask the same engine with a synthetic request `https://<host>/` of type `other` and no initiator. That matches exactly the `||host^` rules without type or party constraints, which are the DNS filter's semantics today (S14 by construction).

The AdGuard Windows builds (the native dialect of AdGuard's CoreLibs) are not used. They would need a second parser, AdGuard's scriptlet library and raw-JS execution.

### 5.2 Syntax supported first

Supported means implemented by adblock-rust and wired through by Sieve. Every list load reports, per list, how many rules were applied, skipped, and the skip reasons (S17: a skipped rule is a count, never silently partial).

- **Network rules.** Patterns `||host^`, `|` anchors, `*`, `^`, `/regex/`, and exceptions `@@`. Modifiers:
  - party: `$third-party`/`$3p`, `$first-party`/`$1p`, `~third-party`
  - `$domain=` (with `~`), `$important`, `$match-case`, `$badfilter`
  - types: `$script`, `$image`, `$stylesheet`, `$xmlhttprequest`/`$xhr`, `$media`, `$font`, `$subdocument`/`$frame`, `$document`/`$doc`, `$websocket`, `$ping`, `$object`, `$other`, `$all`
  - `$redirect=`, `$redirect-rule=`, `$removeparam=`, `$denyallow=`
- **Exception modifiers:** `$document`, `$elemhide`/`$ehide`, `$generichide`/`$ghide`, `$specifichide`/`$shide`, `$genericblock`. **Rule: an unsupported exception is a defect.** Skipping a block rule only under-blocks, while skipping an exception over-blocks and breaks sites. Acceptance (slice 4) requires zero skipped exception rules in the default lists. Every skipped one is either supported or listed with its line.
- **Cosmetic.** `##` site-specific and generic hiding, `#@#` exceptions, `##+js(name, args...)` scriptlets, `#@#+js()` exceptions. Procedural operators as adblock-rust parses them: `:has`, `:has-text`, `:upward`, `:xpath`, `:matches-css`, `:matches-attr`, `:matches-path`, `:min-text-length`, `:remove`, `:style`, `:watch-attr`, `:others`. Applied in the page by the procedural applier (5.5).
- **Trust.** `trusted-*` scriptlets run only from lists marked trusted in the catalogue (uBO's and AdGuard's own) and never from user rules or custom subscriptions. That is uBO's own rule.
- **Not supported first** (skipped and counted): `$csp`, `$header`, `$permissions`, `$replace`, `$urltransform`, `$cookie`, HTML filters `##^`, `$popup` (no popup context in a proxy). The counts decide what is next.

Request facts the matcher needs, all derived from the request itself:
- **type:** `Sec-Fetch-Dest`, else `Accept` and the URL extension.
- **initiator:** `Referer` or `Origin`. `Sec-Fetch-Site` gives cross-site directly.
- **party:** the registrable domain of request and initiator, from the Public Suffix List, which is fetched at runtime and cached.

### 5.3 Matcher design and the performance target

Target: p99 under 20 us per request at 100k+ rules. adblock-rust's design:
- **Network rules.** Rules are indexed by a token hash. A rule is filed under its rarest literal token at compile time. A request URL is tokenized once, and only the buckets of its tokens are checked, plus a small bucket for untokenizable rules. Host-anchored rules use host-hash lookups. Modifiers (type bitmask, party, domain sets) are checked only on candidates.
- **Cosmetics** are keyed by hostname for site-specific rules and by class and id tokens for generic ones.
- **Compiled form.** The compiled engine is serialized (flatbuffers in current versions) and loaded memory-mapped, so a swap is cheap and the RSS is shared.

Sieve wraps it as follows:
- **Immutable snapshot.** One compiled engine snapshot behind an `ArcSwap`, rebuilt off the hot path on any list or user-rule change and swapped atomically. Flows already decided keep their decision (decide once, as in the spike).
- **Rule provenance.** Each result carries the rule text and its list, so the log can show both. adblock-rust can return the matched filter text. Mapping it back to the list is a hash map built at compile time (rule text to list ids).
- **Benchmark (slice 4).** A corpus of 50k real request tuples (URL, type, initiator) recorded by the engine's own log on this machine. URLs are scrubbed to host and path shape, never committed with query strings (S27). Run against the default lists. Pass: p50 and p99 under 20 us, compile time and RSS reported.

### 5.4 Lists on by default, runtime download

Downloaded by the engine over its own validated TLS. Never vendored and never in the installer. The refresh interval comes from each list's own `! Expires:` header, clamped to 1 h to 4 days (derived from data, S49). Requests are conditional (`If-None-Match`, `If-Modified-Since`). The last good copy is kept when a download fails.

| List | URL (uBO dialect) | Licence | Default |
|---|---|---|---|
| AdGuard Base filter (+ EasyList) | `filters.adtidy.org/extension/ublock/filters/2.txt` | GPL-3.0 (AdguardFilters; EasyList dual GPL-3.0 / CC BY-SA 3.0) | on |
| AdGuard Tracking Protection | `.../extension/ublock/filters/3.txt` | GPL-3.0 | on |
| AdGuard URL Tracking | `.../extension/ublock/filters/17.txt` | GPL-3.0 (repo; the catalogue field is empty) | on (it is all `$removeparam`) |
| uBlock filters | `ublockorigin.github.io/uAssets/filters/filters.txt` | GPL-3.0 | on after slice 10 |
| uBlock filters: Quick fixes | `.../uAssets/filters/quick-fixes.txt` | GPL-3.0 | on after slice 10 |
| uBlock filters: Unbreak | `.../uAssets/filters/unbreak.txt` | GPL-3.0 | on whenever a uBO list is on (it carries the exceptions that keep the other lists from breaking sites) |
| AdGuard DNS filter | the current `lists::DEFAULT_LIST_URL` | GPL-3.0 | on (host rules; it moves from the DNS proxy into the one engine) |
| AdGuard Annoyances (cookie notices, popups, mobile banners, widgets, other: 18 to 22) | `.../extension/ublock/filters/18.txt` to `22.txt` | GPL-3.0 | off, optional (AdGuard's default is off) |

The uBO lists are gated by measurement, not opinion. Slice 10 runs the YouTube acceptance with two arms, AdGuard lists only and AdGuard plus uBO lists. Both arms passing turns the uBO lists on, because they add the fastest-moving YouTube fixes. If only one arm passes, that arm is the default, and the numbers are recorded in the plan.

### 5.5 Scriptlets, redirects, procedural applier: sources

- **Scriptlets and redirect resources: uBlock Origin's resources** (`gorhill/uBlock`, GPL-3.0), at a release tag pinned in Sieve's code with the archive's SHA-256. The engine downloads that exact archive at first use, verifies the hash, and assembles the resources with adblock-rust's resource assembler. Why uBO's: the dialect and every uBO list name these scriptlets, AdGuard's uBO builds are converted to them, and adblock-rust is built to consume them. AdGuard Scriptlets would need a name-translation layer and a second resource format.
- **Runtime fetch with a pinned hash** rather than a build-time dependency or "latest", for three reasons. The GPL-3.0 code stays out of Sieve's repo and installer (Sieve has no declared licence yet, Q3). A pinned hash means a compromised download host cannot change the JavaScript that runs in every page (7.1). Updating is a reviewed one-line change to the pin.
- **Cost of pinning.** A list rule that names a scriptlet newer than the pin is skipped and counted. The log says "N rules need a newer resource library". Bump cadence: Q8.
- **From slice 13 (decision of 2026-10-18):** the bundle becomes a signed update (7.5): Sieve republishes the verified archive signed with the user's offline key and a rising version, checked daily, so a bump no longer needs an app release. The pin in code retires then.
- **Procedural applier:** Brave's content-side applier for adblock-rust's procedural JSON (brave-core `components/cosmetic_filters/resources/data/procedural_filters.ts`, MPL-2.0; the path is UNVERIFIED until slice 9 pins a commit). Vendored as one file with its MPL header at a pinned commit, compiled into Sieve's injected script at build time. MPL is file-level, so this is a clean build-time dependency. It consumes exactly the format adblock-rust emits, which AdGuard ExtendedCss (GPL-3.0, a different syntax) does not.

### 5.6 Injection into responses

What is rewritten: only responses to `document` and `subdocument` requests with status 200 to 299, `Content-Type: text/html`, and a body. Everything else streams through byte for byte, apart from network-rule actions. Those are: block (an empty response of the type's expected kind with status 200, the uBO convention, or a connection reset for `other`), redirect (a resource from 5.5), and removeparam (a 307 to the cleaned URL for documents, the upstream URL rewritten for subresources).

How it is rewritten, while streaming:
1. **Request side.** The client's `Accept-Encoding` is intersected with what the engine decodes (gzip, deflate, br, zstd), so it never receives an encoding it cannot read.
2. **Decompression** is streaming (flate2, brotli-decompressor, zstd). It is capped at `inject.maxDecodedBytes` (declared, 64 MiB) and a ratio cap against decompression bombs. Past a cap the connection is reset and logged: a half-rewritten body is never sent.
3. **HTML rewriting** uses lol_html (Cloudflare, BSD-3-Clause), a streaming rewriter with bounded memory. Its output goes to the client uncompressed: the hop is local, so compression buys nothing. `Content-Length` is removed, and HTTP/1.1 switches to chunked.
4. **What is injected,** at the start of `<head>` (or before the first element when there is no head):
   - one `<style nonce>` with the site-specific hide selectors plus the generic selectors, unless `$generichide` applies;
   - one `<script nonce>` that holds the scriptlets for this URL from `url_cosmetic_resources` and the procedural applier with its procedural filters.

   Injecting first means a `<meta http-equiv="Content-Security-Policy">` later in the document does not apply to it.
5. **CSP in headers.** For `Content-Security-Policy` (not `-Report-Only`), per directive that governs our element: `script-src-elem`, else `script-src`, else `default-src`, and the same chain for style. Add `'nonce-<n>'` only when the directive lacks `'unsafe-inline'` or already uses nonces or hashes. Adding a nonce to a directive that relies on `'unsafe-inline'` would disable it and break the site's own inline scripts. When only `default-src` exists, a `script-src` copied from it with the nonce is added. Nothing is ever removed from a policy.
6. **Trusted Types** do not apply to parser-inserted script elements, so the injected script loads. Whether each scriptlet works on pages that require Trusted Types is UNVERIFIED and listed in slice 9.

Generic cosmetic cost: the first build injects the full generic stylesheet into every HTML document, as AdGuard does. Slice 9 measures its size and the added main-thread time on a fixed page set. If p50 exceeds 5 ms, the next step is already identified: emit only the generic selectors whose class or id tokens appear in the HTML as it streams through lol_html. adblock-rust's `hidden_class_id_selectors` does that lookup.

### 5.7 The YouTube path

YouTube ad removal comes from lists and scriptlets only. No YouTube-specific code exists anywhere in the engine, and a law test greps the engine for site names.

**What happens:**
1. `www.youtube.com` is decrypted like any site.
2. Its QUIC flows are refused per section 3, so Chrome and Edge use TCP.
3. Its HTML gets the scriptlets the lists assign (JSON pruning of the player response, constant setting, fetch/XHR response pruning), plus hide rules for feed and masthead ads.
4. Requests to ad and stats endpoints match network rules.
5. `googlevideo.com` media is decrypted and passed through untouched.

**What must work on day one** (slice 10 acceptance, in Chrome, Edge and Firefox):
- A watch page plays a video with no pre-roll or mid-roll ad over 10 consecutive videos.
- No "ad blockers are not allowed" interstitial.
- No sponsored cards or masthead ad in the home feed.
- Seeking, quality change and autoplay of the next video work.

**How breakage is detected:**
1. **Live check `scripts/live/youtube.mjs`,** run by a verifier with the user, under the GPU lease. It drives the installed Chrome through CDP with a temporary profile, over the real network, through the engine. It asserts that the player's `currentTime` advances and that the player never carries its ad-showing state, over a fixed set of 10 videos. It records which list rules and scriptlets applied (from the engine log) and the failure screenshots. Site knowledge lives in this test only, never in the product.
2. **In the product,** the filtering log shows per-page rule hits, so "the scriptlet stopped matching" is visible as missing hits.
3. **Lists refresh** on their own `Expires` (quick fixes expire in hours), so fixes arrive without a Sieve release.
4. **Report a broken site** (8.4), user initiated.

## 6. Performance and resources

Spike numbers (measured, CPU only):
- decode: TLS SNI 245 ns, HTTP Host 354 ns, QUIC Initial 4.1 us per flow
- owner-table match: 176 ns
- verdict at 100k rules: 0.2 us
- ipstack: 16.5 to 17.8 us per packet in a pessimistic one-packet-in-flight test

The spike estimates 1 to 3 us per packet under batched load, which is 2 to 15 percent of one core at 100 Mbit/s. PROBE and slice 3 measure the real number.

**Budgets** (each slice measures its own; failing one is a slice failure, not a note):

| Quantity | Budget | Measured in |
|---|---|---|
| Idle CPU (no traffic) | 0 percent: blocking reads only, no polling loops | 3 |
| Relay CPU, 100 Mbit/s single download, Off app | 15 percent of one core or less | 3 |
| Decrypt CPU, 100 Mbit/s HTTPS download, intercepted | 25 percent of one core or less | 6 |
| Throughput, one intercepted flow | 500 Mbit/s or line rate, whichever is lower | 6 |
| Added latency, new TLS connection | 2 ms p50 or less beyond the upstream round trips (the client's connect is answered locally; the upstream connect starts at the SYN) | 6 |
| Added latency, a request on an open connection | 0.5 ms p50 or less (not counting HTML rewriting) | 6 |
| HTML rewrite | time to first byte 1 ms or less; 100 MB/s or more | 9 |
| Matcher | under 20 us p99 per request at default lists (5.3) | 4 |
| Page load, 20 fixed sites | median +10 percent or less against Sieve off | 9 |
| QUIC to TCP fallback | the first TCP SYN within 100 ms of the first refused Initial | 8 |
| Engine memory | 300 MB RSS or less with default lists and 2,000 open flows | 6, 9 |
| Flow caps | 10,000 concurrent flows; the spike's per-flow byte and segment caps | 3 |

Also measured, without budgets: the attribution success rate and lag (PROBE), ECH pass-through share, the self-healing exclusion rate per app, list compile time, and the generic stylesheet size.

## 7. Security review

### 7.1 Threat model

| Threat | Mitigation |
|---|---|
| Root key theft by a non-admin process or user | CNG non-exportable key, machine scope, key DACL SYSTEM only (2.2). The leaf key is memory only. The root carries EKU serverAuth and pathLen 0 (2.1). Lifetime is one year, with the root removed on off and uninstall. |
| Root key theft by admin-level malware | Out of reach for any local MITM. Mitigated in impact: EKU limits misuse to TLS server certificates, and the root is trusted only on this machine. |
| A malicious local user (another account) | The pipe DACL admits only the enabling user, SYSTEM and Administrators. The client image path is checked. Flow and log events are scoped to the caller's session (1.3). ProgramData is admin only. |
| Same-user malware abusing IPC | No IPC operation signs, exports or mints. User rules cannot use `trusted-*` scriptlets, and there is no raw JS rule in the dialect. Policy changes appear in the app as notices. |
| Service binary or DLL replacement | The install folder, whichever the user picks, is locked to administrators by the installer before any file is copied, and the engine refuses to install or start while a non-admin can own or change its exe, a file beside it, its folder or a folder above (1.5, 7.4). `wintun.dll` is loaded by absolute path with its hash and Authenticode signer ("WireGuard LLC") checked. `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` is set before any load. |
| Update channel tampering: app and engine releases, Sieve's own lists | Ed25519 (minisign) signature from the user's offline key, checked by the engine against its compiled-in public key, plus a signed version that must increase; only the engine writes, and only into the locked folder or admin-only ProgramData (7.5). |
| Update channel tampering: filter lists | Downloaded only over the engine's own validated TLS from the catalogue hosts. Lists cannot add raw JS. `trusted-*` scriptlets run only from catalogue-trusted hosts. Worst case: blocking, hiding, or library scriptlets with hostile arguments on non-excluded sites. |
| Update channel tampering: the resource library | Pinned archive hash in code (5.5). A mismatch refuses the load and keeps the previous verified copy. From slice 13 the bundle is a signed update like the others (7.5), which retires the pin. |
| Update channel tampering: the exclusion list | It can only add pass-through (4.1). A tampered list can at worst stop decryption. |
| Hostile servers | Strict upstream validation, with pass-through on any failure, so the browser judges the real certificate itself (2.6). Memory-safe TLS and HTML parsing (rustls, lol_html). Decompression caps. Per-flow caps. |
| Downgrade | Upstream TLS 1.2+ only. A client that offers only TLS 1.0/1.1 passes through. No early data upstream (2.10). |
| Record now, decrypt later (a recording of today's traffic broken by a future quantum computer) | X25519MLKEM768 preferred first on every TLS session, client side, upstream and DNS upstream (2.7). It protects the key exchange only: certificate and handshake signatures (ECDSA, RSA) stay classical, so it does not stop a future forger, only a future eavesdropper of recorded traffic. |
| DNS privacy on the wire | Lookups leave the machine only encrypted while the engine runs (DoH by default, 1.4); LAN-only split-horizon queries stay on the LAN. |
| Cross-host leakage over HTTP/2 coalescing | Leaf SAN is the SNI only, and 421 for other authorities (2.5). |
| Privacy of the log | Memory only (a ring of 10,000 rows), cleared at engine restart, session-scoped, never written to disk, never sent. Counts per app go to the existing history file, without URLs. Request bodies, cookies and authorization headers are never logged. |
| Network loss through Sieve | Fail open: adapter death removes routes, a watchdog guards against hangs, the route journal cleans up at boot, and the restore shortcut is there (1.5, 1.6). |

### 7.2 Verifier checklist (each item is checked with evidence: a test name, a command output, or a screenshot)

- [ ] The root key is a CNG key, non-exportable, and its DACL lists SYSTEM only (`certutil -csp "Microsoft Software Key Storage Provider" -key` output, run by the user as admin).
- [ ] The root has `CA:true, pathLen:0`, EKU serverAuth only, and the store EKU property is set (`certutil -store Root <thumbprint>`).
- [ ] No file under `ProgramData\Sieve` or the app data dir contains key material (grep for PEM and DER headers, and file listing).
- [ ] Turning HTTPS filtering off removes the root, and uninstall removes the root, the Firefox policy (if Sieve set it), the service, the CNG key and ProgramData (before/after listings).
- [ ] The pipe DACL matches 1.3 (`Get-Acl \\.\pipe\sieve-engine`). A second local user's client is refused. A renamed copy of the app outside Program Files is refused.
- [ ] IPC has no sign, export or mint operation (grep of `sieve-ipc` message types).
- [ ] badssl-style endpoints (expired, wrong host, self-signed, untrusted root, revoked, SHA-1 intermediate, incomplete chain, TLS 1.0, TLS 1.1, RC4, 3DES, null cipher, DH 1024) all pass through, so the browser shows its own error, and never produce a Sieve leaf.
- [ ] A client-certificate site passes through, and the client presents its own certificate.
- [ ] A bank from `banks.txt`, a `.gov` site and an EV site are not decrypted: the issuer seen in the browser is the real CA.
- [ ] A pinning client (for example `curl --cacert` with the public bundle against an intercepted host) gets excluded after one failure. Its retry succeeds, and the notice appears once.
- [ ] Session-0 services are never decrypted (log over 30 min of normal use: no intercept rows with session 0).
- [ ] `taskkill /F` on the engine: network works within 5 s, and `route print` shows no Sieve routes. A simulated hang (debug IPC `Stall`, compiled only in test builds) leads to the watchdog removing routes within `watchdog.stallMs` plus 1 s.
- [ ] A reboot with the engine killed mid-run leaves no stale routes after boot.
- [ ] With the AdGuard service running, the engine refuses to start and says why. With a full-tunnel VPN up, the same.
- [ ] Changing one byte of the cached resource archive makes the engine refuse it and keep the last verified copy.
- [ ] Nothing leaves the machine except requests the user's apps made, list and library downloads, OCSP/CRL/CT/CRLite fetches, and DNS forwarding (network log of the engine's own sockets over 30 min).
- [ ] No site name appears in engine source (law test).
- [ ] The install folder (whatever was chosen) has a protected DACL with no inherited ACEs, grants write only to SYSTEM and Administrators, and holds `sieve-install.marker`; no file in it is owned or writable by anyone else (`scripts/live/engine-install.ps1 -Step install`).
- [ ] The engine refuses a folder users can change: unit tests `service::image::tests` (E: inheritance refused, an E: folder Sieve locked accepted, Program Files default accepted, a user-owned file beside the exe refused) and `the_hooks_icacls_lines_give_the_install_lock`; live, `sc queryex sieve-engine` never shows exit code 3 after a normal install.
- [ ] Signed updates (slice 13): the acceptance tests of 7.5 pass.

### 7.3 Sieve must never

- decrypt when upstream validation fails, or offer any "ignore certificate errors" option;
- weaken validation per site, per app, or by a setting;
- export, persist or transmit a private key, or sign over IPC;
- install a root without the user's explicit act, or leave one behind after off or uninstall;
- send anything off the machine automatically (no telemetry; reports are user actions);
- fail closed (cut the network because Sieve failed);
- run JavaScript in pages other than the pinned resource library and Sieve's own injected script;
- write YouTube or any other site-specific logic into the engine;
- run as SYSTEM from files a non-admin can change, or install anything that is not signed by the user's key with a higher version than the one installed.

### 7.4 Finding, 2026-10-18: a user-writable install folder (fixed)

The slice 2 live check installed Sieve to `E:\Sieve`, a folder the installer let the user choose. It inherited the drive root's ACL: `NT AUTHORITY\Authenticated Users:(I)(M)` on `E:\Sieve` and on `E:\Sieve\sieve-engine.exe`. The `sieve-engine` service runs that exe as LocalSystem, so any signed-in user could replace it and run code as SYSTEM: a local privilege escalation. `C:\ProgramData\Sieve` was locked correctly (an unelevated read was denied). The design had assumed Program Files (1.5) without enforcing it.

The fix (branch `worktree-agent-a6e97b25222738145`), each layer tested on its own:
1. **Installer.** The user keeps the folder choice. The hook locks the chosen folder before copying anything, writes a marker into a folder it created or found empty, and refuses a non-empty folder without the marker (1.5). Law 10 pins the order; an engine test runs the hook's own icacls lines and reads back `INSTALL_DIR_SDDL`.
2. **`install` verb.** Before registering the service: `service::image::check_install` over the exe, every file beside it, the folder and every folder above. A refusal registers nothing and exits 3. It never re-ACLs a folder.
3. **Service start.** The same check at every start; a refusal stops the service with exit code 3 and writes the reason to `last-error.txt`, so a later ACL change cannot leave a SYSTEM service users can replace.
4. **Uninstall and update.** The hooks find the engine through the service's registered ImagePath, so an older build in another folder (the 0.1.0 one in `E:\Sieve`) is still stopped and removed.
5. **The rule** is one pure function over parsed owners and DACLs, with unit tests (the live E: case refused, Program Files' default accepted, an E: folder Sieve locked accepted, an explicit Users write ACE refused, a deny ACE is no grant, a TrustedInstaller owner accepted, a user-owned file beside the exe refused) and real reads (`C:\Program Files` accepted, a folder made under `%TEMP%` refused).
6. **Live check.** `engine-install.ps1` checks that the folder's DACL is protected and grants write only to SYSTEM and Administrators, and that no file in it can be changed by anyone else.

Still UNVERIFIED until the user reruns the live check: the hook on a real elevated install (icacls as the admin, owner set to Administrators), the folder page's refusal on Next, and the service start check as SYSTEM.

### 7.5 Signed updates (design, slice 13)

Every update artefact is signed: app and engine releases (one NSIS installer per release), the scriptlet resource bundle, and Sieve-owned lists (the sensitive never-decrypt list first). Third-party filter lists keep their own channel (5.4): they cannot add code and are fetched over validated TLS.

| Step | What it does | Threat it addresses |
|---|---|---|
| Offline key | The user generates the Ed25519 key pair with minisign (`tauri signer generate` makes the same format) on their own machine and keeps the private key offline, never in the repo, CI or the release host. A law test greps the repo for minisign secret-key headers. | A compromised repo, CI runner or release host cannot sign. |
| Public key in the engine | The public key is compiled into `sieve-engine.exe` (a constant, not a setting or a file). A key change ships inside a release signed by the old key. | A malicious local user or same-user malware cannot swap the trust anchor; the engine sits in the locked folder (7.4). |
| Signed metadata | Each artefact has a `.minisig`. Its trusted comment (covered by the signature) states `sieve-update kind=<app\|engine\|resources\|list:<id>> version=<n>`. An index of current versions is signed the same way and carries an expiry date. | Mix and match (a signed list served as an engine); a freeze (a host serving an old index forever): a stale index is reported, not trusted. |
| Download | The engine fetches over its own validated TLS from the catalogue host into a staging folder inside the locked install folder (data: inside admin-only ProgramData). | MITM and a compromised host get no further than serving bytes: the next step refuses them. Nothing user-writable is ever read back. |
| Verify, before any write to a real file | The engine verifies the signature over the exact staged bytes with the compiled-in key, the kind it asked for, and that the version is higher than the installed one recorded in admin-only ProgramData. Unsigned, tampered, wrong-key, wrong-kind, equal or older: refused, the staging copy deleted, nothing else written, the reason logged and shown in the app. | Tampering, a compromised host, MITM, rollback to an older signed version with known bugs. |
| Apply atomically | The engine renames the old files aside (`*.old`), renames the verified ones into place in the same folder (a rename on one volume is atomic), and restarts the service. The new engine's start runs the folder check (7.4) and reports healthy over the pipe; only then is the `.old` set deleted. A new version that fails to start is replaced by the `.old` set and the version record is not raised. App releases run the verified installer as SYSTEM with `/S /UPDATE` into the same folder. | A half-written or broken update never leaves the machine without a working engine; filtering fails open as always. |
| The app only asks | The pipe gets one message, `RequestUpdate {}`, with no URL, path or data: the engine decides where to fetch from and what to verify. It is rate-limited. The app never writes into the install folder, and Tauri's updater plugin is not used in the unelevated app. | A malicious local user or same-user malware can at most trigger a check; they cannot supply content, a source or a version. |

Acceptance tests for slice 13 (offline unit tests with a test key pair generated in the test, plus one live run by the user):
- a valid artefact verifies; one changed byte, anywhere in the file, is refused;
- an artefact signed by another key is refused; one with no signature is refused;
- a signed artefact whose trusted comment names another kind is refused;
- a version equal to or lower than the installed one is refused, even when correctly signed;
- after each refusal the install folder and ProgramData listings (names, sizes, hashes) are identical to before;
- a valid update applies atomically: during the swap either the whole old set or the whole new set is in place, the `.old` set exists until the new engine reports healthy, and a new engine that exits at start is rolled back to the old set with the version record unchanged;
- the IPC law: `RequestUpdate` is the only update message and carries no fields; no IPC message writes a file;
- the repo law: no minisign secret key anywhere in the tree;
- **live:** the user signs a test release with their offline key, the app requests it, the engine applies it, `sc qc` and the version in the app show the new one, and a re-served older release is refused.

## 8. UI

Everything follows `docs/conventions.md`: flat, aligned to the one layout grid, no containers, no dividers, tokens only, 44 px rows, mono hosts, sentence case, no em dashes, and never a claim of filtering that is not happening. The data comes through hooks over a new `EngineSource` (mock and Tauri, like `DnsSource`). There is one controller, `createEngineController`, as the only writer of the store's `engine` part (the DNS controller pattern).

### 8.1 Certificate status

In Settings, Filtering section, a "Certificate" group:
- state (Installed, Not installed, Expires soon);
- valid until;
- thumbprint (mono, click to copy);
- Firefox (Uses Windows certificates, or Not installed);
- last rotation.

Actions: "Reinstall certificate" (makes a new root) and "Remove certificate" (turns HTTPS filtering off; confirm dialog). There is no "download certificate" page: Sieve has no web endpoint (AdGuard's local cert page is not rebuilt).

### 8.2 Exclusions

"Not decrypted" in Settings, Filtering, uses the B6 domain-list view:
- Rows: host pattern, app (icon and name, or "All apps"), and reason as plain words. The reasons are "You added this", "Sensitive site (banks list)", "Rejected Sieve's certificate (auto)", "Asks for a client certificate (auto)", "EV certificate (auto)".
- Filters by reason. Search. Add (host, optional app). Remove with undo.
- "Try decrypting again" on auto rows.

Floor reasons are not rows, because they cannot be removed. A short line under the list names them once.

The app sheet (Apps) gains one line under its switch: "Sieve decrypts this app's HTTPS except N sites" with a link to the filtered exclusions. For an Off app the line reads "Off: Sieve passes this app's traffic through untouched".

### 8.3 Filtering log

A new route `/log/`, one appended `ROUTES` entry.
- Rows (44 px): time, app icon, host (mono), path (truncated, full on hover in the floating tooltip), type, and outcome in words: Blocked, Redirected, Parameters removed, Hidden N elements, Scriptlets, Passed through (reason), Not decrypted (reason). The rule text (mono) and list name fill the right column.
- Filters (segmented): All, Blocked, Modified, Not decrypted. Search. Pause. Clear.
- Row actions: Copy URL, Unblock (adds an `@@` user rule after preview), Block, Do not decrypt this site, Report a broken site.
- Rows stream from IPC `Log` events into a ring in the store. The log is session-only and in memory on both sides.

### 8.4 Report a broken site

From a log row or the app sheet: a dialog assembles the report locally:
- page URL (editable before anything is shared);
- browser exe;
- lists with versions;
- rules that applied to the page with their lists;
- the resource library pin;
- Sieve version.

Buttons: "Copy report", and "Open issue page", which opens the matching list's public issue page in the default browser (AdGuard's filter issues for AdGuard lists, uAssets issues for uBO lists, picked from the catalogue's homepage field). The page opens with the report text in the clipboard, never in the URL. Nothing is sent by Sieve, ever.

### 8.5 Home and copy laws

- The Home tiles gain "Blocked requests" from engine data (`data-engine-derived`).
- The copy law changes: "blocked" and "ads" may appear only inside engine-derived elements while the engine is running and its checks passed, and never otherwise.
- The DNS card is replaced by an "Engine" card: state, routes up, flows, decrypting yes or no, and the last error.

## 9. Slices

Rules for every slice:
- Each slice is independently verifiable and lands in its own worktree.
- Every traffic-changing feature is a `dataSwitch` (default off) whose `liveCheck` names an ignored `live_*` test. It stays locked until that check passed in the app (`passedChecks`).
- Agents never run elevation, route changes, certificate installs or the service installer. Only the user does. The live checks below are run by the user, with a verifier reading the evidence.
- Every slice that changes traffic passes the kill, reboot and uninstall tests of the rule above, in addition to its own acceptance.
- Commands run in PowerShell. Processes started are killed by tree. Browser checks run under the GPU lease.

New data switches (registry, append only):

| Key | Requires | liveCheck |
|---|---|---|
| `filtering.engine` | none | `live_engine_full_route_relays_and_restores` |
| `filtering.https` | `filtering.engine` | `live_https_intercepts_public_and_passes_floor` |
| `filtering.content` | `filtering.https` | `live_content_injects_into_test_page` |

They retire `filtering.dns` and the never-available `filtering.perApp` gate (in slice 4, with a settings migration). `filtering.systemDns` is already gone (settings schema 3, 2026-10-18).

### Slice 0: read the Wintun probe results (gate)

- **Spec.** The user runs the spike's observe run and enforce test (spike doc section 6), once with AdGuard protection and AdGuard VPN off, once with them on, and pastes the summaries and `probe-report-*.json`. The verifier writes `docs/research/2026-10-17-wintun-probe-results.md`: attribution rate and lag, decode counts by kind (tls, http, quic), forwarder errors, TUN packet counts, adapter and route cleanup after exit, IPv6 behaviour, the AdGuard interplay, and a timed large download through the routed host (CPU and throughput).
- **Acceptance.**
  - attributed / flows is at least 0.95 with AdGuard off;
  - at least one `quic` decode from a real browser;
  - forwarder errors are 0;
  - `route print` and `Get-NetAdapter -Name "Sieve Spike"` find nothing after exit;
  - the enforce test shows `000` for the blocked exe and a status code for the copy.
- **Decides:** go or no-go for slices 3 onward. Any failed item becomes a named spike fix before slice 3.
- **Files:** that research doc only. **Live:** yes, admin terminal, UAC.

### Slice 1: engine workspace, shared crates, no behaviour

- **Spec.** `engine/` workspace with `sieve-ipc` (messages, version, framing, fixture), `sieve-filter` (catalogue, list fetch metadata with `Expires`, adblock-rust compile, exclusion syntax parser, resource-archive verifier), and `sieve-engine` (the spike's flow modules moved in with their tests). The ipstack `build.rs` is patched or vendored so no DLL is copied on build.
- **Acceptance.**
  - `cargo test` in `engine/`: the spike's 95 tests plus new ones pass;
  - `cargo clippy --all-targets -D warnings` is clean;
  - an IPC fixture round trip, and a TS law that reads the same fixture;
  - an exclusion parser test over every E10 syntax form, with bad lines skipped and counted;
  - adblock-rust compiles a fixture list and blocks `||ads.sieve-test.invalid^`;
  - `src-tauri` suites unchanged.
- **Files:** `engine/**`, `src/data/fixtures/engine-ipc-v1.json`, `tests/laws/engine-ipc.test.ts`. **Live:** no. **Switch:** none.

### Slice 2: the service, the pipe, install and uninstall

- **Spec.** Service main (SCM, recovery actions, required privileges trimmed to the measured set), `install`, `uninstall` and `restore` verbs, ProgramData with its ACL, the pipe server with DACL, client check and session scoping, `Hello`/`Status`. App side: `EngineSource`, `createEngineController`, the Engine card showing "Installed, not filtering". NSIS per-machine bundle with install and uninstall hooks.
- **Acceptance.**
  - unit tests for the DACL SDDL string, the client path rule and the version handshake (including `Incompatible`);
  - a TS controller test with a fake source;
  - **live:** after the installer, `sc qc sieve-engine` shows LocalSystem and automatic start; the app shows Installed; a second Windows user's pipe open is denied; uninstall leaves no service, no ProgramData, nothing in `HKLM\SYSTEM\CurrentControlSet\Services\sieve-engine`;
  - (added 2026-10-18, 7.4) the install folder, whichever was chosen, has a protected DACL that grants write only to SYSTEM and Administrators, no file in it is writable by anyone else, and the engine refuses to install or start otherwise (unit tests in `service::image`, the hook's icacls lines run by an engine test).
- **Files:** `engine/crates/sieve-engine/src/{service,ipc}/**`, `src-tauri/tauri.conf.json` (bundle), `src-tauri/windows/hooks.nsh`, `src/data/engine-*.ts`, `src/components/sieve/settings/engine-card.tsx`. **Live:** yes, installer UAC. **Switch:** none (nothing changes traffic).

### Slice 3: full route, relay, DNS on the TUN, crash safety, coexistence

- **Spec.**
  - Wintun adapter and full-route /1s with the derived exclusions (1.4), the route journal, `IP_UNICAST_IF` pinning computed with Sieve's routes ignored, `NotifyRouteChange2`.
  - ipstack relay of every flow with attribution; DNS answered on the TUN by forwarding to the original server and recording the IP-to-names map.
  - Watchdog, crash-loop stop, AdGuard and VPN detection with refusal, `Flows` events into the app's chart (per-app live data from the engine replaces the owner-table polling when the engine runs).
  - No filtering yet: every flow is relayed.
- **Acceptance.**
  - unit tests: exclusion-route derivation from a fixture adapter table, journal replay, pinning-interface choice ignoring Sieve's routes, watchdog trip with a fake clock, coexistence classification from fixture adapter tables;
  - **live `live_engine_full_route_relays_and_restores`** (user, admin):
    - 30 minutes of normal use with browsing, a video call and a game launcher, without a failure;
    - attribution of at least 0.95 of flows;
    - LAN printer and router UI reachable;
    - `taskkill /F` gives network back within 5 s with no Sieve routes left;
    - the `Stall` test build trips the watchdog;
    - a reboot after a kill leaves no stale routes;
    - with AdGuard running, the engine refuses with the message;
  - CPU and memory budgets from section 6 for relay.
- **Files:** `engine/crates/sieve-engine/src/{tun,route,stack,dns,watchdog,coexist}/**`, `src/core/engine.ts`, `src/data/engine-*.ts`, Home and Apps hooks to read engine flows. **Live:** yes. **Switch:** `filtering.engine`.

### Slice 4: host-level network filtering, per-app Off, retire the DNS proxy

- **Spec.**
  - Default lists downloaded and compiled in `sieve-filter`. Host decisions for SNI, Host, QUIC SNI and IP-map flows via the synthetic request (5.1). The per-app Off exemption.
  - DNS resolves and never blocks. ECH stripping and the Firefox canary.
  - Encrypted DNS upstream (1.4): DoH by default (Cloudflare, Quad9), DoT and DoQ selectable in settings, failover in order, split-horizon suffixes to a LAN server only. Slice 3 forwarded lookups to the original server as a relay stage; from this slice on no plain DNS leaves the machine while the engine runs.
  - The log route `/log/` v1 (host level). B6 user rules for the engine.
  - The settings migration retiring `filtering.dns` and `filtering.perApp`; deletion of `src-tauri/src/dns/`. `sysdns` already removed 2026-10-18 (nothing to restore: Sieve never pointed DNS since). The read-only safety net (`windns`, `strandedAdapters`) stays until no supported build can have pointed a machine.
  - The matcher benchmark (5.3).
- **Acceptance.**
  - zero skipped exception rules in the default lists (or each listed);
  - the per-list applied and skipped report is shown in Settings;
  - matcher p99 under 20 us on the scrubbed corpus;
  - unit tests: an Off app's flow to a blocked host is relayed; a sieved app's is closed; a no-name flow to an IP whose every name is blocked is closed, and one with a mixed set is relayed;
  - unit tests: the upstream parser for the three kinds; failover to the second upstream within 2 s when the first never answers (fake clock); split-horizon routing only for a suffix whose server is in a LAN range;
  - **live:** `doubleclick.net` blocked in Edge while an Off copy of curl reaches it; Windows adapter DNS settings unchanged throughout;
  - **live, encrypted DNS:** with the engine on for 10 minutes of normal use, a capture on the physical interface (`pktmon` filtered to port 53) shows no UDP or TCP 53 to a non-LAN address, from the DNS Client service or anyone else; the only resolver traffic is the engine's 443 (DoH), 853 (DoT) or 853/UDP (DoQ) connections. With the first upstream set to an address that never answers (`https://192.0.2.1/dns-query`, a documentation address; a settings change, nothing on the system), lookups answer from the second within 2 s;
  - **live, PQ on the DNS upstream:** the engine's log shows X25519MLKEM768 negotiated with `cloudflare-dns.com`.
- **Files:** `engine/crates/sieve-filter/**`, `engine/crates/sieve-engine/src/{policy,dns}/**`, `src/app/log/**`, `src/components/sieve/log/**`, `src/core/routes.ts` (one entry), `src/core/settings/{registry,migrate}.ts`, removal of `src-tauri/src/dns/**` and its TS seams. **Live:** yes. **Switch:** none new (part of `filtering.engine`).

### Slice 5: root CA, install, Firefox, removal, certificate status

- **Spec.** CNG key, rcgen root with the extensions in 2.1, store install with the EKU property, Firefox policy, rotation logic (clock injected), removal paths, `CertStatus` IPC, and the certificate group UI (8.1).
- **Acceptance.**
  - unit tests on the root's DER (extensions, EKU, pathLen) and on rotation timing with a fake clock;
  - **live** (user): `certutil -store Root` shows the root with Server Authentication only; Firefox shows the root as trusted for an intercepted test page (after slice 6) or in its certificate viewer now; the off switch and uninstall remove root and policy; checklist items 1 to 4 in 7.2.
- **Files:** `engine/crates/sieve-engine/src/ca/**`, `src/components/sieve/settings/certificate-*.tsx`. **Live:** yes. **Switch:** part of `filtering.https` (cannot be on without slice 6).

### Slice 6: TLS interception core, strict validation, pass-through, exclusions

- **Spec.** Everything in section 2 except CT, CRLite and upstream ECH. Upstream first. The verifier stack. The pass-through replay. Leaves and their cache. ALPN, hyper h1 and h2 both ways, 421, WebSocket splice, client-certificate and EV pass-through. The exclusion store and `decrypt()` (4.1) with HttpsExclusions at runtime and the floor. Full-URL network rules: block, redirect, removeparam. No HTML changes.
- **Acceptance.**
  - unit and integration tests against local test servers with rcgen-made chains (expired, wrong name, unknown root, client-cert request, EV OID, ALPN sets, h2 coalescing producing 421);
  - `decrypt()` property tests: no list input can produce Intercept for a floor fact;
  - a rustls test client offering X25519MLKEM768 first negotiates X25519MLKEM768 with the intercepting side, and a client offering only X25519 still connects with X25519;
  - **live `live_https_intercepts_public_and_passes_floor`:** a public site shows Sieve's issuer in Edge, Chrome and Firefox; Chrome's security panel shows X25519MLKEM768 for an intercepted site, and the engine's log shows X25519MLKEM768 on its upstream handshake to `cloudflare.com`; the 7.2 badssl items pass through; a `banks.txt` site shows its real issuer; budgets for TLS from section 6; the bot-challenge count on a fixed 20-site set, with and without Sieve, reported (R5).
- **Files:** `engine/crates/sieve-engine/src/{tls,http,exclusions}/**`, `engine/crates/sieve-filter/src/exclusions.rs`. **Live:** yes. **Switch:** `filtering.https`.

### Slice 7: self-healing pinning exclusion, exclusions UI

- **Spec.** The evidence score in 4.3 with declared dials, notices with grouping, "Try decrypting again", and the exclusions view (8.2) with reasons. The app-sheet line.
- **Acceptance.**
  - unit tests with a fake clock: one fatal alert excludes; two silent closes within the half-life exclude; preconnects later used never do; retry removes and restores history;
  - **live:** a client using its own CA bundle (curl with a bundled cacert) gets excluded after one failure and works on retry; Discord or Steam (if installed) works after at most one failed request; one notice per app.
- **Files:** `engine/crates/sieve-engine/src/heal/**`, `src/components/sieve/settings/exclusions-*.tsx`, `src/components/sieve/apps/app-sheet*.tsx`. **Live:** yes. **Switch:** part of `filtering.https`.

### Slice 8: QUIC per-flow refusal

- **Spec.** ICMP and ICMPv6 port-unreachable synthesis for flows `decrypt()` would intercept (section 3), plus the fallback-time measurement. If the ICMP route proves no faster, a silent drop with the numbers recorded.
- **Acceptance.**
  - unit tests: refused exactly when `decrypt()` says Intercept; relayed for Off, excluded, not HTTP/3 and ECH; the ICMP packet is checksum-correct (v4 and v6);
  - **live:** YouTube and Google Search in Chrome, Edge and Firefox load over TCP via Sieve (`chrome://net-internals` or the log shows h2), with the first TCP SYN within 100 ms of the refused Initial; an Off app's QUIC flows stay QUIC.
- **Files:** `engine/crates/sieve-engine/src/quic/**`. **Live:** yes. **Switch:** part of `filtering.https`.

### Slice 9: content: HTML injection, cosmetics, scriptlets

- **Spec.** Streaming decode and lol_html rewriting with caps, the CSP nonce rules (5.6), site-specific and generic CSS, scriptlets from the pinned uBO resource archive via adblock-rust's assembler, the vendored procedural applier, and `$generichide`/`$elemhide`/`$specifichide` honoured.
- **Acceptance.**
  - unit tests: CSP rewrite table (unsafe-inline left alone, nonce added, default-src copied, report-only untouched); decompression caps; injection position before a meta CSP; resource archive hash mismatch refused;
  - integration: a local test page with a strict header CSP, a meta CSP and Trusted Types gets hidden elements and a running scriptlet;
  - **live `live_content_injects_into_test_page`** plus the page-load and generic-stylesheet budgets on 20 fixed sites; Trusted Types sites listed with which scriptlets work.
- **Files:** `engine/crates/sieve-engine/src/inject/**`, `engine/crates/sieve-filter/src/resources.rs`, `engine/injected/**` (the applier, MPL header kept). **Live:** yes. **Switch:** `filtering.content`.

### Slice 10: YouTube acceptance and the default list set

- **Spec.** `scripts/live/youtube.mjs` (5.7), run in two arms (AdGuard lists only; plus uBO filters, quick fixes and unbreak). The default list set is set from the result. The law test that no site name appears in engine source.
- **Acceptance.** Day-one items of 5.7 pass in Chrome, Edge and Firefox for the chosen arm. The results (videos, ads seen, rules hit, arm) are recorded in the plan.
- **Files:** `scripts/live/youtube.mjs`, `engine/crates/sieve-filter/src/catalogue.rs` (defaults), `engine/tests/no_site_names.rs`. **Live:** yes, under the GPU lease. **Switch:** none new.

### Slice 11: validation parity: CT, CRLite, upstream ECH

- **Spec.** SCT verification with Chrome's policy and the signed log list (refused when stale), CRLite as a hard-fail revocation source, and upstream ECH from HTTPS records (2.9).
- **Acceptance.**
  - unit tests with recorded SCTs and a stale log list;
  - CRLite filter-cascade vectors from Mozilla's crate;
  - **live:** a CT-violating test endpoint passes through; a CRLite-revoked certificate passes through; Cloudflare's ECH test page reports ECH used by Sieve's upstream (log shows it).
- **Files:** `engine/crates/sieve-engine/src/tls/{ct,crlite,ech}.rs`. **Live:** yes. **Switch:** part of `filtering.https`.

### Slice 12: log details and report a broken site

- **Spec.** Log details (rule, list, outcome, request facts), row actions (8.3), and the report dialog (8.4).
- **Acceptance.**
  - component tests: the report contains the listed fields and no query string unless the user leaves it in; "Open issue page" picks the list's issue page; nothing is sent (the network mock records zero requests);
  - e2e at 1280x800 and 375x812 with the alignment and scroll laws.
- **Files:** `src/components/sieve/log/**`, `src/core/report.ts`. **Live:** no (mock), then a look in `pnpm tauri dev`. **Switch:** none.

### Slice 13: signed updates

- **Spec.** 7.5: minisign verification with the compiled-in public key, signed kind and version in the trusted comment, a signed index with expiry, staging inside the locked folder, atomic swap with rollback, `RequestUpdate {}` over the pipe, the app's update notice. The user generates the key pair offline first; the public key is the only part that enters the repo.
- **Acceptance.** The list in 7.5.
- **Files:** `engine/crates/sieve-engine/src/update/**`, `engine/crates/sieve-ipc/src/lib.rs` (one message, fixture bumped), `tests/laws/` (no secret key, the IPC rule). **Live:** yes, the user signs and serves a test release. **Switch:** none (updating never changes traffic by itself).

**UNKNOWN until the probe runs:**
- attribution rate and lag from the TUN;
- whether Wintun's adapter really disappears with a killed process;
- `IP_UNICAST_IF` forwarding without loops on this machine;
- ipstack's real per-packet cost;
- QUIC Initial decoding on live browsers;
- IPv6 through the TUN;
- AdGuard's driver interplay.

Full-route mode is beyond the probe (it routes one host), so slice 3 is its first live test.

## 10. Risks and open questions for the user

Risks:
- **R1. AdGuard on this machine.** Sieve refuses to filter while AdGuard's service runs (1.7). Using Sieve means stopping AdGuard's protection.
- **R2. Decrypting every app, not just browsers.** This goes further than AdGuard, which keeps 42 known apps undecrypted (E3). A pinning app can fail one request before self-healing excludes it.
- **R3. Pinned resource library.** List rules that name newer scriptlets are skipped until the pin is bumped. YouTube fixes can depend on that.
- **R4. QUIC refusal.** Filtered sites load over TCP in Chrome and Edge, which costs a little on lossy networks. The first visit's fallback time is measured in slice 8.
- **R5. TLS fingerprint.** Bot-detection sites may challenge more often through rustls (2.7). Measured in slice 6.
- **R6. Code signing.** Sieve and its installer are unsigned: SmartScreen warnings, and nothing ties the service binary to a publisher. Wintun is signed.

Open questions:
- **Q1.** Is "stop AdGuard to use Sieve" acceptable, or should Sieve support running beside AdGuard with its own HTTPS filtering off?
- **Q2.** HttpsExclusions has no licence. Fetching it at runtime is the plan. Is that acceptable, or should Sieve maintain its own sensitive-site list from scratch?
- **Q3.** What licence will Sieve have? GPL-3.0 lists and uBO resources are fetched at runtime and never distributed. The procedural applier is MPL-2.0 and vendored. adblock-rust is MPL-2.0.
- **Q4.** Decrypt all apps from day one (the decision above), or start with browsers and widen once self-healing is proven in slice 7?
- **Q5.** Firefox: may Sieve set the machine policy `ImportEnterpriseRoots` (2.3)?
- **Q6.** Multi-user: filtering covers every account on the machine, while the log and controls belong to the enabling user. Is that right?
- **Q7.** Root lifetime of one year with silent rotation: acceptable, or ask on each rotation?
- **Q8.** Cadence for bumping the resource-library pin (R3): with each Sieve release, or a separate reviewed update?
- **Q9.** Health sites: is HttpsExclusions' coverage enough, or should health be a category Sieve adds (from what source)?
