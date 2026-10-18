# WFP redirect capture: research note

2026-10-18. Status: research, no code. Nothing was installed, loaded, registered or run for this note. Sources are Microsoft Learn, vendor pages and project READMEs, read on 2026-10-18 (list at the end).

Why it exists: slice 3 failed its relay CPU gate (0.222 cores per 100 Mbit/s against 0.15, about 26 us per 1500-byte packet, 58% of samples in the kernel) and its attribution gate (0.7955 against 0.95). Slice 6 needs 500 Mbit/s with TLS interception through the same path. Michael decided on 2026-10-18 to explore a WFP-redirect capture design in parallel with C0 to C2 (`docs/plans/2026-10-18-slice-3-attribution-and-cpu.md`, decision 3).

## Summary

1. Redirecting an app's connection to a local port needs a kernel WFP callout driver. Windows has no driver-free way to do it: user-mode WFP can permit, block, or (newer builds) choose a route, never rewrite a destination.
2. No existing signed driver fits. WinDivert stays out on its Defender verdict; Windows Packet Filter and NetFilter SDK are commercial, and the packet-level ones keep a user-mode crossing per packet, which is the cost we are trying to remove.
3. Our own callout driver would put host TCP on the kernel's own TCP stack, make host attribution exact, and can fail open through a dynamic WFP session. It cannot see WSL/VM traffic and handles UDP poorly, so it complements Wintun (a hybrid); it does not replace it.
4. Decision for Michael: approve prototype P0 now (no install, measures the relay cost through kernel sockets), and say whether to start the signing identity in parallel (legal entity, EV certificate, Partner Center), which gates every driver path by weeks.

## 1. Can connect redirection work without a kernel driver?

**No.** The pieces:

- Redirection happens in four "redirect layers": `FWPM_LAYER_ALE_BIND_REDIRECT_V4/V6` and `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6` (Windows 7 and later). Microsoft's page opens by saying the feature lets "application layer enforcement (ALE) callout drivers" inspect and redirect connections.
- The redirect itself is a sequence of kernel calls inside a callout's `classifyFn1`: `FwpsRedirectHandleCreate0` (cache one handle), `FwpsQueryConnectionRedirectState0` (required from Windows 8, "to prevent infinite redirecting"), `FwpsAcquireClassifyHandle0`, `FwpsAcquireWritableLayerDataPointer0` (gives an `FWPS_CONNECT_REQUEST0`), change `remoteAddressAndPort`, set `localRedirectTargetPID` and `localRedirectHandle` for a local proxy, store the original destination in `localRedirectContext`, then `FwpsApplyModifiedLayerData0`. All of these are `fwpkclnt.sys` exports.
- A filter added from user mode has an action of `FWP_ACTION_BLOCK`, `FWP_ACTION_PERMIT` or one of the `FWP_ACTION_CALLOUT_*` types, and the callout must be registered by a driver (`FwpsCalloutRegister1` or later for these layers). WFP's own overview describes callouts as "functions exposed by a driver". The built-in callouts cover IPsec, stateful-filtering tweaks, stealth mode, chimney offload and Teredo. None redirects.
- The proxy side is user mode: it reads `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS` and `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` on the accepted socket and sets `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on its outbound socket. The engine could do this half in Rust over Winsock.
- Supported traffic: TCP, UDP, raw UDPv4 without header-include, raw ICMP. Changing the local address and port is supported only at the bind-redirect layer.

Driver-free mechanisms that come close, and why they fall short:

| Mechanism | What it does | Why it is not a redirect to the engine |
|---|---|---|
| `FwpmConnectionPolicyAdd0` (user mode, `FWPM_LAYER_OUTBOUND_NETWORK_CONNECTION_POLICY_V4/V6`) | Per-connection route policy matched on `ALE_APP_ID`, user, ports, addresses. Settings: source address, next-hop interface, next-hop gateway. | Picks a route, never a destination. It could send one app's traffic into the Sieve TUN and leave Off apps (and the engine's own sockets) on the physical interface. The kernel twin `FWPS_CONNECTION_POLICY0` lists Windows 11 24H2 as its minimum; the user-mode page gives no version. |
| System or WinHTTP proxy | Apps that honour it connect to a proxy. | Opt-in per app, not transparent, and it is persistent system state, which the network rule forbids. |
| `netsh interface portproxy` | Listens on a local port and relays. | Inbound listener only; it changes nothing about where an app connects. Persistent. |
| WinNAT static mappings | Port forwarding into a NAT network. | Inbound to guests, not outbound redirection. |
| Windows VPN platform, per-app VPN | Routes listed apps into a VPN plug-in. | Still layer 3 packets into user mode, so it is the TUN design again, plus a UWP plug-in. |

Proven by source: redirect needs a callout driver; the redirect call sequence; supported traffic types; `FwpmConnectionPolicyAdd0` route settings and conditions. Inferred: that no other built-in Windows mechanism redirects per app to a local port (an absence; I found none). Not verified: the minimum Windows build of `FwpmConnectionPolicyAdd0`.

## 2. Signing our own driver in 2026

| Route | What it takes | Loads on | Notes |
|---|---|---|---|
| Attestation signing | Hardware Developer Program registration in Partner Center, an EV code signing certificate on the account, a CAB with `.sys`, `.inf`, `.pdb`, signed with the EV certificate, submitted per build | Windows 10 and 11 desktop. Not Windows Server 2016 and later. | Not Windows Certified, no HLK tests. Cannot go to Windows Update for retail. Microsoft now files it under "for testing scenarios". |
| HLK tested, dashboard signed (WHCP) | All of the above plus an HLK test lab run and submission | Everything, including Server | The route the April 2026 kernel trust policy names. Weeks of test-lab work for a solo developer. |
| Test signing | Self-made certificate, `bcdedit /set testsigning on` | Only machines in test mode, which needs Secure Boot off | Fine for a disposable VM. Never for users. |

Prerequisites, from Microsoft Learn:
- Registration needs an organisation: a Microsoft Entra ID global administrator, company details or a D-U-N-S number, a legal contact who can accept the agreements, and an EV certificate uploaded before approval, followed by a business questionnaire. The EV certificate is needed to register; submissions may then be signed with any Authenticode certificate registered to the account, SHA-2 only.
- Listed EV vendors: Certum, DigiCert, GlobalSign, IdenTrust, Sectigo, SSL.com.

Costs and time:
- EV certificate: SSL.com sells a sole-proprietor EV certificate at $359 a year (about $201 a year on a 5-year term), plus $379 for a YubiKey; their page warns a YubiKey may not meet kernel-driver signing needs. Since June 2023 code-signing keys must live on certified hardware or a cloud HSM. Sectigo's EV is listed as organisations only. (Vendor pages and a reseller; prices change.)
- Partner Center hardware registration: no fee is stated on the registration page (inferred free).
- Calendar time to a first signed driver: entity paperwork and EV validation typically take days to weeks; each later attestation submission is a CAB upload. Inferred, not measured.

Platform policies that bear on a new driver:
- **April 2026 kernel trust policy.** Windows 11 24H2, 25H2, 26H1 and Server 2025 remove trust for the old cross-signed program and, after an evaluation period, load "only WHCP-signed drivers by default" plus an allow list. The coverage I found does not say how attestation signatures are treated. Attestation signatures are issued by Microsoft through the same dashboard (EKU "Windows Hardware Driver Attested Verification"), so I expect them to stay trusted, and drivers like Wintun keep loading. **Inferred, must be confirmed before any money is spent.**
- **Driver Quality Initiative (WinHEC, May 2026).** Microsoft is steering third-party code out of the kernel and tightening partner vetting and WHCP requirements. Direction of travel, not yet a rule for filter drivers.
- **HVCI (memory integrity).** On by default on most new Windows 11 devices. The driver must be HVCI-compatible (no executable pool, no RWX sections). KMDF with current WDK defaults satisfies this; it must be tested with memory integrity on.
- **Vulnerable driver blocklist.** On by default since the Windows 11 2022 update, updated quarterly. It targets known exploitable drivers, malware, and drivers whose behaviour "circumvent[s] the Windows Security Model". A generic redirect or packet API open to any caller is exactly that class. Design consequence: the device object is SYSTEM-only, the driver redirects only to the engine's PID, and it exposes no packet injection.
- **Defender reputation.** No documented reputation system for new kernel drivers was found. WinDivert shows the risk: a legitimate signed driver is flagged because malware ships it (Malwarebytes: `RiskWare.WinDivert.VulnDriver`; on this machine Defender flagged the release zip as `Misleading:Win32/Malgent!AMTB`). A narrow driver that only Sieve's engine can use is a poor tool for malware, which is the best protection available. Microsoft takes driver submissions for analysis through WDSI.

Effort for a solo developer (inferred): the driver is the WFP sample's `ClassifyFunctions_ProxyCallouts.cpp` pattern plus a control device, about 1,500 to 3,000 lines of C on KMDF. Mullvad's `win-split-tunnel` (GPL-3.0-or-later or MPL-2.0, KMDF, WFP, bind redirect) is a licence-compatible reference for structure. Rust is possible through `windows-drivers-rs` but still young. Estimate: 2 to 4 weeks for driver and engine integration, 1 to 2 weeks of stress testing (Driver Verifier, HVCI on, kill and reboot tests), plus the signing identity running in parallel. One bug in this code is a blue screen, not a failed flow.

Proven by source: attestation requirements and limits; registration prerequisites; WHCP-only default under the April 2026 policy (secondary coverage of Microsoft's post); blocklist criteria and default state. Inferred: attestation stays trusted under the new policy; costs beyond the listed prices; calendar time; effort.

## 3. Existing signed drivers

| Driver | What it gives user mode | Licence and redistribution | AV standing | Fit |
|---|---|---|---|---|
| WinDivert 2.2 (basil00) | Packet divert and reinject at network layer, loopback included | LGPL-3.0 or GPL-2.0, user's choice; LGPL-3.0 combines with GPL-3.0 | Defender flagged the official 2.2.2 zip on this machine; Malwarebytes lists it as risky because malware ships it | **Rejected and stays rejected.** The rule is never to work around an AV verdict. It is also packet-level: a transparent proxy on it rewrites and reinjects every packet through user mode, the same per-packet crossing as Wintun. |
| Windows Packet Filter / NDISAPI (NT Kernel Resources) | NDIS lightweight filter: raw packets per adapter | User-mode library MIT. Drivers: free for personal and non-commercial use (MTU 1500, no redistribution rights); Developer licence $3,000 one-time with royalty-free redistribution of pre-built signed drivers; source licence $9,000. Signing of custom builds is the customer's job. GPL is not addressed. | Not checked | Packet-level, below IP: no process identity at all, and still a user-mode crossing per packet. No CPU or attribution gain over Wintun. |
| NetFilter SDK (netfiltersdk.com) | WFP-based transparent TCP/UDP filtering and redirect to a local or remote proxy, with process context | Commercial; prices not on the public page. The user-mode library is proprietary and would be linked into the engine. | Not checked | Functionally closest to AdGuard's design. A proprietary library inside the GPL-3.0 engine needs a licence exception from Michael and dependence on a closed driver; ruled out on licence unless Michael wants that. |
| Portmaster kext (Safing) | Packet verdicts with a kernel verdict cache; new connections asked in user mode | GPL-3.0 | Not checked | No redirect in its documented interface. Their signed binary speaks Portmaster's protocol; any change means our own signature. Source reference only. |
| Mullvad `win-split-tunnel` | Bind redirect of excluded apps to the physical interface; WFP blocking | GPL-3.0-or-later or MPL-2.0 | Ships signed in the Mullvad app | Wrong function (source address, not destination). Best licence-compatible source to start our own driver from. |
| AdGuard `adgnetworkwfpdrv`, `adgnetworksockdrv` | AdGuard's own redirect | Proprietary, private interface | Trusted | Not usable. |

GPL-3.0 and a third-party driver: a kernel driver driven through IOCTLs is a separate program, and shipping it beside Sieve is aggregation under the FSF's reading, as with `wintun.dll` today. Linking a proprietary user-mode library into the engine is not aggregation. Inferred from the FSF FAQ; not legal advice.

Proven by source: licences and prices above (vendor pages, READMEs); Malwarebytes classification; Defender verdict on this machine (wintun spike note). Inferred: NetFilter SDK linking model; GPL aggregation reading. Not checked: AV standing of NDISAPI, NetFilter and Portmaster drivers.

## 4. Attribution, VM traffic and UDP/QUIC in a redirect design

**Host apps: exact.** At the connect-redirect layer the classify metadata carries `processId` and `processPath` ("the process that owns the endpoint"), and the conditions include `ALE_APP_ID` and `ALE_USER_ID`. The callout can put PID, path and the original destination into the redirect context, and the engine reads it with `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` on the accepted socket. Attribution then needs no owner tables, no 250 ms retry and no ETW match for redirected flows. Short-lived sockets cannot be missed, because the classify happens before the first SYN. Inferred residue: services in shared `svchost.exe` still need the service tag (`subProcessTag` is reserved in the docs), the same as today.

**Forwarded WSL/VM traffic: invisible to ALE.** NAT-forwarded guest traffic has no Windows socket, so no ALE layer classifies it. Mullvad's 2020 investigation found WSL2 guest traffic "bypasses all normal layers of WFP" on the host and appears to WFP only at layer 2. The candidate layers are `FWPM_LAYER_IPFORWARD_V4/V6` (forwarding path) and the vSwitch layers (`INGRESS/EGRESS_VSWITCH_*`, callout and switch-extension territory). Neither offers connection redirect; at best a packet callout. Windows 11's Hyper-V firewall for WSL filters by address, port and protocol only, through persistent rules. So under Michael's decisions (forwarded flows stay in the 0.95 denominator and are filtered by domain), **forwarded traffic keeps needing the Wintun path**: it follows the default route into the TUN today, and slice 3 matched WSL flows to NAT sessions there.

**UDP and QUIC: possible, with caveats.**
- Connect redirect works for UDP on the first packet sent. Microsoft documents a known failure: redirecting **connected** UDP sockets (`connect` then `send`) to a local proxy drops the packets ("redirect records are referenced incorrectly"); the stated workaround is `sendto`, which we cannot impose on apps. I expect Chromium's QUIC sockets are connected sockets, so they would hit it. Inferred, to be tested.
- A local UDP proxy also has to keep a per-flow socket to reply from the right address, which is more state than the TCP case.
- Options: (a) keep UDP on the TUN (the hybrid); (b) for apps whose TCP would be intercepted, block UDP 443 per app with a plain user-mode WFP filter in a dynamic session, so browsers fall back to TCP. This is AdGuard's default behaviour (E5 in the HTTPS plan), but it blocks QUIC by app rather than per (app, host) as section 3 of that plan decided. (b) needs a decision.

Proven by source: metadata fields; UDP redirect support and the connected-UDP failure; layer descriptions; Mullvad's WSL2 finding (2020, may have changed). Inferred: Chromium's sockets are connected; vSwitch and forward layers give no practical redirect.

## 5. Expected CPU

Where the bytes go today, per downloaded 1500-byte segment: NIC and kernel TCP on the upstream socket, engine `recv`, ipstack segmenting, the Wintun ring, then the kernel receiving the packet from the TUN as if from a wire (no receive coalescing), plus the app's ACKs travelling back the same way. Measured: 5.33 CPU-seconds for 300 MB, about 26 us per packet, 58% in `ntoskrnl`.

With a connect redirect: the upstream half is identical. The app half becomes a loopback TCP connection. The engine `recv`s whatever the upstream socket has (many KiB per call with receive coalescing) and `send`s it on the accepted socket. The per-packet work (ipstack, ring, TUN receive path, ACK round trips through user mode) is replaced by per-chunk work in the kernel's own TCP, with large loopback segments. The ALE classify runs once per connection ("processing only the first packet in a connection").

Estimate (inferred): at 100 Mbit/s that is 12.5 MB/s, roughly one to two thousand `recv`/`send` pairs per second at 8 to 16 KiB each, plus two extra memory copies per byte. That suggests 0.02 to 0.06 cores per 100 Mbit/s before TLS, against 0.222 now. Interception at 500 Mbit/s adds AES-GCM decrypt and re-encrypt of about 62.5 MB/s each way, a few percent of a core per direction with AES-NI.

Published numbers: I found no published per-byte comparison of WFP redirect against a TUN with a userspace stack on Windows, and no current Windows loopback TCP figure worth quoting. The number has to come from P0 below.

A driver-free middle option worth one experiment (it fits C2 as E7): keep Wintun but stop terminating TCP in user space. Rewrite each TCP packet's addresses in the TUN and hand it back so the kernel's own TCP terminates it on a listener (the "system" stack that sing-box and Clash-family tools offered). It keeps the per-packet ring crossings, which may be most of the 58% kernel time. sing-box has since deprecated that mode in favour of its own stack, citing better peak performance. Expect a smaller win than a WFP redirect.

Proven by source: ALE processes only the first packet; the slice 3 measurements. Inferred: everything numeric about the redirect path.

## 6. Fail-open

What exists while the engine runs: the driver service (registered, loaded), the callout registrations (driver-owned), and the filters that point at the callouts.

| Event | What happens | Evidence |
|---|---|---|
| Engine killed or crashes | If the filters were added in a session opened with `FWPM_SESSION_FLAG_DYNAMIC`, "any objects added during the session are automatically deleted when the session ends". New connections are no longer redirected. Connections already redirected lose their proxy socket and reset; apps reconnect directly. | Session flag: Microsoft Learn. How fast BFE notices a dead client: inferred, the kill test measures it. |
| Engine hung but alive | Redirects continue into a listener that does not accept: new connections hang. Mitigations: the engine watchdog closes its WFP engine handle (filters go) before exiting, as it deletes routes today; and the driver redirects only while the engine has completed a heartbeat IOCTL within N seconds, otherwise it returns permit without redirect. | Design, inferred. |
| Driver unloaded or callout unregistered while filters exist | Filters with `FWP_ACTION_CALLOUT_TERMINATING` or `FWP_ACTION_CALLOUT_UNKNOWN` "are treated as `FWP_ACTION_BLOCK`"; `FWP_ACTION_CALLOUT_INSPECTION` filters "are ignored". **A terminating redirect filter fails closed.** | `FwpsCalloutUnregisterById0` remarks. |
| Reboot | Dynamic filters do not survive. The driver may load again (demand start is better: the engine starts it) but has no filters, so it does nothing. | Inferred. |
| Uninstall | Remove filters (already gone), stop and delete the driver service, delete the `.sys` and driver store entry. | Inferred; needs its own uninstall test. |

Rules that would follow: every filter only in a dynamic session owned by the engine process; never a persistent or boot-time filter; never a terminating callout filter outside a dynamic session. If the redirect callout can be attached as `FWP_ACTION_CALLOUT_INSPECTION` and still apply a redirect, a missing driver degrades to "ignored" (fail open) by construction. I could not confirm that from the docs. The documented samples set `FWP_ACTION_PERMIT` after applying the change, which suggests a terminating or unknown type. Open question for P1.

What persists that did not before: a kernel driver service registration and its file. It changes no network state by itself, but it is new persistent system state and the uninstall test must show it gone.

Proven by source: dynamic-session deletion; block-if-unregistered semantics. Inferred: timing, the heartbeat design, inspection-type redirect.

## 7. Coexistence with AdGuard's redirect

- Every redirect callout must call `FwpsQueryConnectionRedirectState0`. Microsoft's rules: `NOT_REDIRECTED`, proxy it; `REDIRECTED_BY_SELF`, permit or continue; `REDIRECTED_BY_OTHER`, may proxy it again "if it does not trust the other inspector's result"; `PREVIOUSLY_REDIRECTED_BY_SELF` (we redirected it, someone redirected it again), "must not perform redirection". If the connection already goes to a local proxy (`localRedirectHandle` set by another callout), "your callout driver shouldn't attempt to redirect it".
- Our proxy's outbound sockets carry the redirect records through `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`, so our own callout sees them as ours and does not loop. AdGuard's callout sees them as redirected by another; whether AdGuard then redirects them again is AdGuard's choice. Probe run 2 shows AdGuard captures a foreign process's outbound connections today, so a chain app to Sieve to AdGuard to internet is the likely result. That still breaks the "never weaker" rule (we would validate AdGuard's certificates).
- Order between two redirectors is set by sublayer weight and filter weight; a callout can veto with block even without write rights, and `FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS` re-runs us if another callout changes the request after us.
- Gain: a callout at `ALE_AUTH_CONNECT` sees `FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED` with `localRedirectTargetPID`. If that PID is `AdguardSvc.exe`, AdGuard is intercepting. That is the behavioural detection slice 3 asks for (4, "Ordinary AdGuard pause"), exact and per connection.
- Decision unchanged: Sieve does not filter while AdGuard intercepts.

Proven by source: redirect-state rules, redirect records, reauthorize flag, the metadata fields. Inferred: AdGuard's behaviour toward a foreign proxy's sockets (from probe run 2, which used a TUN, not a redirect).

## 8. Hybrid options

| Hybrid | What it buys | What it costs |
|---|---|---|
| H1: exact attribution source only, keep Wintun and ipstack | With ETW (plan A2): exact PID for host TCP connects and UDP sends, driver-free. With a WFP callout: the same, plus redirect flags. User-mode WFP cannot do it: per-connection "allowed" net events need engine options that "persist across reboots" (and the audit policy), which the network rule forbids. | Does nothing for CPU or for forwarded traffic. A driver for attribution alone is not worth it while ETW is open. |
| H2: WFP redirect for host TCP, Wintun for everything else | Host TCP, most bytes and all TLS interception, leaves ipstack. Attribution exact for host TCP. The TUN keeps forwarded VM traffic (domain level, per Michael) and UDP. | A signed driver plus everything in sections 2 and 6. Two capture paths to keep coherent (one policy, one flow log). VM TCP and QUIC bulk still pay ipstack cost. |
| H3: per-app route policy (`FwpmConnectionPolicyAdd0`), no driver | Off apps and the engine's own sockets stay off the TUN, so they cost nothing; could replace `IP_UNICAST_IF` pinning. | No change per sieved byte. Needs Windows 11 24H2 or later (inferred) and a check that policies can live in a dynamic session. |
| H4: Wintun with kernel TCP termination (packet rewrite to a local listener), no driver | Removes ipstack's TCP; keeps signed Wintun; no new signing. | Keeps per-packet ring crossings; win unknown. |

H2 is the realistic shape of a WFP design. H3 and H4 are driver-free and can be measured first.

Proven by source: net-event option persistence; route-policy settings. Inferred: the rest.

## Comparison

| | CPU outlook | Attribution | UDP/QUIC | VM traffic | Fail-open | Signing / AV risk | Licence | Effort |
|---|---|---|---|---|---|---|---|---|
| Current Wintun + ipstack | Measured 0.222 cores per 100 Mbit/s; C2 may reduce it, structural limit likely | Owner tables, 0.7955; ETW (A2) may raise host share | Decoded and relayed today | Captured; NAT match names the VM | Proven: adapter goes with the process, kill test 3.67 s | Wintun signed, no detections | Wintun prebuilt licence, ipstack Apache-2.0 | Built |
| Own WFP callout driver alone | Estimated 0.02 to 0.06 per 100 Mbit/s for host TCP (unmeasured) | Exact for host sockets | Connected-UDP redirect bug; QUIC by per-app block or not at all | Not seen at all | Good with dynamic sessions and heartbeat; terminating filters fail closed if the callout disappears | New Microsoft-signed driver; new-driver AV reputation unknown; April 2026 policy status of attestation to confirm | Ours, GPL-3.0 | Entity, EV, Partner Center; 4 to 6 weeks of driver work (inferred); kernel code to maintain |
| Existing signed drivers | WinDivert, NDISAPI: no gain (per packet). NetFilter SDK: like our own driver | WinDivert, NDISAPI: none from the driver. NetFilter: process context | Depends | Packet drivers see it; NetFilter unknown | Vendor-defined | WinDivert: AV verdict, rejected. Others not checked | WinDivert LGPL-3.0; NDISAPI $3,000 commercial; NetFilter proprietary library | Low code, high licence and trust cost |
| Hybrid H2 (driver for host TCP, Wintun for the rest) | Host TCP as the driver row; VM and UDP as today | Exact for host TCP; ETW and NAT match for the rest | On the TUN as today | On the TUN as today | Both mechanisms' properties; both must be tested | As own driver | GPL-3.0 | Own driver plus integration of two paths |
| H4 (Wintun, kernel TCP termination, no driver) | Unknown; per-packet ring cost stays | As today | As today | As today | As today | None new | As today | One C2 experiment |

## Prototype, if approved

Smallest first, each one only after the previous one shows a reason to continue. Nothing here has been run.

**P0: the relay floor, no install (answers "is the CPU win real").**
- What: a small example binary in `engine/examples/` that listens on `127.0.0.1` as an HTTP CONNECT proxy and relays with the engine's own `flow/relay.rs` code and buffer sizes. `curl.exe -x http://127.0.0.1:<port>` downloads the C0 budget file through it. Process CPU time divided by bytes gives cores per 100 Mbit/s for exactly the user-mode half of a redirect design (accepted loopback socket plus pinned upstream socket). The redirect adds only one ALE classify per connection.
- Protocol: the C0 workload and validity checks; Sieve engine stopped; AdGuard paused under the runner lease (its driver would otherwise capture the relay's upstream socket, as in probe run 2); baseline curl without proxy and candidate, three runs each, median decides.
- Installs: nothing. No elevation, no driver, no route, no WFP object. Removal: the process exits.
- Pass mark: 0.05 cores per 100 Mbit/s or less, with throughput within 10 percent of direct. If it is not clearly below the ipstack path, the WFP idea stops here.

**P1: the redirect itself, in a disposable VM (answers "does it behave and fail open").**
- What: a test-signed KMDF callout driver (connect redirect for TCP to the P0 relay's PID, heartbeat IOCTL, SYSTEM-only device) in a Hyper-V VM with test signing on inside the VM only.
- Measures: ALE classify overhead per connection; CPU per 100 Mbit/s against P0; `taskkill /F` of the engine with `netsh wfp show filters` before and after (filters must vanish and the network must work within 5 s); hung engine (heartbeat stop gives permit); unload with filters present (shows whether the chosen action type fails open or closed); a connected-UDP redirect check with Chromium.
- Installs (VM only): a test certificate, test-signing mode, the driver service. Host change: a Hyper-V VM, which needs Michael's approval because enabling Hyper-V features or creating VMs is a host change. Removal: delete the VM; nothing touches the host's network or boot settings.

**P2: signed driver on Michael's PC.** Only after P0 and P1 pass and the signing identity exists. Installs an attestation-signed driver service; removal is the uninstall path in section 6, verified by the slice kill, reboot and uninstall tests.

## Open questions

1. Are attestation-signed drivers still loaded by default under the April 2026 kernel trust policy? Read Microsoft's post itself and the current policy docs before buying a certificate.
2. Can a connect-redirect callout run as `FWP_ACTION_CALLOUT_INSPECTION` (fails open when unregistered)? P1 answers it.
3. Does Chromium's QUIC use connected UDP sockets on Windows, and does the connected-UDP redirect failure still occur on Windows 11 24H2 and later?
4. Does Michael have, or want, a legal entity that can register for the Hardware Developer Program?

## Sources

Microsoft Learn, WFP:
- Using Bind or Connect Redirection: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- FWPS_CONNECTION_REDIRECT_STATE: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_connection_redirect_state_
- FwpsQueryConnectionRedirectState0: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
- FwpsRedirectHandleCreate0: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsredirecthandlecreate0
- FWPS_INCOMING_METADATA_VALUES0: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0_
- Filtering layer identifiers: https://learn.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
- About Windows Filtering Platform: https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform
- FWPM_ACTION0: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_action0
- FWPM_SESSION0 (FWPM_SESSION_FLAG_DYNAMIC): https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0
- FwpsCalloutUnregisterById0: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutunregisterbyid0
- FwpmConnectionPolicyAdd0: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmconnectionpolicyadd0
- FWPS_CONNECTION_POLICY0: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_connection_policy0
- FwpmEngineSetOption0: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmenginesetoption0
- Failed to redirect connected UDP traffic: https://learn.microsoft.com/en-us/troubleshoot/windows-hardware/drivers/redirection-connected-udp-traffic-local-proxy-fail

Microsoft Learn and blogs, signing and platform policy:
- Driver Signing Options: https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings
- Attestation Sign Windows Drivers: https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation
- Driver Code Signing Requirements: https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs
- Register for the Hardware Developer Program: https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/hardware-program-register
- IHV Attested Signing Service: https://learn.microsoft.com/en-us/windows-hardware/design/compatibility/ihv-attested-signing-service
- Support policy for attestation-signed kernel drivers: https://learn.microsoft.com/en-us/troubleshoot/windows-server/setup-upgrade-and-drivers/support-policy-third-party-kernel-level-attestation
- Removing trust for the cross-signed driver program: https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-driver-security-removing-trust-for-the-cross-signed-driver-pro/4504818
- PCWorld on the April 2026 policy: https://www.pcworld.com/article/3100806/windows-is-finally-fixing-a-years-old-security-hole-in-april.html
- Driver Quality Initiative, WinHEC 2026: https://blogs.windows.com/windowsexperience/2026/05/14/raising-the-bar-together-introducing-the-driver-quality-initiative-at-winhec-2026/
- Microsoft recommended driver block rules: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- HVCI-compatible drivers: https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/implement-hypervisor-protected-code-integrity

Drivers, vendors, licences:
- WinDivert: https://github.com/basil00/WinDivert
- Malwarebytes, RiskWare.WinDivert.VulnDriver: https://www.malwarebytes.com/blog/detections/riskware-windivert-vulndriver
- Windows Packet Filter licensing: https://www.ntkernel.com/windows-packet-filter/licensing/
- NetFilter SDK: https://netfiltersdk.com/
- Portmaster kext: https://github.com/safing/portmaster-windows-kext
- Mullvad win-split-tunnel: https://github.com/mullvad/win-split-tunnel
- Mullvad, Linux under WSL2 can be leaking: https://mullvad.net/en/blog/linux-under-wsl2-can-be-leaking
- SSL.com sole-proprietor EV code signing: https://www.ssl.com/products/software-integrity/code-signing/ev-sole-proprietor/
- sing-box TUN inbound (stack option): https://sing-box.sagernet.org/configuration/inbound/tun/
- windows-drivers-rs: https://github.com/microsoft/windows-drivers-rs
- GNU GPL FAQ, mere aggregation: https://www.gnu.org/licenses/gpl-faq.html#MereAggregation

Repository:
- `docs/plans/2026-10-18-slice-3-attribution-and-cpu.md`
- `docs/plans/2026-10-17-https-filtering.md` (decisions, sections 1, 3, 6)
- `docs/research/2026-10-17-wintun-spike.md` (WinDivert verdict, probe runs, ipstack numbers)
