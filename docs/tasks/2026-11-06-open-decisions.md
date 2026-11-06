# Open decisions and live checks

2026-11-06, main at 399ae1f. Everything here is built and tested offline. Nothing has run against real traffic, and every question has a default already built, so none of them blocks the code. The sections after "Decisions that block something" are copied from each stream's task doc, unedited, and some were settled later: `encrypted-dns` Q3 (ECH stripping and the canary) was built in `dns-extras`, and merge notes are history.

## Live checks, in order

Each needs an admin terminal and network testing allowed. `docs/live/` holds the runbooks. Later checks assume the earlier ones passed.

| # | Runbook | Proves |
|---|---|---|
| 1 | `2026-10-18-cpu-experiments-handoff.md`, `p0-relay-floor.md` | The relay's CPU cost against the 0.15 gate, and which settings to keep |
| 2 | `engine-slice-3.md`, `attribution.md` | Full routing, the 0.95 attribution gate, kill, watchdog, AdGuard pause, reboot and uninstall |
| 3 | `encrypted-dns.md`, `dns-extras.md` | No plain DNS leaves the machine, failover, ECH stripping, private reverse lookups |
| 4 | `engine-slice-5.md` | The root certificate: install, Firefox, removal |
| 5 | `engine-slice-6.md` | HTTPS interception and the never-decrypt floor. Unlocks `filtering.https` |
| 6 | `engine-slice-7.md`, `engine-slice-8.md`, `engine-slice-11.md` | Self-healing exclusions, QUIC refusal, CT, CRLite, ECH upstream |
| 7 | `engine-slice-9.md`, `engine-slice-10.md` | Content injection and YouTube. Unlocks `filtering.content`, and sets the default list set |
| 8 | `updates.md` | A real signed update, once the key pair and host exist |

## Decisions that block something

- **Scriptlet bundle source** (`content` Q1). Until this is answered no scriptlet runs on a real machine, and slice 10 cannot pass.
- **Who publishes the CT log list and CRLite file** (`validation` Q2). Until they are published, CT and CRLite are skipped on every connection.
- **The sensitive seed list** (`tls` Q1). It was written from general knowledge and needs your review before interception is unlocked.
- **Update key pair and host** (`updates` Q1). You generate the key offline; the compiled-in key is a marked placeholder.
- **The Off check U15** (`docs/live/engine-slice-6.md`). It needs a build with the HTTPS switch available, so it cannot gate unlocking that switch. Decide how to prove Off on open connections.
- **Stapled SCTs** (`validation`, recorded as a TENSION on `policy()`). Two live stapled SCTs still pass Sieve; removing that arm for Chrome 148+ reverses finding F5.
- **Off on SYSTEM apps.** `console_user_can_open` needs a privilege the install removes, so it falls back to the account rule and that row's Off exempts nothing. It stays filtered, the safe side. Granting the privilege conflicts with a law.

## Smaller open items from the reviews

- Should a version whose install was interrupted be offered again? Today it is not, until a newer one ships.
- Two ways to block a site exist: the Blocklist editor and "Block a site" in the rules editor.
- `pid 77.exe` loses its Off switch, because the shared key format reads it as a pid row. It fails safe.
- Procedural filters do not re-run on attribute changes. Measure the cost when interception runs on real pages.
- The ratio cap on rewritten pages now answers only at the end of the body, so only the 64 MiB cap bounds a page while it streams.
- A flow already decrypted to a host a list update just added stays open until it ends.
- Settings saves other than the Log's row actions still fail without a message. Later saves do reach the disk.
- The resilience policy wants an error boundary per screen, and `dns-extras` Q5 proposes that as a follow-up.
- Future Codex reports will trip the em-dash law unless the review driver or that folder's rule changes, and the driver's prompt describes another project.

## app-log

From `docs/tasks/2026-11-02-app-log.md`.

- Q1. **Should apps the user turned Off appear in the log?** The Off promise says Sieve "stops tracking" the app; plan 8.3 has "Passed through (reason)", which is the clearest proof an exemption works. Default in this plan: they appear as "Passed through (app is off)", session-only and in memory. The other answer is one line at the engine's emit (C1) plus removing the `app_off` slug. Nothing else depends on it.

Not asked, decided and stated: D16 (query out by default), D13 (stored entries first, then the defaults), D20 (nav order).

## attribution

From `docs/tasks/2026-11-02-attribution.md`.

1. **What goes in "Unidentified virtual machine traffic"?** Your decision says "unmatched forwarded flows", but a flow can only be called forwarded on evidence.
   - **Default in this plan:** a flow with an exact NAT match whose VM cannot be named. A flow with no NAT match at all stays host-unknown or unexplained, with the default policy, outside the group.
   - **The alternative:** also put flows with a lowered TTL in that row. It would show more, but TTL is settable by any host program, so with that row Off a host program could exempt itself. I recommend the default. It affects only what is shown and exempted: both choices count these flows as gate misses.
2. **Should a VM row's name be the system's own?** WSL would show whatever HCS reports as its owner (likely `WSL`), and a Hyper-V VM its `ElementName`. No friendly-name mapping is planned, because any such list would be a hardcoded enumeration. Say if you want one.

Assumed unless you say otherwise: VMs do not appear in Home's chart or history, only in Apps and the counters, since the spec names only those.

## coexist

From `docs/tasks/2026-11-02-coexist.md`.

1. **There is no one-click undo after a pause.** "Start AdGuard again" cannot work from StopPending: `sc start` returns 1056, and a kill is ruled out of product code.
   - Built here: the app says to use AdGuard's own window or restart, and shows no button. Start stays for a truly stopped service.
   - Alternatives, only if he wants them: an "Open AdGuard" button (launching its UI, not a filter action), or asking for a kill-and-start through the prompt, which would change law 8 and his own rule.
   - Does not block the build.
2. **A test packet.** While the switch is on and AdGuard's service exists and is not stopped, the engine sends one SYN every 5 s to a documentation address.
   - It carries no data and reaches no server, but it does leave the PC (when AdGuard is not intercepting), and firewall logs would show it. While not routing, the app's connection list can briefly show the engine's row.
   - A PC without AdGuard, or with it fully stopped, sends none.
   - Built on the assumption this is acceptable. If not, the cadence is the one thing to change (for example, probe at bring-up only), which would leave a resumed AdGuard undetected until the next route change.

## content

From `docs/tasks/2026-11-02-content.md`.

**Q1. Where does the scriptlet bundle come from until slice 13?** F1 makes "the engine downloads uBO's tag archive and runs the Rust assembler" impossible for any recent uBO. The library works either way, since it takes bytes and a pin; this blocks only the real pin. Plan's reason for keeping GPL code out of the repo was "Sieve has no declared licence yet", which is now gone (GPL-3.0).
- (a) Recommended: Michael runs the script at a reviewed uBO tag and publishes the JSON as an asset on Sieve's own release, with the hash pinned in code. Same channel slice 13 signs later.
- (b) Commit the JSON and embed it: no hosting, offline from first run, but each bump needs an app release and the installer grows.
- (c) Pin an old-format uBO and keep the Rust assembler as written: not recommended, because of R3 and the F2 trust hole.

Implementation does not wait on this: all tests use the fixture bundle.

## domain-policy

From `docs/tasks/2026-11-02-domain-policy.md`.

Implementation proceeds on the stated default, and each can be changed later.

1. **URL lists at host level before slice 6.** AdGuard Base and Tracking are written for per-URL matching. `||cdn.example^` with `@@||cdn.example/lib.js` closes the whole host, because no path is visible until decryption exists. Default, as the plan says: every default-on list decides host flows. The alternative is that only the AdGuard DNS filter decides host flows until slice 6, which blocks less but breaks less. It is one line in the catalogue either way, and the live run should inform it.
2. **Exception modifiers adblock-rust lacks.** `$elemhide`, `$specifichide` and `$genericblock` cannot be supported without patching the library. Default: list each skipped line (the spec's "or each listed") and revisit in slice 9, where they first have an effect. The alternative is vendoring a patched adblock-rust now.

## encrypted-dns

From `docs/tasks/2026-11-02-encrypted-dns.md`.

**For the user (each has a default, so nothing blocks; change it before merge if you disagree).**

- **Q1. No encrypted resolver reachable, including hotel, airport and other captive-portal Wi-Fi.** Portals usually need plain DNS to reach their sign-in page, and some networks block 443 and 853 to public resolvers. The spec says never plain, and a plan search for "captive" finds nothing. With the default, DNS answers SERVFAIL for as long as the engine is on, and the way out is turning filtering off (which restores normal DNS at once). The alternative would be a user-visible, time-limited "allow plain DNS to the network's server" exception. **Default: strict, as the spec says, documented in the runbook.** Do you want an exception or a notice instead?
- **Q2. Resolver certificate trust (D4).** `webpki-roots` means a resolver behind a private CA (a home DoH server) or a TLS-inspecting corporate network fails, and resolver certificates get no revocation check. In exchange, verification cannot deadlock on its own DNS. The alternative is the Windows verifier run off the runtime, and resolving the loop some other way, which is more code and a real risk to the watchdog. **Default: `webpki-roots`.** Is a private-CA resolver something you need?

**For the orchestrator (scope, not design).**

- **Q3. Who owns ECH stripping and the Firefox canary?** Plan 1.4 and slice 4 list them beside encrypted DNS, but this stream's brief does not, so they are **out of scope here**. `service::answer` is the natural hook for both, in a follow-up after merge. Until one lands, Firefox's canary resolves normally.
- **Q4. Merge hot spots.** `stack/relay.rs` (the domain-policy and attribution streams likely edit `handle_udp` and `handle_tcp`; this stream removes the DNS branches and moves `egress_socket` and `connect`), `route/table.rs`, the `Backend` trait, `Engine::new`, and `Cargo.lock` plus TLS dependency versions if the root-CA stream also adds rustls: use the versions above so one copy resolves.
- **Q5. Plan text.** The brief's fixture name (`engine-ipc-v1.json`) is stale; this plan uses `engine-ipc-v2.json`.

## root-ca

From `docs/tasks/2026-11-02-root-ca.md`.

The build proceeds on the stated default; each default can change without rework.

1. **May `filtering.https` be switched on before interception exists (slice 6)?** Default, from the plan's "cannot be on without slice 6": no, it stays hidden, and the live check drives it through `policy.json` with the app closed. The alternative is to show the switch now, which means installing a trusted root that does nothing yet, but lets you try off and Remove in the real window. The change is one registry attribute and law 11's list.
2. **Should turning `filtering.engine` off also remove the root?** Default, from 2.4: no, only `filtering.https` off removes it, so an engine pause does not churn roots. The alternative is `wanted = engine && https`, which leaves no root while routing is off, at the price of a new root and key per pause. The change is one line in `control/certs.rs` and its tests.

## ui-backlog

From `docs/tasks/2026-11-02-ui-backlog.md`.

- **Q1. What the password must stand up to, and forgetting it.** Default: a UI gate with the hash in the user's app data; it stops someone at the open app, not someone with file access to the account. A real boundary needs the hash and the check in the engine under admin-only ProgramData, which is an engine change outside this stream. Forgotten password: no in-app reset; deleting `settings-lock.json` clears it, documented in `docs/conventions.md` and not shown in the app, because showing it to the person being locked out defeats the lock.
- **Q2. Does the lock cover turning things off?** Default: yes for every settings write, including the master switch, per-app Off and the engine switch, because "owner controls the settings". Left open while locked: tray and pill Pause and Resume (they write no setting), Quit, and the Start menu "Sieve - restore network" shortcut and uninstall, so nobody can be stuck with a broken network behind a password. If he wants turning off to need no password at all (the fail-open reading), it is one condition in `guard`.
- **Q3. Log hidden behind the lock.** Default: yes (D11).
- **Q4. Plan 1.5 says the first run asks once with "Filter all traffic".** This spec says the guide never changes the network, and those data switches and their live checks do not exist yet. Default: not included; slice 6 adds it as one step.
- **Q5. Rows left out.** Host drill-down (54), Support links (72, needs a public URL), About (73, may belong with `wf-updates`). Default: not built here.
- **Q6. A fourth top-level nav item.** Default: "Filters" in the top bar. The alternative is inside Settings; the screen would move with no change to its parts.
- **Q7. An allowlist that wins over everything.** AdGuard's and uBlock's allowlists beat every rule and cover a site's whole page. A rule cannot do that in adblock 0.13.3. It needs the engine to consult the list of hosts before the rule engine, and, for a site's whole page, a request that knows its initiator, which a name-only flow does not have. Default: not built here (no engine change in this stream), so the copy states the narrower truth. For slice 4 to decide: `filterPolicy` would then send hosts instead of `allowRules`.

## updates

From `docs/tasks/2026-11-02-updates.md`.

The implementation proceeds on the stated default for each; none blocks offline work.

- **Q1. Update host.** Where will releases be served? This decides the URL constant and redirects. GitHub Releases redirects to another host, which D3 refuses as built; signatures make following redirects safe, but the plan says "the catalogue host". Default: the `.invalid` placeholder, no redirects, updates stay `not_configured` until you pick. If you pick GitHub Releases, allow redirects over validated HTTPS.
- **Q2. When do releases install?** Default per D18: never by themselves, only after you click Install update. A release stops the engine for some seconds and closes the app. Data kinds apply daily with no prompt. Tell me if you want releases automatic too.
- **Q3. Engine-only releases.** 7.5 lists both an `engine` kind and "one NSIS installer per release". An engine-only update whose protocol moved leaves the old app shut out ("Reinstall Sieve so both match"). Default: both are built as the plan says, and the runbook says to publish `app` for normal releases and `engine` only for a fix that does not change the protocol. Dropping `engine` would remove D13's first half if you never want it.
- **Q4. Checking while filtering is off.** The daily check contacts your host even when the user has filtering off, and the service description says that while off it "changes nothing on this computer's network". A fetch changes no network state, but it is a request nobody turned on. Default: check daily regardless, per the 2026-10-17 decision, because a stale engine is the worse outcome. The alternative is to check only while `filtering.engine` is on, or when asked.

## content-wire

From `docs/tasks/2026-11-06-content-wire.md`.

Decisions for the user:

**Q1. Where the real scriptlet bundle comes from** (content task Q1, still open; F8). Until it is answered no scriptlet runs on a real machine and slice 10 cannot pass. Default: option (a) there: the user runs `assemble-ubo.mjs` at a reviewed uBO tag and pins the hash. For the live run only, the runbook says edit `RESOURCE_PIN` on a local build and place the JSON as `lists\resources.json`. This stream adds no mechanism for it and does not choose a tag.

**Q2. Does the allowlist stop cosmetics?** `allowRule` is `@@||host^`, and its text promises only that connections go through, so an allowlisted site's pages still get hidden elements and scriptlets once content is on, as in uBO. AdGuard's allowlist turns everything off for that site. Default: keep it, text unchanged; the way to leave a site alone stays "Sites not decrypted" or a `$document` rule. Changing it means `@@||host^$document`, which also changes the network decision on what such pages load, so it should be decided before `filtering.content` is unlocked.

**Q3 (O3). A rewritten page cached by the browser outlives Sieve off.** With a `max-age`, the page still carries its injected style and scriptlets after Sieve is off, until it expires. The network is normal, so the top rule holds as written, but the page is not what the site sent. Default: leave `Cache-Control` alone, as AdGuard does, and read it in U7. The strict alternative is `no-store` on every rewritten document, which costs back-forward cache and repeat loads on every site.

For the orchestrator:

**O1. Merging main into this stream.** The brief branches from `wf2-tls`, which lacks main's a869fd6 (F6). Default: step 0 merges main, because wiring without it ships a reset on real pages. `git merge-tree` shows one conflict, `control/mod.rs`, that the eventual merge of `wf2-tls` hits anyway. If the orchestrator would rather merge `wf2-tls` into main first, step 0 becomes a plain `git merge main` with no conflict left. Tell the executor if neither is wanted; then at least a869fd6 must be cherry-picked.

**O2. `PROTOCOL` stays 3** (D1), following the wave's own precedent. Other wf2 streams adding policy fields should do the same, or one bump covers all at merge.

**Other streams:** `http/hook.rs` gains a defaulted method, `RequestFacts` gains `is_page`, `FlowBook` gains `list_hits`, `Meters` gains `content`. `wf2-quic` is a prerequisite of slice 10's live run only. `D13` may touch `flow/sni.rs` and `dns/` test strings: small, one-line, and any stream adding a real name there will fail the law at merge, which is its purpose.

## dns-extras

From `docs/tasks/2026-11-06-dns-extras.md`.

**For the user (each has a default, so nothing blocks; change it before merge if you disagree).**

- **Q1. Private reverse lookups (recorded for your review, as asked).** Default as specified: a private-range reverse lookup goes to the LAN server when one is known, else NXDOMAIN locally, and never to the public upstream. "Private" is every range the engine already never routes (RFC 1918, CGNAT, loopback, link-local, ULA, multicast and reserved). "Known" is the adapter covering the address, then any adapter with a private DNS server. A LAN server that does not answer gives SERVFAIL. The cost: where the network's DNS is a public resolver (or a VPN's is absent), `Resolve-DnsName 192.168.1.5` says "no such name" even if some other server could know it. The alternative, sending them encrypted, tells Cloudflare your private addressing. Tell me if you want them forwarded on such networks.
- **Q2. A browser turned Off also loses ECH while `filtering.https` is on.** Its lookups go through the DNS Client service, so no app is known at DNS time. Its flows are not decrypted and work normally, but the real site name is visible on the wire, as if the site had no ECH. Plan 2.9 accepts this by saying "names", and there is no way to tell apps apart here. **Default: accept, and state it in the switch's help text when the switch is unlocked.** The alternative is not stripping at all, which sends every ECH site through as host-level only.
- **Q3. The canary and the reverse rule get no switch of their own.** The plan rule says traffic-changing features are data switches, and slice 4 says "Switch: none new (part of `filtering.engine`)". They change the answer for a handful of names, nothing leaves as a result, and they end with the engine. So a user who already passed the engine's check gets them without a new check. **Default: follow slice 4, no new switch; the live items above are run once.** Say if you want them held behind a check.

**For the orchestrator (scope, not design).**

- **Q4. Merge hot spots.** `dns/service.rs` (no other `wf2-*` task doc names it), `stack/dns_flow.rs`, `tls/intercept.rs` (one added method), `control/routing.rs` (one closure at the `Service::new` line), `sieve-filter/src/exclusions.rs` (additive), `settings/setting-row.tsx` (one early return; check `wf2-content-wire` and `wf2-heal` if they add rows), `upstream-grammar.json` (one key).
- **Q5. No error boundary exists in `src`.** The frontend-resilience policy wants one per screen. This stream normalizes and guards its own data and tests the degraded shapes, but a boundary is app-wide, so it is a follow-up proposal, not part of this diff.
- **Q6. Other special-use names** (`home.arpa`, `.local`, single labels) still go to the encrypted upstream unless a suffix claims them. Same kind of leak as Q1, not in this brief. Proposed follow-up, not built.

## heal

From `docs/tasks/2026-11-06-heal.md`.

**Q1. How does the live check reach a non-browser client?** Browsers first means curl, Discord and Steam are never intercepted, so slice 7's own live acceptance cannot run, while the decision table waits on that acceptance before widening. Default: the `live-scope` cargo feature (D10), a diagnostic build like `relay-experiments`, never in a release. Alternative: prove healing only with a browser that rejects the root, which proves the path but not "Discord works". Widening scope for users stays your call after U1 to U5, and is not in this stream.

**Q2. Credit for a pair that has been used.** The plan's literal reading excludes after two quick failures with no success between them, whatever came before. Default: a used pair earns up to `MAX_CREDIT` 2, so it takes four quick closes. Cost: a client that starts pinning silently after having worked fails up to two more times, and fatal alerts are unaffected. Without it, two redundant sockets on a busy site can turn off URL filtering there for that browser. U5 measures it, and the dial is one number.

**Q3. Mass rejection by a client that merely lacks the root (F7).** Default: per-host entries as designed, with the notice's grouping and one "Try decrypting all again". Alternative: when one exe rejects many hosts in a short time, treat it as "this client does not trust the root", which needs an app-level entry and a new dial. Not built until U6 shows it is worth a second mechanism (S52).

**Q4. Rows across Windows sessions.** The store is machine-wide, so a second account already admitted by the pipe's DACL would see another session's hosts in the list, though not in notices. Default: accept, since the DACL admits only the enabling user, SYSTEM and Administrators. Alternative: record the session on auto entries and filter rows, at the cost of a session id that means nothing after a reboot.

## quic

From `docs/tasks/2026-11-06-quic.md`.

**Q1. `Alt-Svc` on intercepted responses.** The TCP response Sieve relays still advertises `h3`, so a browser keeps trying QUIC and being refused until it marks the alternative broken. Removing the header in `http/` would stop most attempts at the source, but it edits every intercepted response beyond what filtering needs, and it belongs to the HTTP path, not this slice. Default: leave responses alone, and let U9 measure the cost. Changing it later is one line in `http/` with its own test.

**Q2. How a refused flow reads on the pipe.** `FlowAction` has `Relayed`, `Failed`, `Blocked`; none is true of a refused flow. Default: close it `Relayed` with 0 bytes plus the `quic_refused` log row, because the app does not read the action today (F8), `Blocked` would contradict your rule and count against the block figures, and a new variant means protocol 4 and a renamed fixture while other streams change the same file. Cost of the default: a false word on the wire, recorded in a comment. If the app ever shows the action, add `Refused` then, with the bump.

**Q3. If ICMP harms a shared socket (U5).** Default: the drop arm stands even if ICMP is faster, since a slower first fallback is better than breaking a connection the user did not ask to touch. It costs the browser's race timer on each refused first visit. Your call if the numbers are close.

## tls

From `docs/tasks/2026-11-06-tls.md`.

**Q1. Which never-decrypt lists?** The decision table says write our own and do not use HttpsExclusions; plan 4.2 and slice 6 still fetch it at runtime, and section 10 Q2 is still open. Default: follow the table. Sieve's own `sensitive` list decides, seeded from a list this stream writes and replaced by signed updates. The HttpsExclusions fetch is built and tested, with `enabled: false`. Cost of the default: a list far smaller than AdGuard's 4,289 entries until it matures, so more sites depend on the floor and on slice 7. Changing it is one word in `SOURCES`. The seed's contents deserve your review before the live check.

**Q2. Browsers with their own DoH.** Under D9 they pass through, since a real ECH cannot be ruled out, so a user with Secure DNS on an explicit provider gets host-level filtering only. Default: accept, and let the log show how often. The alternative is treating every ECH extension as GREASE, as RFC 9849 lets a terminating proxy do, which decrypts those flows too, but it goes against plan 2.9's "passes through".

**Q3. Revocation fetches and the loop guard (F4).** If U5 shows the engine's OCSP and CRL fetches are refused as its own flows, revocation is staple-only until slice 11's CRLite, and 7.2's revoked item fails. Default: leave the guard unchanged in this stream and let U5 decide. The likely fix is relaying the engine's own port 80 flows through `Egress`, which pins outside Sieve's routes and so cannot loop, but changing a safety guard without a live run is not something to do blind.

## validation

From `docs/tasks/2026-11-06-validation.md`.

**Q1. `clubcard-crlite` in place of the named filter-cascade crate.** The brief and plan 2.6 say Mozilla's filter cascade. Mozilla has moved on: a real published file is refused by `rust_cascade` and read by `clubcard-crlite`, the crate from the same team and the one Firefox uses (F1). Default: `clubcard-crlite`, MPL-2.0 like `adblock-rust`, and the plan gets a dated note. The alternative of building cascades ourselves would mean running Mozilla's whole pipeline.

**Q2. Who publishes the two artefacts, and how often?** This is the real decision here. The brief routes data through `update::data_path`, so each file carries a minisign signature from your offline key (decision of 2026-10-18), but upstream changes constantly: the log list daily with a 70-day limit, CRLite every 12 h.
- Default: you run `validation_bundle` and sign by hand at a cadence you pick. CT is fine monthly. A CRLite signed weekly can be up to a week behind Firefox. That lag is safe, because the OS revocation check still runs.
- Consequence to accept: **until you publish, CT and CRLite are skipped on every connection**, and `status.json` says so (`ct_skipped_no_list`). `filtering.https` then behaves as slice 6 does, which is weaker on CT than Chrome. The stream does not block the switch on this; say if you want the unlock to require a list.
- Alternatives, not built: an online data-only signing key, which weakens the offline-key decision; or the engine fetching from Google and Mozilla directly, as plan 2.6 first said, verifying Google's signature and Mozilla's content signature, which is more code and more outbound requests from the engine.
