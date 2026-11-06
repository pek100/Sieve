# Live check: slice 6, TLS interception (`live_https_intercepts_public_and_passes_floor`)

Run by the user, from an admin prompt. Nothing here was run by the stream that built it: every item is UNVERIFIED until you run it. `filtering.https` stays hidden in the app, so the script drives the switch: with the app closed, `scripts/live/engine-ca.ps1 -Step intercept` writes `https`, `sieving` and `engine` true into `policy.json`, leaving every other field as it was. Slice 5's `-Step on` changes only `https`, which holds a root and intercepts nothing: interception needs `sieving` too (`wanted()` in `tls/intercept.rs`), and no flow reaches it without `engine`. Read that script before running it.

Traffic really goes through the engine during this check. Do it when nothing else on this PC depends on the network. Before you start, record `route print`, `Get-DnsClientServerAddress`, `netsh winhttp show proxy` and the firewall rule list. The way out at any point is the engine switch off, or `sieve-engine.exe restore`. When you are done, `-Step off` takes the root away, and opening the app sends your own switches back, `engine` and `sieving` included.

`status.json` (admin-only, `C:\ProgramData\Sieve\engine\`) gains `https`: `intercepted`, `passed`, `upstream_groups`, `client_groups`. No host is ever in it (plan 7.1), so to read one site, read the numbers, load that site alone, read them again.

## Step 0: interception is really on

Believe no floor check before this passes. U4, U5, U6 and U8 pass when the browser shows its own verdict, and a flow nothing intercepted shows exactly that, so with interception off they pass and prove nothing.

1. `powershell -ExecutionPolicy Bypass -File scripts\live\engine-ca.ps1 -Step intercept`. It must print PASS for `the engine holds interception on with routes up`. A FAIL names the blocker: AdGuard running is the usual one.
2. Note `https.intercepted` in `status.json`, load a plain public site in Edge or Chrome (no exclusion, not a bank or a `.gov`), wait for the 30 s rewrite, and note it again.

Pass when `https.intercepted` grew. If it did not, stop and read `routes_up`, `blocker`, `policy.sieving`, `policy.https` and `last_error` in `status.json`, then `https.passed` and the log's reason slugs (see Reading a result).

## Checks

| # | Do | Pass when |
|---|---|---|
| U1 | Load a public site you have no exclusion for in Edge, Chrome and Firefox. Open each browser's certificate viewer, and Chrome's security panel. | The issuer is "Sieve local filtering CA". Chrome shows X25519MLKEM768. |
| U2 | Note `status.json.https`, load that one site, wait for the 30 s rewrite, note it again. | `upstream_groups.X25519MLKEM768` grew. |
| U3 | Chrome with Secure DNS off, load a site; then Secure DNS on with an explicit provider, load it again. | Off: Sieve's issuer (a GREASE ECH extension does not hold it back). On: the real issuer, and the log says `floor:ech`. This is the assumption most likely to surprise (task D9). |
| U4 | Each of badssl.com's: expired, wrong.host, self-signed, untrusted-root, sha1-intermediate, incomplete-chain, tls-v1-0, tls-v1-1, rc4, 3des, null, dh1024. | Each shows the browser's own error (or the browser's own success), never a Sieve certificate. |
| U5 | badssl.com's `revoked` (or another revoked endpoint), then read `own_refused` in `status.json`. | It passes through, with the browser's verdict. Records whether CryptoAPI's fetch was refused by the loop guard: this decides open question Q3. |
| U6 | A site you use a client certificate on, and a site with an EV certificate. | The client presents its own certificate and the site works. The EV site shows its real issuer. |
| U7 | The checks above with a machine that has an enterprise root, if you have one. Time a load with a slow first connection. | `rustls-platform-verifier` agrees with the offline fake's contract on real chains. `TRUST_TIMEOUT` (5 s) is not reached in normal use. |
| U8 | A `.gov` site and a site from `crates/sieve-filter/data/sensitive.txt`. Leave it 30 minutes, then search the log for session 0 flows. Use a non-browser app. | Real issuers. No intercept rows for session 0. The non-browser app is not decrypted. `BrowserSet` found your browsers, including a per-user Chrome read from HKU as SYSTEM. |
| U9 | A site that asks for a certificate after the handshake (TLS 1.3 post-handshake auth), if you know one. | The connection closes, the reason is logged, and the next connect passes through (`auto:client-cert`). |
| U10 | Budgets (plan section 6), measured with the engine's own numbers: decrypt CPU at 100 Mbit/s, one flow's throughput, added time on a new connection and per request, memory at 2,000 flows. | 25 percent of one core; 500 Mbit/s; 2 ms; 0.5 ms; 300 MB. If not, tune `H2_STREAM_WINDOW` and `H2_CONNECTION_WINDOW` (`http/serve.rs`) here. |
| U11 | A fixed 20-site set, with and without Sieve. Count bot-challenge pages. | Reported (risk R5). The upstream hello looks like rustls, not a browser. |
| U12 | Kill, reboot and uninstall tests of `docs/conventions.md` section 0, with interception on. | After a kill: connections reset, the network works within 5 s, every listing matches the before-listing. |
| U13 | A site using WebSockets over HTTP/2 in Chrome and Firefox. | It falls back to HTTP/1.1 for the WebSocket and works (task D12). |
| U14 | Check the app talks to the engine as before, and 7.3 holds. | IPC and the pipe are unchanged. |
| U15 | With a browser holding an intercepted connection (Sieve's issuer), turn that browser's row Off in the app with the engine running, then reload. | The reload shows the real issuer and the log row reads `app_off`. This one cannot be driven from the script: a row only turns Off through `SetPolicy`, the pipe admits only `sieve.exe`, and today's app sends `https: false` whenever it runs, while a restart would end the connection anyway and prove nothing. So it waits for the first build with the switch available. Offline tests cover the engine's path from `SetPolicy` to the closed flow; how a real browser reconnects is what is left to see. |

## Reading a result

- A page that fails only with Sieve on: look in the log for the row. A reason slug tells you why it was not decrypted: `floor:*` is the function's, `list:*` a list's, `auto:*` the engine's own record in `exclusions.json`, `user` yours.
- `floor:no-exclusion-list` on everything means `exclusions.json` could not be read. The engine does not overwrite it: read it, fix or delete it, restart.
- `floor:no-root` on everything means the CA holds no in-date root: see `CertStatus`.

## Not here

Certificate Transparency, CRLite and upstream ECH are slice 11, with their own runbook, `docs/live/engine-slice-11.md`. Self-healing is slice 7, with its own runbook, `docs/live/engine-slice-7.md`. Content rewriting is slice 9. ECH stripping from DNS answers has its own check: run steps 1 to 5 of `dns-extras.md` once this one passes.
