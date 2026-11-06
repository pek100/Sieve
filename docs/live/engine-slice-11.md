# Live check: slice 11, CT, CRLite and upstream ECH

Run by the user, from an admin prompt. Nothing here was run by the stream that built it: every item is UNVERIFIED until you run it. Slice 6's own live check (`docs/live/engine-slice-6.md`) must have passed first, and it uses the same route: with the app closed, `scripts/live/engine-ca.ps1 -Step intercept` writes `https`, `sieving` and `engine` true into `policy.json`. There is no new switch. CT, CRLite and ECH are part of `filtering.https`, which stays hidden in the app.

Traffic really goes through the engine during this check. Do it when nothing else on this PC depends on the network. Before you start, record `route print`, `Get-DnsClientServerAddress`, `netsh winhttp show proxy` and the firewall rule list. The way out at any point is the engine switch off, or `sieve-engine.exe restore`.

## Before you start: the two artefacts

Until both files are on disk, CT and CRLite are skipped on every connection and `status.json.https.ct_skipped_no_list` grows. That is slice 6's behaviour, not a failure. Make and sign them by the section "Slice 11's data" of `docs/live/updates.md`.

To take a bad artefact back, delete its file under `ProgramData\Sieve\engine\updates\` (`list-ct-logs`, `list-crlite`). The engine reads the folder at its next hourly wake, and at the next time the switch goes on. A missing file means no data.

## What to read

`status.json` (admin-only, `C:\ProgramData\Sieve\engine\`), section `https`, rewritten every 30 s:

- `ct_compliant`, `ct_violating`, `ct_skipped_no_list`, `ct_skipped_stale`
- `crlite_revoked`, `crlite_filters`, `ct_list_timestamp` (ms since the epoch)
- `validation_refused`: a file on disk the engine refused, once per file version; what was loaded stays loaded
- `ech_offered`, `ech_accepted`, `ech_failed`

No host is ever in it (plan 7.1), so to read one site, read the numbers, load that site alone, read them again.

## The ignored tests

Each is a reader of the counts around a browser step you perform. The engine decrypts browsers only (scope `Browsers`), so a test binary's own connection would pass through before any of these checks ran; the tests make no connection at all. Run one at a time from `engine/`, with the engine running and interception on:

```powershell
$env:SIEVE_LIVE_STATUS = 'C:\ProgramData\Sieve\engine\status.json'
$env:SIEVE_LIVE_HOST = '<the host of the check>'
cargo test -p sieve-engine --lib live_ct_violating_endpoint_passes_through -- --ignored --nocapture
cargo test -p sieve-engine --lib live_crlite_revoked_passes_through -- --ignored --nocapture
cargo test -p sieve-engine --lib live_upstream_ech_used -- --ignored --nocapture
```

Each test waits for `status.json` to be rewritten, so its first count is current, and prints when to act. Then load the host in a browser, and nothing else. It polls for up to 2 minutes, four rewrites, and fails unless `ct_violating`, `crlite_revoked` or `ech_accepted` respectively grew. The issuer the browser shows is yours to read, as the table says.

Load a host the engine has not judged since interception went on. A rejecting verdict is cached in the engine's memory and the next flow passes through with no check, so a second load does not grow `ct_violating` or `crlite_revoked`. Restarting the engine clears it.

## Checks

| # | Do | Pass when |
|---|---|---|
| U1 | badssl.com's `no-sct` in a browser (`SIEVE_LIVE_HOST=no-sct.badssl.com`). Then a normal public site. | The first shows its real issuer, the log row says `floor:upstream-ct`. The second shows Sieve's issuer, and `ct_compliant` grew. |
| U2 | Run the artefact's filters through the crate's `query` example first to pick an endpoint actually in them, then load it. | It passes through with its real issuer, and `crlite_revoked` grew. |
| U3 | `https://crypto.cloudflare.com/cdn-cgi/trace` in a browser, with Secure DNS off. | It reports `sni=encrypted` through Sieve, and `ech_accepted` grew. No local test can show this: rustls has no ECH server (task F8). |
| U4 | Repeat U5 of slice 6, and read `own_refused`. | Note whether a CRLite hit stands when the OCSP fetch was refused. This weakens Q3 of slice 6. |
| U5 | Time a first connection to a new host and a repeat one, against plan section 6's 2 ms. | Reported. Decides the DNS tap of task D9. Tune `ECH_LOOKUP_WAIT` (300 ms) and `ECH_HANDSHAKE_TIMEOUT` (3 s) here. The offline bench is in-memory only. |
| U6 | Count hosts falling to `floor:upstream-ct` on the fixed 20-site set of U11 of slice 6. | Near none. A large number means a policy reading is wrong, or SCTs by TLS extension (task F4) are commoner than assumed. |
| U7 | Memory and load time with the real bundle. | Within the 300 MB budget. Note whether the `compat` channel would be enough. |
| U8 | A real ECH server rejecting a stale config, if you can find one. | The site still loads, and `ech_failed` grew. |
| U9 | Check whether a real full filter in the `default` channel is V3 or V4 on the day. | The tool takes it either way; note which it was. |
| U10 | Kill, reboot and uninstall tests of `docs/conventions.md` section 0, with all three active. | They match slice 6's result. Nothing here adds system state. |
| U11 | Publish `list:ct-logs` and `list:crlite` through the real update cycle. | The engine picks them up within the hourly wake, `ct_list_timestamp` and `crlite_filters` say so, and `validation_refused` stays 0. |
| U12 | A real ECH taken for GREASE: Chrome with Secure DNS on an explicit provider loads a name publishing ECH whose public name a second app has just resolved at the same address through system DNS (`Resolve-DnsName <public name>`). | Say what you saw: the failed attempt, whether the browser retried without ECH, and with which SNI. `auto:pinning` for (that browser, the public name) appears after the one refusal if its `ech_required` alert arrived (task D9 of `docs/tasks/2026-11-06-tls.md`), and the next load passes through. |

## Reading a result

- `floor:upstream-ct` on a site that works in Chrome: the site may send its SCTs only by TLS extension, which rustls never asks for (task F4). It passes through, so it works; it is simply not decrypted.
- `validation_refused` above 0 on a list you just published: the envelope's Google signature failed, or a filter in the bundle did not parse. What was loaded before stays in force.
- `ct_skipped_stale` growing: the log list is past Chrome's 70 days. Publish a new one. CT is off until then, as it is in Chrome.
- `ech_failed` growing fast with `ech_accepted` flat: every config is being rejected. Each failure costs one extra handshake and then 5 minutes without ECH for that host, and no site breaks.

## Not here

SCTs delivered by TLS extension (rustls does not expose them). `temporal_interval`, which the published policy does not need. `previous_operators` is read only far enough to give no credit for an SCT from before a log's move (the recorded list has none). Retry configs of a rejected ECH attempt (task F10). The fetch of either artefact from Google or Mozilla (task Q2).
