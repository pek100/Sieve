# Live check: engine slice 7, self-healing exclusions

Run by the user. None of this has run. `filtering.https` stays unavailable; this runbook does not unlock it. It needs the slice 6 live route first (`docs/live/engine-slice-6.md`), with the switch driven by `scripts/live/engine-ca.ps1 -Step intercept`, app closed.

The ignored test is `live_self_healing_excludes_a_pinning_client`. It holds no check of its own; this page is the check. A verifier reads the evidence.

## Before you start

Browsers first is a floor fact, so curl, Discord and Steam are never intercepted and can never fail. U1 to U3 therefore need a diagnostic build (task D10):

```
cargo build --release --manifest-path engine/Cargo.toml -p sieve-engine --bin sieve-engine --features live-scope
```

Put `{"scope":"all"}` in `live-scope.json` beside `policy.json` in the engine's folder and restart the service. Any other content, or no file, is the normal floor. A release build has neither this code nor this file's meaning; a law holds no release path to it. Afterwards, delete the file and put the release build back.

Copy the output of `route print`, `Get-DnsClientServerAddress`, `netsh winhttp show proxy` and the firewall rule list first, for U7.

## Checks

| # | What | Pass |
|---|---|---|
| U1 | `curl --cacert <public bundle> https://<intercepted host>/`, twice. First confirm the build's curl honours `--cacert` (schannel builds differ); a curl with OpenSSL or the bundled cacert is the alternative. | The first fails. A row appears: that host, curl, "Rejected Sieve's certificate (auto)". The second works and shows the host's real issuer. One notice. |
| U2 | Discord or Steam, if installed, for a few minutes. | Each works after at most one failed request per host. One notice per app, not per host. |
| U3 | "Try decrypting again" on U1's row, then curl again. | The next curl fails once. The row comes back reading "tried again 1 time, first on" U1's day, not a later one. |
| U4 | What real clients do: for U1 and U2, read which alert or close each client produced. Does any fatal alert arrive after the handshake (task D3)? | Reported, with the client and the alert. Nothing to pass. |
| U5 | 30 minutes of normal browsing in Chrome, Edge and Firefox. Count closes within `SILENT_CLOSE_MS` per host, and `status.json`'s `https.healed` per app. | Zero `auto:pinning` rows expected. The number decides Q2 and `MAX_CREDIT`. |
| U6 | Firefox open during the first enable and during a Reinstall (task F7). | Reported: does it reject until restart, and how many rows does that leave? After a restart, "Try decrypting all again" on Firefox recovers it. The answer decides Q3. |
| U7 | Kill, reboot and uninstall tests of `docs/conventions.md` section 0, with interception on and `exclusions.json` holding entries. | Network works, and the listings match the copies. Nothing of heal's is network state. |
| U8 | A real toast in the Tauri window, its Show action, and the app sheet line for a browser, for curl under `live-scope`, and for an Off app. | The toast opens the filtered view. The line says what the table in task D8 says. |

## What to bring back

The rows of U1 and U3 (a screenshot), the two curl outputs, the alert table of U4, the counts of U5 with the browsers' versions, the answer to U6, the before and after listings of U7.
