# Handoff to the live controller: relay CPU experiments and P0

2026-10-18. Main is at 8886121 or later. Everything below is offline-verified only. Run it under the shared live lease (`C:\Users\Public\sieve-engine-live\runner.lock`), and restore and audit afterwards as before. Claude stays read-only on services, routing and the UI. Plan: `docs/plans/2026-10-18-slice-3-attribution-and-cpu.md`, sections 3 and 6.

## What changed since the last installed build

- **f171c44, production relay fix.** `relay_tcp` dropped the tail of a deciding read that overflowed the classifier's cap. Uploads whose first bytes span reads could arrive cut short. Every future acceptance build includes it. The installed engine (SHA256 `CAC24561...`) does not.
- **85e63cb and ee9a45e, route-delete reporting.** `ERROR_NOT_FOUND` and `ERROR_FILE_NOT_FOUND` count as "already gone". Real failures keep their Win32 codes. The next watchdog or kill run should show whether the earlier "51 failed" were all already gone.
- **The `relay-experiments` cargo feature**, off in production. At start the engine reads `C:\ProgramData\Sieve\engine\experiments.json`. It must be UTF-8 (a BOM is fine; UTF-16 is refused) and at most 4 KiB. All fields are optional:
  - `tun_mtu`: 1280 to 65535, default 1500;
  - `copy_buffer_bytes`: 8192 to 1048576, default tokio's 8 KiB;
  - `tun_batch`: 1 to 256, default 1;
  - `worker_threads`: 1 to 64.

  The values in force and the file's read result appear under `experiments` in status.json. Change the file only while the service is stopped.
- **The `release-lto` cargo profile (E5).**

## Builds (unelevated, from `engine/`)

```powershell
cargo build --release -p sieve-engine                                         # baseline, includes f171c44
cargo build --release -p sieve-engine --features relay-experiments            # E2-E4 and E6, one binary
cargo build --profile release-lto -p sieve-engine --features relay-experiments # E5 on top
```

## Measurement order

Use the C0 workload. Change one variable per comparison, run baseline and candidate back to back three times each, and let the median decide. Space runs at least 5 minutes apart: Cloudflare returned HTTP 429. If Cloudflare keeps refusing, pick another large-file HTTPS endpoint and pass `-Url`, `-Count` and `-Size` to `budget-transfer.ps1`.

1. **P0, the relay floor.** It installs nothing and needs routing off. See `docs/live/p0-relay-floor.md`. Pass mark: 0.05 cores per 100 Mbit/s or less. It decides whether a WFP-redirect design is worth anything.
2. **The baseline:** the new release build (with f171c44), routing on, no experiments.json.
3. **E2:** `{"tun_mtu": 9000}`. Also run a QUIC page load and a large UDP check, because path-MTU probes are the risk.
4. **E3:** `{"copy_buffer_bytes": 262144}`.
5. **E4:** `{"tun_batch": 64}`. A stalled-stack run must still trip the watchdog.
6. **E6:** `{"worker_threads": 2}`, then the default.
7. **E5:** the release-lto binary, with the best combination from steps 3 to 6.

Report each result as cores per 100 Mbit/s, throughput against Sieve off, and working set. The budget stays at 0.15.

## Note

The OpenAI usage limit was reached on 2026-10-18 and resets on 2026-10-25, 18:41. If the Codex desktop session is limited too, these runs wait for it or for Michael.
