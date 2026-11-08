# Live check: slice 10, the video site and the default list set

Run by the user with a verifier reading the evidence, from an admin prompt, under the GPU lease. Nothing here was run by the stream that built it: `scripts/live/youtube.mjs` has been syntax-checked and its pure parts tested, and its two browser drivers have never met a browser. Expect to fix them on the first run.

## Before you start

All of these must be true, or a run says nothing:

- Slice 6's check passed (`docs/live/engine-slice-6.md`) and slice 9's U1 and U2 (`docs/live/engine-slice-9.md`).
- Slice 8 is built and on: without QUIC refusal Chrome reaches the site over HTTP/3, which is never decrypted. The script calls such a run inconclusive.
- A real resource bundle is loaded. `RESOURCE_PIN` is None until open question Q1 of `docs/tasks/2026-11-06-content-wire.md` is answered. Without a bundle no scriptlet runs, and the script calls that inconclusive too.
- You have reviewed `scripts/live/youtube-videos.json`. The ids were written from memory and never checked. An unavailable video counts as not played, and fewer than 10 played is inconclusive.

## Running one arm

The script prints the list ids an arm needs. Give them to `engine-content.ps1`, which puts them in `policy.json` with the app closed. Then wait until `status.json` shows those lists under `filter.lists`, since a list with no downloaded copy is not held: the script reads that before the first video and after the last, and if it differs from the arm at either end, or the file cannot be read, the run is inconclusive.

```
powershell -ExecutionPolicy Bypass -File scripts\live\engine-content.ps1 -Step on -Lists adguard-base,adguard-tracking,adguard-url-tracking,adguard-dns,ubo-badware
powershell -NoProfile -File <tools>\procs\with-gpu.ps1 -Label sieve-youtube -- node scripts\live\youtube.mjs --browser chrome --arm adguard --out C:\Users\Public\sieve-engine-live\youtube
```

The second arm, `adguard+ubo`, adds `ubo-filters,ubo-quick-fixes,ubo-unbreak`. Run both arms in `chrome`, `edge` and `firefox`, then `-Step off`.

The script opens the browser with a temporary profile, watches each video for 30 s, checks the home page, seek, quality change and next-video autoplay, and ends the browser by process tree. A cookie or consent wall in a fresh profile shows as a video not played: answer it by hand in that window, declining what is not needed.

## Reading a result

`youtube-<browser>-<arm>.json` holds the verdict, each video's samples and document facts, and the day-one items. Failure screenshots sit beside it.

- **pass:** 10 played, no ad state, no enforcement message, the engine's issuer, the engine's `content.with_scriptlets` meter grown by at least the videos played (`scriptletDocuments`), the arm's lists held at both ends, and every day-one item checked and working.
- **fail:** an ad or a broken player: an ad state, an enforcement message, or `currentTime` rising in fewer than half of the intervals, not counting those at 0 before playback began. The home page counts ad elements a person could reach: a box with some opacity, not clipped by a collapsed parent, and not wholly above or left of the page. So an element a rule hid or a blocked fetch left empty is no failure. An ad hidden any other way, such as `clip-path`, still counts, so check a home page failure against the screenshot and the Log screen. Read the Log screen for that page's rows, since rule text is there and not in the file.
- **inconclusive:** the run could not show Sieve was doing the work with this arm's lists, or a check could not run. The reasons say why, and `errors` holds what each failed check threw. It is never a pass. A wrong arm, a missing issuer or a missing scriptlet hides any failure too, since that is no evidence against a list; a day-one item that could not run does not hide a failure that was seen.

The script needs an elevated prompt: without `status.json` it cannot say which lists were held. `listHits` counts the connections and decrypted requests each list blocked, redirected or stripped during the run: everything on the machine in that time, not only this browser. It is `null`, not 0, when the file cannot be read. A lookup is never counted, because DNS is not a blocking decision (`domain.rs`). This is by design: plan 7.1 keeps the log in memory and the pipe admits only `sieve.exe`, so per-rule text stays on the Log screen (plan 5.7, as built). The script waits 35 s before each read of `status.json`, past the engine's 30 s rewrite, so a run takes over a minute longer than its videos. On Firefox the certificate cannot be read through BiDi, so the meter is the witness for the issuer as well: a site cannot forge it, where a script in the page could have the engine's shape. The meter counts the machine, not this browser, and frames and day-one pages add to it, so it is a lower bound for the run and not a per-video fact: leave nothing else browsing during a run.

## After both arms

Fill the results table under slice 10 in `docs/plans/2026-10-17-https-filtering.md`. The rule is plan 5.4: both arms pass, the gated rows turn on; only one passes, that arm is the default. The change is one word per row in `engine/crates/sieve-filter/src/catalogue.rs` (`Default::Gated` to `Default::On`), plus `defaults_follow_the_plan_table`.
