# Live check: slice 9, content (`live_content_injects_into_test_page`)

Run by the user, from an admin prompt. Nothing here was run by the stream that built it: every item is UNVERIFIED until you run it. `filtering.content` and `filtering.https` stay hidden in the app, so `scripts/live/engine-content.ps1` drives them with the app closed, as slice 5's script does. Read it first. It touches only `policy.json` and the engine's own service.

Run `docs/live/engine-slice-6.md` first: this check rides on interception. The scriptlet rows also need a real resource bundle, which does not exist yet: `RESOURCE_PIN` is None until open question Q1 of `docs/tasks/2026-11-06-content-wire.md` is answered. For a live run only, edit the pin on a local build and place the JSON as `lists\resources.json`.

Traffic really goes through the engine during this check, so do it when nothing else on this PC depends on the network. Before you start, record `route print`, `Get-DnsClientServerAddress`, `netsh winhttp show proxy` and the firewall rule list. The way out at any point is the engine switch off, or `sieve-engine.exe restore`.

`status.json` (admin-only, `C:\ProgramData\Sieve\engine\`) gains `content`: `rewritten`, `with_scriptlets`, `with_procedural`, `resets`, and `list_hits` by list id. No host is ever in it (plan 7.1), so to read one page, read the numbers, load that page alone, read them again.

## Steps

```
powershell -ExecutionPolicy Bypass -File scripts\live\engine-content.ps1 -Step before
powershell -ExecutionPolicy Bypass -File scripts\live\engine-content.ps1 -Step on
powershell -ExecutionPolicy Bypass -File scripts\live\engine-content.ps1 -Step arm
```

Then the checks. Afterwards `-Step off`.

## Checks

| # | Do | Pass when |
|---|---|---|
| U1 | `-Step arm`, load `https://example.com/` in Edge, Chrome and Firefox. `-Step arm` again. View the page source. | The heading is hidden (the script's rule `example.com##h1`). The source starts with `<style nonce=`. `content.rewritten` grew by one per load. |
| U2 | Real pages with a strict header CSP, a meta CSP and Trusted Types. Open the console on each. | The browser accepts the rewritten policy and our elements run and apply. No CSP violation is reported against the site's own scripts. |
| U3 | A real scriptlet on a page with Trusted Types, and a uBO `world: 'ISOLATED'` entry in the main world. Needs the bundle. | Which work is recorded in the plan (5.6 item 6). |
| U4 | Budgets on 20 fixed sites: page load, generic stylesheet size, main-thread p50, time to first byte, throughput. | Time to first byte 1 ms or less; 100 MB/s; main-thread p50 over 5 ms triggers the token-filter step in 5.6. |
| U5 | Real lists on: read the Filters page's skip counts and the log. | Skip counts recorded, zero skipped exceptions in the default lists, and how many lines the `$document,elemhide` fix touches. |
| U6 | A site whose gzip has trailing bytes, in Firefox. A Chrome with a shared dictionary, on a page that offers `dcb` or `dcz`. | The page loads whole. After narrowing, it arrives injected. |
| U7 | Kill, reboot and uninstall tests of `docs/conventions.md` section 0, with content on. A page with a `max-age`, loaded while on, reloaded after off. | The network is normal in all three. Record how long the cached page keeps its injected elements (open question Q3). |
| U8 | A site served by a service worker. A plain `http://` page. | Neither is injected. Record how many sites lose what. |

## Reading a result

- `content.resets` growing: a page was cut. Read the log for the row and compare with the page's own encoding; a body past `InjectLimits` is a real cap breach, anything else is a bug.
- `rewritten` flat with the rule on: is the page decrypted at all (`https.intercepted`)? Is it HTML with a charset `inject` reads? A `$document` exception on the page empties it by design.
- A rewritten page keeps no `ETag` or `Last-Modified`, so revalidation becomes a full fetch once its freshness runs out. That is by design (`docs/tasks/2026-11-06-content-wire.md` D6).

## Not here

The video site's acceptance is slice 10: `docs/live/engine-slice-10.md`. Page rows in the log are slice 12. The two questions for you before this switch unlocks are Q2 (does the allowlist stop cosmetics) and Q3 (a cached page outliving off), in the task doc.
