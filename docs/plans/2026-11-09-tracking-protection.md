# Tracking protection in the engine (parity rows 26 to 30)

The app has had the `tracking.*` options since 2026-11-08 (registry
`trackingOption`, `src/core/tracking.ts`, `TrackingBlock`), each unavailable
until the engine carries it out. This plan is that work: the engine carries out
every option, logs every change it makes, and the options' own gate goes away.
What still gates them is the switch each needs (below).

## Where it acts, and where it never does

- Only on decrypted requests, in `http::serve`, with the global switch on. A
  flow that is not decrypted (the floor: sensitive sites, pinned apps, apps that
  are not browsers, an app turned off, every exclusion) never reaches that path,
  so nothing here can touch it. Decryption is browsers only today
  (`exclusions::SCOPE`); a test fails the day that changes, because then this
  path would also see apps that are not browsers and must ask first.
- Plain HTTP is not done in this slice. A plain flow is copied byte for byte
  after its host decision (`tls::intercept::run`, the splice for a flow that is
  not TLS); no URL rule acts on it either. Serving it through hyper is its own
  change in `tls/intercept.rs`, which another agent is editing now, and it would
  feed self-healing's evidence with flows it was never built for. Left for a
  later slice, with the URL rules.
- Third-party is the browser's own `Sec-Fetch-Site: cross-site`. A request
  without that header (no current browser sends HTTPS without it) is treated as
  first-party: the safe direction, nothing is changed. TENSION: the header is
  relative to the frame that asked, not the top page, so a third-party frame's
  requests to itself read as same-origin; parity with how a proxy can see it.

## The options

| Name (`Policy.tracking`) | What the engine does | Minimal | Balanced | Strict |
|---|---|---|---|---|
| `gpc` | Adds `Sec-GPC: 1` and `DNT: 1` to every request that lacks them | on | on | on |
| `clientData` | Removes `X-Client-Data` from every request | on | on | on |
| `queryParams` (new) | Removes the built-in tracking parameters (`engine/crates/sieve-engine/data/tracking-params.txt`: `utm_*`, `fbclid`, `gclid`, `msclkid`, `yclid`, `mc_eid` and the rest) from pages and frames. A GET or HEAD page gets a 307 to the clean URL, as `$removeparam` does, so page script cannot read them; the lists' `$removeparam` rules act as before, whatever this says | off | on | on |
| `searchQueries` | Cuts a cross-site `Referer` to its origin, so the site opened from a search does not get the search | off | on | on |
| `referrer` | Removes `Referer` from cross-site requests | off | off | on |
| `thirdPartyCookies` | Caps each `Set-Cookie` of a cross-site response at one hour (`Max-Age=3600`; a deletion stays a deletion, an `Expires` that cannot be read is left alone) | off | off | on |
| `firstPartyCookies` (new) | The same for the site's own responses | off | off | off |
| `webRtc` | Page script: `RTCPeerConnection` and its prefixed forms are gone | off | off | off |
| `push` | Page script: `PushManager.subscribe` refuses, its permission reads denied | off | off | off |
| `location` | Page script: geolocation answers "permission denied" | off | off | off |

Why these defaults:

- Minimal is what cannot break a site: two signals and a header no site needs.
- Balanced, the recommended level, adds what changes no site's behaviour:
  tracking parameters carry nothing a page needs, and an origin-only cross-site
  referrer is what browsers send by default (`strict-origin-when-cross-origin`),
  so only a page that asked for more loses it.
- Strict adds the two that break things: no referrer breaks hotlink checks,
  some downloads, payments and sign-ins; an hour's cookie signs embedded comments,
  players and sign-in buttons out. Each says so beside its switch.
- No level turns on first-party cookies (signs you out of every site every hour),
  WebRTC (calls), push (notifications you chose) or location (maps). Parity with
  the stealth modes these come from, where the same ones are off at every level.

## Gates

- Request and response options require `filtering.https`. The browser-API
  options are page script, which only the content hook writes, so they require
  `filtering.content`.
- Availability now follows the required switch (registry `isAvailable`): an
  option is offered once the switch it needs is. Law 11 says no available
  setting may require an unavailable one, so while `filtering.https` waits for
  slice 6's live check the options stay hidden, by derivation rather than by
  their own `unavailableUntil`, and they appear with that switch, with nothing
  left to remove by hand.
- The engine already drops every tracking name with `https` off (`policy::accept`).

## The log

Each change is on the request's row (slice 12 details), as `LogRow.changes`:
`[{what, count}]`, `what` one of the names above, left out while empty, so an
older app never sees the field unless a newer one asked for tracking. A row that
only a protection changed reads Modified. A request whose response a protection
may change (cookies, page script) is logged when its head arrives, or when the
request ends without one; every other row is logged when the request is ruled,
as before.

## Compatibility

- `TRACKING_NAMES` appends `queryParams` and `firstPartyCookies`; `LogRow`
  appends `changes` with a default. Both are append-only (protocol 3).
- An older engine refuses a policy with a name it does not know. The app's third
  attempt (`policyParts`) sends the tracking the engine holds, so every switch
  still lands. No released build can send any name yet: none offers HTTPS.

## Tests

- Engine, pure: each option on real header shapes (`http::tracking`), the
  parameter list and its parser, cookie capping (Max-Age, Expires in both date
  forms, deletion, session cookies, junk), the browser-API script.
- Engine, through `http::serve` over TLS (h1 and h2): headers as the origin
  receives them, the 307 for a page, cookies as the client receives them, the
  log row's changes, and nothing changed with the switch off or the request
  first-party.
- App: the levels and defaults, availability following the switch, the policy
  sends only options in force, the log's words for each change.

## Left for later

- Plain HTTP (above).
- A per-site exception to tracking protection (the lists' `$stealth`): today a
  site a protection breaks is fixed by turning that protection off, which its
  log row names.
- A minutes setting for the cookie lifetime; the hour is fixed.
- `document.referrer` for a navigation is the browser's own; removing the header
  does not change it, which a page script would (it needs `filtering.content`).
- Cookies a browser already holds are capped only when a site sets them again.
- The `live-scope` test build (never released) can decrypt apps that are not
  browsers; tracking protection would act on them there too.

## Live checks for the test VM

With HTTPS decryption on, in Edge and Firefox, against a page the VM serves:
the request headers a test origin echoes (GPC, DNT, no X-Client-Data, the
referrer cut and removed cross-site), a link with `utm_source` and `fbclid`
landing clean with one 307, a third-party `Set-Cookie` arriving capped, each
change in the log's details, and with each option off the same requests arriving
unchanged. With content filtering on: `RTCPeerConnection`, `PushManager` and
geolocation in a decrypted page as the options say, and in a page that is not
decrypted (a floor site) unchanged.
