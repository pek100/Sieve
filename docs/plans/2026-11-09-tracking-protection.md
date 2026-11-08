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
- For cookies, a top-level navigation (`Sec-Fetch-Dest: document`) is
  first-party whatever `Sec-Fetch-Site` says (`tracking::cookie_party`): a sign-in
  callback, a magic link and a search click arrive cross-site, and what their
  responses set is the opened site's own cookie (second review P1-1). Frames
  (`iframe`) and subresources keep the raw header. The referrer options keep the
  raw header too: a cross-site navigation's referrer is another site's page.
- An exception holds for the built-in protections as it does for the lists: a
  request an `@@` rule allows keeps its parameters; an `@@…$removeparam[=name]`
  line, the user's or a list's, keeps the names it names from the built-in list
  (adblock-rust refuses these lines, so they stay counted as skipped and the
  lists' own `$removeparam` still ignores them; `sieve_filter::rules::KeptParams`
  reads them for the built-in list only); a page with a `$document` exception
  gets no page script, as AdGuard's `$document` turns its stealth mode off.
  `$elemhide` does not stop it: AdGuard's `$elemhide` is about hiding elements
  only (stealth mode has its own `$stealth`, not supported yet).

## The options

| Name (`Policy.tracking`) | What the engine does | Minimal | Balanced | Strict |
|---|---|---|---|---|
| `gpc` | Adds `Sec-GPC: 1` and `DNT: 1` to every request that lacks them; in a page rewritten anyway (content on, something else injected), `navigator.globalPrivacyControl` reads true and `navigator.doNotTrack` "1" | on | on | on |
| `clientData` | Removes `X-Client-Data` from every request | on | on | on |
| `queryParams` (new) | Removes the built-in tracking parameters (`engine/crates/sieve-filter/data/tracking-params.txt`: `utm_*`, `fbclid`, `gclid`, `msclkid`, `yclid`, `mc_cid` and the rest; never a recipient id or a token, such as `mkt_tok`, `_hsenc`, `_hsmi`, `vero_id`, `oly_enc_id`, `oly_anon_id`, `mc_eid`, which sign a reader in, unsubscribe them or fill a form, and are left to the lists' `$removeparam`) from pages and frames, and from the `Location` of a site's own redirect answering one. A GET or HEAD page gets a 307 to the clean URL, as `$removeparam` does, so page script cannot read them; the lists' `$removeparam` rules act as before, whatever this says | off | on | on |
| `searchQueries` | Cuts a cross-site `Referer` to its origin, so the site opened from a search does not get the search | off | on | on |
| `referrer` | Removes `Referer` from cross-site requests | off | off | on |
| `thirdPartyCookies` | Caps each `Set-Cookie` of a cross-site response that is not a top-level navigation at one hour (`Max-Age=3600`; a deletion stays a deletion; a session cookie, with no lifetime, is left to the browser's session; a `Max-Age` that does not read falls back to `Expires`, RFC 6265 5.2.2) | off | off | on |
| `firstPartyCookies` (new) | The same for the site's own responses | off | off | off |
| `webRtc` | Page script: `RTCPeerConnection` and its prefixed forms are gone | off | off | off |
| `push` | Page script: `PushManager.subscribe` refuses, its permission reads denied | off | off | off |
| `location` | Page script: geolocation answers "permission denied", and `navigator.permissions.query({name: 'geolocation'})` reads denied | off | off | off |

## Redirects and loops

A 307 to the clean address cannot loop by itself, but a site can send the page
back to the parameter (second review P2-3). Two guards:

- The `Location` of a site's redirect answering a page loses the built-in
  parameters (the target's own exceptions hold; `rules::clean_location`), so a
  site that sends the reader on with a campaign tag does not meet a second 307.
- A redirect to the very address it answers is the site insisting on the
  parameter: its `Location` is left alone, and the connection remembers that the
  site sent that clean address back (`serve::Move`, 10 s, 16 per connection).
  When the browser then asks for the address with the parameter, it goes as
  asked, and the row reads Passed (`params_kept`) with no change. The memory is
  per connection: a browser that follows the redirect on a new connection meets
  one more 307 before the same thing happens there.

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
only a protection changed reads Modified and says the change in its column,
except the header signals (`gpc`, `clientData`): on at every level, they would
make every decrypted row Modified, so they are in the details sheet only
(second review P2-2). A request whose response a protection may change
(cookies, page script, a page's redirect with `queryParams`) is logged when its
head arrives, or when the request ends without one; every other row is logged
when the request is ruled, as before.

A signed URL (a subresource's, whose signature covers its query) is never
stripped: only pages and frames lose parameters. If a page's own address is
signed and a built-in parameter is part of what it signs, the site refuses it;
the log names the cause, `queryParams` on that page's row, and the fix is a
`$removeparam` exception for that name or the option off (second review P3-8).

`LogRow` and `LogChange` take fields they do not know (second review P3-11):
the log is evidence the app shows, no decision reads it, and its fields are
appended, so an app built from now on reads a newer engine's rows a field short
instead of losing the whole `log` message. Known fields stay required and
typed, and everything the app sends the engine still refuses unknown fields.
Apps built before this still refuse an unknown row field, so a new row field
still waits until those apps are gone or ships with its own default-off switch
as `changes` did.

## Compatibility

- `TRACKING_NAMES` appends `queryParams` and `firstPartyCookies`; `LogRow`
  appends `changes` with a default. Both are append-only (protocol 3).
- An older engine refuses a policy with a name it does not know. The app's third
  attempt (`policyParts`) sends the tracking the engine holds, so every switch
  still lands. No released build can send any name yet: none offers HTTPS.

## Tests

- Engine, pure: each option on real header shapes (`http::tracking`), the
  parameter list and its parser, cookie capping (Max-Age, Expires in both date
  forms, deletion, session cookies left alone, a Max-Age that does not read,
  junk), a top-level navigation's cookie party, the browser-API script, the
  `$removeparam` exceptions and `$document` for the page script.
- Engine, through `http::serve`: the redirect loop of a site that sends its
  parameter back, a site's redirect's `Location` cleaned, exceptions obeyed, a
  sign-in callback's cookies left alone, GPC in a rewritten page.
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
- With `gpc` on, a page that is not rewritten (content off, or nothing else to
  inject) reads the browser's own `navigator.globalPrivacyControl` and
  `doNotTrack` while its requests carry the signals: accepted. Rewriting every
  decrypted page for two values alone would change pages that have nothing else
  to change (second review P3-9).
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
