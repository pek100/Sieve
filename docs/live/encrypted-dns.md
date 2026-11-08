# Live check: encrypted DNS upstreams (slice 4, plan 1.4)

Run by the user, on a machine where the engine is installed and `filtering.engine` is on. Nothing here was run by the implementing stream: every automated test binds loopback only. Commands are for an admin PowerShell prompt. The engine folder below is `C:\ProgramData\Sieve\engine`.

`dns-status.json` beside `status.json` holds the facts these checks read, rewritten every 30 s while routes are up: `mode` (`encrypted`, or `plain` when the user turned Encrypt DNS lookups off), and per upstream its `address`, `connected`, `kx_group`, `alpn`, `answers`, `failures`, and never a queried name. `status.json` says the same mode as `dns_mode`.

**Encryption is the user's switch.** Settings > Filtering > Encrypt DNS lookups is on by default. Off, a lookup that would go encrypted goes in plain text to the server the client addressed, which is the server Windows uses for that adapter without Sieve; the split-horizon, private reverse, canary and update rules stay as they are. Nothing else turns plain on: not an empty or bad list, not a failure. Checks 1 to 11 assume it is on. `kx_group` is `null` for DoQ because quinn does not expose it. Its `answers` counts belong to `docs/live/dns-extras.md`.

**The setting owns the list.** While the app runs, `filtering.upstreams` wins over `dns.json`: at the first probe, and at every probe after, the app reads the engine's list back and overwrites it, and so `dns.json`, if it differs. The setting is never empty, so an untouched app does this too: the default has servers, an import refuses an empty list, and an empty list stored by hand reads as the default. A list written by hand lasts only while the app is closed.

To set a list, use one of these two ways.

- **Through the setting, with the app open.** Edit the Upstream DNS servers row in Settings: add, remove, and move up and down. The row reads back what the engine holds.
- **By hand, with the app quit.** Quit Sieve, and keep it closed for the whole check, because opening it puts the setting's list back. Stop the engine, write `dns.json` beside `policy.json`, and start it. A raised `revision` matters only for later writes through the pipe.

A bad file reads as the defaults and `last_error` in `status.json` says why. Save it as UTF-8, up to 32 KB: `Set-Content -Encoding utf8` is fine (its BOM is accepted), while `>` in Windows PowerShell writes UTF-16, which is refused by name. Setting a good list through the pipe, which the app also does, replaces a bad file and ends its reason in `last_error`.

```json
{ "revision": 1, "upstreams": ["https://192.0.2.1/dns-query", "https://cloudflare-dns.com/dns-query"] }
```

In the settings file the same list is the value of `filtering.upstreams`, with no `revision`.

## 1. No plain DNS leaves the machine without the user's choice

With Encrypt DNS lookups on (the default, `mode` `encrypted`):

```powershell
pktmon filter remove
pktmon filter add dns -d IPv4 -t UDP -p 53
pktmon filter add dnstcp -d IPv4 -t TCP -p 53
pktmon start --capture --pkt-size 0 --file-name C:\Users\Public\sieve-dns.etl
# 10 minutes of normal use
pktmon stop
pktmon etl2txt C:\Users\Public\sieve-dns.etl --out C:\Users\Public\sieve-dns.txt
```

Pass: every port 53 packet is to or from a LAN address, or on the Sieve interface. Resolver traffic shows only on 443, 853 and UDP 853.

## 2. Failover on the real path

List `https://192.0.2.1/dns-query` first, as above (a documentation address that never answers). Run `Measure-Command { Resolve-DnsName example.com -DnsOnly -Type A }` with a name not in the cache. First confirm the list applied: `last_error` does not mention `dns.json`, and `dns-status.json` lists `192.0.2.1`. Otherwise the defaults are answering, or the app overwrote a hand-written list, and this check proves nothing. Pass: an answer, in under 2 s. Later lookups skip the dead upstream for 30 s at a time and take no extra second.

## 3. Post-quantum key exchange with the real resolver

Read `dns-status.json`. Pass: `kx_group` is `X25519MLKEM768` for `cloudflare-dns.com`. Put Quad9 first and read it again; whether Quad9 offers the group was not known when this was written, so `X25519` there is a fact to record, not a failure.

## 4. The bootstrap addresses

Cloudflare and Quad9 must serve those names with valid certificates on the listed addresses (`upstream::DEFAULTS`), IPv4 and IPv6. They come from knowledge, not from a check. Pass: `connected` true for each default, each listed first in turn. For IPv6, repeat on a network with an IPv6 default route.

## 5. Real DoT and DoQ

Try `tls://1.1.1.1`, `tls://dns.quad9.net`, and `quic://` against a resolver you choose (which public resolvers offer DoQ today was not checked). Pass: `connected`, `alpn` `dot` where the server negotiates it (it may be null) and `doq`. Then a named custom upstream, which is looked up over the defaults: pass is `answers` rising, with no port 53 traffic as in check 1.

## 6. The pinned sockets

`own_refused` in `status.json` stays flat over a page load, and a name under the Wi-Fi's own suffix (for example `router.lan`) resolves, over the host route.

## 7. The suffix reader

`Get-DnsClient | Select InterfaceAlias, ConnectionSpecificSuffix, ConnectionSpecificSuffixSearchList` against what the engine resolves locally. A suffix's names go only to a private server in a range excluded from routing; if that server is down they get SERVFAIL, never the public upstream. Corporate-zone coverage stays UNVERIFIED (plan 1.4).

## 8. Windows DNS Client behaviour

SERVFAIL when nothing answers, TC with a retry over TCP (`Resolve-DnsName` of a large TXT record), and a page load straight after a Wi-Fi to Ethernet switch (route changes drop every session).

## 9. Fail open

`docs/live/engine-slice-3.md`'s kill, stop and uninstall flow. Pass: adapter DNS settings are what they were (`Get-DnsClientServerAddress` before and after) and DNS works at once.

## 10. CPU and idle

Idle CPU stays under its gate with sessions open; the slice 3 relay gate is unaffected.

## 11. Release build on another machine

`pnpm engine:build` needs a C toolchain and probably CMake for aws-lc-sys. It built here with CMake present and NASM absent; which path aws-lc-sys took was not determined. Record it here; plan 2.7 asks slice 6's build notes to say which.

## 12. Plain mode, the user's choice

Turn Encrypt DNS lookups off in Settings. Pass: within a probe `dns-status.json` says `mode` `plain`, and check 1's capture shows port 53 traffic only to the servers `Get-DnsClientServerAddress` lists for the adapter (or to a server an app addressed itself), and none on 443, 853 or UDP 853 to the resolver list. A name under the Wi-Fi's own suffix still goes only to its LAN server (check 6). Turn it on again: `mode` is `encrypted` and check 1 passes again with no restart.

## 13. No encrypted resolver reachable

Hotel, airport and other captive-portal networks usually need plain DNS to reach their sign-in page, and some networks block 443 and 853 to public resolvers. With encryption on, DNS answers SERVFAIL for as long as that lasts: failed resolvers mean failed lookups, never plain. Simulate it with an outbound firewall rule blocking TCP 443 and 853 and UDP 853 to the listed resolvers' addresses (remove it after). Pass: after three failed lookups the Home banner names Encrypt DNS lookups, `dns-status.json` still says `encrypted` and the switch is still on; port 53 shows nothing beyond the LAN; removing the rule ends the banner at the next answer. The ways out are the user's: turning Encrypt DNS lookups off (check 12), or turning filtering off, which restores normal DNS at once.
