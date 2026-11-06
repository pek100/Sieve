# Live check: encrypted DNS upstreams (slice 4, plan 1.4)

Run by the user, on a machine where the engine is installed and `filtering.engine` is on. Nothing here was run by the implementing stream: every automated test binds loopback only. Commands are for an admin PowerShell prompt. The engine folder below is `C:\ProgramData\Sieve\engine`.

`dns-status.json` beside `status.json` holds the facts these checks read, rewritten every 30 s while routes are up: per upstream its `address`, `connected`, `kx_group`, `alpn`, `answers`, `failures`, and never a queried name. `kx_group` is `null` for DoQ because quinn does not expose it.

To set a list, stop the engine, write `dns.json` beside `policy.json`, and start it (the app's setting comes with the settings stream). A raised `revision` matters only for later writes through the pipe. A bad file reads as the defaults and `last_error` in `status.json` says why. Save it as UTF-8, up to 32 KB: `Set-Content -Encoding utf8` is fine (its BOM is accepted), while `>` in Windows PowerShell writes UTF-16, which is refused by name. Setting a good list through the pipe replaces a bad file and ends its reason in `last_error`.

```json
{ "revision": 1, "upstreams": ["https://192.0.2.1/dns-query", "https://cloudflare-dns.com/dns-query"] }
```

## 1. No plain DNS leaves the machine

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

List `https://192.0.2.1/dns-query` first, as above (a documentation address that never answers). Run `Measure-Command { Resolve-DnsName example.com -DnsOnly -Type A }` with a name not in the cache. First confirm the list applied: `last_error` does not mention `dns.json`, and `dns-status.json` lists `192.0.2.1`. Otherwise the defaults are answering and this check proves nothing. Pass: an answer, in under 2 s. Later lookups skip the dead upstream for 30 s at a time and take no extra second.

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

## Known consequence: no encrypted resolver reachable

Hotel, airport and other captive-portal networks usually need plain DNS to reach their sign-in page, and some networks block 443 and 853 to public resolvers. The rule is never plain, so DNS answers SERVFAIL for as long as the engine is on. The way out is turning filtering off, which restores normal DNS at once.
