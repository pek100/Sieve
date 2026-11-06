# Live check: slice 8, QUIC per-flow refusal (`live_quic_refused_falls_back_to_tcp`)

Run by the user, from an admin prompt. Nothing here was run by the stream that built it: every item is UNVERIFIED until you run it. `filtering.https` stays hidden in the app, so the switch is driven the way slice 6 drives it: with the app closed, `scripts/live/engine-ca.ps1 -Step intercept` writes `https`, `sieving` and `engine` true into `policy.json`. Read that script before running it. Slice 6's live check (`docs/live/engine-slice-6.md`) passes first: without interception there is nothing to fall back to.

Traffic really goes through the engine during this check. Do it when nothing else on this PC depends on the network. Before you start, record `route print`, `Get-DnsClientServerAddress`, `netsh winhttp show proxy` and the firewall rule list. The way out at any point is the engine switch off, or `sieve-engine.exe restore`. This check never changes a firewall rule.

`status.json` (admin-only, `C:\ProgramData\Sieve\engine\`) gains `quic`: `refusal` (the arm this build is, `port_unreachable` or `silent_drop`), `refused`, `replies`, `send_failed`, `raced`, and `fallback_ms`, the newest 256 raw times in ms from a refused flow's first datagram to the first TCP flow of the same process and host. No host is ever in it (plan 7.1), so to read one site, read the numbers, load that site alone, wait for the 30 s rewrite, read them again. Keep the raw values and take the percentiles yourself.

## The two arms

The arm is one word: `REFUSAL` in `engine/crates/sieve-engine/src/quic/mod.rs`. For the drop arm set it to `Refusal::SilentDrop`, rebuild, and reinstall by the slice 6 route. `the_declared_constant_is_the_port_unreachable_arm` is expected to fail on that build: it pins the word so a flip for a measurement cannot land unnoticed. Change it in the same commit only if the numbers decide for the drop.

## Checks

| # | Do | Pass when |
|---|---|---|
| U1 | With the ICMP arm, load one site with a fresh Chrome profile. In a capture on the Sieve adapter, or by reading U2's numbers, see whether the answer reached the app's socket. The packet quotes a rebuilt header (its IP id and TTL cannot match the original), and it arrives through the firewall on whatever network profile the adapter has. Read only. | `status.json.quic.replies` grew and Chrome moved to TCP sooner than the drop arm. The most likely surprise: if the packet does not arrive, the flow behaves as a drop and U2 shows it. |
| U2 | `fallback_ms` in the ICMP arm and in the drop arm, in Chrome, Edge and Firefox, a fresh profile each, the same few sites. | Against the budget of plan section 6: the first TCP SYN within 100 ms. Plan section 3's rule decides: if ICMP is not faster, the drop stands and the numbers go in the plan. Raw values kept. |
| U3 | YouTube and Google Search in the three browsers. | Each loads over TCP through Sieve: `chrome://net-internals` or the log shows h2 and Sieve's issuer. |
| U4 | An app set to Off, an excluded host, and a non-browser. | Each keeps QUIC: `status.json.quic.replies` delta 0 and the browser shows HTTP/3 for the site. |
| U5 | One refused and one excluded host open at once, in each browser. On Windows `WSAECONNRESET` belongs to the socket, not the destination, so a client that shares a UDP socket could lose the excluded connection. | The excluded host's page keeps working. If it is harmed, the drop arm stands whatever U2 says (open question Q3 of `docs/tasks/2026-11-06-quic.md`). |
| U6 | Kill, reboot and uninstall tests of `docs/conventions.md` section 0, with `filtering.https` on. | After a kill, QUIC works as normal again within 5 s and every listing matches the before-listing. |
| U7 | While reading U2, compare `fallback_ms` with the owner lookup: `attribution-diagnostics` build, `elapsed_ms`. The clock starts at the first datagram read, so the lookup before the decision is in the number. | Reported, not fixed here: what share of the number is attribution, and whether the budget needs a change there. |
| U8 | A 100 Mbit/s download while a browser opens refused flows. | `send_failed` stays 0, and `packets_out` and throughput hold section 6's budgets. `TunSink` writes beside the stack on the same session. |
| U9 | `refused` per page load in each browser, and whether a browser stops trying after its own "broken alternative" mark. | Reported. It feeds open question Q1 of the task (`Alt-Svc`). |

## Reading a result

- The log shows a refused flow as "Not decrypted (quic refused)". It is not a block: the `blocked` figure does not move, and the flow's event closes with 0 bytes.
- A host with a cached rejection is relayed, as TCP passes it through. A first visit to a host whose verdict is not known yet is refused, and TCP then learns the verdict.
- A browser on its own DoH keeps QUIC for a name the engine did not resolve (`floor:ech`). A non-browser's QUIC is relayed (`floor:app-scope`). Both are by design under browsers first.
- `raced` counts TCP flows accepted before the QUIC Initial: a browser that raced the two. They are not samples. A limit of the number: a racing TCP flow decided before the QUIC flow was refused leaves nothing to count, so the next TCP flow of that pair inside 10 s is taken as the sample and reads long. Fresh profiles and one site at a time keep this rare; treat a long tail with that in mind.
- `send_failed` means the ring was full or the session was closing. The flow then behaves as a drop.

## Not here

QUIC termination, Retry and connection close are not built (plan section 3). `Alt-Svc` and HTTPS records are left alone (task Q1).
