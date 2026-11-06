# Engine stall under filtered browser traffic

Use PowerShell for shell commands. CPU-only work; run only the tests your change touches, plus the engine suite once at the end. Do not run services, routes, elevation or any live traffic. List live proofs under UNVERIFIED.

## Evidence (GCP test VM, 2026-11-06, main at 270a10b)

Sieving on, default lists, about 3 minutes into normal curl and headless Edge traffic, the network died and stayed dead for 12 minutes until the test killed the engine:

- Counters froze at flows 604, blocked 90, dns_answers 279, packets_in 73293, packets_out 114110. `not_unicast` still moved slightly (40 to 43), which suggests the TUN reader was alive. That is a hint, not a finding.
- Routes stayed up. `status.json` kept being rewritten. The watchdog did not trip. curl to any host timed out; after the kill, everything worked at once.
- Runs with sieving off did not stall in 15-minute soaks, and 8-minute page tests with sieving on did not stall either. The stalled run used the build with `answer_blocked` (Version Negotiation) and the TCP `abort`, so those are suspects, not settled causes.

No dump exists: the reproduction was interrupted. Do not assume a cause.

## Do

1. Read the path end to end: `tun/`, `stack/mod.rs`, `stack/relay.rs`, `stack/dns_flow.rs`, `quic/`, `dns/service.rs`, `watchdog.rs`, `control/routing.rs`, and `engine/vendor/ipstack` (its channels, session table, `abort`). Find every await or lock that can block the path from TUN read to stack and back: bounded channels, a mutex held across an await, a full `up_packet_sender`, per-flow tasks that never end, DNS upstream waits that hold shared state. Rank candidates by how well each fits the evidence, and say what would disprove each.
2. Fix any cause you can prove with a test that reproduces the stall offline. A guess gets a note, not a change.
3. Make the watchdog end to end, whatever the cause: if packets keep arriving at the adapter but the stack stops making progress for a bounded time, the engine deletes its routes and exits, as the existing trip does, giving the network back. Choose the signal from what the code already counts; it must not trip on an idle machine or a quiet link. Fake-clock tests: trips on a stall with packets offered, stays quiet when idle, stays quiet under slow but moving traffic. Declare the bound and why.
4. Add a status field or log line that says which stage stopped, so the next live run names it.
5. Add to `docs/live/engine-slice-3.md` how to reproduce: sieving on, browser traffic, 15 minutes, and what to capture.

Commit message trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Write the commit message in `CODEX-COMMIT.txt`.

## Report

Candidates ranked with file and line, what was fixed, tests and counts, UNVERIFIED list.
