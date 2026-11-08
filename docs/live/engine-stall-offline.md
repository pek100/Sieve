# Filtered-traffic stall: offline investigation

The supplied VM incident has no dump. Its cause remains unverified. This change fixes observed device-read termination defects and the watchdog's packet-path blind spot, without changing QUIC negotiation, TCP abort, DNS policy or successful packet bytes.

## Ranked candidates and falsifiers

Paths below are relative to the repository. Line anchors refer to this change's source; the source commands below locate them again.

| Rank | Candidate and source | Fit to the supplied incident, not a live finding | What would disprove it |
| --- | --- | --- | --- |
| Highest | Packet worker exits on a device-write error: `engine/vendor/ipstack/src/lib.rs:360`, `engine/crates/sieve-engine/src/tun/device.rs:176`, `engine/crates/sieve-engine/src/control/routing.rs:439` | The write error propagates out of the sole packet loop. Accept ends, but the routing owner remains up. Its status writer and ping task can continue. The reader can subsequently end when its queue disconnects. Offline injection reproduces that blind spot. A little rejected traffic during the transition is possible, but sustained rejected-traffic growth after worker exit would contradict this explanation. | A dump showing the packet worker alive and completing writes after the freeze, or continued adapter reader activity after its receiver was dropped. Capture the actual write error, not just a timeout. |
| Next | Reader termination is mishandled: `engine/vendor/ipstack/src/lib.rs:335`, `engine/crates/sieve-engine/src/tun/device.rs:150` | Before this fix, EOF was processed as empty packets indefinitely; a read error disabled the input branch while other branches waited. Offline tests reproduce both. Frozen arrival counts fit a stopped reader; this does not establish why a real Wintun read would end, or why filtering would trigger it. | The same reader remains alive, admitted packets reach the worker, and the device returns neither EOF nor errors. |
| Next | Packet loop stuck in dispatch or output while the bounded TUN queue is not full: `engine/vendor/ipstack/src/lib.rs:335`, `engine/vendor/ipstack/src/lib.rs:461`, `engine/crates/sieve-engine/src/tun/device.rs:86` | Reader enqueue and scheduler pings can both succeed without stack progress. The pending-write probe demonstrates it in memory. Production `TunDevice::poll_write` returns synchronously, so an async pending write alone is not proof of the Windows failure; a stuck native call or blocked dispatch would require stacks. A persistently full input queue should already trip the old reader beat. | `received`, `dispatched` and `writes_finished` continue moving with the offered input; or a dump shows the stack parked normally waiting for input with no backlog. |
| Lower | Shared flow mutex, per-flow TCP lock or blocking destructor: `engine/crates/sieve-engine/src/stack/relay.rs:164`, `:221`, `:260`; `engine/vendor/ipstack/src/stream/tcp.rs:285`, `:371`, `:455` | Attribution and booking serialize flows. TCP abort takes the per-flow TCB and sends synchronously; Drop blocks waiting for the session task. Either could explain flow-level hangs or runtime exhaustion, but no lock cycle was reproduced. A total executor stall should also suppress the existing ping, contrary to the supplied observation. | All lock owners finish, no lock cycle or destructor wait exists, and stalled flows are instead waiting on remote I/O. Correlate with worker stacks, not just CPU. |
| Lower | Accumulating sessions/tasks or unbounded packet queues: `engine/vendor/ipstack/src/lib.rs:324`, `engine/vendor/ipstack/src/stream/tcp.rs:489`, `engine/crates/sieve-engine/src/stack/relay.rs:348`, `engine/crates/sieve-engine/src/flow/tasks.rs:41` | A blocked UDP task stays until idle; ongoing retransmits can keep it alive. TCP session timers and detached UDP attribution also deserve lifetime evidence. Resource pressure could become global, but the supplied counters do not measure it. | Stable private bytes, task/session/queue counts and prompt session removal while the failure occurs. |
| Lowest | DNS upstream serialization/exhaustion: `engine/crates/sieve-engine/src/dns/service.rs:189`, `:251`; `engine/crates/sieve-engine/src/dns/pool.rs:237`; `engine/crates/sieve-engine/src/dns/dot.rs:111` | Permits, connect completion, TLS writes and upstream replies can delay DNS. The service snapshots shared state before awaiting; upstream exchanges have a common deadline. This fits DNS-only failure better than all packet counters freezing. No shared lock held over an upstream await was found in this path. | Direct-IP established traffic also stops at the stack boundary, or DNS deadlines continue producing answers/failures while the adapter path freezes. |

A full `up_packet_sender` blocking a send is ruled out for the inspected source: `PacketSender` is `UnboundedSender`, including UDP replies and TCP resets. It can consume memory, and output can fail later at the adapter. This distinction is not evidence that Version Negotiation or abort caused the incident. `git diff 270a10b..HEAD -- engine/vendor/ipstack/src/lib.rs engine/vendor/ipstack/src/stream/tcp.rs` showed no packet-loop/channel change between the incident revision and this worktree's base; it showed the additional acknowledged-sequence TCP reset in `abort`.

## Blocking-path inventory

- **TUN** (`tun/mod.rs`, `tun/device.rs`, `tun/batch.rs`): `receive_blocking` is an intentional idle wait. The production `blocking_send` is bounded and inside `beats.tun`; the experimental reader also waits on the slab pool's synchronous `recv` and its bounded batch channel inside that beat. `poll_recv` waits for input. Diagnostic fingerprinting takes its report mutex. Wintun allocate/send are synchronous native calls, with no async timeout. Allocation errors become device-write errors. The normal reader thread is detached; the experimental reader joins on drop after releasing its waits.
- **Stack packet loop** (`vendor/ipstack/src/lib.rs`): one select owns the session table, so it has no table mutex. It awaits device read, session-removal receive and output receive; after selecting input it awaits `process_device_read` (which contains no inner await), and after selecting output it awaits `write_all`, preventing all other branches from progressing. Packet delivery to existing sessions, new stream acceptance and session removal notifications are unbounded synchronous sends. A spawned waiter awaits each stream's destruction oneshot before removing its tuple. Tuple removal and stale sender errors need session-lifetime evidence, not a larger channel.
- **TCP** (`vendor/ipstack/src/stream/tcp.rs`, `tcb.rs`): stream packet and payload channels are unbounded. TCB, shutdown, read-waker and write-waker mutexes are synchronous. TCB processing and waker notifications occur under the TCB guard, but the inspected guarded regions contain no await. `poll_write` can remain pending on the client's window/inflight bytes; `poll_shutdown` can remain pending on FIN completion. `poll_read` drives its timeout. Session tasks await packet or exit receives. Close timers sleep and send on a bounded exit channel after releasing the TCB guard. Drop uses `block_in_place` plus `block_on` for the exit send and session-task join. `abort` does not await a bounded packet send; it closes the TCB and wakes the stream. Timers are spawned separately, so a dump must distinguish sleeping cleanup from a leaked active task.
- **UDP and unknown transports** (`vendor/ipstack/src/stream/udp.rs`, `unknown.rs`, `mod.rs`): receive polls an unbounded queue and idle timer. Writes enqueue synchronously to the common unbounded output channel. UDP Drop sends its destruction oneshot. Unknown transport responses also enqueue synchronously; routing drops unknown streams. There is no output-channel capacity wait here.
- **Relay and booking** (`stack/mod.rs`, `stack/relay.rs`, `stack/egress.rs`, `flow/relay.rs`, `flow/tasks.rs`): attribution's mutex covers the owner lookup, then is released before retry sleep/NAT await. NAT freshness is timeout-bounded on a separate worker. Executable-cache lookup and flow-book operations are synchronous under their own mutexes. Filter/name snapshots and route-table reads end before upstream awaits. TCP joins attribution with a bounded connect, then awaits classification/copy/interception; a healthy idle stream is allowed to persist. Its close helper bounds shutdown. UDP starts a separate attribution task, awaits classified datagrams with idle bounds, joins attribution, then awaits socket connect/send/receive or the refusal loop. Sends inside a selected UDP branch have no outer deadline. Dropping its attribution JoinHandle on an early return detaches that task. FlowTasks reaps completed tasks when spawning, and shutdown aborts and awaits the remaining tasks with a bound. A blocking destructor can still outlive an async timeout.
- **QUIC** (`quic/mod.rs`, `negotiate.rs`, `icmp.rs`, `fallback.rs`): blocked-flow answer writes await the UDP stream's synchronous enqueue; subsequent reads have an idle timeout. Refusal writes ICMP directly through the synchronous TUN sink, bypassing ipstack's output queue. Refusal bookkeeping and fallback samples use short book/fallback mutexes, with no await inside them. Parsing and reply construction have no locks or awaits. An active retransmitting blocked/refused flow need not end, by design.
- **DNS flows and upstreams** (`stack/dns_flow.rs`, `dns/service.rs`, `pool.rs`, `upstream.rs`, `dot.rs`, `doh.rs`, `doq.rs`): attribution precedes serving; book locks bracket synchronous updates. TCP queries await a shared semaphore, UDP uses try-acquire. Query tasks hold the permit over their exchange, not a global mutex, and release it when they finish or are cancelled. Active-service/table/name/health/pool-state locks are released before network awaits. Pool connection sharing awaits a watch receiver after releasing the slot lock. Per-address handshakes and total lookup attempts have deadlines. DoT registers under its pending-map mutex, then awaits bounded write-queue send and reply oneshot without that guard. Its background reader/writer await TLS I/O and close pending waiters on failure. DoH awaits readiness, response and bounded body collection; DoQ awaits stream creation, write and reply. Client reply writes are bounded by DNS_IDLE; the service select does not poll other branches during that write or a TCP permit wait. A starved permit could stall that DNS flow, but no cross-protocol lock cycle was demonstrated.
- **Watchdog/routing** (`watchdog.rs`, `control/routing.rs`, `service/runner.rs`): the watchdog runs outside tokio, waits on a condition variable while disarmed, then samples with its existing sleep. Arm locking is short and the condvar releases the mutex while waiting. Routing awaits coexistence evaluation, validation, acceptance, task teardown and attribution shutdown. The route-table write guard is released before later awaits. The accept task does not itself remove routes on stack failure. Normal teardown disarms before awaiting accept; the existing service stop deadline is separate. Emergency trip calls route cleanup first, then bounded ETW cleanup, records the named stage and exits. Actual OS cleanup and its duration were not exercised.

## Signal and bound

The offered signal is derived from existing `packets_in - not_unicast`, with an additional count for the existing oversized-drop branches. It is compared against the current ipstack worker's consumed packets using a baseline captured before starting the TUN reader. Dispatch completion and output-write start/completion are measured inside the packet loop; worker exit is recorded by a drop guard even on cancellation or unwind. Every hot-path update is an atomic counter, with no new per-packet allocation or mutex.

Each local stage must complete some work within the existing `STALL_MS`. Pending backlog, not a minimum arrival rate or the absence of responses, arms its timer. Completion resets that stage's timer; unrelated progress cannot clear it. With no pending input/output and a live worker, idle and silent-drop traffic do not arm it. A terminated packet worker is a failure even if traffic has since stopped. Routing teardown detaches the monitor; a new routing run gets fresh timers and a new counter baseline.

The following command was run:

```powershell
Select-String -Path engine/crates/sieve-engine/src/watchdog.rs,engine/crates/sieve-engine/src/tun/device.rs,engine/crates/sieve-engine/src/dns/upstream.rs,engine/crates/sieve-engine/src/dns/service.rs,engine/crates/sieve-engine/src/dns/dot.rs -Pattern 'pub const STALL_MS|pub const CHECK_EVERY_MS|const QUEUE|REQUEST_BUDGET:|MAX_IN_FLIGHT:|WRITE_QUEUE:'
```

Observed source constants: `STALL_MS = 5_000`, `CHECK_EVERY_MS = 1_000`, TUN `QUEUE = 4096`, DNS `REQUEST_BUDGET = Duration::from_secs(2)`, `MAX_IN_FLIGHT = 256`, DoT `WRITE_QUEUE = 64`. No new timing or queue threshold is introduced. The watchdog detects a pending stage after `STALL_MS` from its first sample; detection from onset additionally depends on sampling cadence and OS scheduling. This is a local-progress bound, not a promised wall-time bound on Windows route deletion.

## Offline evidence

All commands here ran in PowerShell in this worktree. No services, routes, elevation, GPU processes or live browser traffic were started.

Before changing ipstack's read-result handling:

```powershell
cargo test --offline --manifest-path engine/Cargo.toml -p sieve-engine --lib watchdog::path_tests::adapter_ -- --nocapture
```

Observed: `0 passed; 2 failed`. The read-error probe reported `received: 0, dispatched: 0, exited: false`; the EOF probe reported `received: 1280, dispatched: 1280, exited: false`. The latter is the observed empty-packet count from that execution, not a deterministic rate or threshold. Both asserted that a terminated adapter must end its packet worker. The fix explicitly handles the read result, propagates errors and treats EOF as terminal.

After the fix:

```powershell
cargo test --offline --manifest-path engine/Cargo.toml -p sieve-engine --lib watchdog:: -- --nocapture
```

Observed: `12 passed; 0 failed; 0 ignored`. Tests cover EOF/read failure, a real ipstack worker blocked in a fake device write, a write error that terminates it, old beats missing both failures, stage naming, fake-clock deadline edges, route-before-exit call order, quiet/idle input, multicast/oversized drops, slow progress and monitor replacement. The write tests use in-memory UDP packets, no sockets. Route deletion is a recording fake.

```powershell
cargo test --offline --manifest-path engine/Cargo.toml -p sieve-engine --lib control::tests::packet_path_status -- --nocapture
```

Observed: `1 passed; 0 failed`. The test writes and reads the real status-file serialization, checks the queue-stage name and count-only fields, and confirms the IPC status is unchanged.

```powershell
cargo test --offline --manifest-path engine/Cargo.toml -p sieve-engine --features relay-experiments --lib tun::batch:: -- --nocapture
```

Observed: `3 passed; 0 failed; 0 ignored`. The updated batch test verifies that oversized and non-unicast packets are excluded from the offered-work signal; packet ordering, slab recycling and the existing backpressure heartbeat tests also pass.

The engine workspace suite was run once at the end:

```powershell
cargo test --offline --manifest-path engine/Cargo.toml --workspace -- --quiet
```

Observed engine-library result: `1220 passed; 2 failed; 12 ignored`. The failures were unchanged tests outside this patch:

- `service::image::tests::real::a_real_temp_folder_is_refused`: `refused: C:\Users\Michael: could not read its ACL (WIN32_ERROR(5))`.
- `service::acl::tests::the_hooks_icacls_lines_give_the_install_lock`: `Os { code: 5, kind: PermissionDenied, message: "Access is denied." }` at the descriptor read after its temporary-folder ACL operations.

Cargo exited on the failing library target; subsequent workspace targets were not run. No full-suite pass is claimed, and the permission-sensitive tests were not changed or bypassed.

```powershell
$env:PATH = "C:\Program Files\cursor\resources\app\resources\helpers;" + $env:PATH; node scripts/gate.mjs
```

Observed: `MODULE_NOT_FOUND`, because this checkout has no `scripts/gate.mjs`. No TypeScript/Vite gate pass is claimed.

## Unverified

- Which, if any, candidate caused the supplied VM incident; no live dump was available.
- Wintun read/write error codes, native-call hangs, route deletion, service restart and restored DNS/HTTPS connectivity on the real machine.
- The requested browser soak, idle/quiet/slow-link behavior on Windows, timing under CPU pressure, and per-packet overhead in a live workload.
- A per-flow hang while the packet loop continues dispatching normally. Dispatch proves delivery to a session queue, not application-level success. Remote silence, blocked traffic and a stuck individual relay cannot be distinguished from these counters alone; dumps and flow/upstream counters remain necessary.
- Memory/task growth, lock contention, TCP abort or Version Negotiation as the initiating cause. Their packet behavior was deliberately not changed on suspicion.
- Remaining workspace targets after the suite stopped, and the permission-sensitive checks under an unrestricted user. The generic frontend gate could not run because its script is absent.
