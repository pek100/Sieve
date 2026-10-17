/**
 * Tauri source: asks Rust for a snapshot (`net_snapshot`, slice S1), which
 * reads the machine's TCP and UDP owner-pid tables. Every answer is checked:
 * a protocol version other than ours, or a malformed snapshot, throws a
 * ProtocolError that the UI shows as an error state. A Rust error is passed
 * through as is. It never pretends with empty or mock data.
 *
 * History (plan row 77) is persisted by Rust: after each good sample the
 * source sends its per-app counts (`history_record`; app identity is decided
 * here, by core's tickCounts, once) and reads buckets back with
 * `history_buckets`. A failed write does not fail the sample; the next
 * history read reports it until a write succeeds again.
 */
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import type { HistoryQuery } from "@/core/history";
import { tickCounts } from "@/core/series";
import { PROTOCOL_VERSION, ProtocolError, parseHistory, parseSnapshot, type History, type HistoryRecord, type Snapshot } from "./protocol";
import type { SieveSource } from "./source";

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

/** The version check, said in words a person can act on. */
function checkVersion(raw: unknown): void {
  const v = typeof raw === "object" && raw !== null ? (raw as { v?: unknown }).v : undefined;
  if (v !== PROTOCOL_VERSION) {
    throw new ProtocolError(
      `version ${String(v)} is not ${PROTOCOL_VERSION}: the Sieve backend and this window disagree. Restart Sieve after updating.`,
    );
  }
}

/** One snapshot as a history record: active flows per app. */
export function historyRecord(snap: Snapshot): HistoryRecord {
  const c = tickCounts(snap);
  return {
    t: snap.t,
    apps: [...c.byApp.entries()].map(([app, flows]) => ({ app, name: c.names.get(app) ?? app, flows })),
  };
}

export function createTauriSource(invoke: Invoke = tauriInvoke): SieveSource {
  let writeError: string | null = null;
  return {
    kind: "tauri",
    async sample(): Promise<Snapshot> {
      const raw = await invoke<unknown>("net_snapshot");
      checkVersion(raw);
      const snap = parseSnapshot(raw);
      invoke<void>("history_record", { record: historyRecord(snap) }).then(
        () => (writeError = null),
        (e: unknown) => (writeError = e instanceof Error ? e.message : String(e)),
      );
      return snap;
    },
    async history(query: HistoryQuery): Promise<History> {
      if (writeError !== null) throw new Error(`History is not being saved: ${writeError}`);
      return parseHistory(await invoke<unknown>("history_buckets", { query }));
    },
  };
}
