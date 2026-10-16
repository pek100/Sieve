/**
 * Tauri source: asks Rust for a snapshot (`net_snapshot`, slice S1), which
 * reads the machine's TCP and UDP owner-pid tables. Every answer is checked:
 * a protocol version other than ours, or a malformed snapshot, throws a
 * ProtocolError that the UI shows as an error state. A Rust error is passed
 * through as is. It never pretends with empty or mock data.
 *
 * History is session only until persisted stats exist (plan row 77): the
 * source folds every sample it takes into hourly buckets.
 */
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { isActiveFlow } from "@/core/apps";
import { PROTOCOL_VERSION, ProtocolError, parseSnapshot, type Snapshot } from "./protocol";
import type { HistoryRange, HourBucket, SieveSource } from "./source";

const HOUR = 3_600_000;

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

export function createTauriSource(invoke: Invoke = tauriInvoke): SieveSource {
  const hours = new Map<number, number>();
  return {
    kind: "tauri",
    async sample(): Promise<Snapshot> {
      const raw = await invoke<unknown>("net_snapshot");
      checkVersion(raw);
      const snap = parseSnapshot(raw);
      const hour = Math.floor(snap.t / HOUR) * HOUR;
      hours.set(hour, (hours.get(hour) ?? 0) + snap.flows.filter(isActiveFlow).length);
      return snap;
    },
    async history(range: HistoryRange): Promise<HourBucket[]> {
      return [...hours.entries()]
        .filter(([t]) => t >= range.from && t < range.to)
        .sort(([a], [b]) => a - b)
        .map(([t, flows]) => ({ t, flows }));
    },
  };
}
