/**
 * Tauri source: asks Rust for a snapshot (`net_snapshot`). Until slice S1
 * lands, Rust answers with an error ("not implemented"), which the UI shows
 * as an error state. It never pretends with empty or mock data.
 *
 * History is session only until persisted stats exist (plan row 77): the
 * source folds every sample it takes into hourly buckets.
 */
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { isActiveFlow } from "@/core/apps";
import { parseSnapshot, type Snapshot } from "./protocol";
import type { HistoryRange, HourBucket, SieveSource } from "./source";

const HOUR = 3_600_000;

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

export function createTauriSource(invoke: Invoke = tauriInvoke): SieveSource {
  const hours = new Map<number, number>();
  return {
    kind: "tauri",
    async sample(): Promise<Snapshot> {
      const raw = await invoke<unknown>("net_snapshot");
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
