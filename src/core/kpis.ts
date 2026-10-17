/**
 * Home KPIs from snapshots (pure). Three counts of what the machine is doing
 * now, each with its change since the start of the chart window: sieved
 * apps with connections, connections and remote hosts. They never claim
 * filtering. The fourth Home tile (blocked lookups) is not derived from
 * snapshots: it is the DNS filter's own counter (src/core/dns.ts).
 *
 * Callers pass tracked snapshots (apps.trackedSnapshot), so apps the user
 * turned off are not in any count.
 */
import type { Snapshot } from "@/data/protocol";
import { groupApps, isActiveFlow, isSieved } from "./apps";

export const KPI_IDS = ["apps", "connections", "hosts"] as const;
export type KpiId = (typeof KPI_IDS)[number];

export type KpiValues = Record<KpiId, number>;

export type DeltaDir = "up" | "down" | "flat";

export interface Kpi {
  id: KpiId;
  value: number;
  /** Change against the first snapshot of the window. */
  delta: number;
  dir: DeltaDir;
}

/** The counts for one snapshot. `isOn` says whether an app is effectively on (policy.effectiveOn). */
export function kpiValues(s: Snapshot, isOn: (appKey: string) => boolean): KpiValues {
  const active = s.flows.filter(isActiveFlow);
  return {
    apps: groupApps(s).filter((a) => isSieved(a, isOn(a.key))).length,
    connections: active.length,
    hosts: new Set(active.map((f) => f.remote?.addr)).size,
  };
}

export function deltaDir(delta: number): DeltaDir {
  return delta > 0 ? "up" : delta < 0 ? "down" : "flat";
}

/**
 * KPIs for a window of snapshots (oldest first): the newest values, each
 * compared with the oldest. Null when there is no snapshot yet.
 */
export function kpis(snaps: readonly Snapshot[], isOn: (appKey: string) => boolean): Kpi[] | null {
  if (snaps.length === 0) return null;
  const now = kpiValues(snaps[snaps.length - 1], isOn);
  const start = kpiValues(snaps[0], isOn);
  return KPI_IDS.map((id) => {
    const delta = now[id] - start[id];
    return { id, value: now[id], delta, dir: deltaDir(delta) };
  });
}
