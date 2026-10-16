/**
 * Home KPIs (pure). Four counts of what the machine is doing now, each with
 * its change since the start of the chart window. They count connections,
 * hosts and ports only: Sieve never claims filtering that is not happening.
 */
import type { Snapshot } from "@/data/protocol";
import { groupApps, isActiveFlow, isSieved } from "./apps";
import type { Level } from "./policy";

export const KPI_IDS = ["apps", "connections", "hosts", "ports"] as const;
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

/** The counts for one snapshot. `levelOf` gives each app's effective level. */
export function kpiValues(s: Snapshot, levelOf: (appKey: string) => Level): KpiValues {
  const active = s.flows.filter(isActiveFlow);
  const listening = new Set<string>();
  for (const f of s.flows) {
    if (f.remote === null && (f.state === "listen" || f.proto === "udp")) listening.add(`${f.proto}:${f.local.port}`);
  }
  return {
    apps: groupApps(s).filter((a) => isSieved(a, levelOf(a.key))).length,
    connections: active.length,
    hosts: new Set(active.map((f) => f.remote?.addr)).size,
    ports: listening.size,
  };
}

export function deltaDir(delta: number): DeltaDir {
  return delta > 0 ? "up" : delta < 0 ? "down" : "flat";
}

/**
 * KPIs for a window of snapshots (oldest first): the newest values, each
 * compared with the oldest. Null when there is no snapshot yet.
 */
export function kpis(snaps: readonly Snapshot[], levelOf: (appKey: string) => Level): Kpi[] | null {
  if (snaps.length === 0) return null;
  const now = kpiValues(snaps[snaps.length - 1], levelOf);
  const start = kpiValues(snaps[0], levelOf);
  return KPI_IDS.map((id) => {
    const delta = now[id] - start[id];
    return { id, value: now[id], delta, dir: deltaDir(delta) };
  });
}
