/**
 * Persisted history (plan row 77), the pure side. The Rust store
 * (src-tauri/src/history) keeps per-app counts per minute, hour and day; the
 * mock source answers the same queries. This file owns the grain table the
 * readers choose from and the folds from history to the Home chart and the
 * heatmap.
 *
 * GRAINS mirrors GRAIN_NAMES, GRAIN_MS and GRAIN_KEEP_MS in
 * src-tauri/src/protocol.rs (protocol law).
 */
import type { History } from "@/data/protocol";
import type { HourActivity } from "./heat";
import { bucketSize, rankSeries, type SeriesModel, type SeriesPoint, OTHER_KEY } from "./series";

const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;

export const GRAINS = [
  { name: "minute", ms: MINUTE, keepMs: 2 * DAY },
  { name: "hour", ms: HOUR, keepMs: 35 * DAY },
  { name: "day", ms: DAY, keepMs: 400 * DAY },
] as const;

export type GrainName = (typeof GRAINS)[number]["name"];
export const GRAIN_NAMES = GRAINS.map((g) => g.name) as readonly GrainName[];

export interface HistoryQuery {
  /** Epoch ms, inclusive. */
  from: number;
  /** Epoch ms, exclusive. */
  to: number;
  grain: GrainName;
  /** Bucket width of the answer, a whole number of grain buckets. */
  step: number;
}

export function grainMs(name: GrainName): number {
  return GRAINS.find((g) => g.name === name)?.ms ?? MINUTE;
}

/** The finest grain still kept for the whole period. */
export function grainFor(periodMs: number): GrainName {
  return (GRAINS.find((g) => g.keepMs >= periodMs) ?? GRAINS[GRAINS.length - 1]).name;
}

/** The query that draws `periodMs` ending at `to`: finest kept grain, at most MAX_POINTS buckets. */
export function periodQuery(periodMs: number, to: number): HistoryQuery {
  const grain = grainFor(periodMs);
  const step = bucketSize(periodMs, grainMs(grain));
  return { from: to - periodMs, to, grain, step };
}

/**
 * History without the apps the user turned off (by app key), the saved-history
 * side of apps.trackedSnapshot: counts saved before an app was turned off are
 * left out of the chart and the heatmap too.
 */
export function trackedHistory(h: History, off: ReadonlySet<string>): History {
  return off.size === 0 ? h : { ...h, apps: h.apps.filter((a) => !off.has(a.app)) };
}

/**
 * Mean active connections per hour bucket, for the heatmap: every app's flows
 * in the bucket over the bucket's samples. Buckets with no samples are left
 * out (Sieve was not sampling then), never read as zero.
 */
export function hourActivity(h: History): HourActivity[] {
  const flows = new Map<number, number>();
  for (const a of h.apps) flows.set(a.t, (flows.get(a.t) ?? 0) + a.flows);
  return h.samples.filter((s) => s.n > 0).map((s) => ({ t: s.t, flows: (flows.get(s.t) ?? 0) / s.n }));
}

const round2 = (x: number) => Math.round(x * 100) / 100;

/**
 * The Home chart model for a history period: one point per sampled bucket,
 * each app's mean active connections over the bucket's samples. Ranking,
 * slots and the Other fold are the live chart's (rankSeries), so the two
 * views of the chart cannot disagree on who is named.
 */
export function historySeries(
  h: History,
  o: { periodMs: number; previousSlots?: Readonly<Record<string, number>> },
): SeriesModel {
  const totals = new Map<string, number>();
  const names = new Map<string, string>();
  for (const a of h.apps) {
    totals.set(a.app, (totals.get(a.app) ?? 0) + a.flows);
    names.set(a.app, a.name);
  }
  const { series, slots, top } = rankSeries(totals, names, o.previousSlots ?? {});
  const byBucket = new Map<number, Record<string, number>>();
  for (const a of h.apps) {
    const key = top.has(a.app) ? a.app : OTHER_KEY;
    const row = byBucket.get(a.t) ?? {};
    row[key] = (row[key] ?? 0) + a.flows;
    byBucket.set(a.t, row);
  }
  const points: SeriesPoint[] = h.samples
    .filter((s) => s.n > 0)
    .map((s) => {
      const row = byBucket.get(s.t) ?? {};
      const values: Record<string, number> = {};
      for (const d of series) values[d.key] = round2((row[d.key] ?? 0) / s.n);
      return { t: s.t, values };
    });
  return { series, points, bucketMs: h.step, windowMs: o.periodMs, slots };
}
