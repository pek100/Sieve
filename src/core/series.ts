/**
 * Per-app activity series for the Home chart (B3 derivation, pure).
 * One point per time bucket: how many active (non-listening) flows each app
 * held, averaged over the samples in the bucket. The top SERIES_COUNT apps by
 * window total get a named series and a colour slot; the rest fold into
 * Other. Slots are sticky: an app keeps its slot (its colour) for as long as
 * it stays in the top set, so a live tick never repaints the chart.
 */
import type { Snapshot } from "@/data/protocol";
import { appIdentity, isActiveFlow } from "./apps";

/** Named series shown at most; matches the --series-1..6 tokens. */
export const SERIES_COUNT = 6;

/** Key of the folded remainder. App keys are always lower case, so this never collides. */
export const OTHER_KEY = "OTHER";

/** Most points a series carries; longer windows use wider buckets. */
export const MAX_POINTS = 300;

/** Active flows per app in one snapshot. */
export interface TickCounts {
  t: number;
  total: number;
  byApp: ReadonlyMap<string, number>;
  names: ReadonlyMap<string, string>;
}

// Snapshots are immutable once pushed, so the per-snapshot count is computed once.
const tickCache = new WeakMap<Snapshot, TickCounts>();

export function tickCounts(s: Snapshot): TickCounts {
  const hit = tickCache.get(s);
  if (hit) return hit;
  const idOfPid = new Map<number, { key: string; name: string }>();
  for (const p of s.processes) idOfPid.set(p.pid, appIdentity(p));
  const byApp = new Map<string, number>();
  const names = new Map<string, string>();
  let total = 0;
  for (const f of s.flows) {
    if (!isActiveFlow(f)) continue;
    // A flow whose process vanished between the two OS reads still counts, under its pid.
    const id = idOfPid.get(f.pid) ?? { key: `pid ${f.pid}`, name: `pid ${f.pid}` };
    byApp.set(id.key, (byApp.get(id.key) ?? 0) + 1);
    names.set(id.key, id.name);
    total += 1;
  }
  const out: TickCounts = { t: s.t, total, byApp, names };
  tickCache.set(s, out);
  return out;
}

/** Snapshots inside the window ending at the newest one (oldest first). */
export function windowSnapshots(snapshots: readonly Snapshot[], windowMs: number): readonly Snapshot[] {
  if (snapshots.length === 0) return snapshots;
  const from = snapshots[snapshots.length - 1].t - windowMs;
  let i = 0;
  while (i < snapshots.length && snapshots[i].t < from) i += 1;
  return i === 0 ? snapshots : snapshots.slice(i);
}

/** Bucket width: the sample interval, widened so a window never needs more than MAX_POINTS. */
export function bucketSize(windowMs: number, intervalMs: number): number {
  const iv = Math.max(1, intervalMs);
  return Math.max(iv, Math.ceil(windowMs / MAX_POINTS / iv) * iv);
}

/**
 * Colour slots 1..SERIES_COUNT for the top set. An app that already had a slot
 * keeps it; newcomers take the lowest free slot.
 */
export function assignSlots(top: readonly string[], previous: Readonly<Record<string, number>>): Record<string, number> {
  const out: Record<string, number> = {};
  const used = new Set<number>();
  for (const k of top) {
    const s = previous[k];
    if (s !== undefined && s >= 1 && s <= SERIES_COUNT && !used.has(s)) {
      out[k] = s;
      used.add(s);
    }
  }
  let next = 1;
  for (const k of top) {
    if (out[k] !== undefined) continue;
    while (used.has(next)) next += 1;
    out[k] = next;
    used.add(next);
  }
  return out;
}

export interface SeriesDef {
  key: string;
  name: string;
  /** 1..SERIES_COUNT for named apps, 0 for Other. */
  slot: number;
  /** Sum of active flows over the window's samples. */
  total: number;
}

export interface SeriesPoint {
  /** Bucket start, epoch ms. */
  t: number;
  /** Value per series key (named keys and OTHER_KEY when present). */
  values: Readonly<Record<string, number>>;
}

export interface SeriesModel {
  /** Named series by slot, then Other when anything folded into it. */
  series: SeriesDef[];
  points: SeriesPoint[];
  bucketMs: number;
  windowMs: number;
  /** Slot of every named key, to feed back as `previousSlots` on the next tick. */
  slots: Readonly<Record<string, number>>;
}

export interface SeriesOptions {
  windowMs: number;
  intervalMs: number;
  /** Slots from the previous build; keeps colours sticky. */
  previousSlots?: Readonly<Record<string, number>>;
}

const round2 = (x: number) => Math.round(x * 100) / 100;

/**
 * Who gets named: rank apps by total, keep the top SERIES_COUNT with sticky
 * slots, fold the rest into Other. Shared by the live chart (buildSeries) and
 * the history periods (historySeries in ./history).
 */
export function rankSeries(
  totals: ReadonlyMap<string, number>,
  names: ReadonlyMap<string, string>,
  previous: Readonly<Record<string, number>>,
): { series: SeriesDef[]; slots: Record<string, number>; top: ReadonlySet<string> } {
  // Rank by window total; on a tie an app that already holds a slot stays ahead.
  const ranked = [...totals.entries()]
    .filter(([, n]) => n > 0)
    .sort(
      (a, b) =>
        b[1] - a[1] ||
        Number(previous[b[0]] !== undefined) - Number(previous[a[0]] !== undefined) ||
        a[0].localeCompare(b[0]),
    );
  const top = ranked.slice(0, SERIES_COUNT).map(([k]) => k);
  const slots = assignSlots(top, previous);
  const otherTotal = ranked.slice(SERIES_COUNT).reduce((sum, [, n]) => sum + n, 0);

  const series: SeriesDef[] = top
    .map((key) => ({ key, name: names.get(key) ?? key, slot: slots[key], total: totals.get(key) ?? 0 }))
    .sort((a, b) => a.slot - b.slot);
  if (otherTotal > 0) series.push({ key: OTHER_KEY, name: "Other", slot: 0, total: otherTotal });
  return { series, slots, top: new Set(top) };
}

export function buildSeries(snapshots: readonly Snapshot[], o: SeriesOptions): SeriesModel {
  const bucketMs = bucketSize(o.windowMs, o.intervalMs);
  const ticks = windowSnapshots(snapshots, o.windowMs).map(tickCounts);

  const totals = new Map<string, number>();
  const names = new Map<string, string>();
  for (const tick of ticks) {
    for (const [k, n] of tick.byApp) totals.set(k, (totals.get(k) ?? 0) + n);
    for (const [k, name] of tick.names) names.set(k, name);
  }
  const { series, slots, top: topSet } = rankSeries(totals, names, o.previousSlots ?? {});
  const points: SeriesPoint[] = [];
  let i = 0;
  while (i < ticks.length) {
    const start = Math.floor(ticks[i].t / bucketMs) * bucketMs;
    const sums: Record<string, number> = {};
    for (const s of series) sums[s.key] = 0;
    let n = 0;
    while (i < ticks.length && ticks[i].t < start + bucketMs) {
      for (const [k, c] of ticks[i].byApp) {
        const key = topSet.has(k) ? k : OTHER_KEY;
        if (key in sums) sums[key] += c;
      }
      n += 1;
      i += 1;
    }
    const values: Record<string, number> = {};
    for (const s of series) values[s.key] = round2(sums[s.key] / n);
    points.push({ t: start, values });
  }

  return { series, points, bucketMs, windowMs: o.windowMs, slots };
}

/** Remembers slots between builds. One per chart. */
export function createSlotKeeper() {
  let slots: Readonly<Record<string, number>> = {};
  return {
    build(snapshots: readonly Snapshot[], o: Omit<SeriesOptions, "previousSlots">): SeriesModel {
      const model = buildSeries(snapshots, { ...o, previousSlots: slots });
      slots = model.slots;
      return model;
    },
  };
}

export interface StackLayer {
  key: string;
  lower: number[];
  upper: number[];
}

/**
 * Stack the visible series bottom-up in model order (slot order, Other on top).
 * Hidden series are left out, so the ones above them drop down.
 */
export function stackSeries(model: Pick<SeriesModel, "series" | "points">, hidden: ReadonlySet<string>): {
  layers: StackLayer[];
  max: number;
} {
  const base = model.points.map(() => 0);
  const layers: StackLayer[] = [];
  for (const s of model.series) {
    if (hidden.has(s.key)) continue;
    const lower = [...base];
    const upper = model.points.map((p, j) => round2(lower[j] + (p.values[s.key] ?? 0)));
    upper.forEach((u, j) => (base[j] = u));
    layers.push({ key: s.key, lower, upper });
  }
  return { layers, max: Math.max(0, ...base) };
}

/** A round axis ceiling at or above `x`: 1, 2, 5 times a power of ten. */
export function niceCeiling(x: number): number {
  if (x <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(x));
  for (const m of [1, 2, 5, 10]) if (m * p >= x) return m * p;
  return 10 * p;
}
