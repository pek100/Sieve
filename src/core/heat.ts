/**
 * Hour x weekday heatmap (pure): who is busy when, and how busy.
 *
 * Folds the hour buckets of a history series model (history.historySeries,
 * the same series set, names and colour slots as the Home chart) into a
 * 7 x 24 grid in local time, Monday first. A cell's value per series is the
 * mean of that series over the cell's hours, so a weekday seen twice is not
 * twice as busy; its total is the sum of those means (mean active
 * connections in that hour) and its mix is each series' share of the total,
 * in legend order. heatStack lays a cell's mix out as a stacked bar.
 */
import { OTHER_KEY, type SeriesDef, type SeriesModel } from "./series";

export const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] as const;

/** One series' part of a cell. */
export interface HeatShare {
  key: string;
  name: string;
  /** Colour slot (series.ts): 1..SERIES_COUNT, 0 for Other. */
  slot: number;
  /** Mean active connections of this series in the cell's hours. */
  value: number;
  /** value / total, 0..1. The shares of a cell sum to 1. */
  share: number;
}

export interface HeatCell {
  /** 0 = Monday. */
  day: number;
  hour: number;
  /** Mean active connections over the cell's hours (all series); 0 when nothing was seen. */
  total: number;
  /** Hour buckets folded into this cell; 0 means no data, not zero activity. */
  hours: number;
  /** Series with a part in this cell, in legend order (slot order, Other last). Empty when total is 0. */
  mix: HeatShare[];
}

export interface HeatGrid {
  /** The series set the mix is drawn from: the chart's legend, in order. */
  series: SeriesDef[];
  /** Row-major: day 0 hours 0..23, then day 1, ... */
  cells: HeatCell[];
  /** The largest cell total. */
  max: number;
  /** Hour buckets seen in total. */
  hours: number;
  /** Start of the earliest bucket, epoch ms; null when there is none. */
  first: number | null;
}

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

function spanWords(ms: number): string {
  const days = Math.round(ms / DAY);
  if (days >= 7 && days % 7 === 0) return days === 7 ? "week" : `${days / 7} weeks`;
  if (days >= 1) return days === 1 ? "day" : `${days} days`;
  const hours = Math.max(1, Math.round(ms / HOUR));
  return hours === 1 ? "hour" : `${hours} hours`;
}

/**
 * How far back the heatmap goes, from the buckets the source returned for
 * the range asked: "Last 4 weeks" when they reach back to its start (within
 * an hour), else "Since <first bucket>" (a session-only source, a short mock).
 */
export function heatCaption(grid: Pick<HeatGrid, "first">, range: { from: number; to: number }): string {
  if (grid.first === null) return "No history yet";
  if (grid.first - range.from < HOUR) return `Last ${spanWords(range.to - range.from)}`;
  const first = new Date(grid.first);
  const sameDay = first.toDateString() === new Date(range.to).toDateString();
  const time = first.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return sameDay ? `Since ${time}` : `Since ${first.toLocaleDateString([], { weekday: "short" })} ${time}`;
}

/**
 * The grid of an hour-bucket series model (history.historySeries over hour
 * buckets). Points are sampled buckets only, so an unsampled hour adds
 * nothing and a cell no hour fell into has `hours` 0.
 */
export function heatGrid(model: Pick<SeriesModel, "series" | "points">): HeatGrid {
  const { series, points } = model;
  const sums = Array.from({ length: 7 * 24 }, () => new Map<string, number>());
  const counts = new Array<number>(7 * 24).fill(0);
  let first: number | null = null;
  for (const p of points) {
    const d = new Date(p.t);
    const i = ((d.getDay() + 6) % 7) * 24 + d.getHours();
    for (const s of series) sums[i].set(s.key, (sums[i].get(s.key) ?? 0) + (p.values[s.key] ?? 0));
    counts[i] += 1;
    if (first === null || p.t < first) first = p.t;
  }
  let max = 0;
  const cells = counts.map((n, i): HeatCell => {
    const values = series.map((s) => (n > 0 ? (sums[i].get(s.key) ?? 0) / n : 0));
    const total = values.reduce((a, b) => a + b, 0);
    max = Math.max(max, total);
    const mix =
      total > 0
        ? series.flatMap((s, j) => (values[j] > 0 ? [{ key: s.key, name: s.name, slot: s.slot, value: values[j], share: values[j] / total }] : []))
        : [];
    return { day: Math.floor(i / 24), hour: i % 24, total, hours: n, mix };
  });
  return { series, cells, max, hours: points.length, first };
}

/**
 * Whole percentages for a mix that add up to exactly 100 (largest remainder),
 * in the mix's order. Empty for an empty mix.
 */
export function sharePercents(mix: readonly Pick<HeatShare, "share">[]): number[] {
  const raw = mix.map((m) => m.share * 100);
  const out = raw.map(Math.floor);
  let left = mix.length ? 100 - out.reduce((a, b) => a + b, 0) : 0;
  const order = raw.map((r, i) => ({ i, rem: r - Math.floor(r) })).sort((a, b) => b.rem - a.rem || a.i - b.i);
  for (const { i } of order) {
    if (left <= 0) break;
    out[i] += 1;
    left -= 1;
  }
  return out;
}

/** A stacked segment, in pixels from the bottom of the cell. */
export interface HeatSegment {
  key: string;
  slot: number;
  /** Bottom edge, px above the cell's bottom. */
  y0: number;
  /** Top edge, px above the cell's bottom. */
  y1: number;
}

/** The surface gap drawn between stacked segments, px. */
export const HEAT_GAP_PX = 1;
/** A segment thinner than this (1 px of colour after the gap) is a sliver: it folds into Other. */
export const MIN_SEGMENT_PX = HEAT_GAP_PX + 1;
/** A cell with any activity shows at least this much stack, so quiet is never drawn as empty. */
export const MIN_STACK_PX = 2;

/**
 * Lay a cell's mix out as a stack in a cell `cellPx` tall: the stack is
 * total / max of the cell (length encodes how busy the hour was), split
 * bottom-up in legend order (the chart's stacking order) by share.
 * Slivers under MIN_SEGMENT_PX fold into Other (on top). The largest part
 * never folds, and when Other would itself be a sliver its height goes to
 * the largest part, so a short stack still shows who dominated it and the
 * stack's height always stays the cell's total. Edges are whole pixels.
 * No data or no activity: no segments (an empty cell, never a fake stack).
 */
export function heatStack(cell: Pick<HeatCell, "total" | "mix">, max: number, cellPx: number): HeatSegment[] {
  if (cell.total <= 0 || max <= 0 || cellPx <= 0 || cell.mix.length === 0) return [];
  const stackPx = Math.min(cellPx, Math.max(MIN_STACK_PX, (cell.total / max) * cellPx));
  const largest = cell.mix.reduce((a, b) => (b.share > a.share ? b : a));
  const parts: { key: string; slot: number; px: number }[] = [];
  let other = 0;
  for (const m of cell.mix) {
    const px = m.share * stackPx;
    if (m.key === OTHER_KEY) other += px;
    else if (px < MIN_SEGMENT_PX && m !== largest) other += px;
    else parts.push({ key: m.key, slot: m.slot, px });
  }
  if (other > 0) {
    if (other >= MIN_SEGMENT_PX || largest.key === OTHER_KEY) parts.push({ key: OTHER_KEY, slot: 0, px: other });
    else {
      const big = parts.find((p) => p.key === largest.key);
      if (big) big.px += other;
    }
  }
  const out: HeatSegment[] = [];
  let acc = 0;
  for (const p of parts) {
    const y0 = Math.round(acc);
    acc += p.px;
    const y1 = Math.round(acc);
    if (y1 > y0) out.push({ key: p.key, slot: p.slot, y0, y1 });
  }
  return out;
}
