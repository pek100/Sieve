import { describe, expect, it } from "vitest";
import { createMockSource } from "@/data/mock-source";
import type { Snapshot } from "@/data/protocol";
import {
  assignSlots,
  bucketSize,
  buildSeries,
  createSlotKeeper,
  EMPTY_SET,
  MAX_POINTS,
  niceCeiling,
  OTHER_KEY,
  rankSeries,
  sameSeries,
  SERIES_COUNT,
  seriesSet,
  stackSeries,
  tickCounts,
  windowSnapshots,
} from "./series";

const T0 = 1_760_000_000_000;

async function mockTicks(n: number, seed = 1, scenario: "steady" | "busy" | "empty" = "steady") {
  let t = T0;
  const src = createMockSource({ seed, scenario, now: () => t });
  const out: Snapshot[] = [];
  for (let i = 0; i < n; i++) {
    t = T0 + i * 1000;
    out.push(await src.sample());
  }
  return { out, src, next: async () => ((t += 1000), src.sample()) };
}

const W5 = 5 * 60_000;

/** The model of one window, named by that window's own set. */
const windowModel = (out: readonly Snapshot[], windowMs: number) =>
  buildSeries(out, { windowMs, intervalMs: 1000 }, seriesSet(windowSnapshots(out, windowMs)));

describe("series derivation", () => {
  it("has SERIES_COUNT 6, matching the six series tokens", () => {
    expect(SERIES_COUNT).toBe(6);
  });

  it("counts active non-listening flows per app per tick", async () => {
    const { out } = await mockTicks(1);
    const c = tickCounts(out[0]);
    const active = out[0].flows.filter((f) => f.remote !== null && f.state !== "listen").length;
    expect(c.total).toBe(active);
    expect([...c.byApp.values()].reduce((a, b) => a + b, 0)).toBe(active);
    // System only listens: it never appears.
    expect(c.byApp.has("system")).toBe(false);
  });

  it("shows at most 6 named series plus Other, ranked by window total, Other holding the rest", async () => {
    const { out } = await mockTicks(120);
    const m = windowModel(out, W5);
    const named = m.series.filter((s) => s.key !== OTHER_KEY);
    expect(named.length).toBe(SERIES_COUNT);
    expect(m.series.at(-1)?.key).toBe(OTHER_KEY);
    expect(new Set(named.map((s) => s.slot))).toEqual(new Set([1, 2, 3, 4, 5, 6]));
    const minNamed = Math.min(...named.map((s) => s.total));
    // Every folded app is below every named one.
    const totals = new Map<string, number>();
    for (const s of out) for (const [k, n] of tickCounts(s).byApp) totals.set(k, (totals.get(k) ?? 0) + n);
    const namedKeys = new Set(named.map((s) => s.key));
    for (const [k, n] of totals) if (!namedKeys.has(k)) expect(n).toBeLessThanOrEqual(minNamed);
    // Per point, the series sum equals the tick total (1 s buckets, one sample each).
    const last = m.points.at(-1)!;
    const sum = Object.values(last.values).reduce((a, b) => a + b, 0);
    expect(sum).toBeCloseTo(tickCounts(out.at(-1)!).total, 5);
  });

  it("keeps every top app's colour across 10 more mock ticks (seed 1)", async () => {
    const { out, next } = await mockTicks(60);
    const keeper = createSlotKeeper();
    const snaps = [...out];
    const before = keeper.set(snaps);
    const slotsBefore = new Map(before.series.map((s) => [s.key, s.slot]));
    let after = before;
    for (let i = 0; i < 10; i++) {
      snaps.push(await next());
      after = keeper.set(snaps);
      for (const s of after.series) {
        if (slotsBefore.has(s.key)) expect([s.key, s.slot]).toEqual([s.key, slotsBefore.get(s.key)]);
      }
    }
    // Most of the top set survives 10 ticks; the check above is not vacuous.
    const kept = after.series.filter((s) => s.key !== OTHER_KEY && slotsBefore.has(s.key));
    expect(kept.length).toBeGreaterThanOrEqual(4);
  });

  it("one set, every window: the same series, order and colours in 5 min and 1 h; apps with no data draw flat", async () => {
    const { out } = await mockTicks(900);
    const set = seriesSet(out);
    const five = buildSeries(out, { windowMs: W5, intervalMs: 1000 }, set);
    const hour = buildSeries(out, { windowMs: 3_600_000, intervalMs: 1000 }, set);
    expect(five.series).toBe(set.series);
    expect(hour.series).toBe(set.series);
    expect(five.windowMs).toBe(W5);
    expect(hour.windowMs).toBe(3_600_000);
    expect(five.end).toBe(out.at(-1)!.t);
    // Every point carries every series of the set, zero when the app had nothing then.
    for (const p of [...five.points, ...hour.points]) expect(Object.keys(p.values).sort()).toEqual(set.series.map((s) => s.key).sort());
  });

  it("Other is part of every non-empty set, so the legend never gains or loses it by window", async () => {
    const { out } = await mockTicks(30);
    expect(seriesSet(out).series.at(-1)?.key).toBe(OTHER_KEY);
    expect(seriesSet([])).toEqual({ ...EMPTY_SET, top: new Set() });
  });

  it("assignSlots keeps incumbents and gives newcomers the lowest free slot", () => {
    expect(assignSlots(["a", "b", "c"], {})).toEqual({ a: 1, b: 2, c: 3 });
    expect(assignSlots(["c", "d", "a"], { a: 1, b: 2, c: 3 })).toEqual({ c: 3, a: 1, d: 2 });
    // Out-of-range or duplicate previous slots are reassigned.
    expect(assignSlots(["x", "y"], { x: 9, y: 9 })).toEqual({ x: 1, y: 2 });
  });

  it("windows and buckets: 5 min at 1 s is one point per sample, 1 h never exceeds MAX_POINTS", async () => {
    const { out } = await mockTicks(400);
    expect(windowSnapshots(out, W5).length).toBe(301);
    expect(bucketSize(W5, 1000)).toBe(1000);
    expect(bucketSize(3_600_000, 1000)).toBe(12_000);
    expect(bucketSize(3_600_000, 5000)).toBe(15_000);
    const hour = windowModel(out, 3_600_000);
    expect(hour.points.length).toBeLessThanOrEqual(MAX_POINTS);
    expect(hour.points.length).toBeGreaterThan(30);
  });

  it("empty input and scenario empty give no series", async () => {
    expect(windowModel([], W5).series).toEqual([]);
    const { out } = await mockTicks(5, 1, "empty");
    const m = windowModel(out, W5);
    expect(m.series).toEqual([]);
    expect(m.points.length).toBe(5);
  });

  it("stacking drops hidden series and the ones above fall down", async () => {
    const { out } = await mockTicks(60);
    const m = windowModel(out, W5);
    const all = stackSeries(m, new Set());
    expect(all.layers.map((l) => l.key)).toEqual(m.series.map((s) => s.key));
    const first = m.series[0].key;
    const less = stackSeries(m, new Set([first]));
    expect(less.layers.map((l) => l.key)).not.toContain(first);
    expect(less.layers[0].lower.every((v) => v === 0)).toBe(true);
    expect(less.max).toBeLessThanOrEqual(all.max);
    const top = all.layers.at(-1)!.upper;
    expect(Math.max(...top)).toBe(all.max);
  });

  it("niceCeiling rounds up to 1, 2 or 5 times a power of ten", () => {
    expect([0, 0.4, 1, 3, 7, 12, 51, 260].map(niceCeiling)).toEqual([1, 0.5, 1, 5, 10, 20, 100, 500]);
  });

  it("sameSeries ignores totals but not keys, names, slots or order", () => {
    const names = new Map([
      ["a", "A"],
      ["b", "B"],
    ]);
    const s1 = rankSeries(new Map([["a", 5], ["b", 3]]), names, {});
    const s2 = rankSeries(new Map([["a", 9], ["b", 4]]), names, s1.slots);
    expect(s2).not.toBe(s1);
    expect(sameSeries(s1, s2)).toBe(true);
    // b overtakes a but keeps its slot: same set.
    expect(sameSeries(s1, rankSeries(new Map([["a", 1], ["b", 4]]), names, s1.slots))).toBe(true);
    // New slots (no memory): b takes slot 1, a different colour for both.
    expect(sameSeries(s1, rankSeries(new Map([["a", 1], ["b", 4]]), names, {}))).toBe(false);
    expect(sameSeries(s1, rankSeries(new Map([["a", 5]]), names, s1.slots))).toBe(false);
    expect(sameSeries(s1, rankSeries(new Map([["a", 5], ["b", 3]]), new Map([["a", "A2"], ["b", "B"]]), s1.slots))).toBe(false);
    expect(sameSeries(EMPTY_SET, EMPTY_SET)).toBe(true);
  });
});
