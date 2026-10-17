import { describe, expect, it } from "vitest";
import { createMockSource } from "@/data/mock-source";
import type { History } from "@/data/protocol";
import { GRAINS, grainFor, historySeries, hourActivity, periodQuery, trackedHistory } from "./history";
import { MAX_POINTS, OTHER_KEY, SERIES_COUNT } from "./series";

const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
const NOW = 1_792_224_000_000;

const h = (samples: [number, number][], apps: [number, string, number][], step = HOUR): History => ({
  v: 1,
  grain: "hour",
  step,
  samples: samples.map(([t, n]) => ({ t, n })),
  apps: apps.map(([t, app, flows]) => ({ t, app, name: app.toUpperCase(), flows })),
});

describe("history grains", () => {
  it("picks the finest grain kept for the whole period", () => {
    expect(grainFor(5 * MIN)).toBe("minute");
    expect(grainFor(DAY)).toBe("minute");
    expect(grainFor(7 * DAY)).toBe("hour");
    expect(grainFor(14 * DAY)).toBe("hour");
    expect(grainFor(90 * DAY)).toBe("day");
    expect(grainFor(10_000 * DAY)).toBe("day");
  });

  it("period queries never ask for more than MAX_POINTS buckets and step is a whole number of grains", () => {
    for (const period of [DAY, 7 * DAY, 14 * DAY, 120 * DAY]) {
      const q = periodQuery(period, NOW);
      const g = GRAINS.find((x) => x.name === q.grain)!;
      expect(q.step % g.ms).toBe(0);
      expect(period / q.step).toBeLessThanOrEqual(MAX_POINTS);
      expect(q.to - q.from).toBe(period);
    }
    expect(periodQuery(DAY, NOW)).toMatchObject({ grain: "minute", step: 5 * MIN });
    expect(periodQuery(14 * DAY, NOW)).toMatchObject({ grain: "hour", step: 2 * HOUR });
  });
});

describe("history folds", () => {
  it("hour activity is mean connections per sample; unsampled hours are absent, not zero", () => {
    const a = hourActivity(
      h(
        [
          [0, 10],
          [HOUR, 20],
        ],
        [
          [0, "chrome", 30],
          [0, "slack", 10],
        ],
      ),
    );
    // Hour 0: (30 + 10) / 10 samples; hour 1 was sampled with no flows: a real 0.
    expect(a).toEqual([
      { t: 0, flows: 4 },
      { t: HOUR, flows: 0 },
    ]);
    expect(hourActivity(h([], [[0, "chrome", 5]]))).toEqual([]);
  });

  it("the chart model averages per sample, names the top apps and folds the rest into Other", () => {
    const apps: [number, string, number][] = [];
    for (let i = 0; i < SERIES_COUNT + 2; i++) apps.push([0, `app${i}`, (i + 1) * 60]);
    const m = historySeries(h([[0, 60]], apps), { periodMs: 7 * DAY });
    expect(m.series.filter((s) => s.key !== OTHER_KEY)).toHaveLength(SERIES_COUNT);
    expect(m.series.at(-1)?.key).toBe(OTHER_KEY);
    expect(m.points).toHaveLength(1);
    // app7 had 480 flows over 60 samples: 8 connections on average.
    expect(m.points[0].values.app7).toBe(8);
    // Other: app0 (60) + app1 (120) over 60 samples.
    expect(m.points[0].values[OTHER_KEY]).toBe(3);
    expect(m.windowMs).toBe(7 * DAY);
    expect(m.bucketMs).toBe(HOUR);
  });

  it("slots stay sticky across refreshes", () => {
    const one = historySeries(h([[0, 1]], [[0, "a", 5], [0, "b", 4]]), { periodMs: DAY });
    const two = historySeries(h([[0, 1]], [[0, "b", 9], [0, "a", 5]]), { periodMs: DAY, previousSlots: one.slots });
    expect(two.slots).toEqual(one.slots);
  });

  it("the 24 h, 7 d and 14 d mock periods all draw named series", async () => {
    const src = createMockSource({ seed: 1, now: () => NOW });
    for (const period of [DAY, 7 * DAY, 14 * DAY]) {
      const m = historySeries(await src.history(periodQuery(period, NOW)), { periodMs: period });
      expect(m.series.length).toBeGreaterThan(1);
      expect(m.points.length).toBeGreaterThan(80);
      expect(m.points.length).toBeLessThanOrEqual(MAX_POINTS);
      expect(m.points.every((p, i) => i === 0 || p.t > m.points[i - 1].t)).toBe(true);
    }
  });
});

describe("trackedHistory", () => {
  it("leaves out apps turned off; samples stay, so the gap is not read as zero activity", () => {
    const hist = h([[0, 2]], [[0, "a", 4], [0, "b", 2]]);
    const out = trackedHistory(hist, new Set(["a"]));
    expect(out.apps.map((x) => x.app)).toEqual(["b"]);
    expect(out.samples).toEqual(hist.samples);
    expect(historySeries(out, { periodMs: HOUR }).series.map((x) => x.key)).toEqual(["b"]);
    expect(trackedHistory(hist, new Set())).toBe(hist);
  });
});
