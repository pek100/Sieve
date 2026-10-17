import { describe, expect, it } from "vitest";
import { createMockSource } from "@/data/mock-source";
import type { History } from "@/data/protocol";
import { heatCaption, heatGrid, heatStack, MIN_SEGMENT_PX, MIN_STACK_PX, sharePercents, type HeatCell } from "./heat";
import { historySeries } from "./history";
import { EMPTY_SET, OTHER_KEY, rankSeries, SERIES_COUNT, type SeriesDef } from "./series";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
/** Monday 2026-10-12 00:00 local time. */
const MONDAY = new Date(2026, 9, 12, 0, 0, 0, 0).getTime();

const hours = (r: { from: number; to: number }) => ({ ...r, grain: "hour" as const, step: HOUR });

const def = (key: string, slot: number): SeriesDef => ({ key, name: key === OTHER_KEY ? "Other" : key.toUpperCase(), slot, total: 0 });
const SERIES = [def("chrome", 1), def("slack", 2), def(OTHER_KEY, 0)];
const point = (t: number, values: Record<string, number>) => ({ t, values });

/** A saved history: [t, samples] and [t, app, flows summed over the samples]. */
const history = (samples: [number, number][], apps: [number, string, number][]): History => ({
  v: 1,
  grain: "hour",
  step: HOUR,
  samples: samples.map(([t, n]) => ({ t, n })),
  apps: apps.map(([t, app, flows]) => ({ t, app, name: app.toUpperCase(), flows })),
});

const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0);

describe("heat grid", () => {
  it("folds hour points into a 7 x 24 grid in local time, Monday first, averaging each series over the cell's hours", () => {
    const g = heatGrid({
      series: SERIES,
      points: [
        point(MONDAY + 9 * HOUR, { chrome: 60, slack: 40, [OTHER_KEY]: 0 }),
        point(MONDAY + 7 * DAY + 9 * HOUR, { chrome: 240, slack: 40, [OTHER_KEY]: 20 }),
        point(MONDAY + 6 * DAY + 23 * HOUR, { chrome: 0, slack: 0, [OTHER_KEY]: 50 }),
      ],
    });
    expect(g.cells).toHaveLength(168);
    const mon9 = g.cells[0 * 24 + 9];
    expect([mon9.day, mon9.hour, mon9.total, mon9.hours]).toEqual([0, 9, 200, 2]);
    // Means over the two Mondays: chrome 150, slack 40, Other 10.
    expect(mon9.mix.map((m) => [m.key, m.value, m.share])).toEqual([
      ["chrome", 150, 0.75],
      ["slack", 40, 0.2],
      [OTHER_KEY, 10, 0.05],
    ]);
    const sun23 = g.cells[6 * 24 + 23];
    expect([sun23.day, sun23.hour, sun23.total]).toEqual([6, 23, 50]);
    expect(sun23.mix.map((m) => m.key)).toEqual([OTHER_KEY]);
    expect(g.max).toBe(200);
    expect(g.hours).toBe(3);
    expect(g.first).toBe(MONDAY + 9 * HOUR);
  });

  it("shares in every cell with activity sum to 1 (100 %), in legend order", async () => {
    const now = MONDAY + 28 * DAY;
    const src = createMockSource({ seed: 1, now: () => now });
    const h = await src.history(hours({ from: now - 28 * DAY, to: now }));
    const g = heatGrid(historySeries(h, { periodMs: 28 * DAY, to: now }, EMPTY_SET));
    const order = g.series.map((s) => s.key);
    for (const c of g.cells.filter((c) => c.total > 0)) {
      expect(sum(c.mix.map((m) => m.share))).toBeCloseTo(1, 9);
      expect(sum(sharePercents(c.mix))).toBe(100);
      const idx = c.mix.map((m) => order.indexOf(m.key));
      expect(idx).toEqual([...idx].sort((a, b) => a - b));
    }
  });

  it("uses the chart's series set: same keys, names, slots and order, apps outside it in Other", () => {
    // The live set names chrome (slot 2) and slack (slot 1); zoom is in the history but not the set.
    const set = rankSeries(
      new Map([
        ["chrome", 10],
        ["slack", 20],
      ]),
      new Map([
        ["chrome", "Google Chrome"],
        ["slack", "Slack"],
      ]),
      { chrome: 2, slack: 1 },
    );
    const h = history(
      [[MONDAY + 14 * HOUR, 10]],
      [
        [MONDAY + 14 * HOUR, "chrome", 50],
        [MONDAY + 14 * HOUR, "slack", 30],
        [MONDAY + 14 * HOUR, "zoom", 20],
      ],
    );
    const model = historySeries(h, { periodMs: 28 * DAY, to: MONDAY + DAY }, set);
    const g = heatGrid(model);
    expect(g.series).toBe(model.series);
    expect(g.series).toEqual(set.series);
    const c = g.cells[14];
    expect(c.mix.map((m) => [m.key, m.name, m.slot, m.share])).toEqual([
      ["slack", "Slack", 1, 0.3],
      ["chrome", "Google Chrome", 2, 0.5],
      [OTHER_KEY, "Other", 0, 0.2],
    ]);
  });

  it("with no live set it ranks the history's own apps, the top SERIES_COUNT plus Other, like the chart's history periods", () => {
    const apps: [number, string, number][] = [];
    for (let i = 0; i < SERIES_COUNT + 3; i++) apps.push([MONDAY, `app${i}`, (i + 1) * 10]);
    const g = heatGrid(historySeries(history([[MONDAY, 10]], apps), { periodMs: 28 * DAY, to: MONDAY + DAY }, EMPTY_SET));
    expect(g.series).toHaveLength(SERIES_COUNT + 1);
    expect(g.series.at(-1)?.key).toBe(OTHER_KEY);
    const other = g.cells[0].mix.find((m) => m.key === OTHER_KEY);
    // The three smallest apps: 10 + 20 + 30 over 10 samples.
    expect(other?.value).toBe(6);
  });

  it("an hour never sampled is an empty cell; a sampled hour with no connections is a real zero; neither has a mix", () => {
    const h = history(
      [[MONDAY + 3 * HOUR, 10]],
      [],
    );
    const g = heatGrid(historySeries(h, { periodMs: 28 * DAY, to: MONDAY + DAY }, { series: SERIES, slots: { chrome: 1, slack: 2 }, top: new Set(["chrome", "slack"]) }));
    expect(g.cells[3]).toMatchObject({ hours: 1, total: 0, mix: [] });
    expect(g.cells[4]).toMatchObject({ hours: 0, total: 0, mix: [] });
    expect(g.max).toBe(0);
    const empty = heatGrid({ series: [], points: [] });
    expect(empty.cells.every((c) => c.hours === 0 && c.mix.length === 0)).toBe(true);
    expect([empty.max, empty.hours, empty.first]).toEqual([0, 0, null]);
  });

  it("mock history (4 weeks) is busier on weekday afternoons than at night", async () => {
    const now = MONDAY + 28 * DAY;
    const src = createMockSource({ seed: 1, now: () => now });
    const g = heatGrid(historySeries(await src.history(hours({ from: now - 28 * DAY, to: now })), { periodMs: 28 * DAY, to: now }, EMPTY_SET));
    expect(g.hours).toBe(28 * 24);
    expect(g.cells[2 * 24 + 14].total).toBeGreaterThan(g.max * 0.6);
    expect(g.cells[2 * 24 + 3].total).toBeLessThan(g.max * 0.25);
  });
});

describe("share percentages", () => {
  it("are whole numbers that add up to exactly 100", () => {
    const thirds = sharePercents([{ share: 1 / 3 }, { share: 1 / 3 }, { share: 1 / 3 }]);
    expect(thirds).toEqual([34, 33, 33]);
    expect(sharePercents([{ share: 0.416 }, { share: 0.3 }, { share: 0.284 }])).toEqual([42, 30, 28]);
    // A tie on the remainder goes to the earlier part (the view says "<1%" for a 0 with a share).
    expect(sharePercents([{ share: 0.995 }, { share: 0.005 }])).toEqual([100, 0]);
    expect(sharePercents([])).toEqual([]);
  });
});

describe("heat stack", () => {
  const cell = (total: number, parts: [string, number, number][]): Pick<HeatCell, "total" | "mix"> => ({
    total,
    mix: parts.map(([key, slot, share]) => ({ key, slot, name: key, share, value: share * total })),
  });
  const height = (segs: { y0: number; y1: number }[]) => (segs.length ? segs[segs.length - 1].y1 - segs[0].y0 : 0);

  it("is as tall as the cell's total against the max, split bottom-up in legend order", () => {
    const c = cell(100, [
      ["chrome", 1, 0.5],
      ["slack", 2, 0.3],
      [OTHER_KEY, 0, 0.2],
    ]);
    const s = heatStack(c, 100, 20);
    expect(s.map((x) => [x.key, x.y0, x.y1])).toEqual([
      ["chrome", 0, 10],
      ["slack", 10, 16],
      [OTHER_KEY, 16, 20],
    ]);
    expect(height(heatStack(c, 200, 20))).toBe(10);
    expect(height(heatStack(c, 400, 20))).toBe(5);
  });

  it("folds slivers under MIN_SEGMENT_PX into Other, keeping the stack's height", () => {
    // 20 px stack: zoom 5 % = 1 px and teams 4 % = 0.8 px are slivers; Other 6 % + both = 3 px.
    const c = cell(100, [
      ["chrome", 1, 0.6],
      ["slack", 2, 0.25],
      ["zoom", 3, 0.05],
      ["teams", 4, 0.04],
      [OTHER_KEY, 0, 0.06],
    ]);
    const s = heatStack(c, 100, 20);
    expect(s.map((x) => x.key)).toEqual(["chrome", "slack", OTHER_KEY]);
    expect(height(s)).toBe(20);
    const other = s.at(-1)!;
    expect(other.y1 - other.y0).toBe(3);
    for (const x of s) expect(x.y1 - x.y0).toBeGreaterThanOrEqual(MIN_SEGMENT_PX);
  });

  it("a short stack still shows who dominated it: the largest part never folds and takes a sliver Other", () => {
    // 2 px stack (5 % of the max, raised to MIN_STACK_PX): every part is a sliver.
    const c = cell(5, [
      ["chrome", 1, 0.3],
      ["slack", 2, 0.5],
      [OTHER_KEY, 0, 0.2],
    ]);
    const s = heatStack(c, 100, 20);
    expect(s.map((x) => [x.key, x.y0, x.y1])).toEqual([["slack", 0, MIN_STACK_PX]]);
  });

  it("no activity or no data draws nothing: never a fake stack", () => {
    expect(heatStack(cell(0, []), 100, 20)).toEqual([]);
    expect(heatStack(cell(10, [["chrome", 1, 1]]), 0, 20)).toEqual([]);
    expect(heatStack(cell(10, [["chrome", 1, 1]]), 10, 0)).toEqual([]);
  });
});

describe("heat caption", () => {
  const to = MONDAY + 28 * DAY + 15 * HOUR + 20 * 60_000;
  const range = { from: to - 28 * DAY, to };

  it("derives from the buckets returned, never from the source kind", async () => {
    // Mock, 4 weeks: the buckets reach back to the start of the range.
    const src = createMockSource({ seed: 1, now: () => to });
    const grid = async (r: { from: number; to: number }) =>
      heatGrid(historySeries(await src.history(hours(r)), { periodMs: r.to - r.from, to: r.to }, EMPTY_SET));
    expect(heatCaption(await grid(range), range)).toBe("Last 4 weeks");
    // A history that started today (a fresh install): the first bucket is today.
    expect(heatCaption({ first: to - 2 * HOUR - 20 * 60_000 }, range)).toMatch(/^Since \d/);
    // A shorter history that started on an earlier day names the day.
    expect(heatCaption({ first: to - 3 * DAY }, range)).toMatch(/^Since [A-Za-z]+\.? \d/);
    expect(heatCaption(heatGrid({ series: [], points: [] }), range)).toBe("No history yet");
    const week = { from: to - 7 * DAY, to };
    expect(heatCaption(await grid(week), week)).toBe("Last week");
  });
});
