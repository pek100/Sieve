import { describe, expect, it } from "vitest";
import { createMockSource } from "@/data/mock-source";
import { HEAT_STEPS, heatCaption, heatGrid, heatStep } from "./heat";

const HOUR = 3_600_000;
/** Monday 2026-10-12 00:00 local time. */
const MONDAY = new Date(2026, 9, 12, 0, 0, 0, 0).getTime();

describe("heat grid", () => {
  it("folds buckets into a 7 x 24 grid in local time, Monday first", () => {
    const g = heatGrid([
      { t: MONDAY + 9 * HOUR, flows: 100 },
      { t: MONDAY + 7 * 24 * HOUR + 9 * HOUR, flows: 300 },
      { t: MONDAY + 6 * 24 * HOUR + 23 * HOUR, flows: 50 },
    ]);
    expect(g.cells).toHaveLength(168);
    const mon9 = g.cells[0 * 24 + 9];
    expect([mon9.day, mon9.hour, mon9.value, mon9.hours]).toEqual([0, 9, 200, 2]);
    const sun23 = g.cells[6 * 24 + 23];
    expect([sun23.day, sun23.hour, sun23.value]).toEqual([6, 23, 50]);
    expect(g.max).toBe(200);
    expect(g.hours).toBe(3);
  });

  it("uses 4 steps: none, then thirds of the max", () => {
    expect(HEAT_STEPS).toBe(4);
    expect([0, 1, 33, 34, 66, 67, 100].map((v) => heatStep(v, 100))).toEqual([0, 1, 1, 2, 2, 3, 3]);
    expect(heatStep(5, 0)).toBe(0);
  });

  it("an empty history gives an all-zero grid", () => {
    const g = heatGrid([]);
    expect(g.max).toBe(0);
    expect(g.cells.every((c) => c.step === 0)).toBe(true);
  });

  it("mock history (4 weeks) is busier on weekday afternoons than at night", async () => {
    const now = MONDAY + 28 * 24 * HOUR;
    const src = createMockSource({ seed: 1, now: () => now });
    const g = heatGrid(await src.history({ from: now - 28 * 24 * HOUR, to: now }));
    expect(g.hours).toBe(28 * 24);
    expect(g.cells[2 * 24 + 14].step).toBe(3);
    expect(g.cells[2 * 24 + 3].step).toBe(1);
  });
});

describe("heat caption", () => {
  const to = MONDAY + 28 * 24 * HOUR + 15 * HOUR + 20 * 60_000;
  const range = { from: to - 28 * 24 * HOUR, to };

  it("derives from the buckets returned, never from the source kind", async () => {
    // Mock, 4 weeks: the buckets reach back to the start of the range.
    const src = createMockSource({ seed: 1, now: () => to });
    expect(heatCaption(heatGrid(await src.history(range)), range)).toBe("Last 4 weeks");
    // A session-only source (Tauri until persisted history): the first bucket is today.
    const session = heatGrid([{ t: to - 2 * HOUR - 20 * 60_000, flows: 10 }]);
    expect(heatCaption(session, range)).toMatch(/^Since \d/);
    // A shorter history that started on an earlier day names the day.
    const days = heatGrid([{ t: to - 3 * 24 * HOUR, flows: 10 }]);
    expect(heatCaption(days, range)).toMatch(/^Since [A-Za-z]+\.? \d/);
    expect(heatCaption(heatGrid([]), range)).toBe("No history yet");
    expect(heatCaption(heatGrid(await src.history({ from: to - 7 * 24 * HOUR, to })), { from: to - 7 * 24 * HOUR, to })).toBe(
      "Last week",
    );
  });
});
