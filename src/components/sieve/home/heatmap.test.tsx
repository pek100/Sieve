import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { heatGrid, type HeatGrid } from "@/core/heat";
import { historySeries } from "@/core/history";
import { EMPTY_SET, SERIES_COUNT } from "@/core/series";
import { createMockSource } from "@/data/mock-source";
import { Heatmap } from "./heatmap";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
/** Monday 2026-10-12 00:00 local time, four weeks on. */
const NOW = new Date(2026, 9, 12, 0, 0, 0, 0).getTime() + 28 * DAY;

/** Four weeks of the mock's saved history, ranked by itself (6 apps plus Other), as Home folds it. */
async function mockGrid(seed = 1): Promise<HeatGrid> {
  const src = createMockSource({ seed, now: () => NOW });
  const h = await src.history({ from: NOW - 28 * DAY, to: NOW, grain: "hour", step: HOUR });
  return heatGrid(historySeries(h, { periodMs: 28 * DAY, to: NOW }, EMPTY_SET));
}

const plot = (c: HTMLElement) => c.querySelector<SVGSVGElement>("svg[data-heat-plot]")!;

describe("heatmap performance", () => {
  it("draws 168 cells in one SVG: a track each plus at most 7 segments, nothing per cell beyond that", async () => {
    const grid = await mockGrid();
    expect(grid.series).toHaveLength(SERIES_COUNT + 1);
    const t0 = performance.now();
    const { container } = render(<Heatmap grid={grid} caption="Last 4 weeks" base={{ kind: "ready" }} />);
    const ms = performance.now() - t0;
    const svgs = container.querySelectorAll("svg[data-heat-plot]");
    expect(svgs).toHaveLength(1);
    const cells = plot(container).querySelectorAll("g[data-cell]");
    expect(cells).toHaveLength(168);
    const segments = plot(container).querySelectorAll("rect[data-series]").length;
    const nodes = plot(container).querySelectorAll("*").length;
    // A g, a track and its segments per cell; no hover ring while nothing is pointed at.
    expect(nodes).toBe(168 * 2 + segments);
    expect(segments).toBeLessThanOrEqual(168 * (SERIES_COUNT + 1));
    for (const c of cells) expect(Number(c.getAttribute("data-segments"))).toBe(c.querySelectorAll("rect[data-series]").length);
    // jsdom is far slower than a browser; this only catches an accidental blow-up (it measured well under this).
    expect(ms).toBeLessThan(1500);
    console.info(`heatmap: ${nodes} SVG nodes (${segments} segments), first render ${ms.toFixed(0)} ms in jsdom`);
  });
});
