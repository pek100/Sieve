import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { heatGrid, type HeatGrid } from "@/core/heat";
import { historySeries } from "@/core/history";
import { EMPTY_SET, SERIES_COUNT } from "@/core/series";
import { createMockSource } from "@/data/mock-source";
import { cellBox, cellLabel, Heatmap, moveCell } from "./heatmap";

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

describe("heatmap cells", () => {
  it("each cell draws its heatStack segments, bottom-up in legend order, in the series colours", async () => {
    const grid = await mockGrid();
    const { container } = render(<Heatmap grid={grid} caption="Last 4 weeks" base={{ kind: "ready" }} />);
    const order = grid.series.map((s) => s.key);
    let stacked = 0;
    for (const g of plot(container).querySelectorAll<SVGGElement>("g[data-cell]")) {
      const cell = grid.cells[Number(g.dataset.index)];
      const rects = [...g.querySelectorAll<SVGRectElement>("rect[data-series]")];
      if (cell.total === 0) expect(rects).toHaveLength(0);
      else expect(rects.length).toBeGreaterThan(0);
      // Bottom-up: each segment sits above the one before it, in legend order.
      const ys = rects.map((r) => Number(r.getAttribute("y")));
      expect(ys).toEqual([...ys].sort((a, b) => b - a));
      const idx = rects.map((r) => order.indexOf(r.dataset.series!));
      expect(idx).toEqual([...idx].sort((a, b) => a - b));
      for (const r of rects) {
        const slot = grid.series.find((s) => s.key === r.dataset.series)!.slot;
        expect(r.getAttribute("class")).toBe(slot === 0 ? "fill-series-other" : `fill-series-${slot}`);
      }
      if (rects.length >= 3) stacked += 1;
    }
    expect(stacked).toBeGreaterThan(20);
  });

  it("a cell with no data is the quiet track alone, never a fake stack", async () => {
    const grid = await mockGrid();
    // Keep only Wednesdays: every other day is unseen.
    const wed = heatGrid({ series: grid.series, points: [] });
    const cells = grid.cells.map((c, i) => (c.day === 2 ? c : wed.cells[i]));
    const { container } = render(<Heatmap grid={{ ...grid, cells }} caption="Since Wed 00:00" base={{ kind: "ready" }} />);
    const mon = plot(container).querySelector('g[data-day="0"][data-hour="14"]')!;
    expect(mon.querySelectorAll("rect")).toHaveLength(1);
    expect(mon.querySelector("rect")!.getAttribute("class")).toContain("opacity-50");
    expect(mon).toHaveAccessibleName("Mon 14:00, no data for this hour yet");
    const wed14 = plot(container).querySelector('g[data-day="2"][data-hour="14"]')!;
    expect(wed14.querySelectorAll("rect[data-series]").length).toBeGreaterThan(1);
  });

  it("every cell has an accessible name: when, how busy, then who with whole percentages, largest first", async () => {
    const grid = await mockGrid();
    render(<Heatmap grid={grid} caption="Last 4 weeks" base={{ kind: "ready" }} />);
    const map = screen.getByRole("group", { name: /^Connections by app, weekday and hour, last 4 weeks\. Busiest: \w{3} \d\d:00\./ });
    const cells = within(map).getAllByRole("img");
    expect(cells).toHaveLength(168);
    const c = grid.cells[2 * 24 + 14];
    const name = cellLabel(c);
    expect(within(map).getByRole("img", { name })).toBe(cells[2 * 24 + 14]);
    expect(name).toMatch(/^Wed 14:00, \d+ open connections on average: /);
    const pcts = [...name.matchAll(/ (\d+)%/g)].map((m) => Number(m[1]));
    expect(pcts.reduce((a, b) => a + b, 0)).toBe(100);
    expect(pcts).toEqual([...pcts].sort((a, b) => b - a));
    expect(pcts).toHaveLength(c.mix.length);
  });

  it("hovering a cell shows a portal tooltip: the hour, the total, then each app's share with its colour, largest first", async () => {
    const grid = await mockGrid();
    const { container } = render(<Heatmap grid={grid} caption="Last 4 weeks" base={{ kind: "ready" }} />);
    const svg = plot(container);
    // jsdom lays nothing out: give the plot the fallback's size at the origin.
    const vb = svg.getAttribute("viewBox")!.split(" ").map(Number);
    vi.spyOn(svg, "getBoundingClientRect").mockReturnValue({ left: 0, top: 0, width: vb[2], height: vb[3], right: vb[2], bottom: vb[3], x: 0, y: 0, toJSON: () => ({}) });
    const box = cellBox(2, 14, vb[2], vb[3]);
    fireEvent.pointerMove(svg, { clientX: box.x + box.w / 2, clientY: box.y + box.h / 2 });
    const tip = screen.getByRole("tooltip");
    expect(container.contains(tip)).toBe(false);
    expect(tip.closest("[title]")).toBeNull();
    const c = grid.cells[2 * 24 + 14];
    expect(tip).toHaveTextContent(/^Wed 14:00 to 15:00/);
    expect(tip).toHaveTextContent(`${Math.round(c.total)} open connections on average`);
    const rows = within(tip).getAllByRole("listitem");
    expect(rows).toHaveLength(c.mix.length);
    const largest = [...c.mix].sort((a, b) => b.share - a.share);
    rows.forEach((row, i) => {
      expect(row).toHaveTextContent(largest[i].name);
      expect(row.querySelector("span")!.className).toContain(largest[i].slot === 0 ? "bg-series-other" : `bg-series-${largest[i].slot}`);
    });
    expect(plot(container).querySelector("[data-heat-ring]")).not.toBeNull();
    fireEvent.pointerLeave(svg);
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("the keyboard reaches the map with one Tab and moves through cells with the arrows", async () => {
    const grid = await mockGrid();
    const { container } = render(<Heatmap grid={grid} caption="Last 4 weeks" base={{ kind: "ready" }} />);
    expect(plot(container).querySelectorAll('[tabindex="0"]')).toHaveLength(1);
    const user = userEvent.setup();
    await user.tab();
    expect(document.activeElement).toHaveAttribute("data-index", "0");
    expect(screen.getByRole("tooltip")).toHaveTextContent(/^Mon 00:00 to 01:00/);
    await user.keyboard("{ArrowRight}{ArrowRight}{ArrowDown}");
    expect(document.activeElement).toHaveAttribute("data-index", String(1 * 24 + 2));
    expect(screen.getByRole("tooltip")).toHaveTextContent(/^Tue 02:00 to 03:00/);
    await user.keyboard("{End}");
    expect(document.activeElement).toHaveAttribute("data-index", String(1 * 24 + 23));
    await user.keyboard("{ArrowRight}{ArrowUp}{ArrowUp}");
    expect(document.activeElement).toHaveAttribute("data-index", "23");
    // Still one tab stop, now on the focused cell; leaving the map hides the tooltip.
    expect(plot(container).querySelector('[tabindex="0"]')).toHaveAttribute("data-index", "23");
    await user.tab();
    expect(screen.queryByRole("tooltip")).toBeNull();
    expect(moveCell(0, [-1, -1])).toBe(0);
    expect(moveCell(167, [1, 1])).toBe(167);
  });

  it("the legend is the chart's series in order, with their colours", async () => {
    const grid = await mockGrid();
    render(<Heatmap grid={grid} caption="Last 4 weeks" base={{ kind: "ready" }} />);
    const items = within(screen.getByRole("list", { name: "Apps in the map" })).getAllByRole("listitem");
    expect(items.map((li) => li.textContent)).toEqual(grid.series.map((s) => s.name));
    expect(items.at(-1)!.textContent).toBe("Other");
    items.forEach((li, i) => {
      const slot = grid.series[i].slot;
      expect(li.querySelector("span")!.className).toContain(slot === 0 ? "bg-series-other" : `bg-series-${slot}`);
    });
  });

  it("no history: says so, draws no map", () => {
    render(<Heatmap grid={heatGrid({ series: [], points: [] })} caption="No history yet" base={{ kind: "ready" }} />);
    expect(screen.getByText(/No activity recorded yet/)).toBeInTheDocument();
    expect(document.querySelector("svg[data-heat-plot]")).toBeNull();
    render(<Heatmap grid={null} caption="" base={{ kind: "loading" }} />);
  });
});

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
