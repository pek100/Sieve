import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { OTHER_KEY, SERIES_COUNT } from "@/core/series";
import { createMockSource } from "@/data/mock-source";
import type { Clock } from "@/data/poller";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { HomeScreen } from "./home-screen";

/** Manual clock: timers fire only when the test advances time (same idea as poller.test.ts). */
function fakeClock(start = 1_760_000_000_000) {
  let now = start;
  let seq = 0;
  const timers = new Map<number, { at: number; fn: () => void }>();
  const clock: Clock = {
    now: () => now,
    setTimeout: (fn, ms) => {
      const id = ++seq;
      timers.set(id, { at: now + ms, fn });
      return id;
    },
    clearTimeout: (h) => void timers.delete(h as number),
  };
  const flush = () => new Promise<void>((r) => setTimeout(r, 0));
  return {
    clock,
    flush,
    async advance(ms: number) {
      const target = now + ms;
      for (;;) {
        const due = [...timers.entries()].filter(([, t]) => t.at <= target).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        timers.delete(due[0]);
        now = due[1].at;
        due[1].fn();
        await flush();
      }
      now = target;
      await flush();
    },
  };
}

async function setup(scenario: "steady" | "empty" | "error" = "steady", seconds = 60) {
  const fc = fakeClock();
  const source = createMockSource({ seed: 1, scenario, now: fc.clock.now });
  const runtime = createRuntime({ source, settings: memoryBackend(), clock: fc.clock });
  render(
    <SieveProvider runtime={runtime}>
      <HomeScreen />
    </SieveProvider>,
  );
  await act(async () => {
    await runtime.settings.ready;
    await fc.flush();
  });
  await act(() => fc.advance(seconds * 1000));
  return { runtime, fc };
}

const chart = () => screen.getByRole("region", { name: "Connections per app" });
const areas = () => [...chart().querySelectorAll<SVGPathElement>('path[data-part="area"]')];
const legendChips = () => within(within(chart()).getByRole("list", { name: "Series" })).getAllByRole("button");

/** Upper-edge y values of a line path ("M x y L x y ..."). */
const ys = (d: string) => d.slice(1).split("L").map((pt) => Number(pt.trim().split(" ")[1]));

describe("home chart", () => {
  it("shows at most 6 named series plus Other; toggling a legend chip removes it and restacks", async () => {
    await setup();
    const chips = legendChips();
    expect(chips.length).toBeLessThanOrEqual(SERIES_COUNT + 1);
    expect(chips.at(-1)).toHaveTextContent("Other");
    const keys = areas().map((p) => p.dataset.series);
    expect(keys).toHaveLength(chips.length);
    expect(keys.at(-1)).toBe(OTHER_KEY);

    // Hide the bottom series: its path goes, the one above drops onto the baseline.
    const bottom = keys[0]!;
    const second = keys[1]!;
    const secondBefore = chart().querySelector(`path[data-series="${second}"][data-part="area"]`)!.getAttribute("d");
    await userEvent.click(chips[0]);
    expect(chips[0]).toHaveAttribute("aria-pressed", "false");
    expect(chart().querySelector(`path[data-series="${bottom}"]`)).toBeNull();
    const secondAfter = chart().querySelector(`path[data-series="${second}"][data-part="area"]`)!.getAttribute("d");
    expect(secondAfter).not.toBe(secondBefore);
    // Its lower edge is now the baseline: the closing vertex sits at y = 200.
    expect(secondAfter!.replace(/Z$/, "").split("L").at(-1)!.trim().split(" ")[1]).toBe("200");

    // Toggle back on.
    await userEvent.click(chips[0]);
    expect(chips[0]).toHaveAttribute("aria-pressed", "true");
    expect(chart().querySelector(`path[data-series="${bottom}"][data-part="area"]`)).not.toBeNull();
  });

  it("a live tick keeps the same path nodes and no series restarts from zero", async () => {
    const { fc } = await setup();
    const svg = chart().querySelector("svg[data-chart-plot]")!;
    const before = new Map(areas().map((p) => [p.dataset.series!, p]));
    const lineBefore = new Map(
      [...chart().querySelectorAll<SVGPathElement>('path[data-part="line"]')].map((p) => [p.dataset.series!, p.getAttribute("d")!]),
    );
    await act(() => fc.advance(1000));
    let same = 0;
    for (const p of areas()) {
      const old = before.get(p.dataset.series!);
      if (!old) continue;
      expect(p).toBe(old);
      same += 1;
    }
    expect(same).toBeGreaterThanOrEqual(SERIES_COUNT - 1);
    // One more vertex per line, and every line with data stays off the baseline.
    for (const line of chart().querySelectorAll<SVGPathElement>('path[data-part="line"]')) {
      const prev = lineBefore.get(line.dataset.series!);
      const d = line.getAttribute("d")!;
      if (prev) expect(ys(d).length).toBe(ys(prev).length + 1);
      expect(Math.min(...ys(d))).toBeLessThan(200);
    }
    // The tick moved the bucket times, so the plot slides instead of morphing.
    expect(svg).toHaveAttribute("data-sliding");
  });
});

describe("home copy and KPIs", () => {
  it("never says ads, trackers or blocked; KPI labels name connections, hosts or ports", async () => {
    await setup();
    expect(document.body.textContent ?? "").not.toMatch(/\b(ads|trackers|blocked)\b/i);
    const tiles = screen.getByRole("group", { name: "Right now" }).querySelectorAll("section[data-kpi]");
    expect(tiles).toHaveLength(4);
    for (const t of tiles) expect(t.getAttribute("aria-label")).toMatch(/connections|hosts|ports/i);
    // Numbers are shown, with a delta chip each.
    expect(within(tiles[1] as HTMLElement).getByText(/^\d+$/)).toBeInTheDocument();
    expect(tiles[1].querySelector("[data-dir]")).not.toBeNull();
    // At most one accent container tile.
    expect([...tiles].filter((t) => t.className.includes("bg-mint-container"))).toHaveLength(1);
  });

  it("every icon-only button has an accessible name", async () => {
    await setup();
    for (const b of screen.getAllByRole("button")) expect(b).toHaveAccessibleName();
  });

  it("top apps are tinted with their chart colour", async () => {
    await setup();
    const list = within(screen.getByRole("region", { name: "Top apps" })).getByRole("list");
    const rows = within(list).getAllByRole("listitem");
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.length).toBeLessThanOrEqual(SERIES_COUNT);
    const charted = new Set(areas().map((p) => p.dataset.series));
    const first = rows[0].getAttribute("data-app")!;
    if (charted.has(first)) expect(rows[0].innerHTML).toMatch(/bg-series-[1-6]/);
  });
});

describe("home pause", () => {
  it("the pause pill pauses the poller with a banner; resume restarts it", async () => {
    const { runtime } = await setup();
    await userEvent.click(screen.getByRole("button", { name: "Pause" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "For 15 minutes" }));
    const st = runtime.store.getState().status;
    expect(st.pausedUntil).not.toBeNull();
    expect(screen.getAllByText(/^Paused until/).length).toBeGreaterThan(0);
    expect(screen.getByRole("note")).toHaveTextContent(/Sampling is paused until/);

    await userEvent.click(screen.getByRole("button", { name: "Resume" }));
    expect(runtime.store.getState().status.pausedUntil).toBeNull();
    expect(screen.queryByRole("note")).toBeNull();
    expect(screen.getByRole("button", { name: "Pause" })).toBeEnabled();
  });
});

describe("home states", () => {
  it("scenario empty shows one serif line and one action", async () => {
    await setup("empty", 5);
    const serif = document.querySelectorAll(".font-serif");
    expect(serif).toHaveLength(1);
    expect(serif[0]).toHaveTextContent("Nothing is talking right now");
    expect(within(chart()).getByRole("button", { name: "Show the whole session" })).toBeInTheDocument();
  });

  it("scenario error shows the error card and no numbers", async () => {
    await setup("error", 5);
    expect(within(chart()).getByRole("alert")).toHaveTextContent(/scenario error/);
    const tiles = screen.getByRole("group", { name: "Right now" });
    expect(tiles.textContent).not.toMatch(/\d/);
    expect(within(tiles).getAllByText("No data")).toHaveLength(4);
    expect(within(screen.getByRole("region", { name: "Top apps" })).getByRole("alert")).toBeInTheDocument();
  });

  it("shows skeletons before the first sample", () => {
    const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend(), clock: fakeClock().clock });
    render(
      <SieveProvider runtime={runtime}>
        <HomeScreen />
      </SieveProvider>,
    );
    expect(chart()).toHaveAttribute("aria-busy", "true");
  });
});
