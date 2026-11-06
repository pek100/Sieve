import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { STRANDED_DNS_TEXT } from "@/core/dns";
import { OTHER_KEY, SERIES_COUNT } from "@/core/series";
import { createMockEngine } from "@/data/engine-mock";
import { createMockSource } from "@/data/mock-source";
import type { Clock } from "@/data/poller";
import { createMockWindowsDns } from "@/data/safety-net";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { HomeScreen } from "./home-screen";
import { WINDOWS } from "./use-home";

// Each setup drives 45 one-second ticks through React (about 1.7 s alone); under the
// full parallel suite that passed the 5 s default and the overrun cascaded into the next tests.
vi.setConfig({ testTimeout: 20_000 });

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

async function setup(scenario: "steady" | "empty" | "error" = "steady", seconds = 45) {
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

  it("switching the window changes only the time range: same legend, same path nodes, new scale", async () => {
    const { runtime } = await setup("steady", 30);
    // Freeze the data so only the switch can change anything.
    act(() => runtime.poller.pauseFor(5));
    const legend = () => legendChips().map((b) => b.textContent);
    const before = legend();
    const nodes = [...chart().querySelectorAll("svg[data-chart-plot] path")];
    const scaleNow = () => chart().querySelector("g[data-slide]")!.getAttribute("data-scale")!;
    const scales: string[] = [];
    for (const w of [...WINDOWS.slice(1), WINDOWS[0]]) {
      await userEvent.click(within(chart()).getByRole("radio", { name: w.label }));
      if (w.history) await vi.waitFor(() => expect(chart().querySelector('path[data-part="line"]')!.getAttribute("d")!.split("L").length).toBeGreaterThan(80));
      expect(legend()).toEqual(before);
      const now = [...chart().querySelectorAll("svg[data-chart-plot] path")];
      expect(now).toHaveLength(nodes.length);
      now.forEach((p, i) => expect(p).toBe(nodes[i]));
      scales.push(scaleNow());
    }
    // One hour spans the unit: 1 h is scale 1, 5 min 12, 14 d 1/336.
    expect(scales).toEqual(["1", "0.5", "0.042", "0.006", "0.003", "12"]);
  });

  it("when the data covers less than the window, the plot says where it starts", async () => {
    await setup("steady", 30);
    await userEvent.click(within(chart()).getByRole("radio", { name: "1 h" }));
    const start = chart().querySelector<HTMLElement>("[data-data-start]")!;
    expect(start).not.toBeNull();
    expect(start).toHaveTextContent(/^Sieve started \d/);
    // 30 s of a 1 h window: the boundary sits near the right edge.
    expect(parseFloat(start.style.width)).toBeGreaterThan(95);
  });
});
const CLAIMS = /\b(ads|trackers|blocked)\b/i;

describe("home copy and KPIs", () => {
  it("law: Home never says ads, trackers or blocked; the fourth tile is the engine, from facts, linking to Settings > Engine", async () => {
    await setup();
    expect(document.body.textContent ?? "").not.toMatch(CLAIMS);
    const group = screen.getByRole("group", { name: "Right now" });
    const tiles = group.querySelectorAll("section[data-kpi]");
    expect(tiles).toHaveLength(4);
    // Snapshot tiles name apps, connections or hosts.
    for (const t of group.querySelectorAll("section[data-kpi]:not([data-kpi=engine])")) {
      expect(t.getAttribute("aria-label")).toMatch(/apps|connections|hosts/i);
    }
    // The apps count is isSieved (effectively on, with a connection): sieved apps, and its label says so.
    expect(group.querySelector('section[data-kpi="apps"]')).toHaveAttribute("aria-label", "Sieved apps");
    // No DNS filter tile: the app-hosted filter is gone.
    expect(group.querySelector('[data-kpi="blocked"], [data-dns-derived]')).toBeNull();
    expect(screen.queryByText(/DNS filter/)).toBeNull();
    const engine = group.querySelector<HTMLElement>('section[data-kpi="engine"]')!;
    expect(engine).toHaveAttribute("aria-label", "Engine");
    // The mock engine is not installed (a browser has none).
    await vi.waitFor(() => expect(engine).toHaveAttribute("data-engine-phase", "not_installed"));
    expect(within(engine).getByText("Not installed")).toBeInTheDocument();
    expect(within(engine).getByRole("link", { name: "Details in Settings" })).toHaveAttribute("href", expect.stringMatching(/^\/settings\/?#engine$/));
    // Numbers are shown, with a delta chip each.
    expect(within(tiles[1] as HTMLElement).getByText(/^\d+$/)).toBeInTheDocument();
    expect(tiles[1].querySelector("[data-dir]")).not.toBeNull();
    // One accent tile, mint by its number only: no tile has a container (surface, border, elevation, radius).
    expect([...tiles].filter((t) => t.hasAttribute("data-accent"))).toHaveLength(1);
    expect(tiles[0].querySelector("[data-numeric]")!.className).toContain("text-primary");
    for (const t of tiles) expect(t.className).not.toMatch(/\b(bg-|shadow-|rounded|border|p-\d)/);
  });

  it("law, the engine filtering hosts: Home says the state and never says blocked", async () => {
    const runtime = createRuntime({
      source: createMockSource({ seed: 1 }),
      settings: memoryBackend({ schema: 5, values: { "filtering.engine": true } }),
      engine: createMockEngine("hosts"),
    });
    render(
      <SieveProvider runtime={runtime}>
        <HomeScreen />
      </SieveProvider>,
    );
    const engine = () => screen.getByRole("group", { name: "Right now" }).querySelector<HTMLElement>('section[data-kpi="engine"]')!;
    await vi.waitFor(() => expect(engine()).toHaveAttribute("data-engine-phase", "filtering"));
    expect(within(engine()).getByText("Filtering hosts")).toBeInTheDocument();
    expect(document.body.textContent ?? "").not.toMatch(CLAIMS);
  });

  it("law, settings from an old build with DNS filtering on: nothing starts, Home never says blocked, the safety banner points to Windows only", async () => {
    const fc = fakeClock();
    const runtime = createRuntime({
      source: createMockSource({ seed: 1, now: fc.clock.now }),
      settings: memoryBackend({ schema: 3, values: { "filtering.dns": true } }),
      clock: fc.clock,
      // An adapter asks 127.0.0.1 and ::1 (left by an old build).
      windowsDns: createMockWindowsDns({ pointed: true }),
    });
    render(
      <SieveProvider runtime={runtime}>
        <HomeScreen />
      </SieveProvider>,
    );
    await act(async () => {
      await runtime.settings.ready;
      await fc.flush();
    });
    await act(() => fc.advance(20_000));
    const banner = runtime.notices.list().find((n) => n.surface === "banner");
    expect(banner?.text).toBe(STRANDED_DNS_TEXT);
    expect(banner?.action).toBeUndefined();
    expect(screen.getByRole("group", { name: "Right now" }).querySelector('section[data-kpi="engine"]')).not.toBeNull();
    expect(document.body.textContent ?? "").not.toMatch(CLAIMS);
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
    expect(screen.getByRole("note")).toHaveTextContent(/Sampling is paused until/);
    // One control per job: Resume is the pill only; the phase lives on the top bar's master switch, not on Home.
    expect(screen.getAllByRole("button", { name: /resume/i })).toHaveLength(1);
    expect(document.querySelectorAll("[data-phase]")).toHaveLength(0);

    await userEvent.click(screen.getByRole("button", { name: "Resume" }));
    expect(runtime.store.getState().status.pausedUntil).toBeNull();
    expect(screen.queryByRole("note")).toBeNull();
    expect(screen.getByRole("button", { name: "Pause" })).toBeEnabled();
  });
});

describe("home paused banner (derived from status.pausedUntil)", () => {
  /** Home mounted or not, as when the user navigates to Apps and back. */
  function Routed({ home }: { home: boolean }) {
    return home ? <HomeScreen /> : <p>elsewhere</p>;
  }

  it("shows whoever paused, survives navigating away and back, and goes on a resume made elsewhere", async () => {
    const fc = fakeClock();
    const runtime = createRuntime({ source: createMockSource({ seed: 1, now: fc.clock.now }), settings: memoryBackend(), clock: fc.clock });
    const ui = (home: boolean) => (
      <SieveProvider runtime={runtime}>
        <Routed home={home} />
      </SieveProvider>
    );
    const { rerender } = render(ui(true));
    await act(async () => {
      await runtime.settings.ready;
      await fc.flush();
    });
    await act(() => fc.advance(3000));
    expect(screen.queryByRole("note")).toBeNull();

    // Paused by something other than the pill (the tray calls the same poller action).
    act(() => runtime.poller.pauseFor(5));
    expect(screen.getByRole("note")).toHaveTextContent(/Sampling is paused until/);

    // Navigate away and back while paused: the banner is still there.
    rerender(ui(false));
    rerender(ui(true));
    expect(screen.getByRole("note")).toHaveTextContent(/Sampling is paused until/);

    // Resume while Home is not mounted, then come back: no stale banner.
    rerender(ui(false));
    act(() => runtime.poller.resume());
    rerender(ui(true));
    expect(screen.queryByRole("note")).toBeNull();

    // A pause that runs out by itself takes the banner with it.
    act(() => runtime.poller.pauseFor(5));
    expect(screen.getByRole("note")).toBeInTheDocument();
    await act(() => fc.advance(5 * 60_000 + 1000));
    expect(screen.queryByRole("note")).toBeNull();
  });
});

describe("home history periods", () => {
  it("24 h, 7 d and 14 d draw named series from the source's history; KPIs stay live", async () => {
    await setup("steady", 10);
    for (const label of ["24 h", "7 d", "14 d"]) {
      await userEvent.click(within(chart()).getByRole("radio", { name: label }));
      await vi.waitFor(() => expect(areas().length).toBeGreaterThan(1));
      // Hundreds of history buckets, never the 10 live samples.
      const line = chart().querySelector('path[data-part="line"]')!.getAttribute("d")!;
      expect(line.split("L").length).toBeGreaterThan(80);
    }
    // Three snapshot numbers; the Engine tile has none.
    expect(document.querySelectorAll("section[data-kpi] [data-numeric]")).toHaveLength(3);
  });

  it("an empty history says so instead of drawing nothing", async () => {
    await setup("empty", 3);
    await userEvent.click(within(chart()).getByRole("radio", { name: "7 d" }));
    expect(await within(chart()).findByText("No history for this period yet")).toBeInTheDocument();
  });

  it("a failing history read is an error card on the chart, not a crash", async () => {
    await setup("error", 3);
    await userEvent.click(within(chart()).getByRole("radio", { name: "24 h" }));
    expect(await within(chart()).findByText(/History could not be read: .*scenario error/)).toBeInTheDocument();
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
    // The three snapshot tiles; the Engine tile does not depend on the snapshot source.
    expect(within(tiles).getAllByText("No data")).toHaveLength(3);
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
