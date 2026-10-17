import { expect, test, type Page } from "@playwright/test";

const HOME = "/?source=mock&seed=1";

async function openHome(page: Page, query = HOME) {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(query);
  return errors;
}

/** Wait until the chart holds at least `points` samples (one per second at the default interval). */
async function waitForData(page: Page, points = 2) {
  const line = page.getByRole("region", { name: "Connections per app" }).locator('path[data-part="line"]').first();
  await expect(line).toBeAttached();
  await expect
    .poll(async () => ((await line.getAttribute("d")) ?? "").split("L").length, { timeout: 15_000 })
    .toBeGreaterThanOrEqual(points);
  // Three snapshot numbers; the DNS tile says Off while the filter is off.
  await expect(page.locator("section[data-kpi] [data-numeric]")).toHaveCount(3);
  await expect(page.getByRole("region", { name: "When apps are busy" }).locator("[data-step]").first()).toBeVisible();
}

const regions = (page: Page) => ({
  chart: page.getByRole("region", { name: "Connections per app" }),
  kpis: page.getByRole("group", { name: "Right now" }),
  top: page.getByRole("region", { name: "Top apps" }),
  heat: page.getByRole("region", { name: "When apps are busy" }),
});

test.describe("home", () => {
  test("at 1280x800 the chart, 4 KPI tiles, top apps and heatmap fit with no scroll", async ({ page }, info) => {
    test.skip(info.project.name !== "desktop", "desktop layout only");
    const errors = await openHome(page);
    await waitForData(page, 8);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Sieving now");

    const dims = await page.evaluate(() => ({
      sh: document.documentElement.scrollHeight,
      sw: document.documentElement.scrollWidth,
      ih: window.innerHeight,
      iw: window.innerWidth,
    }));
    expect(dims.ih).toBe(800);
    expect(dims.sh).toBeLessThanOrEqual(dims.ih);
    expect(dims.sw).toBeLessThanOrEqual(dims.iw);

    const r = regions(page);
    const boxes = [r.chart, r.top, r.heat, ...(await page.locator("section[data-kpi]").all())];
    expect(boxes).toHaveLength(7);
    for (const loc of boxes) {
      const b = (await loc.boundingBox())!;
      expect(b.y).toBeGreaterThanOrEqual(0);
      expect(b.x).toBeGreaterThanOrEqual(0);
      expect(b.y + b.height).toBeLessThanOrEqual(800);
      expect(b.x + b.width).toBeLessThanOrEqual(1280);
    }
    // Three-column layout: chart two thirds next to the KPI block, top apps next to the heatmap.
    const chart = (await r.chart.boundingBox())!;
    const kpis = (await r.kpis.boundingBox())!;
    expect(Math.abs(chart.y - kpis.y)).toBeLessThan(2);
    expect(chart.width).toBeGreaterThan(kpis.width * 1.8);

    // First minute: the data already spans a good part of the plot, not a sliver at the right edge.
    const fill = await r.chart.evaluate((el) => {
      const plot = el.querySelector("svg[data-chart-plot]")!.getBoundingClientRect();
      const line = el.querySelector('path[data-part="line"]')!.getBoundingClientRect();
      return line.width / plot.width;
    });
    expect(fill).toBeGreaterThan(0.3);

    await page.screenshot({ path: "test-results/screens/home-desktop.png" });
    expect(errors).toEqual([]);
  });

  test("at 960x800 the grid is two columns", async ({ page }, info) => {
    test.skip(info.project.name !== "desktop", "desktop project resizes to 960");
    await page.setViewportSize({ width: 960, height: 800 });
    await openHome(page);
    await waitForData(page);
    const r = regions(page);
    const kpis = (await r.kpis.boundingBox())!;
    const top = (await r.top.boundingBox())!;
    const chart = (await r.chart.boundingBox())!;
    // KPI block and top apps share a row, side by side, each about half the width.
    expect(Math.abs(kpis.y - top.y)).toBeLessThan(2);
    expect(top.x).toBeGreaterThan(kpis.x + kpis.width);
    expect(Math.abs(kpis.width - top.width)).toBeLessThan(2);
    expect(chart.width).toBeGreaterThan(kpis.width * 1.9);
    const sw = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(sw).toBeLessThanOrEqual(0);
    await page.screenshot({ path: "test-results/screens/home-960.png", fullPage: true });
  });

  test("at 375 wide it is one column with no horizontal scroll", async ({ page }, info) => {
    test.skip(info.project.name !== "mobile", "mobile project only");
    await openHome(page);
    await waitForData(page, 6);
    const r = regions(page);
    const xs = await Promise.all([r.chart, r.kpis, r.top, r.heat].map(async (l) => (await l.boundingBox())!));
    for (const b of xs) {
      expect(Math.abs(b.x - xs[0].x)).toBeLessThan(2);
      expect(Math.abs(b.width - xs[0].width)).toBeLessThan(2);
    }
    const sw = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(sw).toBeLessThanOrEqual(0);
    // Card titles are not cut off: a header action that does not fit wraps under the title.
    for (const h of await page.getByRole("main").getByRole("heading", { level: 2 }).all()) {
      expect(await h.evaluate((e) => e.scrollWidth <= e.clientWidth)).toBe(true);
    }
    await page.screenshot({ path: "test-results/screens/home-mobile.png", fullPage: true });
  });

  test("with the DNS filter off, never says ads, trackers or blocked; tiles name apps, connections, hosts and the filter", async ({ page }) => {
    await openHome(page);
    await waitForData(page);
    const text = await page.locator("body").innerText();
    expect(text).not.toMatch(/\b(ads|trackers|blocked)\b/i);
    for (const tile of await page.locator("section[data-kpi]:not([data-dns-derived])").all()) {
      expect(await tile.getAttribute("aria-label")).toMatch(/apps|connections|hosts/i);
    }
    await expect(page.locator('section[data-kpi="apps"]')).toHaveAttribute("aria-label", "Sieved apps");
    await expect(page.locator('section[data-kpi="blocked"]')).toHaveAttribute("aria-label", "DNS filter");
  });

  test("the pause pill pauses until the chosen time and resume restarts sampling", async ({ page }, info) => {
    await openHome(page);
    await waitForData(page, 4);
    const status = page.getByRole("status");
    await expect(status).toHaveAttribute("data-phase", "live");
    await page.getByRole("main").getByRole("button", { name: "Pause" }).click();
    await page.getByRole("menuitem", { name: "For 5 minutes" }).click();
    await expect(status).toHaveAttribute("data-phase", "paused");
    await expect(status).toContainText(/Paused until \d/);
    await expect(page.getByRole("note")).toContainText("Sampling is paused until");
    // Resume is one control, and the status shows once per window (top bar).
    await expect(page.getByRole("button", { name: /resume/i })).toHaveCount(1);
    await expect(page.locator("[data-phase]")).toHaveCount(1);
    // The chip says the phase in words at every width, not only by its dot colour.
    await expect(status.locator("span:visible", { hasText: /Paused/ }).first()).toBeVisible();
    // ...and the wider chip does not slide under the nav.
    const nav = (await page.getByRole("navigation", { name: "Main" }).boundingBox())!;
    const chip = (await status.boundingBox())!;
    expect(chip.x).toBeGreaterThanOrEqual(nav.x + nav.width);
    await page.screenshot({ path: `test-results/screens/home-paused-${info.project.name}.png` });
    if (info.project.name === "desktop") {
      // The banner takes its height from the grid, not from the window: still no scroll at 1280x800.
      const dims = await page.evaluate(() => ({ sh: document.documentElement.scrollHeight, ih: window.innerHeight }));
      expect(dims.sh).toBeLessThanOrEqual(dims.ih);
      for (const loc of [regions(page).heat, regions(page).top, regions(page).chart]) {
        const b = (await loc.boundingBox())!;
        expect(b.y + b.height).toBeLessThanOrEqual(800);
      }
      // No KPI value (a number, or the DNS tile's Off line) is clipped by its tile.
      for (const tile of await page.locator("section[data-kpi]").all()) {
        const t = (await tile.boundingBox())!;
        const n = (await tile.locator("p").last().boundingBox())!;
        expect(n.y + n.height).toBeLessThanOrEqual(t.y + t.height);
      }
    }

    // Paused means no new samples: the newest bucket stays put.
    const d1 = await page.locator('path[data-part="line"]').first().getAttribute("d");
    await page.waitForTimeout(2200);
    expect(await page.locator('path[data-part="line"]').first().getAttribute("d")).toBe(d1);

    await page.getByRole("main").getByRole("button", { name: "Resume", exact: true }).click();
    await expect(status).toHaveAttribute("data-phase", "live");
    await expect(page.getByRole("note")).toHaveCount(0);
  });

  test("scenario empty shows one serif line and one action", async ({ page }, info) => {
    await openHome(page, "/?source=mock&seed=1&scenario=empty");
    const serif = page.locator(".font-serif");
    await expect(serif).toHaveCount(1);
    await expect(serif).toHaveText("Nothing is talking right now");
    await expect(regions(page).chart.getByRole("button", { name: "Show the whole session" })).toBeVisible();
    await page.screenshot({ path: `test-results/screens/home-empty-${info.project.name}.png`, fullPage: true });
  });

  test("scenario error shows the error card and no mock numbers", async ({ page }, info) => {
    await openHome(page, "/?source=mock&seed=1&scenario=error");
    const r = regions(page);
    await expect(r.chart.getByRole("alert")).toContainText("scenario error");
    // The three snapshot tiles; the DNS tile does not depend on the snapshot source and says Off.
    await expect(r.kpis.getByText("No data")).toHaveCount(3);
    expect(await r.kpis.innerText()).not.toMatch(/\d/);
    await expect(r.top.getByRole("alert")).toBeVisible();
    await expect(page.locator('path[data-part="area"]')).toHaveCount(0);
    await page.screenshot({ path: `test-results/screens/home-error-${info.project.name}.png`, fullPage: true });
  });
});
