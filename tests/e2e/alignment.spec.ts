import { expect, test, type Locator, type Page } from "@playwright/test";

/**
 * The alignment law (the user: "alignment, alignment, alignment").
 *
 * Every page sits on one 12 column grid inside one page container:
 * - the page title, every top-level region and the top bar's logo start on the container's left line;
 * - the header actions, every region and the top bar's right controls end on its right line;
 * - every region's left edge is a column start and its right edge a column end (within 1 px);
 * - siblings never overlap and keep at least the gutter between them;
 * - nothing overflows a region, the chart legend or the range control sideways;
 * - section headers that share a row share a top.
 * The gutter is 24 px on desktop and 16 px at 640 px and narrower, the same as the side padding.
 *
 * Measured on the mock source, at the desktop (1280x800, also 960x800) and mobile (375x812) projects.
 */

type Box = { x: number; y: number; width: number; height: number };
const right = (b: Box) => b.x + b.width;
const bottom = (b: Box) => b.y + b.height;
const TOL = 1;

const gutterFor = (width: number) => (width <= 640 ? 16 : 24);

function collectErrors(page: Page) {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  return errors;
}

/** Union of the visible boxes of an element's leaf content (so a stretched wrapper does not count). */
async function contentBox(loc: Locator): Promise<Box> {
  return loc.evaluate((root) => {
    let l = Infinity;
    let r = -Infinity;
    let t = Infinity;
    let b = -Infinity;
    for (const el of [root, ...root.querySelectorAll("*")]) {
      if (el.childElementCount > 0) continue;
      if (el.closest(".sr-only")) continue;
      const box = el.getBoundingClientRect();
      if (box.width === 0 || box.height === 0) continue;
      const cs = getComputedStyle(el);
      if (cs.visibility === "hidden" || cs.display === "none") continue;
      l = Math.min(l, box.left);
      r = Math.max(r, box.right);
      t = Math.min(t, box.top);
      b = Math.max(b, box.bottom);
    }
    return { x: l, y: t, width: r - l, height: b - t };
  });
}

/** The shared lines: page title left, header actions right, and the 12 column grid between them. */
async function gridLines(page: Page) {
  const vw = page.viewportSize()!.width;
  const g = gutterFor(vw);
  const title = (await page.getByRole("heading", { level: 1 }).boundingBox())!;
  // The header row: the first block of <main>, which holds the title.
  const header = page.getByRole("heading", { level: 1 }).locator("xpath=ancestor::main/div[1]");
  const actions = await header.evaluate((h) => {
    let r = -Infinity;
    for (const el of h.querySelectorAll("button, a, [role=switch]")) {
      if (el.closest("[data-notice-slot]")) continue;
      const b = el.getBoundingClientRect();
      if (b.width > 0) r = Math.max(r, b.right);
    }
    return r;
  });
  const L = title.x;
  const R = actions;
  const col = (R - L - 11 * g) / 12;
  const starts = Array.from({ length: 12 }, (_, i) => L + i * (col + g));
  const ends = starts.map((s) => s + col);
  return { L, R, g, col, starts, ends, vw };
}

const near = (x: number, lines: number[]) => lines.some((l) => Math.abs(l - x) <= TOL);

/**
 * `regions`: top-level siblings (snapped, no overflow, gutter apart).
 * `members`: things inside a region that must also run edge to edge on the grid (list rows); snapped, not compared as siblings.
 */
async function expectOnGrid(page: Page, regions: Record<string, Locator>, members: Record<string, Locator> = {}) {
  const grid = await gridLines(page);
  const bar = page.getByRole("banner");
  // The logo is the bar's first picture; the right controls are its right-most pressables.
  const logo = (await bar.locator("svg").first().boundingBox())!;
  const controls = await bar.evaluate((h) => {
    let r = -Infinity;
    for (const el of h.querySelectorAll("button, a, [role=switch]")) {
      const b = el.getBoundingClientRect();
      if (b.width > 0) r = Math.max(r, b.right);
    }
    return { x: r, y: 0, width: 0, height: 0 };
  });
  const failures: string[] = [];
  if (Math.abs(logo.x - grid.L) > TOL) failures.push(`top bar logo starts at ${logo.x.toFixed(1)}, page title at ${grid.L.toFixed(1)}`);
  if (Math.abs(right(controls) - grid.R) > TOL)
    failures.push(`top bar controls end at ${right(controls).toFixed(1)}, header actions at ${grid.R.toFixed(1)}`);
  if (grid.L < grid.g - TOL) failures.push(`page title at ${grid.L.toFixed(1)}, inside the ${grid.g} px side padding`);
  if (grid.vw - grid.R < grid.g - TOL) failures.push(`header actions end ${(grid.vw - grid.R).toFixed(1)} px from the edge`);

  const boxes: [string, Box][] = [];
  const all = [...Object.entries(regions).map(([n, l]) => [n, l, true] as const), ...Object.entries(members).map(([n, l]) => [n, l, false] as const)];
  for (const [name, loc, sibling] of all) {
    for (const [i, one] of (await loc.all()).entries()) {
      const b = await one.boundingBox();
      if (!b || b.width === 0) continue;
      const label = (await loc.count()) > 1 ? `${name}[${i}]` : name;
      if (!near(b.x, grid.starts)) failures.push(`${label} starts at ${b.x.toFixed(1)}, not on a column start`);
      if (!near(right(b), grid.ends)) failures.push(`${label} ends at ${right(b).toFixed(1)}, not on a column end`);
      const overflow = await one.evaluate((el) => el.scrollWidth - el.clientWidth);
      if (overflow > TOL) failures.push(`${label} overflows sideways by ${overflow} px`);
      if (sibling && i === 0) boxes.push([label, b]);
    }
  }
  // Siblings: no overlap, at least the gutter between them.
  for (let i = 0; i < boxes.length; i++)
    for (let j = i + 1; j < boxes.length; j++) {
      const [an, a] = boxes[i];
      const [bn, b] = boxes[j];
      const sameRow = Math.min(bottom(a), bottom(b)) - Math.max(a.y, b.y) > TOL;
      const sameCol = Math.min(right(a), right(b)) - Math.max(a.x, b.x) > TOL;
      if (sameRow && sameCol) failures.push(`${an} and ${bn} overlap`);
      else if (sameRow) {
        const gap = Math.max(b.x - right(a), a.x - right(b));
        if (gap < grid.g - TOL) failures.push(`${an} and ${bn} are ${gap.toFixed(1)} px apart, gutter ${grid.g}`);
      }
    }
  return { grid, failures };
}

async function noSidewaysOverflow(page: Page) {
  return page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
}

// ---------------------------------------------------------------- Home

async function openHome(page: Page, extra = "") {
  await page.goto(`/?source=mock&seed=1${extra}`);
  const line = page.getByRole("region", { name: "Connections per app" }).locator('path[data-part="line"]').first();
  await expect(line).toBeAttached();
  await expect.poll(async () => ((await line.getAttribute("d")) ?? "").split("L").length, { timeout: 15_000 }).toBeGreaterThanOrEqual(4);
  await expect(page.getByRole("region", { name: "When apps are busy" }).locator("[data-cell]").first()).toBeVisible();
}

const homeRegions = (page: Page) => ({
  chart: page.getByRole("region", { name: "Connections per app" }),
  kpis: page.getByRole("group", { name: "Right now" }),
  top: page.getByRole("region", { name: "Top apps" }),
  heat: page.getByRole("region", { name: "When apps are busy" }),
});

async function homeLaw(page: Page) {
  const r = homeRegions(page);
  const { grid, failures } = await expectOnGrid(page, r);
  const chart = (await r.chart.boundingBox())!;

  // Legend and range control stay inside the chart's column.
  const legend = r.chart.getByRole("list", { name: "Series" });
  const legendOverflow = await legend.evaluate((el) => el.scrollWidth - el.clientWidth);
  if (legendOverflow > TOL) failures.push(`legend overflows by ${legendOverflow} px`);
  for (const chip of await legend.getByRole("listitem").all()) {
    const b = (await chip.boundingBox())!;
    if (b.x < chart.x - TOL || right(b) > right(chart) + TOL) failures.push(`legend chip at ${b.x.toFixed(1)}..${right(b).toFixed(1)} leaves the chart column`);
  }
  for (const ctl of await r.chart.getByRole("radiogroup", { name: "Chart window" }).all()) {
    if (!(await ctl.isVisible())) continue;
    const b = (await ctl.boundingBox())!;
    if (b.x < chart.x - TOL || right(b) > right(chart) + TOL) failures.push(`range control ${b.x.toFixed(1)}..${right(b).toFixed(1)} leaves the chart column`);
    const o = await ctl.evaluate((el) => el.scrollWidth - el.clientWidth);
    if (o > TOL) failures.push(`range control overflows by ${o} px`);
  }

  // Rows: headers share a top; the KPI block spans the chart's header top to its plot bottom.
  const kpis = (await r.kpis.boundingBox())!;
  const top = (await r.top.boundingBox())!;
  const heat = (await r.heat.boundingBox())!;
  if (Math.min(bottom(chart), bottom(kpis)) - Math.max(chart.y, kpis.y) > 0) {
    const chartHeader = (await r.chart.locator("header").first().boundingBox())!;
    const kpiTop = await contentBox(r.kpis);
    // The first KPI label row is the chart header's row: same top, same height, so the label and the title share a centre line.
    const label = (await r.kpis.locator("[data-kpi-label]").first().boundingBox()) ?? kpiTop;
    if (Math.abs(chartHeader.y - label.y) > TOL) failures.push(`KPI block top ${label.y.toFixed(1)} vs chart header top ${chartHeader.y.toFixed(1)}`);
    if (Math.abs(chartHeader.height - label.height) > TOL && chartHeader.height < 48)
      failures.push(`KPI label row ${label.height.toFixed(1)} px tall, chart header ${chartHeader.height.toFixed(1)} px`);
    const plot = (await r.chart.locator("svg[data-chart-plot]").boundingBox())!;
    if (Math.abs(bottom(kpiTop) - bottom(plot)) > TOL) failures.push(`KPI block bottom ${bottom(kpiTop).toFixed(1)} vs plot bottom ${bottom(plot).toFixed(1)}`);
  }
  if (Math.min(bottom(top), bottom(heat)) - Math.max(top.y, heat.y) > 0) {
    const a = (await r.top.getByRole("heading", { level: 2 }).boundingBox())!;
    const b = (await r.heat.getByRole("heading", { level: 2 }).boundingBox())!;
    if (Math.abs(a.y - b.y) > TOL) failures.push(`Top apps title top ${a.y.toFixed(1)} vs heatmap title top ${b.y.toFixed(1)}`);
    if (Math.abs(bottom(a) - bottom(b)) > TOL) failures.push(`Top apps title baseline ${bottom(a).toFixed(1)} vs heatmap ${bottom(b).toFixed(1)}`);
  }

  // Top apps counts sit in their own column, right aligned, inside Top apps.
  const counts = await r.top.locator("[data-count]").all();
  if (counts.length === 0) failures.push("Top apps has no [data-count] column");
  const rights = new Set<number>();
  for (const c of counts) {
    const b = (await c.boundingBox())!;
    rights.add(Math.round(right(b)));
    if (right(b) > right(top) + TOL) failures.push(`a Top apps count ends at ${right(b).toFixed(1)}, outside Top apps`);
  }
  if (rights.size > 1) failures.push(`Top apps counts end at ${[...rights].join(", ")}: not one right-aligned column`);

  // Heatmap: day labels in their own column, centred on their rows; hour labels under their columns.
  const days = await r.heat.locator("[data-day-label]").all();
  if (days.length !== 7) failures.push(`heatmap has ${days.length} day labels`);
  for (const [d, label] of days.entries()) {
    const lb = (await label.boundingBox())!;
    const cell = (await r.heat.locator(`[data-day="${d}"][data-hour="0"]`).boundingBox())!;
    if (right(lb) > cell.x + TOL) failures.push(`day label ${d} runs into the cells`);
    if (Math.abs(lb.y + lb.height / 2 - (cell.y + cell.height / 2)) > TOL) failures.push(`day label ${d} is not centred on its row`);
  }
  for (const label of await r.heat.locator("[data-hour-label]").all()) {
    const h = Number(await label.getAttribute("data-hour-label"));
    const lb = (await label.boundingBox())!;
    const cell = (await r.heat.locator(`[data-day="6"][data-hour="${h}"]`).boundingBox())!;
    if (Math.abs(lb.x - cell.x) > TOL) failures.push(`hour label ${h} does not start under its column`);
  }
  return { grid, failures };
}

test.describe("alignment law", () => {
  // With the mock's generated app icons too (&icons=1): real icons must not move a line.
  for (const extra of ["", "&icons=1"]) {
    test(`Home snaps to the grid${extra}`, async ({ page }) => {
      const errors = collectErrors(page);
      await openHome(page, extra);
      if (extra) await expect(page.getByRole("region", { name: "Top apps" }).locator("[data-app-icon=image]").first()).toBeVisible();
      const { failures } = await homeLaw(page);
      expect(failures, failures.join("\n")).toEqual([]);
      expect(await noSidewaysOverflow(page)).toBeLessThanOrEqual(0);
      expect(errors).toEqual([]);
    });
  }

  test("Home snaps to the grid at 960x800", async ({ page }, info) => {
    test.skip(info.project.name !== "desktop", "desktop project resizes to 960");
    await page.setViewportSize({ width: 960, height: 800 });
    await openHome(page);
    const { failures } = await homeLaw(page);
    expect(failures, failures.join("\n")).toEqual([]);
  });

  for (const extra of ["", "&icons=1"]) {
  test(`Apps snaps to the grid; toggles end on the header actions' line${extra}`, async ({ page }) => {
    const errors = collectErrors(page);
    await page.goto(`/apps/?source=mock&seed=1${extra}`);
    const rows = page.getByTestId("app-row");
    await expect(rows.first()).toBeVisible();
    if (extra) await expect(page.locator("[data-testid=app-row] [data-app-icon=image]").first()).toBeVisible();
    const { grid, failures } = await expectOnGrid(page, { list: page.getByRole("region", { name: "All apps" }) }, { rows });
    for (const sw of (await page.getByRole("main").getByRole("switch").all()).slice(0, 12)) {
      const b = (await sw.boundingBox())!;
      if (Math.abs(right(b) - grid.R) > TOL) failures.push(`a toggle ends at ${right(b).toFixed(1)}, header actions at ${grid.R.toFixed(1)}`);
    }
    // The count belongs to the header row, next to the title.
    const count = (await page.getByTestId("sieved-count").boundingBox())!;
    const title = (await page.getByRole("heading", { level: 1 }).boundingBox())!;
    if (count.y > bottom(title) || bottom(count) < title.y) failures.push("the sieved count is not on the title's line");
    expect(failures, failures.join("\n")).toEqual([]);
    expect(await noSidewaysOverflow(page)).toBeLessThanOrEqual(0);
    expect(errors).toEqual([]);
  });
  }

  /** The Log on the grid, at the project's size and, on desktop, at 960x800 too; with rows and empty. */
  test("Log snaps to the grid, with rows and empty; each row's menu ends on the header actions' line", async ({ page }, info) => {
    const errors = collectErrors(page);
    const sizes = info.project.name === "desktop" ? [{ width: 1280, height: 800 }, { width: 960, height: 800 }] : [{ width: 375, height: 812 }];
    await page.addInitScript(() => {
      if (location.search.includes("engine=hosts")) window.localStorage.setItem("sieve.settings", JSON.stringify({ schema: 5, values: { "filtering.engine": true } }));
      else window.localStorage.removeItem("sieve.settings");
    });
    for (const size of sizes) {
      await page.setViewportSize(size);
      await page.goto("/log/?source=mock&seed=1&engine=hosts");
      const rows = page.getByTestId("log-row");
      await expect(rows.first()).toBeVisible();
      await page.getByRole("button", { name: "Pause the log" }).click();
      const toolbar = page.getByRole("searchbox", { name: "Search the log" }).locator("xpath=ancestor::div[contains(@class,'flex-wrap')][1]");
      const { grid, failures } = await expectOnGrid(page, { toolbar, list: page.getByRole("region", { name: "Log rows" }) }, { rows });
      for (const r of await rows.all()) {
        const b = (await r.getByRole("button", { name: /^Actions for/ }).boundingBox())!;
        if (Math.abs(right(b) - grid.R) > TOL) failures.push(`a row's menu ends at ${right(b).toFixed(1)}, header actions at ${grid.R.toFixed(1)}`);
        const h = (await r.boundingBox())!.height;
        if (h !== 44) failures.push(`a log row is ${h}px tall`);
      }
      expect(failures, `${size.width}: ${failures.join("\n")}`).toEqual([]);
      expect(await noSidewaysOverflow(page)).toBeLessThanOrEqual(0);

      await page.goto("/log/?source=mock&seed=1");
      await expect(page.getByText("Nothing to show")).toBeVisible();
      const empty = await expectOnGrid(page, { list: page.getByRole("region", { name: "Log rows" }) });
      expect(empty.failures, `${size.width} empty: ${empty.failures.join("\n")}`).toEqual([]);
      expect(await noSidewaysOverflow(page)).toBeLessThanOrEqual(0);
    }
    expect(errors).toEqual([]);
  });

  test("Settings snaps to the grid: rail on the title's line, content to the actions' line", async ({ page }) => {
    const errors = collectErrors(page);
    await page.goto("/settings/?source=mock&seed=1");
    await expect(page.locator("[data-setting]").first()).toBeVisible();
    // The content column: the search field's parent column.
    const content = page.getByRole("searchbox", { name: "Search settings" }).locator("xpath=../..");
    const { grid, failures } = await expectOnGrid(page, {
      rail: page.getByRole("navigation", { name: "Settings sections" }),
      content,
    });
    const rail = await contentBox(page.getByRole("navigation", { name: "Settings sections" }));
    if (Math.abs(rail.x - grid.L) > TOL) failures.push(`rail starts at ${rail.x.toFixed(1)}, title at ${grid.L.toFixed(1)}`);
    const col = (await content.boundingBox()) ?? { x: NaN, y: 0, width: NaN, height: 0 };
    // Search, section titles and row controls share the content column's edges.
    const search = (await page.getByRole("searchbox", { name: "Search settings" }).locator("xpath=..").boundingBox())!;
    if (Math.abs(search.x - col.x) > TOL || Math.abs(right(search) - right(col)) > TOL)
      failures.push(`search ${search.x.toFixed(1)}..${right(search).toFixed(1)} vs column ${col.x}..${right(col)}`);
    // A section's header row (its icon, if any, then the title) starts on the column's line.
    for (const h of await page.getByRole("main").locator("section > header").all()) {
      const b = (await h.boundingBox())!;
      if (Math.abs(b.x - col.x) > TOL || Math.abs(right(b) - right(col)) > TOL)
        failures.push(`section header "${await h.innerText()}" spans ${b.x.toFixed(1)}..${right(b).toFixed(1)}, column ${col.x}..${right(col)}`);
    }
    for (const row of await page.locator("[data-setting]").all()) {
      const b = (await row.boundingBox())!;
      if (Math.abs(b.x - col.x) > TOL || Math.abs(right(b) - right(col)) > TOL) failures.push(`row ${await row.getAttribute("data-setting")} is not column wide`);
    }
    // One owner for the upstream servers: their registry row.
    if ((await page.getByText("Upstream DNS servers", { exact: true }).count()) > 1) failures.push("Upstream DNS servers appears more than once");
    expect(failures, failures.join("\n")).toEqual([]);
    expect(await noSidewaysOverflow(page)).toBeLessThanOrEqual(0);
    expect(errors).toEqual([]);
  });

  test("list rows are set apart by space, never a line, and keep 44 px rows where they are pressed", async ({ page }) => {
    const lined = (sel: string) =>
      page.evaluate((s) => {
        const out: string[] = [];
        for (const el of document.querySelectorAll<HTMLElement>(s)) {
          const cs = getComputedStyle(el);
          for (const side of ["Top", "Bottom"] as const) {
            const w = parseFloat(cs.getPropertyValue(`border-${side.toLowerCase()}-width`));
            const style = cs.getPropertyValue(`border-${side.toLowerCase()}-style`);
            if (w > 0 && style !== "none") out.push(`${s} ${el.textContent?.slice(0, 20)}: ${side} border ${w}px`);
          }
        }
        return out;
      }, sel);
    const failures: string[] = [];
    await page.goto("/apps/?source=mock&seed=1");
    await expect(page.getByTestId("app-row").first()).toBeVisible();
    failures.push(...(await lined("[data-testid=app-row]")));
    for (const r of (await page.getByTestId("app-row").all()).slice(0, 5)) {
      const h = (await r.boundingBox())!.height;
      if (h < 44) failures.push(`app row ${h}px tall`);
    }
    await page.goto("/settings/?source=mock&seed=1");
    await expect(page.locator("[data-setting]").first()).toBeVisible();
    failures.push(...(await lined("[data-setting]")), ...(await lined("[data-adapter]")), ...(await lined("main section")));
    await page.goto("/?source=mock&seed=1");
    await expect(page.getByRole("region", { name: "Top apps" }).locator("li").first()).toBeVisible();
    failures.push(...(await lined("main li")));
    await page.addInitScript(() => window.localStorage.setItem("sieve.settings", JSON.stringify({ schema: 5, values: { "filtering.engine": true } })));
    await page.goto("/log/?source=mock&seed=1&engine=hosts");
    await expect(page.getByTestId("log-row").first()).toBeVisible();
    failures.push(...(await lined("[data-testid=log-row]")));
    expect(failures, failures.join("\n")).toEqual([]);
  });

  test("switching the time window changes only the time range", async ({ page }, info) => {
    test.skip(info.project.name !== "desktop", "the segmented control is the desktop control");
    await openHome(page);
    // Freeze the data so only the switch can change anything.
    await page.getByRole("main").getByRole("button", { name: "Pause" }).click();
    await page.getByRole("menuitem", { name: "For 5 minutes" }).click();
    const chart = homeRegions(page).chart;
    const legend = () => chart.getByRole("list", { name: "Series" }).getByRole("listitem").allInnerTexts();
    const plot = chart.locator("svg[data-chart-plot]");
    const before = await legend();
    const box = (await plot.boundingBox())!;
    expect(before.length).toBeGreaterThan(1);
    await page.evaluate(() => {
      document.querySelectorAll("svg[data-chart-plot] path").forEach((p, i) => ((p as unknown as { __law: number }).__law = i + 1));
    });
    const marked = await page.evaluate(() => document.querySelectorAll("svg[data-chart-plot] path").length);
    const failures: string[] = [];
    for (const name of ["1 h", "Session", "24 h", "7 d", "14 d", "5 min"]) {
      await chart.getByRole("radio", { name }).click();
      // Long enough for a history read and the rescale.
      await page.waitForTimeout(700);
      if (await chart.getByRole("alert").count()) failures.push(`${name}: the chart shows an error`);
      const now = await legend();
      if (now.join("|") !== before.join("|")) failures.push(`${name}: legend ${now.join(", ")} (was ${before.join(", ")})`);
      const b = (await plot.boundingBox()) ?? { x: NaN, y: NaN, width: NaN, height: NaN };
      if (Math.abs(b.x - box.x) > TOL || Math.abs(b.y - box.y) > TOL || Math.abs(b.width - box.width) > TOL || Math.abs(b.height - box.height) > TOL)
        failures.push(`${name}: plot moved from ${JSON.stringify(box)} to ${JSON.stringify(b)}`);
      const same = await page.evaluate(() => {
        const ps = [...document.querySelectorAll("svg[data-chart-plot] path")];
        return { n: ps.length, kept: ps.filter((p) => (p as unknown as { __law?: number }).__law !== undefined).length };
      });
      if (same.n !== marked || same.kept !== marked) failures.push(`${name}: ${same.kept} of ${same.n} path nodes kept (had ${marked})`);
      await page.screenshot({ path: `test-results/screens/window-${name.replace(/\s+/g, "")}.png` });
    }
    expect(failures, failures.join("\n")).toEqual([]);
  });
});
