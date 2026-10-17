import { expect, test, type Page } from "@playwright/test";

/**
 * "When apps are busy": each weekday x hour cell is a stack of app shares in
 * the chart's series colours, as tall as the hour was busy. Screenshots at
 * 1280x800 and 960x800 (desktop project) and 375x812 (mobile project) go to
 * test-results/screens/heatmap-<w>x<h>.png.
 */

const HOME = "/?source=mock&seed=1";

async function openHome(page: Page) {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(HOME);
  const line = page.getByRole("region", { name: "Connections per app" }).locator('path[data-part="line"]').first();
  await expect(line).toBeAttached();
  await expect.poll(async () => ((await line.getAttribute("d")) ?? "").split("L").length, { timeout: 15_000 }).toBeGreaterThanOrEqual(4);
  const heat = page.getByRole("region", { name: "When apps are busy" });
  await expect(heat.locator("[data-cell]").first()).toBeVisible();
  return { errors, heat };
}

const sizes = (project: string) =>
  project === "mobile"
    ? [{ width: 375, height: 812 }]
    : [
        { width: 1280, height: 800 },
        { width: 960, height: 800 },
      ];

test.describe("heatmap", () => {
  test("cells are stacks of app shares in the chart's colours; screenshots per size", async ({ page }, info) => {
    for (const size of sizes(info.project.name)) {
      await page.setViewportSize(size);
      const { errors, heat } = await openHome(page);
      await expect(heat.locator("[data-cell]")).toHaveCount(168);

      // Every segment's colour is its series' colour in the chart.
      const mismatched = await page.evaluate(() => {
        const out: string[] = [];
        const fillOf = new Map<string, string>();
        for (const p of document.querySelectorAll<SVGPathElement>('svg[data-chart-plot] path[data-part="area"]'))
          fillOf.set(p.dataset.series!, getComputedStyle(p).fill);
        for (const r of document.querySelectorAll<SVGRectElement>("svg[data-heat-plot] rect[data-series]")) {
          const want = fillOf.get(r.dataset.series!);
          const got = getComputedStyle(r).fill;
          if (want !== got) out.push(`${r.dataset.series}: heat ${got}, chart ${want ?? "none"}`);
        }
        return [...new Set(out)];
      });
      expect(mismatched).toEqual([]);

      // Busy hours carry several apps; nothing draws more than the 7 series.
      const counts = await heat.locator("[data-cell]").evaluateAll((els) => els.map((e) => Number(e.getAttribute("data-segments"))));
      expect(Math.max(...counts)).toBeLessThanOrEqual(7);
      expect(counts.filter((n) => n >= 3).length).toBeGreaterThan(20);

      await heat.screenshot({ path: `test-results/screens/heatmap-${size.width}x${size.height}.png` });
      expect(errors).toEqual([]);
    }
  });

  test("hover and keyboard show the cell's tooltip: the hour, the total, the shares largest first", async ({ page }, info) => {
    const { errors, heat } = await openHome(page);
    const tag = info.project.name === "mobile" ? "375x812" : "1280x800";
    // Wednesday 14:00: office hours, several apps.
    const cell = heat.locator('[data-day="2"][data-hour="14"]');
    const box = (await cell.boundingBox())!;
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    const tip = page.getByRole("tooltip");
    await expect(tip).toBeVisible();
    await expect(tip).toContainText("Wed 14:00 to 15:00");
    await expect(tip).toContainText(/\d+ open connections on average/);
    // "<1%" is a part that rounds to nothing: it counts 0 towards the 100.
    const pcts = (await tip.getByRole("listitem").allInnerTexts()).map((t) => (/<1%/.test(t) ? 0 : Number(t.match(/(\d+)%/)?.[1] ?? NaN)));
    expect(pcts.length).toBeGreaterThan(1);
    expect(pcts.reduce((a, b) => a + b, 0)).toBe(100);
    expect(pcts).toEqual([...pcts].sort((a, b) => b - a));
    // The tooltip stays in the window; the cell's accessible name says the same.
    const t = (await tip.boundingBox())!;
    const vp = page.viewportSize()!;
    expect(t.x >= 0 && t.y >= 0 && t.x + t.width <= vp.width && t.y + t.height <= vp.height).toBe(true);
    await expect(cell).toHaveAccessibleName(/^Wed 14:00, \d+ open connections on average: .+ \d+%/);
    await page.screenshot({ path: `test-results/screens/heatmap-${tag}-tooltip.png` });
    await page.mouse.move(0, 0);
    await expect(tip).toHaveCount(0);

    // Keyboard: one tab stop, the arrows move it, the focused cell shows its tooltip.
    await heat.locator('[data-cell][tabindex="0"]').focus();
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    for (let i = 0; i < 20; i++) await page.keyboard.press("ArrowRight");
    await expect(heat.locator('[data-day="2"][data-hour="20"]')).toBeFocused();
    await expect(tip).toContainText("Wed 20:00 to 21:00");
    await page.screenshot({ path: `test-results/screens/heatmap-${tag}-keyboard.png` });
    expect(errors).toEqual([]);
  });
});
