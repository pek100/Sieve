import { expect, test, type Page } from "@playwright/test";

/**
 * Review screenshots (looked at by a person after layout work): Home, Apps
 * and Settings at 1280x800 and 960x800 (desktop project) and 375x812 (mobile
 * project), into test-results/screens/layout-<page>-<w>x<h>.png. The time
 * windows are shot by alignment.spec.ts (window-<name>.png). Each shot
 * waits for real content, so none is of a loading state.
 */
const PAGES = [
  { name: "home", url: "/?source=mock&seed=1", ready: (p: Page) => p.locator('svg[data-chart-plot] path[data-part="line"]').first() },
  { name: "apps", url: "/apps/?source=mock&seed=1", ready: (p: Page) => p.getByTestId("app-row").first() },
  { name: "settings", url: "/settings/?source=mock&seed=1", ready: (p: Page) => p.locator("[data-setting]").first() },
];

test.describe("layout screenshots", () => {
  for (const p of PAGES) {
    test(`${p.name}`, async ({ page }, info) => {
      const sizes = info.project.name === "desktop" ? [{ width: 1280, height: 800 }, { width: 960, height: 800 }] : [{ width: 375, height: 812 }];
      for (const size of sizes) {
        await page.setViewportSize(size);
        await page.goto(p.url);
        await expect(p.ready(page)).toBeAttached();
        // A few samples, so the chart has a line to show.
        if (p.name === "home") await page.waitForTimeout(3000);
        await page.screenshot({ path: `test-results/screens/layout-${p.name}-${size.width}x${size.height}.png` });
      }
    });
  }
});
