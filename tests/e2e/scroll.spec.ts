import { expect, test, type Locator, type Page } from "@playwright/test";

/**
 * The scroll law (the user: "shouldn't be scroll like that", "only vertical styled scroll").
 *
 * At the smallest window (960x640), the default (1280x800) and a large one (1600x1000), on every page:
 * - nothing ever scrolls sideways: not the document, not the content area, not while a tooltip shows
 *   at the right-most and bottom-most heatmap cell or the right edge of the chart;
 * - the window itself never scrolls; only the content area under the top bar does, and the top bar
 *   stays at the top while it does;
 * - the content area's scrollbar is the thin token one (8 px), not the 17 px Windows default;
 * - Home fits without any scroll from 1280x800 up;
 * - an element with a custom tooltip carries no native `title` as well.
 */

const SIZES = [
  { width: 960, height: 640 },
  { width: 1280, height: 800 },
  { width: 1600, height: 1000 },
];
const PAGES = [
  { name: "Home", url: "/?source=mock&seed=1" },
  { name: "Apps", url: "/apps/?source=mock&seed=1" },
  { name: "Settings", url: "/settings/?source=mock&seed=1" },
];

async function measure(page: Page) {
  return page.evaluate(() => {
    const root = document.querySelector<HTMLElement>("[data-scroll-root]");
    const doc = document.documentElement;
    return {
      docX: doc.scrollWidth - window.innerWidth,
      docY: doc.scrollHeight - window.innerHeight,
      windowScrolled: window.scrollX !== 0 || window.scrollY !== 0,
      rootX: root ? root.scrollWidth - root.clientWidth : NaN,
      rootY: root ? root.scrollHeight - root.clientHeight : NaN,
      gutter: root ? root.offsetWidth - root.clientWidth : NaN,
    };
  });
}

/** Hover `target`, wait for a custom tooltip, and check it neither widens the page nor doubles a native title. */
async function hoverWithTooltip(page: Page, target: Locator, failures: string[], label: string) {
  await target.scrollIntoViewIfNeeded();
  const box = (await target.boundingBox())!;
  await page.mouse.move(box.x + box.width - 2, box.y + box.height - 2);
  const tip = page.getByRole("tooltip");
  await expect(tip.first()).toBeVisible();
  const vp = page.viewportSize()!;
  const t = (await tip.first().boundingBox())!;
  if (t.x < 0 || t.y < 0 || t.x + t.width > vp.width || t.y + t.height > vp.height) failures.push(`${label}: tooltip leaves the window ${JSON.stringify(t)}`);
  const m = await measure(page);
  if (m.docX > 0 || m.rootX > 0) failures.push(`${label}: sideways overflow ${m.docX} / ${m.rootX} px while the tooltip shows`);
  const titled = await target.evaluate((el) => el.closest("[title]")?.getAttribute("title") ?? null);
  if (titled !== null) failures.push(`${label}: also has a native title "${titled}"`);
  await page.mouse.move(0, 0);
}

test.describe("scroll law", () => {

  for (const size of SIZES) {
    for (const p of PAGES) {
      test(`${p.name} at ${size.width}x${size.height}: vertical scroll in the content area only`, async ({ page }, info) => {
        test.skip(info.project.name !== "desktop", "window sizes are set on the desktop project");
        await page.setViewportSize(size);
        await page.goto(p.url);
        await expect(page.getByRole("heading", { level: 1 })).toHaveText(p.name === "Home" ? "Sieving now" : p.name);
        if (p.name === "Home") {
          await expect(page.getByRole("region", { name: "When apps are busy" }).locator("[data-step]").first()).toBeVisible();
          await expect(page.locator('svg[data-chart-plot] path[data-part="line"]').first()).toBeAttached();
        } else {
          await expect(page.locator(p.name === "Apps" ? "[data-testid=app-row]" : "[data-setting]").first()).toBeVisible();
        }
        const failures: string[] = [];
        const m = await measure(page);
        if (m.docX > 0) failures.push(`document is ${m.docX} px wider than the window`);
        if (m.rootX > 0) failures.push(`content area scrolls sideways by ${m.rootX} px`);
        if (m.docY > 0) failures.push(`the window scrolls vertically by ${m.docY} px (only the content area may)`);
        if (m.gutter !== 8) failures.push(`content area scrollbar is ${m.gutter} px, not the thin 8 px one`);
        if (p.name === "Home" && size.width >= 1280 && m.rootY > 0) failures.push(`Home scrolls by ${m.rootY} px at ${size.width}x${size.height}`);

        if (p.name === "Home") {
          const heat = page.getByRole("region", { name: "When apps are busy" });
          await hoverWithTooltip(page, heat.locator('[data-day="6"][data-hour="23"]'), failures, "last heatmap cell");
          const plot = page.locator("svg[data-chart-plot]").locator("xpath=..");
          await hoverWithTooltip(page, plot, failures, "chart right edge");
        }

        // Scrolling the content area moves the content, never the window or the top bar.
        if (m.rootY > 0) {
          await page.locator("[data-scroll-root]").evaluate((el) => el.scrollTo(0, el.scrollHeight));
          const bar = (await page.getByRole("banner").boundingBox())!;
          if (bar.y !== 0) failures.push(`top bar moved to y=${bar.y} when the content scrolled`);
          const after = await measure(page);
          if (after.windowScrolled) failures.push("the window scrolled");
          if (after.docX > 0 || after.rootX > 0) failures.push("sideways overflow after scrolling");
        }
        await page.screenshot({ path: `test-results/screens/scroll-${p.name.toLowerCase()}-${size.width}x${size.height}.png` });
        expect(failures, failures.join("\n")).toEqual([]);
      });
    }
  }
});
