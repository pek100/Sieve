import { expect, test, type Page, type TestInfo } from "@playwright/test";

/** Persisted history on Home: the 24 h, 7 d and 14 d periods and the heatmap read source.history(). */

async function openHome(page: Page, query = "/?source=mock&seed=1") {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(query);
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  return errors;
}

const chart = (page: Page) => page.getByRole("region", { name: "Connections per app" });
const firstLine = (page: Page) => chart(page).locator('path[data-part="line"]').first();
const vertices = async (page: Page) => ((await firstLine(page).getAttribute("d")) ?? "").split("L").length;
/** The x axis start label (the one left of "Now"). */
const axisStart = (page: Page) => chart(page).locator("span", { hasText: /^Now$/ }).locator("xpath=preceding-sibling::span[1]");

/** Pick a chart window the way a person would at this width: segmented from 640 up, a select below. */
async function pickWindow(page: Page, info: TestInfo, label: string) {
  if (info.project.name === "mobile") {
    await chart(page).getByRole("combobox", { name: "Chart window" }).click();
    await page.getByRole("option", { name: label, exact: true }).click();
  } else {
    await chart(page).getByRole("radiogroup", { name: "Chart window" }).getByRole("radio", { name: label, exact: true }).click();
  }
}

const WEEKDAY = /\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b/;

test.describe("history periods", () => {
  test("24 h, 7 d and 14 d draw persisted buckets at once; longer spans label the weekday", async ({ page }, info) => {
    const errors = await openHome(page);
    await expect(firstLine(page)).toBeAttached();

    // A live window right after load holds a handful of samples.
    const live = await vertices(page);
    expect(live).toBeLessThan(30);

    for (const [label, weekday] of [
      ["24 h", false],
      ["7 d", true],
      ["14 d", true],
    ] as const) {
      await pickWindow(page, info, label);
      // History arrives in one read, not one sample per second: many buckets without waiting.
      await expect.poll(() => vertices(page), { timeout: 5_000, message: label }).toBeGreaterThan(100);
      await expect(chart(page).getByRole("list", { name: "Series" }).getByRole("listitem").first()).toBeVisible();
      const start = (await axisStart(page).innerText()).trim();
      if (weekday) expect(start, label).toMatch(WEEKDAY);
      else expect(start, label).not.toMatch(WEEKDAY);
      expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
    }
    await page.screenshot({ path: `test-results/screens/home-history-14d-${info.project.name}.png`, fullPage: info.project.name === "mobile", animations: "disabled" });

    // Back to a live window: the ring, not history (few samples again), KPIs never left live.
    await pickWindow(page, info, "5 min");
    await expect.poll(() => vertices(page), { timeout: 5_000 }).toBeLessThan(60);
    await expect(page.getByRole("status")).toHaveAttribute("data-phase", "live");
    expect(errors).toEqual([]);
  });

  test("the heatmap reads four weeks of history and says so", async ({ page }) => {
    await openHome(page);
    const heat = page.getByRole("region", { name: "When apps are busy" });
    await expect(heat.locator("[data-step]").first()).toBeVisible();
    await expect(heat).toContainText("Last 4 weeks");
    // 7 days x 24 hours.
    await expect(heat.locator("[data-step]")).toHaveCount(168);
  });

  test("a period with no saved counts says so instead of drawing an empty plot", async ({ page }, info) => {
    await openHome(page, "/?source=mock&seed=1&scenario=empty");
    await pickWindow(page, info, "7 d");
    await expect(chart(page)).toContainText("No history for this period yet");
    await expect(chart(page).locator('path[data-part="line"]')).toHaveCount(0);
    await page.screenshot({ path: `test-results/screens/home-history-empty-${info.project.name}.png` });
  });
});
