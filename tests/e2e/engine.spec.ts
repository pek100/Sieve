import { expect, test, type Page } from "@playwright/test";

/** Settings > Filtering, the Engine block, against the mock engine's fixture answers. */
async function openEngine(page: Page, scenario?: string) {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(`/settings/?source=mock&seed=1${scenario ? `&engine=${scenario}` : ""}`);
  const block = page.getByRole("region", { name: "Engine" });
  await expect(block).toBeVisible();
  return { block, errors };
}

const noHorizontalScroll = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);

test.describe("engine", () => {
  test("a browser has no engine: Not installed, said from the facts", async ({ page }, info) => {
    const { block, errors } = await openEngine(page);
    await expect(block.locator("[data-engine-phase]")).toHaveAttribute("data-engine-phase", "not_installed");
    await expect(block.locator("[data-engine-state]")).toHaveText("Not installed");
    await block.scrollIntoViewIfNeeded();
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await block.screenshot({ path: `test-results/screens/engine-missing-${info.project.name}.png` });
    expect(errors).toEqual([]);
  });

  test("installed and idle: Installed, not filtering, with the engine's version", async ({ page }, info) => {
    const { block, errors } = await openEngine(page, "idle");
    await expect(block.locator("[data-engine-state]")).toHaveText("Installed, not filtering");
    await expect(block).toContainText("Engine version 0.1.0");
    await expect(block).not.toContainText(/blocked|is filtering/i);
    await block.screenshot({ path: `test-results/screens/engine-idle-${info.project.name}.png` });
    expect(errors).toEqual([]);
  });

  test("installed but stopped: Not running", async ({ page }) => {
    const { block, errors } = await openEngine(page, "stopped");
    await expect(block.locator("[data-engine-state]")).toHaveText("Not running");
    expect(errors).toEqual([]);
  });

  test("the engine's left edge sits on the column of the other Filtering blocks", async ({ page }, info) => {
    test.skip(info.project.name !== "desktop", "one column on a phone");
    const { block } = await openEngine(page, "idle");
    const dns = (await page.getByRole("region", { name: "DNS filter" }).boundingBox())!;
    const engine = (await block.boundingBox())!;
    expect(Math.abs(engine.x - dns.x)).toBeLessThanOrEqual(1);
    expect(Math.abs(engine.width - dns.width)).toBeLessThanOrEqual(1);
    expect(engine.y).toBeGreaterThanOrEqual(dns.y + dns.height);
  });
});
