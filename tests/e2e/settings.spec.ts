import { expect, test, type Page } from "@playwright/test";

const SETTINGS = "/settings/?source=mock&seed=1";

async function openSettings(page: Page) {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(SETTINGS);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Settings");
  await expect(page.locator("[data-setting]").first()).toBeVisible();
  return errors;
}

const noHorizontalScroll = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
const row = (page: Page, key: string) => page.locator(`[data-setting="${key}"]`);

test.describe("settings", () => {
  test("renders every section from the registry with no horizontal scroll", async ({ page }, info) => {
    const errors = await openSettings(page);
    await expect(page.getByRole("link", { name: "Settings" })).toHaveAttribute("aria-current", "page");
    const rail = page.getByRole("navigation", { name: "Settings sections" });
    await expect(rail.getByRole("link")).toHaveText(["Appearance", "Sampling", "Startup", "Apps", "Filtering"]);
    // Ten registry keys: theme, sieving, interval, launch at startup, levels, my apps,
    // DNS filtering, upstreams, Windows uses Sieve, per-app filtering.
    await expect(page.locator("[data-setting]")).toHaveCount(10);
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);

    if (info.project.name === "desktop") {
      // Rail on the left, a column of about 720 px beside it.
      const r = (await rail.boundingBox())!;
      const col = (await page.getByRole("region", { name: "Appearance" }).boundingBox())!;
      expect(r.x + r.width).toBeLessThanOrEqual(col.x);
      expect(col.width).toBeLessThanOrEqual(721);
      expect(col.width).toBeGreaterThan(600);
    } else {
      // One column: the rail wraps above the cards.
      const r = (await rail.boundingBox())!;
      const col = (await page.getByRole("region", { name: "Appearance" }).boundingBox())!;
      expect(r.y + r.height).toBeLessThanOrEqual(col.y);
    }
    await page.screenshot({ path: `test-results/screens/settings-${info.project.name}.png`, fullPage: true });
    expect(errors).toEqual([]);
  });

  test("per-app filtering is a locked switch that says why; DNS filtering is a live switch", async ({ page }, info) => {
    await openSettings(page);
    const perApp = row(page, "filtering.perApp");
    await perApp.scrollIntoViewIfNeeded();
    await expect(perApp.getByRole("switch")).toBeDisabled();
    await expect(perApp.getByRole("switch")).not.toBeChecked();
    await expect(perApp).toContainText("network driver");
    await expect(perApp).toContainText("live_per_app_filter_blocks_one_app");
    await expect(row(page, "filtering.dns").getByRole("switch")).toBeEnabled();
    await expect(row(page, "filtering.systemDns").getByRole("switch")).toBeDisabled();
    await expect(row(page, "filtering.systemDns")).toContainText("Needs DNS filtering, which is off.");
    // Launch at startup needs the desktop app; the browser shows why.
    await expect(row(page, "startup.launchAtLogin").getByRole("switch")).toBeDisabled();
    await expect(row(page, "startup.launchAtLogin")).toContainText("Only the desktop app");
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await perApp.screenshot({ path: `test-results/screens/settings-locked-${info.project.name}.png` });
  });

  test("search narrows the rows; a change persists across a reload", async ({ page }) => {
    await openSettings(page);
    await page.getByRole("searchbox", { name: "Search settings" }).fill("theme");
    await expect(page.locator("[data-setting]")).toHaveCount(1);
    await row(page, "appearance.theme").getByRole("radio", { name: "Light" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await page.getByRole("searchbox", { name: "Search settings" }).fill("nothing like this");
    await expect(page.getByText("No setting matches")).toBeVisible();
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  });

  test("import previews the change before applying; reset to defaults can be undone", async ({ page }, info) => {
    await openSettings(page);
    await page.getByRole("button", { name: "Settings actions" }).click();
    await page.getByRole("menuitem", { name: "Import settings" }).click();
    const file = JSON.stringify({ kind: "sieve.settings", schema: 1, values: { "sampling.intervalMs": 2000, "filtering.dns": true } });
    await page.getByRole("textbox", { name: "Settings file to import" }).fill(file);
    await page.getByRole("button", { name: "Preview changes" }).click();
    await expect(page.getByRole("list", { name: "Changes" })).toContainText("Sample every");
    await expect(page.getByRole("list", { name: "Not imported" })).toContainText("filtering.dns");
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await page.screenshot({ path: `test-results/screens/settings-import-${info.project.name}.png` });
    await page.getByRole("button", { name: "Apply 1 change" }).click();
    await expect(row(page, "sampling.intervalMs")).toContainText("2 s");
    await expect(row(page, "filtering.dns").getByRole("switch")).not.toBeChecked();

    await page.getByRole("button", { name: "Settings actions" }).click();
    await page.getByRole("menuitem", { name: "Reset to defaults" }).click();
    await page.getByRole("button", { name: "Reset to defaults" }).click();
    await expect(row(page, "sampling.intervalMs")).toContainText("1 s");
    // The import's toast may still be up: undo the reset, from its own toast.
    await page.getByRole("listitem").filter({ hasText: "Settings reset to defaults" }).getByRole("button", { name: "Undo" }).click();
    await expect(row(page, "sampling.intervalMs")).toContainText("2 s");
  });
});
