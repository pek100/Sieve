import { expect, test, type Page } from "@playwright/test";

/**
 * The app-hosted DNS filter is gone (engine slice 4): Settings and Home show
 * no DNS switch, card or tile, settings from an old build start nothing, and
 * the read-only safety net (?pointed=1: a Windows adapter that still asks
 * 127.0.0.1 and ::1) points to Windows network settings only. Nothing here
 * touches the machine's DNS: the mock stands in for Rust, and Sieve never
 * changes Windows DNS anyway.
 */
const SETTINGS = "/settings/?source=mock&seed=1";
const HOME = "/?source=mock&seed=1";
const STRANDED =
  "Windows is set to use Sieve for DNS, but nothing of Sieve's answers there, so sites may not load. Set DNS back to automatic in Windows network settings.";

async function open(page: Page, url: string) {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(url);
  return errors;
}

/**
 * Settings stored by builds that had DNS filtering in the UI: schema 2 (with
 * "Point Windows at Sieve" on too) or schema 3. Set once, before the first load.
 */
async function storedByOldBuild(page: Page, schema: 2 | 3) {
  await page.addInitScript((s) => {
    if (localStorage.getItem("sieve.settings") === null) {
      localStorage.setItem("sieve.settings", JSON.stringify({ schema: s, values: { "filtering.dns": true, "filtering.systemDns": true, "filtering.upstreams": ["1.1.1.1"] } }));
    }
  }, schema);
}

const banner = (page: Page) => page.locator("[data-banner]").filter({ hasText: "Windows is set to use Sieve for DNS" });
const noHorizontalScroll = async (page: Page) =>
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);

/** Nothing of the DNS filter on this page: no switch, row, card or tile. */
async function noDnsFilter(page: Page) {
  await expect(page.locator('[data-setting="filtering.dns"], [data-setting="filtering.systemDns"]')).toHaveCount(0);
  await expect(page.getByRole("switch", { name: /DNS filtering/ })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "DNS filter" })).toHaveCount(0);
  await expect(page.locator("[data-dns-card], [data-dns-derived], [data-kpi=blocked]")).toHaveCount(0);
}

test.describe("dns filter, gone", () => {
  test("Settings: no DNS switch or card; Filtering shows the engine and the encrypted upstreams", async ({ page }, info) => {
    const errors = await open(page, SETTINGS);
    const engine = page.getByRole("region", { name: "Engine" });
    await expect(engine).toBeVisible();
    await noDnsFilter(page);
    await expect(page.getByRole("navigation", { name: "Settings sections" }).getByRole("link", { name: "Filtering" })).toBeVisible();
    await expect(page.locator('[data-setting="filtering.upstreams"]')).toContainText("https://cloudflare-dns.com/dns-query");
    await page.getByRole("searchbox", { name: "Search settings" }).fill("upstream");
    await expect(page.locator("[data-setting]")).toHaveCount(1);
    await page.getByRole("searchbox", { name: "Search settings" }).fill("");
    await page.locator("#section-filtering").scrollIntoViewIfNeeded();
    await noHorizontalScroll(page);
    await page.locator("#section-filtering").screenshot({ path: `test-results/screens/dns-gone-settings-${info.project.name}.png` });
    expect(errors).toEqual([]);
  });

  test("Home: no DNS tile; the Engine tile says what the engine is and links to Settings > Engine", async ({ page }, info) => {
    const errors = await open(page, HOME);
    const tile = page.locator('section[data-kpi="engine"]');
    await expect(tile).toHaveAttribute("aria-label", "Engine");
    await expect(tile.locator("[data-engine-state]")).toHaveText("Not installed");
    await noDnsFilter(page);
    expect(await page.locator("body").innerText()).not.toMatch(/\b(ads|trackers|blocked)\b/i);
    await expect(banner(page)).toHaveCount(0);
    await noHorizontalScroll(page);
    await page.getByRole("group", { name: "Right now" }).screenshot({ path: `test-results/screens/dns-gone-home-${info.project.name}.png` });
    await tile.getByRole("link", { name: "Details in Settings" }).click();
    await expect(page).toHaveURL(/\/settings\/#engine$/);
    await expect(page.getByRole("region", { name: "Engine" })).toBeInViewport();
    expect(errors).toEqual([]);
  });

  test("safety net: an adapter asks 127.0.0.1 and ::1, so Home says so and points to Windows network settings only", async ({ page }, info) => {
    const errors = await open(page, `${HOME}&pointed=1`);
    await expect(banner(page)).toHaveCount(1);
    await expect(banner(page)).toContainText(STRANDED);
    // No action: Sieve never changes Windows DNS.
    await expect(banner(page).getByRole("button", { name: /Turn DNS filtering on|Point Windows|Restore my DNS/ })).toHaveCount(0);
    await noHorizontalScroll(page);
    await banner(page).screenshot({ path: `test-results/screens/dns-safety-home-${info.project.name}.png` });
    await page.getByRole("link", { name: "Settings", exact: true }).click();
    await expect(page.getByRole("region", { name: "Engine" })).toBeVisible();
    await noDnsFilter(page);
    expect(errors).toEqual([]);
  });

  for (const schema of [2, 3] as const) {
    test(`settings from a schema ${schema} build with DNS filtering on: nothing starts, Home never says blocked`, async ({ page }) => {
      await storedByOldBuild(page, schema);
      const errors = await open(page, `${HOME}&pointed=1`);
      await expect(page.locator('section[data-kpi="engine"]')).toHaveAttribute("aria-label", "Engine");
      // Nothing answers on loopback: the safety banner says so.
      await expect(banner(page)).toContainText(STRANDED);
      await noDnsFilter(page);
      expect(await page.locator("body").innerText()).not.toMatch(/\b(ads|trackers|blocked)\b/i);
      // The stored document reads through the migration: the bare upstream is gone.
      await page.getByRole("link", { name: "Settings", exact: true }).click();
      await expect(page.getByRole("region", { name: "Engine" })).toBeVisible();
      await noDnsFilter(page);
      await expect(page.locator('[data-setting="filtering.upstreams"]')).not.toContainText("1.1.1.1");
      expect(errors).toEqual([]);
    });
  }
});
