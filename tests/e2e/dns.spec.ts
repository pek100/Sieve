import { expect, test, type Page } from "@playwright/test";

/**
 * The DNS filter with the mock DNS source (?dns=off|error, ?pointed=1 for a
 * Windows adapter that still asks 127.0.0.1 and ::1): the Settings >
 * Filtering card in each state, the safety notice and the Home tile.
 * Nothing here touches the machine's DNS: the mock stands in for Rust, and
 * Sieve never changes Windows DNS anyway.
 */
const SETTINGS = "/settings/?source=mock&seed=1";
const HOME = "/?source=mock&seed=1";
const STRANDED =
  "Windows is set to use Sieve for DNS, but Sieve's DNS filter is not running, so sites may not load. Reset DNS in Windows network settings, or turn DNS filtering on.";

async function open(page: Page, url: string) {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(url);
  return errors;
}

/**
 * Settings stored by a build that still had "Point Windows at Sieve" (schema
 * 2): DNS filtering on, the retired Windows DNS switch on. Set once, before
 * the first load.
 */
async function storedByOldBuild(page: Page) {
  await page.addInitScript(() => {
    if (localStorage.getItem("sieve.settings") === null) {
      localStorage.setItem("sieve.settings", JSON.stringify({ schema: 2, values: { "filtering.dns": true, "filtering.systemDns": true } }));
    }
  });
}

const card = (page: Page) => page.getByRole("region", { name: "DNS filter" });
const phase = (page: Page) => card(page).locator("[data-dns-phase]");
const banner = (page: Page) => page.locator("[data-banner]").filter({ hasText: "Windows is set to use Sieve for DNS" });
const noHorizontalScroll = async (page: Page) =>
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);

test.describe("dns filter", () => {
  test("off: the card says off and what it covers, with no Windows DNS block", async ({ page }, info) => {
    const errors = await open(page, `${SETTINGS}&dns=off`);
    await expect(phase(page)).toHaveAttribute("data-dns-phase", "off");
    await expect(card(page)).toContainText("Off. Lookups go to Windows' own DNS servers.");
    await expect(card(page).locator("[data-dns-scope]")).toHaveText(
      "Only lookups sent straight to 127.0.0.1:53 are filtered for now; filtering for the whole computer comes later.",
    );
    // Removed 2026-10-18: no adapter list, no Point or Restore buttons, no Windows DNS switch.
    await expect(card(page).getByRole("list", { name: "Network adapters" })).toHaveCount(0);
    await expect(card(page).getByRole("button", { name: /Point Windows|Restore my DNS/ })).toHaveCount(0);
    await expect(card(page).getByRole("heading", { name: "Windows DNS" })).toHaveCount(0);
    await expect(page.locator('[data-setting="filtering.systemDns"]')).toHaveCount(0);
    await expect(card(page).locator("[data-dns-stranded]")).toHaveCount(0);
    await card(page).scrollIntoViewIfNeeded();
    await noHorizontalScroll(page);
    await card(page).screenshot({ path: `test-results/screens/dns-off-${info.project.name}.png` });
    expect(errors).toEqual([]);
  });

  test("turning it on runs the filter: counters, list, self check, and top domains for lookups that reach it", async ({ page }, info) => {
    // An adapter still asks 127.0.0.1 and ::1, so lookups reach the filter once it runs.
    const errors = await open(page, `${SETTINGS}&dns=off&pointed=1`);
    await expect(card(page).locator("[data-dns-stranded]")).toHaveText(STRANDED);
    await card(page).getByRole("switch", { name: "DNS filtering" }).click();
    await expect(phase(page)).toHaveAttribute("data-dns-phase", "running");
    await expect(card(page)).toContainText("Running on 127.0.0.1:53 and [::1]:53.");
    await expect(card(page).locator("[data-dns-check=pass]")).toBeVisible();
    await expect(card(page).locator("[data-dns-list]")).toContainText("51,234 block rules");
    // The filter answers there now: the safety notice is gone.
    await expect(card(page).locator("[data-dns-stranded]")).toHaveCount(0);
    // The settings row follows the same switch.
    await expect(page.locator('[data-setting="filtering.dns"]').getByRole("switch")).toBeChecked();
    // Lookups arrive (every 2 s) and some are blocked; the domains are in the mono font.
    const top = card(page).getByRole("list", { name: "Most blocked domains" });
    await expect(top.getByRole("listitem").nth(1)).toBeVisible({ timeout: 15_000 });
    expect(await top.locator(".font-mono").first().evaluate((e) => getComputedStyle(e).fontFamily)).toMatch(/JetBrains Mono/i);
    await card(page).scrollIntoViewIfNeeded();
    await noHorizontalScroll(page);
    await card(page).screenshot({ path: `test-results/screens/dns-running-${info.project.name}.png` });
    expect(errors).toEqual([]);
  });

  test("error: port 53 busy turns the switch back off and says why", async ({ page }, info) => {
    const errors = await open(page, `${SETTINGS}&dns=error`);
    await card(page).getByRole("switch", { name: "DNS filtering" }).click();
    await expect(phase(page)).toHaveAttribute("data-dns-phase", "error");
    await expect(card(page).getByRole("alert")).toContainText("os error 10048");
    await expect(card(page).getByRole("switch", { name: "DNS filtering" })).not.toBeChecked();
    await expect(page.getByText(/DNS filtering could not start/).first()).toBeVisible();
    await card(page).scrollIntoViewIfNeeded();
    await noHorizontalScroll(page);
    await card(page).screenshot({ path: `test-results/screens/dns-error-${info.project.name}.png` });
    expect(errors).toEqual([]);
  });

  test("AdGuard running: the card warns that AdGuard's DNS protection must be paused", async ({ page }) => {
    await open(page, `${SETTINGS}&adguard=1`);
    await expect(card(page).getByRole("note", { name: "AdGuard is running" })).toContainText("Pause AdGuard's DNS protection");
  });

  test("Home: the tile says Off with a link to Settings > Filtering while the filter is off", async ({ page }, info) => {
    const errors = await open(page, `${HOME}&dns=off`);
    const tile = page.locator('section[data-kpi="blocked"]');
    await expect(tile).toHaveAttribute("aria-label", "DNS filter");
    await expect(tile).toContainText("Off");
    await expect(page.locator('section[data-kpi="apps"]')).toHaveAttribute("aria-label", "Sieved apps");
    expect(await page.locator("body").innerText()).not.toMatch(/\b(ads|trackers|blocked)\b/i);
    await expect(banner(page)).toHaveCount(0);
    await noHorizontalScroll(page);
    await page.getByRole("group", { name: "Right now" }).screenshot({ path: `test-results/screens/dns-home-off-${info.project.name}.png` });
    await tile.getByRole("link", { name: "Turn on in Settings" }).click();
    await expect(page).toHaveURL(/\/settings\/#section-filtering$/);
    await expect(card(page)).toBeVisible();
    expect(errors).toEqual([]);
  });

  test("safety net: an adapter asks 127.0.0.1 and ::1 with the filter off, so Home says so until the filter answers", async ({ page }, info) => {
    const errors = await open(page, `${HOME}&pointed=1`);
    await expect(banner(page)).toHaveCount(1);
    await expect(banner(page)).toContainText(STRANDED);
    await noHorizontalScroll(page);
    await banner(page).screenshot({ path: `test-results/screens/dns-safety-home-${info.project.name}.png` });
    // The DNS card says the same, for as long as it is true.
    await page.getByRole("link", { name: "Settings", exact: true }).click();
    await expect(card(page).locator("[data-dns-stranded]")).toHaveText(STRANDED);
    await expect(card(page).getByRole("button", { name: /Point Windows|Restore my DNS/ })).toHaveCount(0);
    await card(page).scrollIntoViewIfNeeded();
    await noHorizontalScroll(page);
    await card(page).screenshot({ path: `test-results/screens/dns-safety-card-${info.project.name}.png` });
    // Its one action turns DNS filtering on; with a listener there, the notice goes.
    await page.getByRole("link", { name: "Home", exact: true }).click();
    await banner(page).getByRole("button", { name: "Turn DNS filtering on" }).click();
    await expect(banner(page)).toHaveCount(0);
    await expect(page.locator('section[data-kpi="blocked"]')).toHaveAttribute("aria-label", "Blocked lookups");
    expect(errors).toEqual([]);
  });

  test("Home with settings from an old build: DNS filtering starts, the retired switch is gone, the tile counts blocked lookups", async ({ page }, info) => {
    await storedByOldBuild(page);
    const errors = await open(page, `${HOME}&pointed=1`);
    const tile = page.locator('section[data-kpi="blocked"]');
    await expect(tile).toHaveAttribute("aria-label", "Blocked lookups");
    await expect.poll(async () => Number(((await tile.locator("[data-numeric]").innerText()) || "0").replace(/\D/g, "")), { timeout: 15_000 }).toBeGreaterThan(1);
    // The filter started before the safety net looked: no banner.
    await expect(banner(page)).toHaveCount(0);
    // "blocked" only inside the DNS-derived tile; never ads or trackers.
    const outside = await page.evaluate(() => {
      const copy = document.body.cloneNode(true) as HTMLElement;
      for (const el of copy.querySelectorAll("[data-dns-derived], [data-sonner-toaster]")) el.remove();
      return copy.innerText ?? copy.textContent ?? "";
    });
    expect(outside).not.toMatch(/\b(ads|trackers|blocked)\b/i);
    expect(await page.locator("body").innerText()).not.toMatch(/\b(ads|trackers)\b/i);
    await noHorizontalScroll(page);
    await page.getByRole("group", { name: "Right now" }).screenshot({ path: `test-results/screens/dns-home-running-${info.project.name}.png` });
    // The stored schema 2 document reads through the migration: the Windows DNS switch is dropped, never shown.
    await page.getByRole("link", { name: "Settings", exact: true }).click();
    await expect(page.locator('[data-setting="filtering.dns"]').getByRole("switch")).toBeChecked();
    await expect(page.locator('[data-setting="filtering.systemDns"]')).toHaveCount(0);
    expect(errors).toEqual([]);
  });

  test("global Sieving off: the running filter passes everything through and says Paused, never stops", async ({ page }, info) => {
    await storedByOldBuild(page);
    const errors = await open(page, `${HOME}&pointed=1`);
    const tile = page.locator('section[data-kpi="blocked"]');
    await expect(tile).toHaveAttribute("aria-label", "Blocked lookups");
    await page.getByRole("banner").getByRole("switch", { name: "Sieving" }).click();
    await expect(tile).toHaveAttribute("aria-label", "DNS filter");
    await expect(tile.locator("[data-dns-paused]")).toContainText("Paused");
    await page.getByRole("group", { name: "Right now" }).screenshot({ path: `test-results/screens/dns-home-paused-${info.project.name}.png` });
    // Pass-through still answers: no safety banner.
    await expect(banner(page)).toHaveCount(0);
    // Settings says the same: still running, in pass-through.
    await page.getByRole("link", { name: "Settings", exact: true }).click();
    await expect(phase(page)).toHaveAttribute("data-dns-phase", "paused");
    await expect(card(page)).toContainText("Paused while Sieving is off");
    await expect(page.locator('[data-setting="filtering.dns"]').getByRole("switch")).toBeChecked();
    // On again: blocking resumes.
    await page.getByRole("banner").getByRole("switch", { name: "Sieving" }).click();
    await expect(phase(page)).toHaveAttribute("data-dns-phase", "running");
    await noHorizontalScroll(page);
    expect(errors).toEqual([]);
  });
});
