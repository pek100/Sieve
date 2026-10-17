import { expect, test, type Page } from "@playwright/test";

/**
 * The DNS filter with the mock DNS source (?dns=off|running|error): the
 * Settings > Filtering card in each state and the Home tile. Nothing here
 * touches the machine's DNS: the mock stands in for Rust.
 */
const SETTINGS = "/settings/?source=mock&seed=1";
const HOME = "/?source=mock&seed=1";

async function open(page: Page, url: string) {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(url);
  return errors;
}

const card = (page: Page) => page.getByRole("region", { name: "DNS filter" });
const phase = (page: Page) => card(page).locator("[data-dns-phase]");
const noHorizontalScroll = async (page: Page) =>
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);

test.describe("dns filter", () => {
  test("off: the card says off, shows Windows' own DNS, Point is disabled", async ({ page }, info) => {
    const errors = await open(page, `${SETTINGS}&dns=off`);
    await expect(phase(page)).toHaveAttribute("data-dns-phase", "off");
    await expect(card(page)).toContainText("Off. Lookups go to Windows' own DNS servers.");
    await expect(card(page).getByRole("list", { name: "Network adapters" }).getByRole("listitem")).toHaveCount(2);
    await expect(card(page).getByRole("button", { name: "Point Windows at Sieve" })).toBeDisabled();
    await card(page).scrollIntoViewIfNeeded();
    await noHorizontalScroll(page);
    await card(page).screenshot({ path: `test-results/screens/dns-off-${info.project.name}.png` });
    expect(errors).toEqual([]);
  });

  test("turning it on runs the filter: counters, list, self check, top domains after pointing", async ({ page }, info) => {
    const errors = await open(page, `${SETTINGS}&dns=off`);
    await card(page).getByRole("switch", { name: "DNS filtering" }).click();
    await expect(phase(page)).toHaveAttribute("data-dns-phase", "running");
    await expect(card(page)).toContainText("Running on 127.0.0.1:53 and [::1]:53.");
    await expect(card(page).locator("[data-dns-check=pass]")).toBeVisible();
    await expect(card(page).locator("[data-dns-list]")).toContainText("51,234 block rules");
    // The settings row follows the same switch.
    await expect(page.locator('[data-setting="filtering.dns"]').getByRole("switch")).toBeChecked();
    const point = card(page).getByRole("button", { name: "Point Windows at Sieve" });
    await expect(point).toBeEnabled();
    await point.click();
    await expect(card(page).locator("[data-system-dns]")).toHaveAttribute("data-system-dns", "pointed");
    await expect(page.locator('[data-setting="filtering.systemDns"]').getByRole("switch")).toBeChecked();
    // Lookups now arrive (every 2 s) and some are blocked; the domains are in the mono font.
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
    await expect(page.locator('section[data-kpi="apps"]')).toHaveAttribute("aria-label", "Watched apps");
    expect(await page.locator("body").innerText()).not.toMatch(/\b(ads|trackers|blocked)\b/i);
    await noHorizontalScroll(page);
    await page.getByRole("group", { name: "Right now" }).screenshot({ path: `test-results/screens/dns-home-off-${info.project.name}.png` });
    await tile.getByRole("link", { name: "Turn on in Settings" }).click();
    await expect(page).toHaveURL(/\/settings\/#section-filtering$/);
    await expect(card(page)).toBeVisible();
    expect(errors).toEqual([]);
  });

  test("Home after a restart while Windows points at Sieve: the filter starts and the tile counts blocked lookups", async ({ page }, info) => {
    const errors = await open(page, `${HOME}&dns=running`);
    const tile = page.locator('section[data-kpi="blocked"]');
    await expect(tile).toHaveAttribute("aria-label", "Blocked lookups");
    await expect(page.getByText("Windows uses Sieve for DNS, so Sieve started its DNS filter.")).toBeVisible();
    await expect.poll(async () => Number(((await tile.locator("[data-numeric]").innerText()) || "0").replace(/\D/g, "")), { timeout: 15_000 }).toBeGreaterThan(1);
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
    expect(errors).toEqual([]);
  });
});
