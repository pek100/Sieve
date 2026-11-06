import { expect, test, type Page } from "@playwright/test";

/**
 * The Log route (plan 8.3, 8.4) against the mock engine's fixture rows, at
 * 1280x800 and 375x812. Every test routes anything but 127.0.0.1 to abort and
 * stubs `window.open`, so "Open issue page" can never reach the internet; it
 * asserts what would have opened and that nothing went out.
 */
const LOG = "/log/?source=mock&seed=1&engine=hosts";
const ADGUARD_ISSUES = "https://github.com/AdguardTeam/AdguardFilters/issues";

interface Opened {
  __opened?: string[];
}

async function setup(page: Page, url = LOG, switchOn = true) {
  const errors: string[] = [];
  const outside: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await page.route("**/*", (route) => {
    const u = new URL(route.request().url());
    if (u.protocol === "data:" || u.hostname === "127.0.0.1") return route.continue();
    outside.push(u.href);
    return route.abort();
  });
  await page.addInitScript(() => {
    (window as Opened).__opened = [];
    window.open = ((u: string) => {
      (window as Opened).__opened!.push(u);
      return null;
    }) as typeof window.open;
  });
  if (switchOn) await page.addInitScript(() => window.localStorage.setItem("sieve.settings", JSON.stringify({ schema: 5, values: { "filtering.engine": true } })));
  await page.goto(url);
  return { errors, outside };
}

const rows = (page: Page) => page.getByTestId("log-row");
const noHorizontalScroll = async (page: Page) =>
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
const rowOf = (page: Page, host: string) => rows(page).filter({ has: page.locator("[data-log-host]", { hasText: host }) }).first();
/** The mock adds rows; a paused log holds still for what follows. */
const hold = async (page: Page) => {
  await expect(rows(page).first()).toBeVisible();
  await page.getByRole("button", { name: "Pause the log" }).click();
  await expect(page.getByRole("button", { name: "Resume the log" })).toBeVisible();
};

test.describe("log", () => {
  test("the rows, the filters and the search; the nav has the route", async ({ page }, info) => {
    const { errors, outside } = await setup(page);
    await expect(rows(page).first()).toBeVisible();
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Log");
    // Every filter's label fits its cell.
    for (const r of await page.getByRole("radiogroup", { name: "Show" }).getByRole("radio").all()) {
      expect(await r.evaluate((b) => b.scrollWidth - b.clientWidth)).toBeLessThanOrEqual(0);
    }
    await expect(page.getByRole("link", { name: "Log", exact: true })).toHaveAttribute("aria-current", "page");
    await hold(page);
    await noHorizontalScroll(page);
    for (const r of (await rows(page).all()).slice(0, 5)) expect((await r.boundingBox())!.height).toBe(44);
    await page.screenshot({ path: `test-results/screens/log-rows-${info.project.name}.png` });

    const show = page.getByRole("radiogroup", { name: "Show" });
    await show.getByRole("radio", { name: "Blocked" }).click();
    for (const r of await rows(page).all()) await expect(r).toHaveAttribute("data-outcome", "blocked");
    await show.getByRole("radio", { name: "Not decrypted" }).click();
    for (const r of await rows(page).all()) await expect(r).toHaveAttribute("data-outcome", "not_decrypted");
    await show.getByRole("radio", { name: "All" }).click();

    const search = page.getByRole("searchbox", { name: "Search the log" });
    await search.fill("tracker.example");
    await expect(rows(page).locator("[data-log-host]")).toHaveText(["tracker.example.org"]);
    await search.fill("zzzz");
    await expect(page.getByText("No row matches")).toBeVisible();
    await noHorizontalScroll(page);
    await page.getByRole("button", { name: "Show every row" }).click();
    await expect(rows(page).first()).toBeVisible();

    await page.getByRole("button", { name: "Clear the log" }).click();
    await expect(page.getByText("Nothing yet")).toBeVisible();
    expect(outside).toEqual([]);
    expect(errors).toEqual([]);
  });

  test("a row's details, and the row menu's preview: nothing is written until it is confirmed; Undo takes it back", async ({ page }, info) => {
    const { errors, outside } = await setup(page);
    await hold(page);
    await rowOf(page, "news.example.com").getByRole("button", { name: /^news\.example\.com,/ }).click();
    const sheet = page.getByRole("dialog");
    await expect(sheet).toContainText("news.example.com##.banner");
    await expect(sheet).toContainText("uBlock filters");
    await expect(sheet).toContainText("Connection");
    await expect(sheet).toContainText("firefox.exe");
    await noHorizontalScroll(page);
    await page.screenshot({ path: `test-results/screens/log-details-${info.project.name}.png` });
    await page.keyboard.press("Escape");
    await expect(sheet).toHaveCount(0);

    const stored = () => page.evaluate(() => JSON.parse(window.localStorage.getItem("sieve.settings")!).values["filtering.userRules"] ?? null);
    await rowOf(page, "ads.example.com").getByRole("button", { name: "Actions for ads.example.com" }).click();
    await expect(page.getByRole("menuitem")).toHaveText(["Copy URL", "Unblock", "Do not decrypt this site", "Report a broken site"]);
    await page.getByRole("menuitem", { name: "Unblock" }).click();
    const preview = page.getByRole("dialog");
    await expect(preview.locator("[data-rule-preview]")).toHaveText("@@||ads.example.com^");
    expect(await stored()).toBeNull();
    await page.screenshot({ path: `test-results/screens/log-preview-${info.project.name}.png` });
    await preview.getByRole("button", { name: "Add it" }).click();
    await expect(page.getByText("Added @@||ads.example.com^ to your rules.")).toBeVisible();
    await expect.poll(stored).toEqual(["@@||ads.example.com^"]);
    await page.getByRole("button", { name: "Undo" }).click();
    await expect.poll(stored).toBeNull();
    expect(outside).toEqual([]);
    expect(errors).toEqual([]);
  });

  for (const { action, host, key, line } of [
    { action: "Unblock", host: "ads.example.com", key: "filtering.userRules", line: "@@||ads.example.com^" },
    { action: "Block", host: "shop.example.net", key: "filtering.userRules", line: "||shop.example.net^" },
    { action: "Do not decrypt this site", host: "shop.example.net", key: "filtering.exclusions", line: "shop.example.net" },
  ]) {
    test(`from the details sheet, ${action}: Cancel goes back to the sheet; once added nothing covers the toast, and a real click on Undo takes it back`, async ({ page }) => {
      const { errors, outside } = await setup(page);
      await hold(page);
      const stored = () => page.evaluate((k) => JSON.parse(window.localStorage.getItem("sieve.settings")!).values[k] ?? null, key);
      await rowOf(page, host).getByRole("button", { name: new RegExp(`^${host.replaceAll(".", "\\.")},`) }).click();
      const details = page.locator("[data-log-details-actions]");

      await details.getByRole("button", { name: action }).click();
      await page.getByRole("button", { name: "Cancel" }).click();
      await expect(details).toBeVisible();
      expect(await stored()).toBeNull();

      await details.getByRole("button", { name: action }).click();
      await expect(page.locator("[data-rule-preview]")).toHaveText(line);
      await page.getByRole("button", { name: "Add it" }).click();
      await expect.poll(stored).toEqual([line]);
      await expect(page.getByRole("dialog")).toHaveCount(0);
      // Not forced: Playwright clicks only once the toast is what the point hits. It expires after 4 s.
      await page.getByRole("button", { name: "Undo" }).click({ timeout: 3_000 });
      await expect.poll(stored).toBeNull();
      expect(outside).toEqual([]);
      expect(errors).toEqual([]);
    });
  }

  test("the report: no query by default, restored on request, copied, and nothing is sent", async ({ page, context }, info) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    const { errors, outside } = await setup(page);
    await hold(page);
    // The page is ready: from here on nothing may be requested at all.
    const requests: string[] = [];
    page.on("request", (r) => requests.push(r.url()));

    const row = rows(page).filter({ has: page.locator('[data-log-outcome]', { hasText: "Parameters removed" }) });
    await row.getByRole("button", { name: "Actions for news.example.com" }).click();
    await page.getByRole("menuitem", { name: "Report a broken site" }).click();
    const dialog = page.getByRole("dialog");
    const url = dialog.getByRole("textbox", { name: "Page URL" });
    const report = dialog.getByRole("textbox", { name: "The report" });
    await expect(url).toHaveValue("https://news.example.com/article/42");
    await expect(report).toHaveValue(/Page URL: https:\/\/news\.example\.com\/article\/42\n/);
    await expect(report).not.toHaveValue(/s3cret|utm_source=mail/);
    await expect(report).toHaveValue(/Browser: firefox\.exe/);
    await expect(report).toHaveValue(/AdGuard Base filter: 2\.3\.72/);
    await expect(report).toHaveValue(/Resource library pin: sha256:0f4e2c7a/);
    await expect(report).toHaveValue(/Sieve version: browser preview/);
    await noHorizontalScroll(page);
    await page.screenshot({ path: `test-results/screens/log-report-${info.project.name}.png` });

    await dialog.getByRole("button", { name: "Add the query string back" }).click();
    await expect(report).toHaveValue(/token=s3cret/);
    await url.fill("https://news.example.com/article/42");

    await dialog.getByRole("button", { name: "Copy report" }).click();
    // Windows' clipboard reads back with CRLF line ends.
    await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toMatch(/Page URL: https:\/\/news\.example\.com\/article\/42\r?\n/);

    await dialog.getByRole("button", { name: "Open issue page" }).click();
    await expect.poll(() => page.evaluate(() => (window as Opened).__opened)).toEqual([ADGUARD_ISSUES]);
    const opened = (await page.evaluate(() => (window as Opened).__opened))![0];
    expect(opened).not.toContain("?");
    expect(opened).not.toContain("news.example.com");

    expect(requests).toEqual([]);
    expect(outside).toEqual([]);
    expect(errors).toEqual([]);
  });

  test("the app sheet opens the same report, with no URL yet", async ({ page, context }) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    const { errors, outside } = await setup(page, "/apps/?source=mock&seed=1&engine=hosts");
    await page.getByTestId("app-row").first().getByRole("button", { name: /Open details/ }).click();
    await page.getByRole("button", { name: "Report a broken site" }).click();
    const report = page.getByRole("textbox", { name: "The report" });
    await expect(report).toHaveValue(/Page URL: not known/);
    await expect(page.getByRole("button", { name: "Open issue page" })).toBeEnabled();
    expect(outside).toEqual([]);
    expect(errors).toEqual([]);
  });

  test("no engine: the empty state says why, from the engine's facts, and the switch stays out of it", async ({ page }, info) => {
    const { errors, outside } = await setup(page, "/log/?source=mock&seed=1", false);
    await expect(page.getByText("Nothing to show")).toBeVisible();
    await expect(page.getByRole("region", { name: "Log rows" })).toContainText("not installed on this computer");
    await expect(page.getByRole("button", { name: "Clear the log" })).toBeDisabled();
    await noHorizontalScroll(page);
    await page.screenshot({ path: `test-results/screens/log-empty-${info.project.name}.png` });
    expect(outside).toEqual([]);
    expect(errors).toEqual([]);
  });

  test("an unreadable log says so, and the screen stays", async ({ page }) => {
    const { errors, outside } = await setup(page, `${LOG}&log=error`);
    await expect(page.getByRole("alert").filter({ hasText: "could not be read" })).toBeVisible();
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Log");
    expect(outside).toEqual([]);
    expect(errors).toEqual([]);
  });
});
