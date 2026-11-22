import { expect, test, type Page } from "@playwright/test";

const GUIDE = "/?source=mock&seed=1&welcome=1&engine=adguard";
/** Home's title. */
const HOME = "Sieving now";
const SWITCH_KEYS = ["filtering.engine", "filtering.https", "filtering.content"];

const noHorizontalScroll = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
const step = (page: Page, id: string) => page.locator(`[data-welcome-step="${id}"]`);
const stored = (page: Page) => page.evaluate(() => JSON.parse(window.localStorage.getItem("sieve.settings")!).values as Record<string, unknown>);
/** What the guide wrote besides the switches, which the engine's first answer may have stored as it held them. */
const notSwitches = (values: Record<string, unknown>) => Object.fromEntries(Object.entries(values).filter(([k]) => !SWITCH_KEYS.includes(k)));

test.describe("first-run guide", () => {
  test("walks all steps; after Finish, Home shows and a reload does not bring it back", async ({ page }, info) => {
    const errors: string[] = [];
    page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto(GUIDE);

    // The mock engine was set up before (AdGuard running, routing on, HTTPS off): it keeps that, so the HTTPS step shows.
    for (const id of ["what", "switches", "https", "adguard"] as const) {
      await expect(step(page, id)).toBeVisible();
      expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
      await page.screenshot({ path: `test-results/screens/welcome-${id}-${info.project.name}.png`, fullPage: true });
      if (id === "switches") {
        await expect(step(page, id).getByRole("switch")).toHaveCount(3);
        const route = step(page, id).getByRole("switch", { name: "Route traffic through the engine" });
        await expect(route).toBeChecked();
        await expect(route).toBeEnabled();
        await expect(step(page, id).getByRole("switch", { name: "Decrypt HTTPS traffic" })).not.toBeChecked();
      }
      if (id !== "adguard") await page.getByRole("button", { name: "Next" }).click();
    }
    await expect(step(page, "adguard").getByRole("button", { name: "Pause AdGuard" })).toBeVisible();
    await expect(page.getByText("Pausing AdGuard asks its Windows service")).toBeVisible();
    await page.getByRole("button", { name: "Finish" }).click();

    await expect(page.locator("[data-welcome-step]")).toHaveCount(0);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(HOME);
    await page.reload();
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(HOME);
    await expect(page.locator("[data-welcome-step]")).toHaveCount(0);
    const values = await stored(page);
    expect(notSwitches(values)).toEqual({ "startup.welcomeDone": true });
    for (const k of SWITCH_KEYS) expect(values[k], k).not.toBe(true);
    expect(errors).toEqual([]);
  });

  test("Skip leaves at once and changes only its flag", async ({ page }) => {
    await page.goto(GUIDE);
    await page.getByRole("button", { name: "Skip" }).click();
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(HOME);
    expect(notSwitches(await stored(page))).toEqual({ "startup.welcomeDone": true });
  });

  test("a new install: the switches are on, and turning one off in the guide stores it as Settings does", async ({ page }) => {
    await page.goto("/?source=mock&seed=1&welcome=1&engine=idle");
    await page.getByRole("button", { name: "Next" }).click();
    const route = step(page, "switches").getByRole("switch", { name: "Route traffic through the engine" });
    await expect(route).toBeChecked();
    await expect(step(page, "switches").getByRole("switch", { name: "Decrypt HTTPS traffic" })).toBeChecked();
    await route.click();
    await expect(route).not.toBeChecked();
    await expect.poll(async () => (await stored(page))["filtering.engine"]).toBe(false);
  });

  test("a browser without ?welcome=1 never shows it", async ({ page }) => {
    await page.goto("/?source=mock&seed=1");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(HOME);
    await expect(page.locator("[data-welcome-step]")).toHaveCount(0);
  });
});
