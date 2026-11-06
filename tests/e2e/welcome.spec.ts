import { expect, test, type Page } from "@playwright/test";

const GUIDE = "/?source=mock&seed=1&welcome=1&engine=adguard";
/** Home's title. */
const HOME = "Sieving now";

const noHorizontalScroll = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
const step = (page: Page, id: string) => page.locator(`[data-welcome-step="${id}"]`);

test.describe("first-run guide", () => {
  test("walks all steps; after Finish, Home shows and a reload does not bring it back", async ({ page }, info) => {
    const errors: string[] = [];
    page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto(GUIDE);

    for (const [id, name] of [["what", "what"], ["switches", "switches"], ["adguard", "adguard"]] as const) {
      await expect(step(page, id)).toBeVisible();
      expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
      await page.screenshot({ path: `test-results/screens/welcome-${name}-${info.project.name}.png`, fullPage: true });
      if (id === "switches") {
        const sw = step(page, id).getByRole("switch");
        await expect(sw).toHaveCount(1);
        await expect(sw).toBeDisabled();
        await expect(sw).not.toBeChecked();
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
    expect(await page.evaluate(() => JSON.parse(window.localStorage.getItem("sieve.settings")!).values)).toEqual({ "startup.welcomeDone": true });
    expect(errors).toEqual([]);
  });

  test("Skip leaves at once and changes only its flag", async ({ page }) => {
    await page.goto(GUIDE);
    await page.getByRole("button", { name: "Skip" }).click();
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(HOME);
    expect(await page.evaluate(() => JSON.parse(window.localStorage.getItem("sieve.settings")!).values)).toEqual({ "startup.welcomeDone": true });
  });

  test("a browser without ?welcome=1 never shows it", async ({ page }) => {
    await page.goto("/?source=mock&seed=1");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(HOME);
    await expect(page.locator("[data-welcome-step]")).toHaveCount(0);
  });
});
