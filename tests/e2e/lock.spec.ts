import { expect, test, type Page } from "@playwright/test";

/** The mock's own test password (src/data/lock-mock.ts), memory only. */
const MOCK_PASSWORD = "mock-password";
const NEW_PASSWORD = "a good password";

const noHorizontalScroll = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
const block = (page: Page) => page.locator("[data-password-block]");
const row = (page: Page, key: string) => page.locator(`[data-setting="${key}"]`);

test.describe("settings password", () => {
  test("set, lock, a wrong password says so, unlock", async ({ page }, info) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("/settings/?source=mock&seed=1&lock=none#section-password");
    await block(page).scrollIntoViewIfNeeded();
    await expect(block(page)).toHaveAttribute("data-lock-phase", "none");
    await block(page).getByRole("button", { name: "Set a password" }).click();
    const set = page.getByRole("dialog", { name: "Set a password" });
    await set.getByLabel("New password", { exact: true }).fill(NEW_PASSWORD);
    await set.getByLabel("New password again").fill(NEW_PASSWORD);
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await page.screenshot({ path: `test-results/screens/lock-set-${info.project.name}.png` });
    await set.getByRole("button", { name: "Set password" }).click();
    await expect(block(page)).toHaveAttribute("data-lock-phase", "unlocked");

    await block(page).getByRole("button", { name: "Lock now" }).click();
    await expect(block(page)).toHaveAttribute("data-lock-phase", "locked");
    await expect(row(page, "appearance.theme").getByRole("radio", { name: "Light" })).toBeDisabled();

    await block(page).getByRole("button", { name: "Unlock" }).click();
    const unlock = page.getByRole("dialog", { name: "Unlock settings" });
    await unlock.getByLabel("Password").fill("not the password");
    await unlock.getByRole("button", { name: "Unlock" }).click();
    await expect(unlock.getByRole("alert")).toHaveText("That is not the password.");
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await page.screenshot({ path: `test-results/screens/lock-wrong-${info.project.name}.png` });
    await unlock.getByLabel("Password").fill(NEW_PASSWORD);
    await unlock.getByRole("button", { name: "Unlock" }).click();
    await expect(unlock).toHaveCount(0);
    await expect(block(page)).toHaveAttribute("data-lock-phase", "unlocked");
    await expect(row(page, "appearance.theme").getByRole("radio", { name: "Light" })).toBeEnabled();
    expect(errors).toEqual([]);
  });

  test("with a password, Settings rows are disabled with the note and the master switch asks", async ({ page }, info) => {
    await page.goto("/settings/?source=mock&seed=1&lock=set");
    const theme = row(page, "appearance.theme");
    await expect(theme.locator("[data-lock=password]")).toContainText("Settings are locked.");
    await expect(theme.getByRole("radio", { name: "Light" })).toBeDisabled();
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await page.screenshot({ path: `test-results/screens/lock-rows-${info.project.name}.png` });

    await page.getByRole("banner").getByRole("switch", { name: "Sieving" }).click();
    const unlock = page.getByRole("dialog", { name: "Unlock settings" });
    await expect(unlock).toBeVisible();
    await expect(page.getByRole("banner").getByRole("switch", { name: "Sieving" })).toBeChecked();
    await unlock.getByLabel("Password").fill(MOCK_PASSWORD);
    await unlock.getByRole("button", { name: "Unlock" }).click();
    await expect(page.getByRole("banner").getByRole("switch", { name: "Sieving" })).not.toBeChecked();
    await expect(theme.locator("[data-lock=password]")).toHaveCount(0);
  });

  test("the top bar's lock shows only with a password, and Filters is read only while locked", async ({ page }, info) => {
    await page.goto("/filters/?source=mock&seed=1&lock=set");
    await expect(page.getByRole("region", { name: "Filter lists" })).toBeVisible();
    await expect(page.locator('[data-list="adguard-base"]').getByRole("switch")).toBeDisabled();
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    if (info.project.name === "desktop") await expect(page.getByRole("banner").getByRole("button", { name: "Unlock settings" })).toBeVisible();
    else await expect(page.getByRole("banner").getByRole("button", { name: "Unlock settings" })).toBeHidden();
    await page.goto("/?source=mock&seed=1");
    await expect(page.getByRole("banner").getByRole("button", { name: /Lock now|Unlock settings/ })).toHaveCount(0);
  });
});
