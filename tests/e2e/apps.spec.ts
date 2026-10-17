import { expect, test, type Page } from "@playwright/test";

const APPS = "/apps/?source=mock&seed=1";
const CHROME = "google chrome";

const row = (page: Page, key: string) => page.locator(`[data-testid="app-row"][data-app="${key}"]`);

function collectErrors(page: Page) {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("response", (r) => r.status() >= 400 && errors.push(`${r.status()} ${r.url()}`));
  return errors;
}

async function noHorizontalScroll(page: Page) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
}

test.describe("apps", () => {
  test("lists apps by derived category with 44 px rows, each sieved by default", async ({ page }, info) => {
    const errors = collectErrors(page);
    await page.goto(APPS);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Apps");
    await expect(page.getByRole("link", { name: "Apps" })).toHaveAttribute("aria-current", "page");

    const system = page.getByRole("region", { name: /^System/ });
    await expect(system.getByText("Microsoft Windows Operating System")).toBeVisible();
    const apps = page.getByRole("region", { name: /^Apps\s*\d/ });
    await expect(apps.locator(`[data-app="${CHROME}"]`)).toBeVisible();

    const box = await row(page, CHROME).boundingBox();
    expect(box?.height).toBe(44);

    const toggle = row(page, CHROME).getByRole("switch", { name: "Sieve Google Chrome" });
    await expect(toggle).toBeChecked();
    // Off is honest about DNS: said once, as the toggle's description and tooltip.
    await expect(toggle).toHaveAttribute("title", /DNS blocking still covers it/);
    await expect(page.getByTestId("sieved-count")).toContainText(/^\d+ being sieved$/);
    await expect(page.getByRole("radio")).toHaveCount(0);

    await noHorizontalScroll(page);
    await page.screenshot({ path: `test-results/screens/apps-${info.project.name}.png`, fullPage: true });
    expect(errors).toEqual([]);
  });

  test("turning an app off survives a reload; other apps stay on", async ({ page }) => {
    await page.goto(APPS);
    const toggle = row(page, CHROME).getByRole("switch");
    await toggle.click();
    await expect(toggle).not.toBeChecked();
    await page.reload();
    await expect(row(page, CHROME).getByRole("switch")).not.toBeChecked();
    await expect(row(page, "discord").getByRole("switch")).toBeChecked();
  });

  test("?app=<key> opens that app's panel directly, hosts in mono", async ({ page }, info) => {
    const errors = collectErrors(page);
    await page.goto(`${APPS}&app=${encodeURIComponent(CHROME)}`);
    const sheet = page.getByRole("dialog");
    await expect(sheet.getByRole("heading", { name: "Google Chrome" })).toBeVisible();
    const host = sheet.getByTestId("host").first();
    await expect(host).toBeVisible();
    expect(await host.evaluate((el) => getComputedStyle(el).fontFamily)).toContain("JetBrains Mono");
    const connection = await sheet.getByTestId("connection-row").first().boundingBox();
    expect(connection?.height).toBe(44);
    // Let the slide-in finish so the screenshot shows the resting sheet.
    await sheet.evaluate((el) => Promise.all(el.getAnimations({ subtree: true }).map((a) => a.finished)));
    const rect = await sheet.boundingBox();
    expect(rect!.x + rect!.width).toBeLessThanOrEqual(info.project.use.viewport!.width);
    await noHorizontalScroll(page);
    await page.screenshot({ path: `test-results/screens/apps-detail-${info.project.name}.png` });

    await page.keyboard.press("Escape");
    await expect(sheet).toHaveCount(0);
    await expect(page).not.toHaveURL(/app=/);
    expect(errors).toEqual([]);
  });

  test("search with no match shows the no-results state and Escape clears it", async ({ page }) => {
    await page.goto(APPS);
    // Rows come from client data, so this waits for hydration; typing into the static
    // box before React attaches loses the value under a loaded machine.
    await expect(row(page, CHROME)).toBeVisible();
    const box = page.getByRole("searchbox", { name: "Search apps" });
    await box.fill("zzzz-nothing");
    await expect(page.getByText("Nothing by that name")).toBeVisible();
    await expect(page.getByTestId("app-row")).toHaveCount(0);
    await box.press("Escape");
    await expect(box).toHaveValue("");
    await expect(row(page, CHROME)).toBeVisible();
  });

  test("add a program by path, then remove it with undo", async ({ page }, info) => {
    await page.goto(APPS);
    await page.getByRole("button", { name: "Add app" }).click();
    const dialog = page.getByRole("dialog", { name: "Add an app" });
    await dialog.getByLabel("Program path").fill("D:\\Tools\\quiet.exe");
    await dialog.getByRole("button", { name: "Add" }).click();
    const mine = page.getByRole("region", { name: /^Mine/ });
    await expect(mine.locator('[data-app="quiet"]')).toBeVisible();
    await page.screenshot({ path: `test-results/screens/apps-mine-${info.project.name}.png`, fullPage: true });

    await page.getByRole("button", { name: "Remove quiet from my apps" }).click();
    await expect(mine.locator('[data-app="quiet"]')).toHaveCount(0);
    await page.getByRole("button", { name: "Undo" }).click();
    await expect(mine.locator('[data-app="quiet"]')).toBeVisible();
  });
});
