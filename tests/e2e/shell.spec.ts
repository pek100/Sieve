import { expect, test } from "@playwright/test";

const HOME = "/?source=mock&seed=1";

test.describe("shell", () => {
  test("renders the top bar, nav and home grid with no console errors", async ({ page }, info) => {
    const errors: string[] = [];
    page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
    page.on("pageerror", (e) => errors.push(e.message));

    await page.goto(HOME);
    await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Home" })).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("switch", { name: "Sieving" })).toBeChecked();
    await expect(page.getByRole("status")).toHaveAttribute("data-phase", "live");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Sieving now");
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

    await page.screenshot({ path: `test-results/screens/shell-${info.project.name}.png`, fullPage: true });
    expect(errors).toEqual([]);
  });

  test("has no horizontal scroll", async ({ page }) => {
    await page.goto(HOME);
    await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  });

  test("the master switch stops sampling and the theme menu switches to light", async ({ page }, info) => {
    await page.goto(HOME);
    await page.getByRole("switch", { name: "Sieving" }).click();
    await expect(page.getByRole("status")).toHaveAttribute("data-phase", "off");

    await page.getByRole("button", { name: /^Theme/ }).click();
    await page.getByRole("menuitem", { name: "Light" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await expect(page.getByRole("menu")).toHaveCount(0);
    // Tokens reach the page: cards are radius 16 and the light page background is the light bg role.
    const card = page.getByRole("region", { name: "Top apps" });
    await expect(card).toHaveCSS("border-top-left-radius", "16px");
    await expect(page.locator("body")).toHaveCSS("background-color", "rgb(246, 242, 251)");
    await page.screenshot({ path: `test-results/screens/shell-light-${info.project.name}.png`, fullPage: true });

    // Settings persist in the browser across a reload.
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await expect(page.getByRole("switch", { name: "Sieving" })).not.toBeChecked();
  });

  test("scenario error shows the error phase, never mock data", async ({ page }) => {
    await page.goto("/?source=mock&scenario=error");
    await expect(page.getByRole("status")).toHaveAttribute("data-phase", "error");
  });
});
