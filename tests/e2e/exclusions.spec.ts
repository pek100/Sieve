import { expect, test, type Page } from "@playwright/test";

/**
 * Settings > Filtering, "Not decrypted", against the mock engine that holds HTTPS on
 * (`?heal=1`: the app cannot turn it on while `filtering.https` is unavailable).
 */
const noHorizontalScroll = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);

async function openGroup(page: Page, extra = "") {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(`/settings/?source=mock&seed=1&engine=idle&heal=1${extra}#not-decrypted`);
  const group = page.getByRole("region", { name: "Not decrypted" });
  await expect(group).toBeVisible();
  return { group, errors };
}

const lines = (group: ReturnType<Page["getByRole"]>) => group.locator("[data-exclusion-row] .font-mono");

test.describe("exclusions", () => {
  for (const [name, viewport] of [
    ["wide", { width: 1280, height: 800 }],
    ["narrow", { width: 375, height: 812 }],
  ] as const) {
    test(`the group at ${viewport.width}x${viewport.height}, no sideways overflow`, async ({ page }, info) => {
      await page.setViewportSize(viewport);
      const { group, errors } = await openGroup(page);
      await expect(lines(group)).toHaveCount(4);
      await expect(group).toContainText(/Rejected Sieve's certificate \(auto\), tried again 1 time, first on .*2026/);
      await expect(group).toContainText("Sieve never decrypts these");
      await expect(group.getByRole("radiogroup", { name: "Filter by reason" })).toBeVisible();
      expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
      await group.screenshot({ path: `test-results/screens/exclusions-${name}-${info.project.name}.png` });
      expect(errors).toEqual([]);
    });
  }

  test("a deep link filters", async ({ page }, info) => {
    const { group } = await openGroup(page, "&exclusionsApp=client.exe&exclusionsReason=pinning");
    await expect(lines(group)).toHaveText(['"pin.example"']);
    await expect(group.getByRole("radio", { name: "Rejected" })).toBeChecked();
    await expect(group.getByRole("button", { name: "Try decrypting all again" })).toBeVisible();
    await group.screenshot({ path: `test-results/screens/exclusions-filtered-${info.project.name}.png` });
    await group.getByRole("button", { name: "Try decrypting all again" }).click();
    await expect(lines(group)).toHaveCount(0);
    await group.getByRole("button", { name: "Show every row" }).click();
    await expect(lines(group)).toHaveCount(3);
    const asked = new URL(page.url()).searchParams;
    expect([asked.get("exclusionsApp"), asked.get("exclusionsReason")]).toEqual([null, null]);
  });

  test("a link carrying every file of an app holds the rows of the one that was excluded, and can try them", async ({ page }) => {
    const { group } = await openGroup(page, "&exclusionsApp=agent.exe&exclusionsApp=client.exe&exclusionsReason=pinning");
    await expect(lines(group)).toHaveText(['"pin.example"']);
    await group.getByRole("button", { name: "Try decrypting all again" }).click();
    await expect(lines(group)).toHaveCount(0);
  });

  test("the toast appears once with two grouped exclusions, and Show opens the filtered view", async ({ page }, info) => {
    await page.goto("/?source=mock&seed=1&engine=idle&heal=1");
    const first = page.getByText("rejected Sieve's certificate for pin.example");
    const grouped = page.getByText("rejected Sieve's certificate for 2 sites");
    await expect(first.or(grouped)).toBeVisible();
    await expect(grouped).toBeVisible({ timeout: 10_000 });
    await expect(first).toHaveCount(0);
    await expect(grouped).toHaveCount(1);
    await page.screenshot({ path: `test-results/screens/exclusions-toast-${info.project.name}.png` });
    await page.getByRole("button", { name: "Show" }).click();
    await expect(page).toHaveURL(/\/settings\/\?exclusionsApp=client\.exe&exclusionsReason=pinning#not-decrypted$/);
    const group = page.getByRole("region", { name: "Not decrypted" });
    await expect(lines(group)).toHaveText(['"pin.example"']);
    await expect(group).toBeInViewport();
  });

  test("the group filters in place when the toast is followed from Settings", async ({ page }) => {
    await page.goto("/settings/?source=mock&seed=1&engine=idle&heal=1");
    const group = page.getByRole("region", { name: "Not decrypted" });
    await expect(lines(group)).toHaveCount(4);
    await page.getByRole("button", { name: "Show" }).click();
    await expect(lines(group)).toHaveText(['"pin.example"']);
  });

  test("with the engine not holding HTTPS, the user's rows and one line", async ({ page }) => {
    await page.goto("/settings/?source=mock&seed=1&engine=idle#not-decrypted");
    const group = page.getByRole("region", { name: "Not decrypted" });
    await expect(group).toContainText("Sieve is not decrypting HTTPS right now");
    await group.getByRole("textbox", { name: "Add a site not to decrypt" }).fill("shop.example");
    await group.getByRole("button", { name: "Add" }).click();
    await expect(lines(group)).toHaveText(["shop.example"]);
    await group.getByRole("button", { name: "Remove shop.example" }).click();
    await expect(lines(group)).toHaveCount(0);
    await page.getByRole("button", { name: "Undo" }).click();
    await expect(lines(group)).toHaveText(["shop.example"]);
  });
});
