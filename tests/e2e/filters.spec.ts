import { expect, test, type Page } from "@playwright/test";

const FILTERS = "/filters/?source=mock&seed=1";

async function open(page: Page, extra = "") {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(`${FILTERS}${extra}`);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Filters");
  await expect(page.getByRole("region", { name: "Filter lists" })).toBeVisible();
  return errors;
}

const noHorizontalScroll = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
const list = (page: Page, id: string) => page.locator(`[data-list="${id}"]`);
const group = (page: Page, id: string) => page.locator(`[data-list-group="${id}"]`);

test.describe("filters", () => {
  test("the catalogue says nothing is loaded and nothing is applied, with no 0 and no sideways scroll", async ({ page }, info) => {
    const errors = await open(page);
    await expect(page.getByRole("link", { name: "Filters" })).toHaveAttribute("aria-current", "page");
    await expect(list(page, "adguard-base")).toContainText("Not loaded yet");
    await expect(page.locator("[data-filters-pending]")).toContainText("No filter list is in force yet");
    await expect(page.locator("[data-list-catalogue]")).not.toContainText("0 applied");
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await page.screenshot({ path: `test-results/screens/filters-${info.project.name}.png`, fullPage: true });
    expect(errors).toEqual([]);
  });

  test("toggling a list persists across a reload; a gated list is shut", async ({ page }) => {
    await open(page);
    const sw = list(page, "adguard-cookies").getByRole("switch");
    await expect(sw).not.toBeChecked();
    await sw.click();
    await expect(sw).toBeChecked();
    await page.reload();
    await expect(list(page, "adguard-cookies").getByRole("switch")).toBeChecked();
    await expect(list(page, "ubo-filters").getByRole("switch")).toBeDisabled();
    await expect(list(page, "ubo-filters")).toContainText("Waiting on testing");
  });

  test("the group switch changes its lists", async ({ page }) => {
    await open(page);
    const annoyances = group(page, "annoyances");
    await expect(annoyances).toContainText("0 of 5 on");
    await annoyances.getByRole("switch", { name: "All annoyances lists" }).click();
    await expect(annoyances).toContainText("5 of 5 on");
    await expect(list(page, "adguard-popups").getByRole("switch")).toBeChecked();
    await list(page, "adguard-popups").getByRole("switch").click();
    await expect(annoyances).toContainText("4 of 5 on");
  });

  test("?lists=loaded shows counts; the not-applied line goes", async ({ page }, info) => {
    await open(page, "&lists=loaded");
    await expect(list(page, "adguard-base")).toContainText("48,211 applied, 12 skipped");
    await expect(page.locator("[data-filters-pending]")).toHaveCount(0);
    await list(page, "adguard-base").locator("[data-list-count]").hover();
    await expect(page.getByRole("tooltip")).toContainText("unrecognised option");
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await page.screenshot({ path: `test-results/screens/filters-loaded-${info.project.name}.png` });
  });

  test("?lists=error shows the block's error state and the rest of the screen lives", async ({ page }) => {
    await page.goto(`${FILTERS}&lists=error`);
    await expect(page.getByRole("region", { name: "Filter lists" }).getByRole("alert")).toContainText("could not be read");
    await expect(page.getByRole("textbox", { name: "User rules" })).toBeVisible();
  });

  test("rules: an error names its line and stops the save; a saved rule persists; allowlist add and undo", async ({ page }, info) => {
    await open(page);
    const editor = page.getByRole("textbox", { name: "User rules" });
    await editor.fill("! note\n||bad rule^");
    await expect(page.getByRole("list", { name: "Rule problems" })).toContainText("Line 2");
    await expect(page.getByRole("button", { name: "Save rules" })).toBeDisabled();
    await editor.fill("! note\n||good.example^");
    await page.getByRole("button", { name: "Save rules" }).click();
    await expect(page.getByRole("button", { name: "Save rules" })).toBeDisabled();
    await page.getByRole("textbox", { name: "Block a site" }).fill("https://ads.example.com/x");
    await page.getByRole("button", { name: "Add rule" }).click();
    await expect(editor).toHaveValue("! note\n||good.example^\n||ads.example.com^");

    await page.getByRole("textbox", { name: "Add to Allowlist" }).fill("WWW.Example.com");
    await page.locator("[data-domain-list]", { has: page.getByRole("textbox", { name: "Add to Allowlist" }) }).getByRole("button", { name: "Add", exact: true }).click();
    const entry = page.locator('[data-domain="www.example.com"]');
    await expect(entry).toBeVisible();
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await page.screenshot({ path: `test-results/screens/filters-rules-${info.project.name}.png`, fullPage: true });
    await page.reload();
    await expect(page.getByRole("textbox", { name: "User rules" })).toHaveValue("! note\n||good.example^");
    await expect(entry).toBeVisible();
    await entry.getByRole("button", { name: "Remove www.example.com" }).click();
    await expect(entry).toHaveCount(0);
    await page.getByRole("listitem").filter({ hasText: "Removed www.example.com" }).getByRole("button", { name: "Undo" }).click();
    await expect(entry).toBeVisible();
  });

  test("rules the engine could not hold are refused where they are saved, with the reason, and stay in the editor", async ({ page }) => {
    await open(page);
    const editor = page.getByRole("textbox", { name: "User rules" });
    // Under the editor's own line limit, over what one policy can carry.
    const lines = Array.from({ length: 4_900 }, (_, i) => `||a-long-enough-host-name-for-a-rule-number-${i}.tracker.for-a-rule-that-takes-room.example.com^`);
    // As a paste lands: fill() inserts text through the editing path, too slow for half a megabyte.
    await editor.evaluate((el, text) => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(el, text);
      el.dispatchEvent(new Event("input", { bubbles: true }));
    }, lines.join("\n"));
    await page.getByRole("button", { name: "Save rules" }).click();
    await expect(page.getByRole("list", { name: "Rule problems" }).getByRole("alert")).toContainText("the engine can hold, so this was not saved");
    await expect(editor).toHaveValue(new RegExp(`number-${lines.length - 1}\\.`));
    await page.reload();
    await expect(page.getByRole("textbox", { name: "User rules" })).toHaveValue("");
  });
});
