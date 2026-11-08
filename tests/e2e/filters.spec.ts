import { expect, test, type Page } from "@playwright/test";
import { MAX_RULE_LINES } from "../../src/core/rules";
import { POLICY_BUDGETS, budgetBytes, defaultValue } from "../../src/core/settings/registry";

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
    await expect(page.locator('[data-choice="balanced"]').first(), "turning one more list on is no longer Balanced").toHaveAttribute("aria-checked", "false");
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
    await page.getByRole("textbox", { name: "Site" }).fill("https://ads.example.com/x");
    await expect(page.locator("[data-rule-meaning]")).toContainText("Blocks ads.example.com and every address under it");
    await page.getByRole("button", { name: "Add rule" }).click();
    await expect(editor).toHaveValue("! note\n||good.example^\n||ads.example.com^");
    await expect(page.locator("[data-rule-added]")).toContainText("Rule added.");

    await page.getByRole("textbox", { name: "Add to Allowlist" }).fill("WWW.Example.com");
    await page.locator("[data-domain-list]", { has: page.getByRole("textbox", { name: "Add to Allowlist" }) }).getByRole("button", { name: "Add", exact: true }).click();
    const entry = page.locator('[data-domain="www.example.com"]');
    await expect(entry).toBeVisible();
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await page.screenshot({ path: `test-results/screens/filters-rules-${info.project.name}.png`, fullPage: true });
    await page.reload();
    await expect(page.getByRole("textbox", { name: "User rules" })).toHaveValue("! note\n||good.example^\n||ads.example.com^");
    await expect(entry).toBeVisible();
    await entry.getByRole("button", { name: "Remove www.example.com" }).click();
    await expect(entry).toHaveCount(0);
    await page.getByRole("listitem").filter({ hasText: "Removed www.example.com" }).getByRole("button", { name: "Undo" }).click();
    await expect(entry).toBeVisible();
  });

  test("rules the engine could not hold are refused where they are saved, with the reason, and stay in the editor", async ({ page }) => {
    await open(page);
    const editor = page.getByRole("textbox", { name: "User rules" });
    // Over the rules budget and under the editor's own line limit, both derived: a change to either that leaves no such paste fails here, by name.
    const rule = (i: number) => `||a-long-enough-host-name-for-a-rule-number-${i}.tracker.for-a-rule-that-takes-room.example.com^`;
    const rulesBudget = POLICY_BUDGETS.find((b) => b.keys.includes("filtering.userRules"))!;
    const lines = Array.from({ length: Math.ceil(rulesBudget.bytes / rule(0).length) + 1 }, (_, i) => rule(i));
    expect(lines.length).toBeLessThanOrEqual(MAX_RULE_LINES);
    expect(budgetBytes(rulesBudget, (key) => (key === "filtering.userRules" ? lines : defaultValue(key)))).toBeGreaterThan(rulesBudget.bytes);
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

  test("the protection level: Balanced first, Strict in one click with an Undo, Custom by itself, back in one action", async ({ page }, info) => {
    const errors = await open(page);
    const levels = page.getByRole("radiogroup", { name: "Protection level", exact: true });
    const level = (name: RegExp) => levels.getByRole("radio", { name });
    await expect(level(/^Balanced/)).toHaveAttribute("aria-checked", "true");
    await expect(level(/^Balanced/)).toContainText("Recommended");
    const top = await levels.boundingBox();
    expect(top, "the level is the first thing under the title").not.toBeNull();
    expect(top!.y).toBeLessThan(info.project.name === "mobile" ? 400 : 260);
    await level(/^Strict/).click();
    await expect(group(page, "annoyances")).toContainText("5 of 5 on");
    await page.getByRole("listitem").filter({ hasText: "Using Strict" }).getByRole("button", { name: "Undo" }).click();
    await expect(level(/^Balanced/)).toHaveAttribute("aria-checked", "true");
    await list(page, "adguard-tracking").getByRole("switch").click();
    await expect(page.locator("[data-profile-custom]")).toContainText("Custom");
    await page.screenshot({ path: `test-results/screens/filters-custom-${info.project.name}.png` });
    await page.locator("[data-profile-custom]").getByRole("button", { name: "Back to recommended" }).click();
    await expect(level(/^Balanced/)).toHaveAttribute("aria-checked", "true");
    await expect(list(page, "adguard-tracking").getByRole("switch")).toBeChecked();
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    expect(errors).toEqual([]);
  });

  test("tracking protection is not shown while the engine does not carry it out", async ({ page }) => {
    await open(page);
    await expect(page.locator("[data-own-lists]")).toBeVisible();
    await expect(page.locator("[data-tracking]")).toHaveCount(0);
    await expect(page.getByText("Ask sites not to track you")).toHaveCount(0);
  });

  test("an own list by address: added, refused with a sentence when it is not https, its rules viewable with the engine", async ({ page }, info) => {
    const errors = await open(page, "&engine=filtering");
    const address = page.getByRole("textbox", { name: "List address" });
    await address.fill("http://lists.example/mine.txt");
    await page.getByRole("button", { name: "Add list" }).click();
    await expect(page.locator("[data-own-error]")).toContainText("https only");
    await address.fill("https://lists.example/My%20blocklist.txt");
    await page.getByRole("button", { name: "Add list" }).click();
    const own = page.locator("[data-own-list]");
    await expect(own).toHaveCount(1);
    await expect(own).toContainText("My blocklist");
    await own.getByRole("button", { name: "Actions for My blocklist" }).click();
    await page.getByRole("menuitem", { name: "View rules" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.locator("[data-rules-caption]")).toContainText("rules");
    await dialog.getByRole("searchbox").fill("pixel");
    await expect(dialog.locator("[data-rules-caption]")).toHaveText(/^105 of 420 rules match\.$/);
    await expect(dialog.getByRole("listitem").first()).toContainText("pixel");
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await page.screenshot({ path: `test-results/screens/filters-rules-view-${info.project.name}.png` });
    await page.keyboard.press("Escape");
    expect(errors, "before the reload").toEqual([]);
    await page.reload();
    await expect(page.locator("[data-own-list]")).toContainText("My blocklist");
    expect(errors).toEqual([]);
  });
});
