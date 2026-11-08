import { expect, test, type Page } from "@playwright/test";

/**
 * The owner's story: a game launcher's updater suddenly fails. Apps shows it
 * under "Having trouble" with the likely cause in words; its sheet lists what
 * went wrong and fixes it in one step. Everything stays on this PC: every
 * request but the local server's is refused, and none is made.
 */
const APPS = "/apps/?source=mock&seed=1&engine=filtering";

function collectErrors(page: Page) {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("response", (r) => r.status() >= 400 && errors.push(`${r.status()} ${r.url()}`));
  return errors;
}

/** Only the static server answers; anything else would be data leaving the PC. */
async function localOnly(page: Page) {
  const outside: string[] = [];
  await page.route("**/*", (route) => {
    const url = new URL(route.request().url());
    if (url.hostname === "127.0.0.1") return route.continue();
    outside.push(url.href);
    return route.abort();
  });
  return outside;
}

async function switchedOn(page: Page) {
  await page.goto("/settings/?source=mock&seed=1&engine=filtering");
  const route = page.getByRole("switch", { name: /Route traffic through the engine/ });
  await expect(route).toBeVisible();
  if (!(await route.isChecked())) await route.click();
  await expect(route).toBeChecked();
}

async function noHorizontalScroll(page: Page) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
}

test("a failing updater: found under Having trouble, the cause in words, fixed in one step, nothing sent", async ({ page }, info) => {
  const errors = collectErrors(page);
  const outside = await localOnly(page);
  await switchedOn(page);
  await page.goto(`${APPS}&issues=some`);

  const trouble = page.getByTestId("trouble");
  await expect(trouble).toBeVisible();
  const game = trouble.locator('[data-testid="trouble-row"][data-app="game launcher"]');
  await expect(game).toContainText("9 of 40 connections had trouble");
  await expect(game).toContainText("Sieve is the likely cause.");
  // A VM's row is named as the Apps screen names it, never by its key.
  await expect(trouble.locator('[data-testid="trouble-row"][data-app="vm:devbox"]')).toContainText("DevBox");
  await expect(trouble).not.toContainText("vm:devbox");
  // First on the page, above every group.
  const mine = page.getByRole("button", { name: /^Mine/ });
  expect((await trouble.boundingBox())!.y).toBeLessThan((await mine.boundingBox())!.y);
  await noHorizontalScroll(page);
  await page.screenshot({ path: `test-results/screens/issues-list-${info.project.name}.png`, fullPage: true });

  await game.getByRole("button").click();
  const problems = page.getByTestId("app-problems");
  await expect(problems).toBeVisible();
  await expect(problems.getByTestId("problem").first()).toContainText("It refused to let Sieve look inside its secure connection: cdn.game.example, 4 times");
  await expect(problems.getByText("Likely the network or the server, not Sieve").first()).toBeVisible();
  await expect(page.getByRole("dialog").getByRole("heading", { name: "launcher.exe" })).toBeVisible();
  // The sheet's slide has ended (the master switch's breathing never does).
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running" || a.effect?.getTiming().iterations === Infinity));
  await page.screenshot({ path: `test-results/screens/issues-sheet-${info.project.name}.png` });

  await problems.getByRole("button", { name: "Unblock this site: updates.game.example" }).click();
  const dialog = page.getByRole("dialog", { name: /Unblock updates.game.example/ });
  await expect(dialog.getByText("@@||updates.game.example^")).toBeVisible();
  await dialog.getByRole("button", { name: "Add it" }).click();
  await expect(page.getByText("Added @@||updates.game.example^ to your rules.")).toBeVisible();

  expect(outside).toEqual([]);
  expect(errors).toEqual([]);
});

test("degraded and failed answers never break the screen", async ({ page }) => {
  const errors = collectErrors(page);
  await switchedOn(page);
  await page.goto(`${APPS}&issues=partial`);
  await expect(page.locator('[data-testid="trouble-row"]')).toHaveCount(1);
  await page.goto(`${APPS}&issues=error`);
  await expect(page.getByTestId("trouble-error")).toBeVisible();
  await expect(page.locator('[data-testid="app-row"]').first()).toBeVisible();
  await noHorizontalScroll(page);
  expect(errors).toEqual([]);
});

test("no trouble, no block: the screen claims nothing", async ({ page }) => {
  await switchedOn(page);
  await page.goto(APPS);
  await expect(page.locator('[data-testid="app-row"]').first()).toBeVisible();
  await expect(page.getByTestId("trouble")).toHaveCount(0);
});
