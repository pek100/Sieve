import { expect, test, type Page } from "@playwright/test";

/** Settings > Filtering, the Certificate group, against the mock engine's fixture answers. */
async function openCertificate(page: Page, query: string) {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(`/settings/?source=mock&seed=1&${query}`);
  const group = page.getByRole("region", { name: "Certificate" });
  await expect(group).toBeVisible();
  return { group, errors };
}

const noHorizontalScroll = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
const state = (group: ReturnType<Page["getByRole"]>) => group.locator("[data-certificate-state]");

test.describe("certificate", () => {
  test("installed: every fact, and Remove asks first", async ({ page }, info) => {
    const { group, errors } = await openCertificate(page, "engine=idle&cert=installed");
    await expect(state(group)).toHaveText("Installed");
    await expect(group).toContainText("Valid until");
    await expect(group).toContainText("Uses Windows certificates");
    await expect(group).toContainText("a9993e364706816aba3e25717850c26c9cd0d89d");
    await expect(group).toContainText("Last rotation");
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await group.screenshot({ path: `test-results/screens/certificate-installed-${info.project.name}.png` });

    await group.getByRole("button", { name: "Remove certificate" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText("turns HTTPS filtering off");
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toHaveCount(0);
    expect(errors).toEqual([]);
  });

  test("expires soon: the state and the engine's own reason", async ({ page }, info) => {
    const { group, errors } = await openCertificate(page, "engine=idle&cert=expires_soon");
    await expect(state(group)).toHaveText("Expires soon");
    await expect(group.getByRole("alert")).toContainText("could not be created");
    await expect(group).toContainText("Does not use Windows certificates");
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await group.screenshot({ path: `test-results/screens/certificate-expires-soon-${info.project.name}.png` });
    expect(errors).toEqual([]);
  });

  test("not installed: only the state line", async ({ page }, info) => {
    const { group, errors } = await openCertificate(page, "engine=idle&cert=not_installed");
    await expect(state(group)).toHaveText("Not installed");
    await expect(group.getByRole("button")).toHaveCount(0);
    await expect(group).not.toContainText("Valid until");
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await group.screenshot({ path: `test-results/screens/certificate-not-installed-${info.project.name}.png` });
    expect(errors).toEqual([]);
  });

  test("no engine: the state is unknown and one line says why", async ({ page }) => {
    const { group, errors } = await openCertificate(page, "engine=missing");
    await expect(state(group)).toHaveText("Unknown");
    await expect(group).toContainText("The engine is not installed");
    expect(errors).toEqual([]);
  });

  test("the HTTPS switch has no row until interception exists", async ({ page }) => {
    await openCertificate(page, "engine=idle");
    await expect(page.locator('[data-setting="filtering.https"]')).toHaveCount(0);
  });
});
