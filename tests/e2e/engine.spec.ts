import { expect, test, type Page } from "@playwright/test";

/** Settings > Filtering, the Engine block, against the mock engine's fixture answers. */
async function openEngine(page: Page, scenario?: string) {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(`/settings/?source=mock&seed=1${scenario ? `&engine=${scenario}` : ""}`);
  const block = page.getByRole("region", { name: "Engine" });
  await expect(block).toBeVisible();
  return { block, errors };
}

const noHorizontalScroll = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);

/** The user's engine switch stored on, as an earlier session would leave it. */
const switchedOn = (page: Page) =>
  page.addInitScript(() => window.localStorage.setItem("sieve.settings", JSON.stringify({ schema: 4, values: { "filtering.engine": true } })));

test.describe("engine", () => {
  test("a refused copy locks the switch, explains where to open Sieve, and leaves its stored wish alone", async ({ page }) => {
    await switchedOn(page);
    const { block, errors } = await openEngine(page, "refused");
    await expect(block.locator("[data-engine-phase]")).toHaveAttribute("data-engine-phase", "refused");
    const row = page.getByRole("group", { name: "Route traffic through the engine", exact: true });
    await expect(row.getByRole("switch")).toBeDisabled();
    await expect(row.getByRole("switch")).not.toBeChecked();
    await expect(row.locator("[data-lock=engine]")).toHaveText(
      "This copy of Sieve is not the installed one, so it cannot control the engine. Open Sieve from the Start menu.",
    );
    expect(await page.evaluate(() => JSON.parse(window.localStorage.getItem("sieve.settings")!).values["filtering.engine"])).toBe(true);
    expect(errors).toEqual([]);
  });

  test("a browser has no engine: Not installed, said from the facts", async ({ page }, info) => {
    const { block, errors } = await openEngine(page);
    await expect(block.locator("[data-engine-phase]")).toHaveAttribute("data-engine-phase", "not_installed");
    await expect(block.locator("[data-engine-state]")).toHaveText("Not installed");
    await block.scrollIntoViewIfNeeded();
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await block.screenshot({ path: `test-results/screens/engine-missing-${info.project.name}.png` });
    expect(errors).toEqual([]);
  });

  test("installed and idle: Installed, not routing, with the engine's version", async ({ page }, info) => {
    const { block, errors } = await openEngine(page, "idle");
    await expect(block.locator("[data-engine-state]")).toHaveText("Installed, not routing");
    await expect(block).toContainText("Engine version 0.1.0");
    await expect(block).not.toContainText(/blocked|is filtering/i);
    await block.screenshot({ path: `test-results/screens/engine-idle-${info.project.name}.png` });
    expect(errors).toEqual([]);
  });

  test("the switch routes traffic through the engine; nothing is blocked, and the engine's counters are stated", async ({ page }, info) => {
    const { block, errors } = await openEngine(page, "idle");
    const toggle = page.getByRole("switch", { name: "Route traffic through the engine" });
    await expect(toggle).not.toBeChecked();
    await toggle.click();
    await expect(block.locator("[data-engine-state]")).toHaveText("Routing traffic");
    await expect(block.locator("[data-engine-detail]")).toContainText("Nothing is blocked yet");
    await expect(block.locator("[data-engine-split]")).toContainText("Corp VPN sends some traffic around Sieve");
    await expect(block.locator("[data-engine-attribution]")).toContainText("tied to an app");
    await block.scrollIntoViewIfNeeded();
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await block.screenshot({ path: `test-results/screens/engine-routing-${info.project.name}.png` });
    await toggle.click();
    await expect(block.locator("[data-engine-state]")).toHaveText("Installed, not routing");
    expect(errors).toEqual([]);
  });

  test("AdGuard running: the engine waits, the offer says it stops AdGuard's service, and Start AdGuard again undoes it", async ({ page }, info) => {
    await switchedOn(page);
    const { block, errors } = await openEngine(page, "adguard");
    await expect(block.locator("[data-engine-state]")).toHaveText("Waiting for AdGuard");
    const offer = block.locator("[data-adguard-offer]");
    await expect(offer).toHaveAttribute("data-adguard-offer", "pause");
    await expect(offer).toContainText("Pausing AdGuard stops its Windows service (Adguard Service). Windows asks you to approve it.");
    await block.scrollIntoViewIfNeeded();
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await block.screenshot({ path: `test-results/screens/engine-adguard-${info.project.name}.png` });
    await block.getByRole("button", { name: "Pause AdGuard" }).click();
    await expect(block.locator("[data-engine-state]")).toHaveText("Routing traffic");
    await expect(offer).toHaveAttribute("data-adguard-offer", "start");
    await block.getByRole("button", { name: "Start AdGuard again" }).click();
    await expect(block.locator("[data-engine-state]")).toHaveText("Waiting for AdGuard");
    expect(errors).toEqual([]);
  });

  test("a full-tunnel VPN pauses the engine and names the adapter", async ({ page }) => {
    await switchedOn(page);
    const { block, errors } = await openEngine(page, "vpn");
    await expect(block.locator("[data-engine-state]")).toHaveText("Paused for a VPN");
    await expect(block.locator("[data-engine-detail]")).toContainText("Paused while AdGuard VPN is connected");
    expect(errors).toEqual([]);
  });

  test("installed but stopped: Not running", async ({ page }) => {
    const { block, errors } = await openEngine(page, "stopped");
    await expect(block.locator("[data-engine-state]")).toHaveText("Not running");
    expect(errors).toEqual([]);
  });

  test("the engine sits on the settings column, under the other sections", async ({ page }, info) => {
    test.skip(info.project.name !== "desktop", "one column on a phone");
    const { block } = await openEngine(page, "idle");
    // The DNS filter that used to sit above it is hidden until the engine replaces it.
    const apps = (await page.getByRole("region", { name: "Apps" }).boundingBox())!;
    const engine = (await block.boundingBox())!;
    expect(Math.abs(engine.x - apps.x)).toBeLessThanOrEqual(1);
    expect(Math.abs(engine.width - apps.width)).toBeLessThanOrEqual(1);
    expect(engine.y).toBeGreaterThanOrEqual(apps.y + apps.height);
  });

  test("Home's Engine tile says the same state from the same facts, unclipped, and links to Settings > Engine", async ({ page }, info) => {
    const errors: string[] = [];
    page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
    page.on("pageerror", (e) => errors.push(e.message));
    for (const [scenario, state] of [
      ["missing", "Not installed"],
      ["stopped", "Not running"],
      ["idle", "Installed, not routing"],
    ] as const) {
      await page.goto(`/?source=mock&seed=1&engine=${scenario}`);
      const tile = page.locator('section[data-kpi="engine"]');
      await expect(tile.locator("[data-engine-state]")).toHaveText(state);
      await expect(tile.getByRole("link", { name: "Details in Settings" })).toHaveAttribute("href", /\/settings\/#engine$/);
      // The longest state still fits its tile (the alignment and clipping laws see the same box).
      const t = (await tile.boundingBox())!;
      const last = (await tile.locator("p").last().boundingBox())!;
      expect(last.y + last.height, scenario).toBeLessThanOrEqual(t.y + t.height);
      expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
      if (scenario === "idle") await page.getByRole("group", { name: "Right now" }).screenshot({ path: `test-results/screens/engine-home-idle-${info.project.name}.png` });
    }
    expect(errors).toEqual([]);
  });
});
