import { expect, test, type Page } from "@playwright/test";

const SETTINGS = "/settings/?source=mock&seed=1";

async function openSettings(page: Page) {
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(SETTINGS);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Settings");
  await expect(page.locator("[data-setting]").first()).toBeVisible();
  return errors;
}

const noHorizontalScroll = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
const row = (page: Page, key: string) => page.locator(`[data-setting="${key}"]`);

test.describe("settings", () => {
  test("renders every section from the registry with no horizontal scroll", async ({ page }, info) => {
    const errors = await openSettings(page);
    await expect(page.getByRole("link", { name: "Settings" })).toHaveAttribute("aria-current", "page");
    const rail = page.getByRole("navigation", { name: "Settings sections" });
    // Filtering stays: it carries the engine.
    await expect(rail.getByRole("link")).toHaveText(["Appearance", "Sampling", "Startup", "Apps", "Filtering", "Notifications", "Filter lists", "Password"]);
    // Eighteen rows: theme, sieving, interval, launch at startup, welcome guide finished, apps turned
    // off, my apps, the engine's switch, the blocked and allowed domains, the encrypted upstreams, your
    // rules and the sites not decrypted, desktop notifications, lists changed, user rules, allowlist,
    // lock again after. There is no Windows DNS row: Sieve never changes Windows DNS.
    await expect(page.locator("[data-setting]")).toHaveCount(16);
    await expect(row(page, "filtering.engine").getByRole("switch")).not.toBeChecked();
    await expect(page.getByText("Upstream DNS servers", { exact: true })).toHaveCount(1);
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);

    if (info.project.name === "desktop") {
      // Rail on the left (3 grid columns), the content beside it (9 columns; alignment.spec.ts checks the lines).
      const r = (await rail.boundingBox())!;
      const col = (await page.getByRole("region", { name: "Appearance" }).boundingBox())!;
      expect(r.x + r.width).toBeLessThanOrEqual(col.x);
      expect(col.width).toBeGreaterThan(r.width * 2.5);
    } else {
      // One column: the rail wraps above the cards.
      const r = (await rail.boundingBox())!;
      const col = (await page.getByRole("region", { name: "Appearance" }).boundingBox())!;
      expect(r.y + r.height).toBeLessThanOrEqual(col.y);
    }
    await page.screenshot({ path: `test-results/screens/settings-${info.project.name}.png`, fullPage: true });
    expect(errors).toEqual([]);
  });

  test("the upstream editor: add, reorder, read back, and it fits at every width", async ({ page }, info) => {
    await page.route("**/*", (route) => (new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort()));
    await page.goto(`${SETTINGS}&engine=idle`);
    const editor = row(page, "filtering.upstreams");
    await editor.scrollIntoViewIfNeeded();
    await editor.getByRole("radio", { name: "DoT" }).click();
    await editor.getByRole("textbox", { name: "Add to Upstream DNS servers" }).fill("dns.example");
    await editor.getByRole("button", { name: "Add", exact: true }).click();
    await expect(editor.locator("[data-upstream]").last()).toHaveAttribute("data-upstream", "tls://dns.example");

    // Moved first: it is tried first, and the engine's list follows.
    for (let moves = 2; moves > 0; moves--) await editor.getByRole("button", { name: "Move tls://dns.example up" }).click();
    await expect(editor.locator("[data-upstream]").first()).toHaveAttribute("data-upstream", "tls://dns.example");
    await expect(editor.locator("[data-upstream-readback]")).toHaveText("The engine uses this list.");

    // A long DoH address wraps inside the row.
    const long = `https://a-very-long-resolver-name.dns.example/dns-query?profile=${"0123456789".repeat(6)}`;
    await editor.getByRole("textbox", { name: "Add to Upstream DNS servers" }).fill(long);
    await editor.getByRole("button", { name: "Add", exact: true }).click();
    await expect(editor.locator("[data-upstream]").last()).toHaveAttribute("data-upstream", long);
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await editor.screenshot({ path: `test-results/screens/settings-upstreams-${info.project.name}.png` });

    if (info.project.name !== "desktop") {
      await editor.getByRole("textbox", { name: "Add to Upstream DNS servers" }).fill("x.example");
      const controls = editor.locator("button:enabled, input, [role=radio]");
      for (const control of await controls.all()) {
        const box = (await control.boundingBox())!;
        expect(Math.round(box.height), await control.evaluate((e) => e.outerHTML.slice(0, 80))).toBeGreaterThanOrEqual(44);
      }
    }

    await page.reload();
    await editor.scrollIntoViewIfNeeded();
    await expect(editor.locator("[data-upstream]").first()).toHaveAttribute("data-upstream", "tls://dns.example");
    await expect(editor.locator("[data-upstream]")).toHaveCount(4);
  });

  test("there is no per-app filtering row, no Windows DNS row and no DNS filtering switch", async ({ page }, info) => {
    await openSettings(page);
    await expect(row(page, "filtering.perApp")).toHaveCount(0);
    await expect(row(page, "filtering.systemDns")).toHaveCount(0);
    await expect(row(page, "filtering.dns")).toHaveCount(0);
    await expect(page.getByRole("region", { name: "DNS filter" })).toHaveCount(0);
    // Launch at startup needs the desktop app; the browser shows why.
    const startup = row(page, "startup.launchAtLogin");
    await startup.scrollIntoViewIfNeeded();
    await expect(startup.getByRole("switch")).toBeDisabled();
    await expect(startup).toContainText("Only the desktop app");
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await startup.screenshot({ path: `test-results/screens/settings-locked-${info.project.name}.png` });
  });

  test("every section ends at its content: the last one (Filtering's engine) is not stretched", async ({ page }) => {
    await openSettings(page);
    const gaps = await page.evaluate(() =>
      [...document.querySelectorAll<HTMLElement>("main [id^='section-'] section[aria-label]:not(section[aria-label] section)")].map((s) => {
        const own = s.getBoundingClientRect();
        let content = own.top;
        // Leaves only: a wrapper stretched with the section would hide the gap.
        for (const d of s.querySelectorAll("*")) if (d.childElementCount === 0) content = Math.max(content, d.getBoundingClientRect().bottom);
        return { name: s.getAttribute("aria-label"), height: own.height, gap: own.bottom - content };
      }),
    );
    // Five registry sections with rows (Filtering's is the engine's switch, slice 3), then the engine and its certificate, then the backlog's sections.
    expect(gaps.map((g) => g.name)).toEqual(["Appearance", "Sampling", "Startup", "Apps", "Filtering", "Engine", "Certificate", "Notifications", "Filter lists", "Password"]);
    // Was 686 px of empty space under Filtering's rows: its card took the height of its wrapper (Card h-full).
    // Allowed: a row's own bottom padding (16) and at most a section's padding.
    for (const g of gaps) expect(g.gap, `${g.name} ends ${g.gap}px below its content`).toBeLessThanOrEqual(40);
  });

  test("search narrows the rows; a change persists across a reload", async ({ page }) => {
    await openSettings(page);
    await page.getByRole("searchbox", { name: "Search settings" }).fill("theme");
    await expect(page.locator("[data-setting]")).toHaveCount(1);
    await row(page, "appearance.theme").getByRole("radio", { name: "Light" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await page.getByRole("searchbox", { name: "Search settings" }).fill("nothing like this");
    await expect(page.getByText("No setting matches")).toBeVisible();
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  });

  test("import previews the change before applying; reset to defaults can be undone", async ({ page }, info) => {
    await openSettings(page);
    await page.getByRole("button", { name: "Settings actions" }).click();
    await page.getByRole("menuitem", { name: "Import settings" }).click();
    const file = JSON.stringify({ kind: "sieve.settings", schema: 5, values: { "sampling.intervalMs": 2000, "filtering.dns": true } });
    await page.getByRole("textbox", { name: "Settings file to import" }).fill(file);
    await page.getByRole("button", { name: "Preview changes" }).click();
    await expect(page.getByRole("list", { name: "Changes" })).toContainText("Sample every");
    await expect(page.getByRole("list", { name: "Not imported" })).toContainText("filtering.dns");
    await expect(page.getByRole("list", { name: "Not imported" })).toContainText("Not a setting in this version of Sieve");
    expect(await noHorizontalScroll(page)).toBeLessThanOrEqual(0);
    await page.screenshot({ path: `test-results/screens/settings-import-${info.project.name}.png` });
    await page.getByRole("button", { name: "Apply 1 change" }).click();
    await expect(row(page, "sampling.intervalMs")).toContainText("2 s");
    await expect(row(page, "filtering.dns")).toHaveCount(0);

    await page.getByRole("button", { name: "Settings actions" }).click();
    await page.getByRole("menuitem", { name: "Reset to defaults" }).click();
    await page.getByRole("button", { name: "Reset to defaults" }).click();
    await expect(row(page, "sampling.intervalMs")).toContainText("1 s");
    // The import's toast may still be up: undo the reset, from its own toast.
    await page.getByRole("listitem").filter({ hasText: "Settings reset to defaults" }).getByRole("button", { name: "Undo" }).click();
    await expect(row(page, "sampling.intervalMs")).toContainText("2 s");
  });
});
