/**
 * The injected style action in a real browser: jsdom's parser has no var()
 * shorthand behaviour, and that is exactly where the action can erase a style.
 */
import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";

const BOOTSTRAP = readFileSync("engine/injected/bootstrap.js", "utf8");

async function styled(page: import("@playwright/test").Page, arg: string, before = "") {
  return page.evaluate(
    ([source, arg, before]) => {
      const el = document.createElement("div");
      el.setAttribute("style", before);
      document.body.append(el);
      const run = new Function(`${source}\nreturn sieveRunProcedural;`)();
      const applier = { compileProceduralSelector: (s: unknown) => s, applyCompiledSelector: () => [el] };
      run(applier, [{ selector: [], action: { type: "style", arg } }]);
      const computed = getComputedStyle(el);
      return { inline: el.getAttribute("style"), background: computed.backgroundColor, width: el.style.width };
    },
    [BOOTSTRAP, arg, before],
  );
}

test.describe("the style action", () => {
  test.beforeEach(async ({ page }) => {
    await page.setContent(`<!doctype html><body style="--x: rgb(255, 0, 0)"></body>`);
  });

  test("a shorthand holding var() survives, and the page's own styles with it", async ({ page }) => {
    const result = await styled(page, "background: var(--x)", "width: 10px");
    expect(result.background).toBe("rgb(255, 0, 0)");
    expect(result.width).toBe("10px");
  });

  test("a plain declaration still lands", async ({ page }) => {
    expect((await styled(page, "background: rgb(0, 0, 255)")).background).toBe("rgb(0, 0, 255)");
  });
});
