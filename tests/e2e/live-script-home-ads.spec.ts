import { expect, test } from "@playwright/test";
import { HOME_ADS } from "../../scripts/live/youtube.mjs";

/**
 * What scripts/live/youtube.mjs counts on the home page, in a real browser, since a
 * hidden element's boxes are layout that jsdom does not do. The site is not visited:
 * the page here is written from the script's own selector, loopback only.
 */
const AD = "masthead-ad";
const ad = (attributes: string, inner = "") => `<div id="${AD}" ${attributes}>${inner}</div>`;
const FILLED = "ad";

test.describe("the home page ad count", () => {
  for (const [name, html, count] of [
    ["a shown ad counts", ad("", FILLED), 1],
    ["hidden by a rule, it does not", ad('style="display:none!important"', FILLED), 0],
    ["inside a hidden parent, it does not", `<div style="display:none">${ad("", FILLED)}</div>`, 0],
    ["an empty placeholder a blocked fetch left, it does not", ad(""), 0],
    ["collapsed to no height, it does not", ad('style="height:0;overflow:hidden"', FILLED), 0],
    ["invisible, it does not", ad('style="visibility:hidden"', FILLED), 0],
    ["a wrapper with no box of its own holding a shown ad counts", ad('style="display:contents"', `<div>${FILLED}</div>`), 1],
  ] as const) {
    test(name, async ({ page }) => {
      await page.setContent(`<!doctype html><body>${html}</body>`);
      expect(await page.evaluate(HOME_ADS)).toBe(count);
    });
  }
});
