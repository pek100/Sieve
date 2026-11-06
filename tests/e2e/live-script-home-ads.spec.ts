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
/** An element inside, so the measure of descendants is what is under test. */
const HOLDING = `<div>${FILLED}</div>`;
const ABSOLUTE = "position:absolute;width:10px;height:10px";

test.describe("the home page ad count", () => {
  for (const [name, html, count] of [
    ["a shown ad counts", ad("", FILLED), 1],
    ["hidden by a rule, it does not", ad('style="display:none!important"', FILLED), 0],
    ["inside a hidden parent, it does not", `<div style="display:none">${ad("", FILLED)}</div>`, 0],
    ["an empty placeholder a blocked fetch left, it does not", ad(""), 0],
    ["collapsed to no height, it does not", ad('style="height:0;overflow:hidden"', FILLED), 0],
    ["collapsed to no height, holding an element, it does not", ad('style="height:0;overflow:hidden"', HOLDING), 0],
    ["collapsed to no width, holding an element, it does not", ad('style="width:0;overflow:hidden"', HOLDING), 0],
    ["inside a collapsed parent, it does not", `<div style="height:0;overflow:hidden">${ad("", HOLDING)}</div>`, 0],
    ["no height but nothing clips it, it counts", ad('style="height:0"', HOLDING), 1],
    ["out of flow, past a collapsed parent's clip, it counts", ad('style="height:0;overflow:hidden"', `<div style="${ABSOLUTE}"></div>`), 1],
    ["invisible, it does not", ad('style="visibility:hidden"', FILLED), 0],
    ["no opacity, it does not", ad('style="opacity:0"', HOLDING), 0],
    ["inside a parent of no opacity, it does not", `<div style="opacity:0">${ad("", HOLDING)}</div>`, 0],
    ["faint, it counts", ad('style="opacity:0.1"', HOLDING), 1],
    ["off the page's left end, it does not", ad('style="position:absolute;left:-9999px"', HOLDING), 0],
    ["off the page's top end, it does not", ad('style="position:absolute;top:-9999px"', HOLDING), 0],
    ["below the fold, where a scroll reaches, it counts", ad('style="margin-top:9999px"', HOLDING), 1],
    ["past the right end, where a scroll reaches, it counts", ad('style="position:absolute;left:9999px"', HOLDING), 1],
    ["a wrapper with no box of its own holding a shown ad counts", ad('style="display:contents"', HOLDING), 1],
  ] as const) {
    test(name, async ({ page }) => {
      await page.setContent(`<!doctype html><body>${html}</body>`);
      expect(await page.evaluate(HOME_ADS)).toBe(count);
    });
  }
});
