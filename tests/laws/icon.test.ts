/**
 * The app icon, the favicon and the top-bar logo are one drawing:
 * scripts/make-icon.mjs derives the geometry into sieve-mark.json and draws
 * the icons from it; SieveMark draws the logo from the same JSON. This law
 * fails when someone edits one and not the other, or breaks the stripe fit.
 */
import { describe, expect, it } from "vitest";
import mark from "@/components/sieve/shell/sieve-mark.json";
import { read } from "./files";

describe("icon law", () => {
  const source = read("src-tauri/icons/source.svg");

  it("the favicon is the icon source, byte for byte", () => {
    expect(read("src/app/icon.svg")).toBe(source);
  });

  it("the icon source draws the mark's rim, bowl and every slot, in the mint primary, on transparent", () => {
    const { rim, bowl, slots } = mark;
    expect(source).toContain(`viewBox="0 0 ${mark.size} ${mark.size}"`);
    expect(source).toContain(`<rect x="${rim.x}" y="${rim.y}" width="${rim.width}" height="${rim.height}"`);
    expect(source).toContain(`<circle cx="${bowl.cx}" cy="${bowl.cy}" r="${bowl.r}" fill="#fff"/>`);
    expect(source).toContain(`stroke-width="${slots.width}"`);
    for (const [x1, y1, x2, y2] of slots.lines) expect(source).toContain(`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"/>`);
    expect(source.match(/<line /g)).toHaveLength(slots.lines.length);
    const primary = read("src/styles/tokens.css").match(/--primary:\s*(#[0-9a-fA-F]{6})/)?.[1];
    expect(source).toContain(`fill="${primary}"`);
    // Slots are cut by a mask, never painted in a background colour.
    expect(source).toContain('mask="url(#bowl)"');
    expect(source).not.toMatch(/stroke="#(?!000)/);
  });

  it("the slots are fitted: evenly spaced, every one on a line x + y = c, the first and last stripes centred on the bowl's extremes", () => {
    const { bowl, slots } = mark;
    const cs = slots.lines.map(([x1, y1, x2, y2]) => {
      expect(Math.abs(x1 + y1 - (x2 + y2))).toBeLessThan(0.02);
      return x2 + y2;
    });
    const steps = cs.slice(1).map((c, i) => c - cs[i]);
    for (const s of steps) expect(Math.abs(s - steps[0])).toBeLessThan(0.02);
    // Stripe centres sit half a step outside the outermost slots; they must land on the extremes.
    const lo = bowl.cx - bowl.r + bowl.cy;
    const hi = bowl.cx + bowl.cy + bowl.r * Math.SQRT2;
    expect(Math.abs(cs[0] - steps[0] / 2 - lo)).toBeLessThan(0.05);
    expect(Math.abs(cs[cs.length - 1] + steps[0] / 2 - hi)).toBeLessThan(0.05);
  });

  it("the tray uses the app's window icon, so it is this mark too (dimmed while not live)", () => {
    const tray = read("src-tauri/src/tray.rs");
    expect(tray).toContain("app.default_window_icon()");
    expect(tray).toContain("dimmed_rgba(i.rgba())");
  });
});
