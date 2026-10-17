/**
 * The app icon, the favicon and the top-bar logo are one drawing: the
 * geometry in sieve-mark.json, drawn by scripts/make-icon.mjs (icons) and by
 * SieveMark (logo). This law fails when someone edits one and not the other.
 */
import { describe, expect, it } from "vitest";
import mark from "@/components/sieve/shell/sieve-mark.json";
import { read } from "./files";

describe("icon law", () => {
  const source = read("src-tauri/icons/source.svg");

  it("the favicon is the icon source, byte for byte", () => {
    expect(read("src/app/icon.svg")).toBe(source);
  });

  it("the icon source draws the mark's ring and every mesh line, in the mint primary", () => {
    const { ring, lines } = mark;
    expect(source).toContain(`viewBox="0 0 ${mark.size} ${mark.size}"`);
    expect(source).toContain(`<circle cx="${ring.cx}" cy="${ring.cy}" r="${ring.r}" fill="none"`);
    expect(source).toContain(`stroke-width="${ring.width}"`);
    expect(source).toContain(`stroke-width="${lines.width}"`);
    for (const [x1, y1, x2, y2] of lines.segments) expect(source).toContain(`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"/>`);
    expect(source.match(/<line /g)).toHaveLength(lines.segments.length);
    const primary = read("src/styles/tokens.css").match(/--primary:\s*(#[0-9a-fA-F]{6})/)?.[1];
    expect(source).toContain(`stroke="${primary}"`);
    // Mint on transparent: no background shape.
    expect(source).not.toMatch(/<rect/);
  });

  it("the tray uses the app's window icon, so it is this mark too (dimmed while not live)", () => {
    const tray = read("src-tauri/src/tray.rs");
    expect(tray).toContain("app.default_window_icon()");
    expect(tray).toContain("dimmed_rgba(i.rgba())");
  });
});
