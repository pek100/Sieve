/**
 * Law 6, no containers (the user, 2026-10-17: "lose all containers and
 * cards"): Sieve's own components never draw a card. The card elevation
 * (shadow-l1), the card radius (rounded-lg) and the filled accent tile
 * (bg-mint-container) are not used in src/components/sieve; the Card block
 * itself has no surface, border, shadow, radius or padding.
 */
import { describe, expect, it } from "vitest";
import { hits, read, walk } from "./files";

describe("no containers law", () => {
  it("no card elevation, card radius or filled accent tile in Sieve's components", () => {
    const files = walk("src/components/sieve", [".ts", ".tsx"]).filter((f) => !/\.test\.tsx?$/.test(f));
    expect(files.length).toBeGreaterThan(20);
    expect(files.flatMap((f) => hits(f, /\b(shadow-l1|rounded-lg|bg-mint-container)\b/))).toEqual([]);
  });

  it("the Card block's own classes carry no surface, border, shadow, radius or padding", () => {
    const card = read("src/components/sieve/shell/card.tsx");
    const section = card.match(/<section[\s\S]*?className=\{cn\("([^"]+)"/)?.[1];
    expect(section).toBeDefined();
    expect(section).not.toMatch(/\b(bg-|border|shadow-|rounded|p-\d|px-|py-)/);
  });
});
