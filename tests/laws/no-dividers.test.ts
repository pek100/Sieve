/**
 * Law 7, no dividers (the user, 2026-10-17: "hr's are ugly, margins and
 * padding are always better"): nothing in src/components draws a line
 * between things. No top or bottom border used as a separator (border-t,
 * border-b, border-y and their variants such as last:border-b-0), no
 * divide-*, no <hr>, no Separator part. Lists, rows, sections and footers
 * are set apart by space from the spacing ladder, with more space between
 * groups than inside them. Focus rings (outline, ring) and the all-round
 * border of a form control are not separators and stay allowed.
 */
import { describe, expect, it } from "vitest";
import { hits, walk } from "./files";

const DIVIDER = /(?<![\w-])(?:[\w-]+:)*(?:border-[tby](?:-[\w/.[\]-]+)?|divide-[\w/-]+)(?![\w-])|<hr\b|Separator\b/;

describe("no dividers law", () => {
  it("no separator lines in src/components", () => {
    const files = walk("src/components", [".ts", ".tsx"]).filter((f) => !/\.test\.tsx?$/.test(f));
    expect(files.length).toBeGreaterThan(30);
    expect(files.flatMap((f) => hits(f, DIVIDER))).toEqual([]);
  });

  it("the pattern catches what it is for and lets focus rings and control borders through", () => {
    for (const bad of ["border-b border-outline", "last:border-b-0", "border-t", "divide-y", "<hr />", "DropdownMenuSeparator", "data-[side=top]:border-b"])
      expect(DIVIDER.test(bad), bad).toBe(true);
    for (const ok of ["border border-outline", "border-2", "outline-2 outline-primary", "ring-2", "rounded-b-xl", "border-l", "bottom-0"])
      expect(DIVIDER.test(ok), ok).toBe(false);
  });
});
