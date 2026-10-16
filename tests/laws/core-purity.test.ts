/**
 * Law 5, core purity: src/core is plain TypeScript. No React, Next, Tauri,
 * DOM or clock; its only outside import is `import type` from the protocol.
 * Time inside a derivation is the newest snapshot's `t`.
 */
import { describe, expect, it } from "vitest";
import { hits, read, walk } from "./files";

const CORE = walk("src/core", [".ts"]).filter((f) => !f.endsWith(".test.ts"));

describe("core purity law", () => {
  it("imports nothing outside src/core except protocol types", () => {
    const bad = CORE.flatMap((f) =>
      read(f)
        .split(/\r?\n/)
        .flatMap((line, i) => {
          const m = line.match(/^\s*import\s+(type\s+)?.*from\s+["']([^"']+)["']/);
          if (!m) return [];
          const [, isType, spec] = m;
          if (spec.startsWith(".")) return [];
          if (spec === "@/data/protocol" && isType) return [];
          if (spec.startsWith("@/core/")) return [];
          return [`${f}:${i + 1}: ${line.trim()}`];
        }),
    );
    expect(bad).toEqual([]);
  });

  it("never reads the clock, randomness or the DOM", () => {
    const re = /Date\.now|new Date\(\s*\)|Math\.random|performance\.now|\bwindow\.\w|\bdocument\.\w|localStorage/;
    expect(CORE.flatMap((f) => hits(f, re))).toEqual([]);
  });
});
