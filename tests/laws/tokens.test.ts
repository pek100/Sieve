/**
 * Law 1, tokens: colours live only in src/styles/tokens.css, themes switch
 * through [data-theme] role tokens (no `dark:` classes), and Sieve's own
 * components use only the spacing ladder 4/8/12/16/20/24/32/40.
 */
import { describe, expect, it } from "vitest";
import { hits, read, walk } from "./files";

const TOKENS = "src/styles/tokens.css";
const SOURCES = walk("src", [".ts", ".tsx", ".css"]).filter((f) => f !== TOKENS);

// Recharts paints its defaults with literal attributes; shadcn's chart.tsx
// matches them with attribute selectors such as [stroke='#ccc']. Those are
// selectors, not colours we use.
const ATTR_SELECTOR = /\[(?:stroke|fill)='#[0-9a-fA-F]{3,8}'\]/g;
const COLOUR = /#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?|oklch|oklab|lab|lch|hwb)\(/;

describe("token law", () => {
  it("has no colour literal outside tokens.css", () => {
    const found = SOURCES.flatMap((f) =>
      read(f)
        .split(/\r?\n/)
        .flatMap((line, i) => (COLOUR.test(line.replace(ATTR_SELECTOR, "")) ? [`${f}:${i + 1}: ${line.trim()}`] : [])),
    );
    expect(found).toEqual([]);
  });

  it("has no dark: variant classes (themes swap role tokens instead)", () => {
    expect(SOURCES.flatMap((f) => hits(f, /\bdark:[^\s"'`]/))).toEqual([]);
  });

  it("keeps Sieve components on the spacing ladder", () => {
    const LADDER = new Set(["0", "1", "2", "3", "4", "5", "6", "8", "10"]);
    const SPACING =
      /(?<![\w-])-?(?:p|px|py|pt|pb|pl|pr|ps|pe|m|mx|my|mt|mb|ml|mr|gap|gap-x|gap-y|space-x|space-y)-(\d+(?:\.\d+)?)(?![\w.])/g;
    const files = [...walk("src/components/sieve", [".tsx", ".ts"]), ...walk("src/app", [".tsx"])];
    const found = files.flatMap((f) =>
      read(f)
        .split(/\r?\n/)
        .flatMap((line, i) =>
          [...line.matchAll(SPACING)].filter((m) => !LADDER.has(m[1])).map((m) => `${f}:${i + 1}: ${m[0]}`),
        ),
    );
    expect(found).toEqual([]);
  });

  it("references only CSS variables that are defined", () => {
    // Defined: tokens.css and globals.css declarations. Runtime-owned prefixes
    // (Tailwind internals, Radix measurements, sonner, chart colours set inline) are exempt.
    const defined = new Set(
      [read(TOKENS), read("src/app/globals.css")].flatMap((css) => [...css.matchAll(/(--[\w-]+)\s*:/g)].map((m) => m[1])),
    );
    const RUNTIME = /^--(tw-|radix-|normal-|color-|border-radius|accordion-|lightningcss|gap$)/;
    const REF = /var\((--[\w-]+)|\((--[\w-]+)\)/g;
    const found = SOURCES.flatMap((f) =>
      read(f)
        .split(/\r?\n/)
        .flatMap((line, i) =>
          [...line.matchAll(REF)]
            .map((m) => m[1] ?? m[2])
            .filter((name) => !defined.has(name) && !RUNTIME.test(name))
            .map((name) => `${f}:${i + 1}: ${name}`),
        ),
    );
    expect(found).toEqual([]);
  });

  it("defines every role in both themes", () => {
    const css = read(TOKENS);
    const block = (selector: string) => {
      const start = css.indexOf(selector);
      return css.slice(start, css.indexOf("}", start));
    };
    const names = (s: string) => new Set([...s.matchAll(/^\s*(--[\w-]+):/gm)].map((m) => m[1]));
    const dark = names(block(':root[data-theme="dark"] {'));
    const light = names(block(':root[data-theme="light"] {'));
    const missing = [...dark].filter((n) => !light.has(n));
    expect(missing).toEqual([]);
  });
});
