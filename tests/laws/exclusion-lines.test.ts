/**
 * The exclusion line grammar and its words: the app reads a line as the engine
 * does (one table, read by `engine/crates/sieve-filter/tests/exclusion_lines.rs`
 * too), and every reason the engine can give has words here.
 */
import { describe, expect, it } from "vitest";
import { APP_PARAM, FLOOR_WORDS, exclusionReasonWords, exclusionsLink, exeFileName, parseExclusionLine } from "@/core/exclusions";
import table from "@/data/fixtures/exclusion-lines.json";
import { read, walk } from "./files";

const FILTER = read("engine/crates/sieve-filter/src/exclusions.rs");

function slugsIn(body: string, prefix: string): string[] {
  return [...body.matchAll(new RegExp(`"(${prefix}[a-z-]+)"`, "g"))].map((m) => m[1]);
}

describe("exclusion line law", () => {
  it("every line of the shared table reads as it says", () => {
    expect(table.lines.length).toBeGreaterThanOrEqual(20);
    for (const c of table.lines) {
      const got = parseExclusionLine(c.line);
      if (c.refused) expect(got, c.line).toEqual({ refused: c.refused });
      else expect(got, c.line).toEqual({ kind: c.kind, value: c.value, apps: c.apps });
    }
  });

  it("an address form both parsers take reads as an address, though the engine writes it shorter", () => {
    for (const line of table.ipForms) expect(parseExclusionLine(line), line).toEqual({ kind: "ip", value: line, apps: [] });
  });

  it("the Rust test reads the same table", () => {
    expect(read("engine/crates/sieve-filter/tests/exclusion_lines.rs")).toContain("exclusion-lines.json");
    expect(read("engine/crates/sieve-engine/src/exclusions/browsers.rs")).toContain("exclusion-lines.json");
  });

  it("an exe folds as the engine folds it: ASCII only, so a non-ASCII capital stays", () => {
    expect(table.exes.some((c) => /[^\x00-\x7f]/.test(c.exe))).toBe(true);
    for (const c of table.exes) {
      expect(exeFileName(c.exe), c.exe).toBe(c.file);
      expect(exclusionsLink(`?${APP_PARAM}=${encodeURIComponent(c.exe)}`).apps, c.exe).toEqual([c.folded]);
    }
  });

  it("every floor fact the crate declares has words, and no words are left over", () => {
    const body = FILTER.match(/impl Floor \{[\s\S]*?\n\}/)?.[0] ?? "";
    const slugs = slugsIn(body, "floor:");
    expect(slugs.length).toBe(Number(body.match(/ALL: \[Self; (\d+)\]/)?.[1]));
    expect(Object.keys(FLOOR_WORDS).sort()).toEqual([...slugs].sort());
  });

  it("only the engine controller writes the slice, and only one hook reads its rows", () => {
    const source = (dir: string) => walk(dir, [".ts", ".tsx"]).filter((f) => !/\.test\./.test(f));
    expect(source("src").filter((f) => /\.setEngine\(/.test(read(f)))).toEqual(["src/data/engine-controller.ts"]);
    expect(source("src/components").filter((f) => /\.exclusions\b/.test(read(f)))).toEqual(["src/components/sieve/settings/use-exclusions.ts"]);
  });

  it("no release path builds the live-scope feature", () => {
    const pkg = read("package.json");
    expect(pkg).not.toContain("live-scope");
    expect(read("src-tauri/windows/hooks.nsh")).not.toContain("live-scope");
    for (const f of walk("scripts", [".mjs", ".js", ".ps1", ".ts"])) {
      if (!f.startsWith("scripts/live/")) expect(read(f), f).not.toContain("live-scope");
    }
    const cargo = read("engine/crates/sieve-engine/Cargo.toml");
    expect(cargo.match(/^default\s*=/m), "no default feature can carry it").toBeNull();
    expect(read("engine/crates/sieve-engine/src/exclusions/mod.rs")).toContain("pub const SCOPE: Scope = Scope::Browsers;");
  });

  it("every auto reason the crate declares has words of its own", () => {
    const body = FILTER.match(/impl AutoReason \{[\s\S]*?\n\}/)?.[0] ?? "";
    const slugs = slugsIn(body, "auto:");
    expect(slugs).toHaveLength(3);
    for (const slug of slugs) expect(exclusionReasonWords(slug), slug).not.toBe(slug);
  });
});
