/**
 * Law 13, filter lists: the catalogue has one owner, the engine crate. The
 * fixture the app and its Rust command share equals catalogue.rs, row by row and
 * in order (a Rust test ties the command to the fixture). Every list has a group,
 * and no component names a list. User rules: an import cannot smuggle in a
 * trusted scriptlet.
 */
import { describe, expect, it } from "vitest";
import { LIST_GROUPS, listGroup } from "@/core/filter-lists";
import { EMPTY_DOC } from "@/core/settings/document";
import { isValidValue } from "@/core/settings/registry";
import { EXPORT_KIND, planImport } from "@/core/settings/transfer";
import fixture from "@/data/fixtures/filter-lists-v1.json";
import { hits, read, walk } from "./files";

interface Row {
  id: string;
  title: string;
  url: string;
  default: string;
  trusted: boolean;
  licence: string;
}

const defaultName = (d: string) => d.replace(/^Default::/, "").replace(/\(.*\)$/, "").toLowerCase();

/** The table as catalogue.rs spells it: its two macros and its plain struct rows. */
function catalogueRows(): Row[] {
  const src = read("engine/crates/sieve-filter/src/catalogue.rs");
  const base = (name: string) => {
    const m = src.match(new RegExp(`macro_rules! ${name}[\\s\\S]*?url: concat!\\("([^"]+)", (\\$n, )?`));
    if (!m) throw new Error(`macro ${name} not found`);
    return m[1];
  };
  const adguardBase = base("adguard");
  const uassetsBase = base("uassets");
  const table = src.slice(src.indexOf("pub const LISTS"), src.indexOf("/// The list with this id."));
  const rows: { at: number; row: Row }[] = [];
  const macroRow = /(adguard|uassets)!\("([^"]+)", "([^"]+)", "([^"]+)", (Default::\w+(?:\([^)]*\))?)\)/g;
  for (const m of table.matchAll(macroRow)) {
    const url = m[1] === "adguard" ? `${adguardBase}${m[4]}.txt` : `${uassetsBase}${m[4]}`;
    rows.push({ at: m.index, row: { id: m[2], title: m[3], url, licence: "GPL-3.0-only", default: defaultName(m[5]), trusted: true } });
  }
  const plainRow = /List \{\s*id: "([^"]+)",\s*title: "([^"]+)",\s*url: "([^"]+)",\s*licence: "([^"]+)",\s*default: (Default::\w+),\s*trusted: (true|false),/g;
  for (const m of table.matchAll(plainRow)) {
    rows.push({ at: m.index, row: { id: m[1], title: m[2], url: m[3], licence: m[4], default: defaultName(m[5]), trusted: m[6] === "true" } });
  }
  return rows.sort((a, b) => a.at - b.at).map((r) => r.row);
}

describe("filter list law", () => {
  const rows = catalogueRows();

  it("the parser of catalogue.rs reads every row", () => {
    const declared = read("engine/crates/sieve-filter/src/catalogue.rs").match(/^\s+(adguard!\(|uassets!\(|List \{$)/gm) ?? [];
    expect(rows.length).toBeGreaterThanOrEqual(12);
    // `List {` also opens the macros' own bodies (two of them, deeper indented).
    expect(rows.length).toBe(declared.length - 2);
  });

  /** A fixture row without its report: what catalogue.rs spells. */
  const asRow = (l: Row & { report: unknown }): Row => ({ id: l.id, title: l.title, url: l.url, licence: l.licence, default: l.default, trusted: l.trusted });

  it("the fixture's pending example equals catalogue.rs, row by row and in order, every report null", () => {
    expect(fixture.examples.pending.lists.map(asRow)).toEqual(rows);
    expect(fixture.examples.pending.lists.every((l) => l.report === null)).toBe(true);
  });

  it("the loaded example is the same lists with counts", () => {
    expect(fixture.examples.loaded.lists.map(asRow)).toEqual(rows);
    const gated = rows.filter((r) => r.default === "gated").map((r) => r.id);
    for (const l of fixture.examples.loaded.lists) if (gated.includes(l.id)) expect(l.report, l.id).toBeNull();
  });

  it("every list has a group; tracking and annoyances are not empty", () => {
    const groups = new Set(LIST_GROUPS.map((g) => g.id));
    for (const r of rows) expect(groups.has(listGroup(r)), r.id).toBe(true);
    for (const id of ["tracking", "annoyances"]) expect(rows.filter((r) => listGroup(r) === id).length, id).toBeGreaterThan(0);
  });

  it("no file under src/components names a list id or list title", () => {
    const files = walk("src/components", [".ts", ".tsx"]).filter((f) => !/\.test\.tsx?$/.test(f));
    const names = rows.flatMap((r) => [r.id, r.title]).map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
    expect(files.flatMap((f) => hits(f, new RegExp(names.join("|"))))).toEqual([]);
  });

  it("an import cannot smuggle in a trusted scriptlet or a junk host: refused with the reason, the current value kept", () => {
    expect(isValidValue("filters.userRules", ["##+js(trusted-x)"])).toBe(false);
    expect(isValidValue("filters.userRules", ["example.com##+js(trusted-x)"])).toBe(false);
    expect(isValidValue("filters.userRules", ["||a.example^", "! note"])).toBe(true);
    expect(isValidValue("filters.userRules", [""])).toBe(false);
    expect(isValidValue("filters.allowlist", ["a.example"])).toBe(true);
    for (const bad of ["localhost", "1.2.3.4", "WWW.Example.com", "https://a.example/"]) expect(isValidValue("filters.allowlist", [bad]), bad).toBe(false);
    expect(isValidValue("filters.lists", { x: "on" })).toBe(true);
    expect(isValidValue("filters.lists", { x: "loud" })).toBe(false);

    const current = { schema: EMPTY_DOC.schema, values: { "filters.userRules": ["||kept.example^"] } };
    const plan = planImport(current, JSON.stringify({ kind: EXPORT_KIND, schema: EMPTY_DOC.schema, values: { "filters.userRules": ["##+js(trusted-x)"] } }));
    expect(plan.ok).toBe(true);
    if (!plan.ok) return;
    expect(plan.refused).toEqual([{ key: "filters.userRules", reason: expect.stringContaining("trusted scriptlet") }]);
    expect(plan.next.values["filters.userRules"]).toEqual(["||kept.example^"]);
  });
});
