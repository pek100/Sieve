/**
 * Law 13, filter lists: the catalogue has one owner, the engine crate. The
 * fixture the app and its Rust command share equals catalogue.rs, row by row and
 * in order (a Rust test ties the command to the fixture). Every list has a group,
 * and no component names a list. User rules: an import cannot smuggle in a
 * trusted scriptlet.
 */
import { describe, expect, it } from "vitest";
import { LIST_GROUPS, listGroup } from "@/core/filter-lists";
import { EMPTY_DOC, readValue, writeValue } from "@/core/settings/document";
import { MAX_POLICY_BYTES, POLICY_BUDGETS, budgetBytes, isSettingKey, isValidValue } from "@/core/settings/registry";
import { EXPORT_KIND, planImport } from "@/core/settings/transfer";
import fixture from "@/data/fixtures/filter-lists-v1.json";
import { createSettingsStore, memoryBackend } from "@/data/settings-store";
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

describe("law: one store for the user's own rules", () => {
  it("the editors' keys are the ones the engine controller sends, and no second set exists", () => {
    for (const gone of ["filters.userRules", "filters.allowlist"]) expect(isSettingKey(gone), gone).toBe(false);
    const hook = read("src/hooks/use-filters.ts");
    const controller = read("src/data/engine-controller.ts");
    for (const key of ["filtering.userRules", "filtering.allowedDomains", "filtering.blockedDomains", "filters.lists"]) {
      expect(hook, key).toContain(key);
      expect(controller, key).toContain(key);
    }
    expect(read("src/core/log-actions.ts")).toContain("filtering.userRules");
  });
});

describe("law: what the engine could not hold is refused where it is saved", () => {
  /** About 20k pasted lines, each a valid rule. */
  const PASTED = Array.from({ length: 20_000 }, (_, i) => `||a-rule-for-host-number-${i}.tracker.example^$third-party`);
  const rulesBudget = POLICY_BUDGETS.find((b) => b.keys.includes("filtering.userRules"))!;

  it("settings within their budgets always fit one policy, with room for the switches and the catalogue's every list", () => {
    const spent = POLICY_BUDGETS.reduce((sum, b) => sum + b.bytes, 0);
    const lists = new TextEncoder().encode(JSON.stringify(fixture.examples.pending.lists.map((l) => l.id))).length;
    const domainLists = new TextEncoder().encode(JSON.stringify({ domain_lists: [{ kind: "block", entries: [], enabled: true }, { kind: "allow", entries: [], enabled: true }] })).length;
    expect(spent + lists + domainLists + 256).toBeLessThanOrEqual(MAX_POLICY_BYTES);
  });

  it("every setting the policy carries from a list or a map is in a budget", () => {
    const controller = read("src/data/engine-controller.ts");
    const wanted = controller.slice(controller.indexOf("function wantedPolicy"), controller.indexOf("/** One form of a policy"));
    const budgeted = POLICY_BUDGETS.flatMap((b) => b.keys) as string[];
    const sent = [...wanted.matchAll(/settings\.get\("([a-z.A-Z]+)"\)/g)].map((m) => m[1]).filter((k) => k !== "filters.lists");
    expect(sent.length).toBeGreaterThan(0);
    for (const key of sent) expect(budgeted, key).toContain(key);
  });

  it("a save over the budget is refused with a sentence, and nothing changes", async () => {
    const store = createSettingsStore(memoryBackend({ schema: EMPTY_DOC.schema, values: { "filtering.userRules": ["||kept.example^"] } }));
    await store.ready;
    await expect(store.set("filtering.userRules", PASTED)).rejects.toThrow(/Your rules.*more than the \d+ KB the engine can hold, so this was not saved/);
    expect(store.get("filtering.userRules")).toEqual(["||kept.example^"]);
  });

  it("the budget is shared: a big allowlist counts against the rules", () => {
    const half = PASTED.slice(0, 5_000);
    const hosts = half.map((_, i) => `a-rather-long-name-for-an-allowed-host-number-${i}.tracker.example`);
    const withHosts = writeValue(EMPTY_DOC, "filtering.allowedDomains", hosts);
    expect(() => writeValue(withHosts, "filtering.userRules", half)).toThrow(/not saved/);
    expect(writeValue(EMPTY_DOC, "filtering.userRules", half).values["filtering.userRules"]).toEqual(half);
  });

  it("a group an older build stored over the budget can still be made smaller, and only smaller", () => {
    const over = { schema: EMPTY_DOC.schema, values: { "filtering.userRules": PASTED } };
    expect(budgetBytes(rulesBudget, (k) => readValue(over, k))).toBeGreaterThan(rulesBudget.bytes);
    expect(writeValue(over, "filtering.userRules", PASTED.slice(0, -1)).values["filtering.userRules"]).toHaveLength(PASTED.length - 1);
    expect(() => writeValue(over, "filtering.userRules", [...PASTED, "||one-more.example^"])).toThrow(/not saved/);
  });

  it("an import over the budget is refused with the same sentence, the current value kept, the rest of the file applied", () => {
    const current = { schema: EMPTY_DOC.schema, values: { "filtering.userRules": ["||kept.example^"] } };
    const plan = planImport(current, JSON.stringify({ kind: EXPORT_KIND, schema: EMPTY_DOC.schema, values: { "filtering.userRules": PASTED, "appearance.theme": "light" } }));
    expect(plan.ok).toBe(true);
    if (!plan.ok) return;
    expect(plan.refused).toEqual([{ key: "filtering.userRules", reason: expect.stringMatching(/Your rules.*not saved/) }]);
    expect(plan.next.values["filtering.userRules"]).toEqual(["||kept.example^"]);
    expect(plan.next.values["appearance.theme"]).toBe("light");
  });
});

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
    expect(isValidValue("filtering.userRules", ["##+js(trusted-x)"])).toBe(false);
    expect(isValidValue("filtering.userRules", ["example.com##+js(trusted-x)"])).toBe(false);
    expect(isValidValue("filtering.userRules", ["||a.example^", "! note"])).toBe(true);
    expect(isValidValue("filtering.userRules", [""])).toBe(false);
    expect(isValidValue("filtering.allowedDomains", ["a.example"])).toBe(true);
    for (const bad of ["localhost", "1.2.3.4", "WWW.Example.com", "https://a.example/"]) expect(isValidValue("filtering.allowedDomains", [bad]), bad).toBe(false);
    expect(isValidValue("filters.lists", { x: "on" })).toBe(true);
    expect(isValidValue("filters.lists", { x: "loud" })).toBe(false);

    const current = { schema: EMPTY_DOC.schema, values: { "filtering.userRules": ["||kept.example^"] } };
    const plan = planImport(current, JSON.stringify({ kind: EXPORT_KIND, schema: EMPTY_DOC.schema, values: { "filtering.userRules": ["##+js(trusted-x)"] } }));
    expect(plan.ok).toBe(true);
    if (!plan.ok) return;
    expect(plan.refused).toEqual([{ key: "filtering.userRules", reason: expect.stringContaining("trusted scriptlet") }]);
    expect(plan.next.values["filtering.userRules"]).toEqual(["||kept.example^"]);
  });

  it.each(["! note\nexample.com##+js(trusted-x)", "example.com##.ad\n||evil.example^$important", "! note\r||evil.example^", "||a.example^\n"])(
    "one element is one line: an import cannot carry a second rule inside %j",
    (smuggled) => {
      expect(isValidValue("filtering.userRules", [smuggled])).toBe(false);
      const current = { schema: EMPTY_DOC.schema, values: { "filtering.userRules": ["||kept.example^"] } };
      const plan = planImport(current, JSON.stringify({ kind: EXPORT_KIND, schema: EMPTY_DOC.schema, values: { "filtering.userRules": ["||fine.example^", smuggled] } }));
      expect(plan.ok).toBe(true);
      if (!plan.ok) return;
      expect(plan.refused).toEqual([{ key: "filtering.userRules", reason: expect.stringContaining("line break") }]);
      expect(plan.changes).toEqual([]);
      expect(plan.next.values["filtering.userRules"]).toEqual(["||kept.example^"]);
    },
  );
});
