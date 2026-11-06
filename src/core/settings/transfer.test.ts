import { describe, expect, it, vi } from "vitest";
import { EMPTY_DOC, readValue, writeValue, type SettingsDoc } from "./document";
import { SETTINGS_SCHEMA, SETTING_KEYS, isAvailable, settingDef } from "./registry";

// One test runs the import rules for a data switch as a build where one is available would.
const availability = vi.hoisted(() => ({ every: false }));
vi.mock("./registry", async (importOriginal) => {
  const real = await importOriginal<typeof import("./registry")>();
  return { ...real, isAvailable: (k: Parameters<typeof real.isAvailable>[0]) => availability.every || real.isAvailable(k) };
});
import { EXPORT_KIND, exportText, formatNumber, formatValue, numberChoices, planImport, resetAllText, resetPlan, searchSettings } from "./transfer";

const changed: SettingsDoc = writeValue(writeValue(EMPTY_DOC, "appearance.theme", "light"), "apps.pinned", ["C:\\Tools\\a.exe"]);

describe("settings export and import", () => {
  it("export carries only changed known values and round-trips through import with no change", () => {
    const text = exportText({ ...changed, values: { ...changed.values, "future.key": 1 } });
    const parsed = JSON.parse(text);
    expect(parsed.kind).toBe(EXPORT_KIND);
    expect(Object.keys(parsed.values).sort()).toEqual(["appearance.theme", "apps.pinned"]);
    const plan = planImport(changed, text);
    expect(plan.ok && plan.changes).toEqual([]);
  });

  it("import replaces: lists every key that changes, and keys missing from the file go back to default", () => {
    const file = JSON.stringify({ kind: EXPORT_KIND, schema: 1, values: { "sampling.intervalMs": 2000 } });
    const plan = planImport(changed, file);
    if (!plan.ok) throw new Error(plan.error);
    expect(plan.changes.map((c) => [c.key, c.from, c.to])).toEqual([
      ["appearance.theme", "light", "dark"],
      ["sampling.intervalMs", 1000, 2000],
      ["apps.pinned", ["C:\\Tools\\a.exe"], []],
    ]);
    expect(readValue(plan.next, "sampling.intervalMs")).toBe(2000);
    expect(readValue(plan.next, "appearance.theme")).toBe("dark");
  });

  it("refuses unknown keys, invalid values and turning on any data switch, keeping the current value", () => {
    const file = JSON.stringify({
      kind: EXPORT_KIND,
      schema: 2,
      values: {
        "appearance.theme": "neon",
        "nope.key": true,
        "filtering.dns": true,
        "filtering.systemDns": true,
        "apps.levels": { chrome: "loud" },
        "filtering.upstreams": ["dns.google"],
      },
    });
    const plan = planImport(changed, file);
    if (!plan.ok) throw new Error(plan.error);
    // A schema 2 file: the migration drops the bare upstream, and the retired switches, before the plan sees them.
    expect(plan.refused.map((r) => r.key).sort()).toEqual(["appearance.theme", "apps.levels", "nope.key"]);
    expect(plan.next.values).not.toHaveProperty("filtering.systemDns");
    expect(plan.next.values).not.toHaveProperty("filtering.dns");
    expect(plan.next.values).not.toHaveProperty("filtering.upstreams");
    // A current file with a bare upstream is refused as a bad value.
    const current = planImport(changed, JSON.stringify({ kind: EXPORT_KIND, schema: SETTINGS_SCHEMA, values: { "filtering.upstreams": ["1.1.1.1"], "filtering.dns": true } }));
    if (!current.ok) throw new Error(current.error);
    expect(current.refused).toEqual([
      { key: "filtering.upstreams", reason: "Not a valid value for this setting" },
      { key: "filtering.dns", reason: "Not a setting in this version of Sieve" },
    ]);
    // A refused known key keeps its current value: the theme stays light.
    expect(readValue(plan.next, "appearance.theme")).toBe("light");
    // Every data switch, every time: no import path turns one on.
    for (const key of SETTING_KEYS.filter((k) => settingDef(k).kind === "dataSwitch")) {
      const one = planImport(EMPTY_DOC, JSON.stringify({ kind: EXPORT_KIND, schema: 1, values: { [key]: true } }));
      expect(one.ok && readValue(one.next, key), key).toBe(false);
    }
  });

  it("an available data switch: an import never turns it on, turning it off is imported, one already on stays on", () => {
    const refused = planImport(EMPTY_DOC, JSON.stringify({ kind: EXPORT_KIND, schema: SETTINGS_SCHEMA, values: { "filtering.engine": true } }));
    expect(refused.ok && refused.refused.find((r) => r.key === "filtering.engine")?.reason).toMatch(/never turns this on/);
    expect(refused.ok && readValue(refused.next, "filtering.engine")).toBe(false);
    const on = writeValue(EMPTY_DOC, "filtering.engine", true);
    const off = planImport(on, JSON.stringify({ kind: EXPORT_KIND, schema: SETTINGS_SCHEMA, values: {} }));
    expect(off.ok && readValue(off.next, "filtering.engine")).toBe(false);
    const kept = planImport(on, JSON.stringify({ kind: EXPORT_KIND, schema: SETTINGS_SCHEMA, values: { "filtering.engine": true } }));
    expect(kept.ok && readValue(kept.next, "filtering.engine")).toBe(true);
  });

  it("says plainly when the text is not a settings file", () => {
    expect(planImport(EMPTY_DOC, "{nope")).toEqual({ ok: false, error: expect.stringMatching(/not valid JSON/) });
    expect(planImport(EMPTY_DOC, JSON.stringify({ values: {} }))).toEqual({ ok: false, error: expect.stringMatching(/not a Sieve settings file/) });
    expect(planImport(EMPTY_DOC, JSON.stringify({ kind: EXPORT_KIND, schema: 0, values: {} })).ok).toBe(false);
  });

  it("reset to defaults lists what changes and keeps keys a newer Sieve wrote", () => {
    const doc = { ...changed, values: { ...changed.values, "future.key": 1 } };
    const plan = resetPlan(doc);
    expect(plan.changes.map((c) => c.key)).toEqual(["appearance.theme", "apps.pinned"]);
    expect(plan.next.values).toEqual({ "future.key": 1 });
    expect(resetPlan(EMPTY_DOC).changes).toEqual([]);
  });

  it("reset to defaults keeps a finished welcome guide: it is a record of what happened, not a preference", () => {
    const doc = writeValue(writeValue(EMPTY_DOC, "startup.welcomeDone", true), "appearance.theme", "light");
    const plan = resetPlan(doc);
    expect(plan.next.values).toEqual({ "startup.welcomeDone": true });
    expect(plan.changes.map((c) => c.key)).toEqual(["appearance.theme"]);
    expect(resetPlan(EMPTY_DOC).next.values).toEqual({});
    expect(resetAllText()).toContain(settingDef("startup.welcomeDone").label);
  });
});

describe("settings search and words", () => {
  it("matches label, help, key, section and options, every word, in registry order", () => {
    expect(searchSettings("")).toEqual(SETTING_KEYS.filter(isAvailable));
    expect(searchSettings("theme")).toEqual(["appearance.theme"]);
    expect(searchSettings("LIGHT")).toEqual(["appearance.theme"]);
    expect(searchSettings("dns")).toEqual(["filtering.upstreams"]);
    expect(searchSettings("per-app filtering")).toEqual([]);
    expect(searchSettings("turned off")).toEqual(["apps.levels"]);
    expect(searchSettings("startup")).toEqual(["startup.launchAtLogin", "startup.welcomeDone"]);
    expect(searchSettings("sample every")).toEqual(["sampling.intervalMs"]);
    expect(searchSettings("zzzz")).toEqual([]);
  });

  it("formats values the way a person reads them", () => {
    expect(formatNumber(1500, "ms")).toBe("1.5 s");
    expect(formatNumber(500, "ms")).toBe("500 ms");
    expect(formatValue("appearance.theme", "dark")).toBe("Dark");
    expect(formatValue("filtering.engine", false)).toBe("Off");
    expect(formatValue("apps.levels", { a: "off", b: "off" })).toBe("2 apps");
    expect(formatValue("apps.levels", {})).toBe("None");
    expect(formatValue("apps.pinned", [])).toBe("None");
    expect(formatValue("filtering.upstreams", ["tls://a.example", "quic://b.example"])).toBe("tls://a.example, quic://b.example");
    const choices = numberChoices("sampling.intervalMs");
    expect(choices[0]).toBe(500);
    expect(choices.at(-1)).toBe(10_000);
    expect(choices).toContain(1000);
  });
});
