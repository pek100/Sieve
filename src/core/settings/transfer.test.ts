import { describe, expect, it } from "vitest";
import { EMPTY_DOC, readValue, writeValue, type SettingsDoc } from "./document";
import { SETTING_KEYS, settingDef } from "./registry";
import { EXPORT_KIND, exportText, formatNumber, formatValue, numberChoices, planImport, resetPlan, searchSettings } from "./transfer";

const unlocked = () => false;
const changed: SettingsDoc = writeValue(writeValue(EMPTY_DOC, "appearance.theme", "light"), "apps.pinned", ["C:\\Tools\\a.exe"]);

describe("settings export and import", () => {
  it("export carries only changed known values and round-trips through import with no change", () => {
    const text = exportText({ ...changed, values: { ...changed.values, "future.key": 1 } });
    const parsed = JSON.parse(text);
    expect(parsed.kind).toBe(EXPORT_KIND);
    expect(Object.keys(parsed.values).sort()).toEqual(["appearance.theme", "apps.pinned"]);
    const plan = planImport(changed, text, unlocked);
    expect(plan.ok && plan.changes).toEqual([]);
  });

  it("import replaces: lists every key that changes, and keys missing from the file go back to default", () => {
    const file = JSON.stringify({ kind: EXPORT_KIND, schema: 1, values: { "sampling.intervalMs": 2000 } });
    const plan = planImport(changed, file, unlocked);
    if (!plan.ok) throw new Error(plan.error);
    expect(plan.changes.map((c) => [c.key, c.from, c.to])).toEqual([
      ["appearance.theme", "light", "dark"],
      ["sampling.intervalMs", 1000, 2000],
      ["apps.pinned", ["C:\\Tools\\a.exe"], []],
    ]);
    expect(readValue(plan.next, "sampling.intervalMs")).toBe(2000);
    expect(readValue(plan.next, "appearance.theme")).toBe("dark");
  });

  it("refuses unknown keys, invalid values and turning on a locked data switch, keeping the current value", () => {
    const file = JSON.stringify({
      kind: EXPORT_KIND,
      schema: 1,
      values: { "appearance.theme": "neon", "nope.key": true, "filtering.dns": true, "apps.levels": { chrome: "loud" } },
    });
    const plan = planImport(changed, file, (k) => settingDef(k).kind === "dataSwitch");
    if (!plan.ok) throw new Error(plan.error);
    expect(plan.refused.map((r) => r.key).sort()).toEqual(["appearance.theme", "apps.levels", "filtering.dns", "nope.key"]);
    expect(plan.refused.find((r) => r.key === "filtering.dns")?.reason).toMatch(/live check/);
    expect(readValue(plan.next, "filtering.dns")).toBe(false);
    // A refused known key keeps its current value: the theme stays light.
    expect(readValue(plan.next, "appearance.theme")).toBe("light");
    // Once the check has passed, the same file may turn the switch on.
    const open = planImport(EMPTY_DOC, file, () => false);
    expect(open.ok && readValue(open.next, "filtering.dns")).toBe(true);
  });

  it("says plainly when the text is not a settings file", () => {
    expect(planImport(EMPTY_DOC, "{nope", unlocked)).toEqual({ ok: false, error: expect.stringMatching(/not valid JSON/) });
    expect(planImport(EMPTY_DOC, JSON.stringify({ values: {} }), unlocked)).toEqual({ ok: false, error: expect.stringMatching(/not a Sieve settings file/) });
    expect(planImport(EMPTY_DOC, JSON.stringify({ kind: EXPORT_KIND, schema: 0, values: {} }), unlocked).ok).toBe(false);
  });

  it("reset to defaults lists what changes and keeps keys a newer Sieve wrote", () => {
    const doc = { ...changed, values: { ...changed.values, "future.key": 1 } };
    const plan = resetPlan(doc);
    expect(plan.changes.map((c) => c.key)).toEqual(["appearance.theme", "apps.pinned"]);
    expect(plan.next.values).toEqual({ "future.key": 1 });
    expect(resetPlan(EMPTY_DOC).changes).toEqual([]);
  });
});

describe("settings search and words", () => {
  it("matches label, help, key, section and options, every word, in registry order", () => {
    expect(searchSettings("")).toEqual(SETTING_KEYS);
    expect(searchSettings("theme")).toEqual(["appearance.theme"]);
    expect(searchSettings("LIGHT")).toEqual(["appearance.theme"]);
    expect(searchSettings("dns")).toEqual(["filtering.dns"]);
    expect(searchSettings("startup")).toEqual(["startup.launchAtLogin"]);
    expect(searchSettings("sample every")).toEqual(["sampling.intervalMs"]);
    expect(searchSettings("zzzz")).toEqual([]);
  });

  it("formats values the way a person reads them", () => {
    expect(formatNumber(1500, "ms")).toBe("1.5 s");
    expect(formatNumber(500, "ms")).toBe("500 ms");
    expect(formatValue("appearance.theme", "dark")).toBe("Dark");
    expect(formatValue("filtering.dns", false)).toBe("Off");
    expect(formatValue("apps.levels", { a: "off", b: "off" })).toBe("2 apps set");
    expect(formatValue("apps.pinned", [])).toBe("None");
    const choices = numberChoices("sampling.intervalMs");
    expect(choices[0]).toBe(500);
    expect(choices.at(-1)).toBe(10_000);
    expect(choices).toContain(1000);
  });
});
