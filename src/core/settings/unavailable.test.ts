/**
 * What `unavailableUntil` does, with two real keys mocked unavailable, a switch
 * and a list (the real registry's list is one switch, so a loop over it would
 * never see a list; law 11 holds that list). An unavailable key has no row,
 * search, export, import or reset, reads as its default and takes no other value.
 */
import { describe, expect, it, vi } from "vitest";

const SWITCH = "filtering.engine";
const LIST = "apps.pinned";
const hidden = vi.hoisted(() => new Set<string>(["filtering.engine", "apps.pinned"]));
vi.mock("./registry", async (importOriginal) => {
  const real = await importOriginal<typeof import("./registry")>();
  return { ...real, isAvailable: (k: string) => !hidden.has(k) };
});

import { EMPTY_DOC, knownValues, normalizeDoc, readValue, writeValue } from "./document";
import { offUnavailableSwitches } from "./migrate";
import { SETTINGS_SCHEMA, defaultValue } from "./registry";
import { EXPORT_KIND, exportText, planImport, resetPlan, searchSettings } from "./transfer";

const stored = { schema: SETTINGS_SCHEMA, values: { [SWITCH]: true, [LIST]: ["C:\\a.exe"], "appearance.theme": "light" } };

describe("an unavailable setting", () => {
  it("reads as its default whatever is stored", () => {
    expect(readValue(stored, SWITCH)).toBe(false);
    expect(readValue(stored, LIST)).toEqual(defaultValue(LIST));
    expect(readValue(stored, "appearance.theme")).toBe("light");
  });

  it("takes no other value; its default clears the stored one", () => {
    expect(() => writeValue(EMPTY_DOC, SWITCH, true)).toThrow(/not available/);
    expect(() => writeValue(EMPTY_DOC, LIST, ["C:\\a.exe"])).toThrow(/not available/);
    expect(writeValue(stored, SWITCH, false).values).not.toHaveProperty(SWITCH);
  });

  it("is not searched", () => {
    expect(searchSettings("")).not.toContain(SWITCH);
    expect(searchSettings("route traffic")).not.toContain(SWITCH);
    expect(searchSettings("my apps")).not.toContain(LIST);
  });

  it("is not exported", () => {
    expect(knownValues(stored)).toEqual({ "appearance.theme": "light" });
    expect(JSON.parse(exportText(stored)).values).toEqual({ "appearance.theme": "light" });
  });

  it("is not imported: the entry is refused and the stored value survives", () => {
    const file = JSON.stringify({ kind: EXPORT_KIND, schema: SETTINGS_SCHEMA, values: { [SWITCH]: true, [LIST]: ["C:\\b.exe"] } });
    const plan = planImport(stored, file);
    if (!plan.ok) throw new Error(plan.error);
    expect(plan.refused.map((r) => [r.key, r.reason])).toEqual([
      [SWITCH, "Not available in this version of Sieve"],
      [LIST, "Not available in this version of Sieve"],
    ]);
    expect(plan.next.values[LIST]).toEqual(["C:\\a.exe"]);
    expect(plan.changes.map((c) => c.key)).toEqual(["appearance.theme"]);
  });

  it("is not reset: the stored value stays as it is", () => {
    const reset = resetPlan(stored);
    expect(reset.next.values).toEqual({ [SWITCH]: true, [LIST]: ["C:\\a.exe"] });
    expect(reset.changes.map((c) => c.key)).toEqual(["appearance.theme"]);
  });

  it("schema 3 -> 4: a stored unavailable data switch is dropped; other unavailable values are kept, unread", () => {
    expect(offUnavailableSwitches(stored.values)).toEqual({ [LIST]: ["C:\\a.exe"], "appearance.theme": "light" });
    const doc = normalizeDoc({ schema: 3, values: stored.values });
    expect(doc.values).not.toHaveProperty(SWITCH);
    expect(readValue(doc, SWITCH)).toBe(false);
  });
});
