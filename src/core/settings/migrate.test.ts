import { describe, expect, it } from "vitest";
import { normalizeDoc, readValue } from "./document";
import { levelsToOnOff, migrate } from "./migrate";
import { SETTINGS_SCHEMA } from "./registry";

describe("settings migration law", () => {
  it("every schema below the current one has a step, so any old document reaches the current schema", () => {
    for (let s = 1; s < SETTINGS_SCHEMA; s++) expect(migrate({ schema: s, values: {} }).schema, `from ${s}`).toBe(SETTINGS_SCHEMA);
  });

  it("1 -> 2: off stays off, watch and sieve become the default (not stored)", () => {
    const v1 = { "apps.levels": { chrome: "off", slack: "watch", code: "sieve", teams: "off" }, "appearance.theme": "light" };
    const out = migrate({ schema: 1, values: v1 });
    expect(out).toEqual({ schema: 2, values: { "apps.levels": { chrome: "off", teams: "off" }, "appearance.theme": "light" } });
  });

  it("1 -> 2: nothing off leaves no apps.levels entry; a corrupt value is dropped too", () => {
    expect(levelsToOnOff({ "apps.levels": { slack: "watch", x: "sieve", y: 3 } })).toEqual({});
    // Not a map: left for readValue to treat as the default.
    expect(levelsToOnOff({ "apps.levels": "loud" })).toEqual({ "apps.levels": "loud" });
    expect(levelsToOnOff({})).toEqual({});
  });

  it("1 -> 2: the retired per-app filtering switch stays as an unknown key, kept and ignored", () => {
    const out = migrate({ schema: 1, values: { "filtering.perApp": false } });
    expect(out.values).toEqual({ "filtering.perApp": false });
  });

  it("through the stored document: an old file reads the new model", () => {
    const doc = normalizeDoc({ schema: 1, values: { "apps.levels": { chrome: "off", slack: "watch" } } });
    expect(doc.schema).toBe(2);
    expect(readValue(doc, "apps.levels")).toEqual({ chrome: "off" });
  });

  it("a newer document is kept as is", () => {
    const newer = { schema: SETTINGS_SCHEMA + 1, values: { "apps.levels": { a: "watch" } } };
    expect(migrate(newer)).toBe(newer);
  });
});
