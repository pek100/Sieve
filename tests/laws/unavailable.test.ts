/**
 * Law 11, unavailable settings. `unavailableUntil` stays as a mechanism (its
 * behaviour is pinned in src/core/settings/unavailable.test.ts, with real keys
 * mocked unavailable), and today only the HTTPS switch carries it. The DNS
 * filter's keys waited for engine slice 4, which retired `filtering.dns` and
 * brought `filtering.upstreams` back. Real registry here, never mocked. An
 * unavailable key must name a plan that exists and names it, and no available
 * key may require it.
 */
import { describe, expect, it } from "vitest";
import { HTTPS_SWITCH } from "@/core/engine";
import { normalizeDoc, readValue } from "@/core/settings/document";
import { migrate } from "@/core/settings/migrate";
import { REGISTRY, SETTINGS_SCHEMA, SETTING_KEYS, isAvailable, settingDef } from "@/core/settings/registry";
import { searchSettings } from "@/core/settings/transfer";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { ROOT, read } from "./files";

const RETIRED = ["filtering.dns", "filtering.perApp"];
const unavailable = SETTING_KEYS.filter((k) => !isAvailable(k));

describe("unavailable settings law", () => {
  it("only the HTTPS switch is unavailable, until interception exists", () => {
    expect(unavailable).toEqual([HTTPS_SWITCH]);
  });

  it("every unavailable key names a plan step whose plan exists and names the key", () => {
    for (const k of unavailable) {
      const until = settingDef(k).unavailableUntil ?? "";
      const path = until.match(/docs\/[\w./-]+\.md/)?.[0];
      expect(path, k).toBeDefined();
      expect(existsSync(join(ROOT, path!)), `${k}: ${path}`).toBe(true);
      expect(read(path!), `${path} names ${k}`).toContain(k);
    }
  });

  it("no available setting requires an unavailable one", () => {
    for (const k of SETTING_KEYS.filter(isAvailable)) {
      const req = settingDef(k).requires;
      if (req) expect(unavailable as string[], k).not.toContain(req);
    }
  });

  it("the retired keys are not in the registry, and the kept one is shown", () => {
    expect(SETTINGS_SCHEMA).toBe(5);
    for (const k of RETIRED) expect(REGISTRY, k).not.toHaveProperty(k);
    expect(isAvailable("filtering.upstreams")).toBe(true);
    expect(searchSettings("upstream")).toEqual(["filtering.upstreams"]);
  });

  it.each([1, 2, 3, 4])("schema 5 drops the retired keys from schema %i, on or off", (schema) => {
    for (const on of [true, false]) {
      const out = migrate({ schema, values: { "filtering.dns": on, "filtering.perApp": on } });
      expect(out).toEqual({ schema: SETTINGS_SCHEMA, values: {} });
    }
  });

  it.each([1, 2, 3, 4])("a stored bare upstream from schema %i reads as the encrypted defaults", (schema) => {
    const doc = normalizeDoc({ schema, values: { "filtering.upstreams": ["9.9.9.9"] } });
    expect(doc.values).toEqual({});
    expect(readValue(doc, "filtering.upstreams")).toEqual(settingDef("filtering.upstreams").default);
  });
});
