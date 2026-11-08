/**
 * Law 11, unavailable settings. `unavailableUntil` stays as a mechanism (its
 * behaviour is pinned in src/core/settings/unavailable.test.ts, with real keys
 * mocked unavailable), and today the HTTPS and content switches carry it. The DNS
 * filter's keys waited for engine slice 4, which retired `filtering.dns` and
 * brought `filtering.upstreams` back. Real registry here, never mocked. An
 * unavailable key must name a plan that exists and names it, and no available
 * key may require it.
 */
import { describe, expect, it } from "vitest";
import { CONTENT_SWITCH, HTTPS_SWITCH } from "@/core/engine";
import { normalizeDoc, readValue } from "@/core/settings/document";
import { migrate } from "@/core/settings/migrate";
import { REGISTRY, SETTINGS_SCHEMA, SETTING_KEYS, isAvailable, settingDef } from "@/core/settings/registry";
import { exportText, resetPlan, searchSettings } from "@/core/settings/transfer";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { ROOT, read } from "./files";

const RETIRED = ["filtering.dns", "filtering.perApp"];
const unavailable = SETTING_KEYS.filter((k) => !isAvailable(k));

describe("unavailable settings law", () => {
  it("the HTTPS and content switches are unavailable, until their live checks have run", () => {
    expect(unavailable).toEqual([HTTPS_SWITCH, CONTENT_SWITCH]);
  });

  it("the content switch is not searched, exported or reset, and reads off whatever is stored", () => {
    const stored = { schema: SETTINGS_SCHEMA, values: { [CONTENT_SWITCH]: true, "appearance.theme": "light" } };
    expect(searchSettings("")).not.toContain(CONTENT_SWITCH);
    expect(searchSettings("filter inside pages")).toEqual([]);
    expect(JSON.parse(exportText(stored)).values).toEqual({ "appearance.theme": "light" });
    expect(resetPlan(stored).changes.map((c) => c.key)).toEqual(["appearance.theme"]);
    expect(readValue(stored, CONTENT_SWITCH)).toBe(false);
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

  // Declared exception: the tracking protections act inside decrypted traffic.
  // They are shown, locked with the reason, until the HTTPS switch is available
  // (task: filter profiles), and the policy never carries one before then
  // (src/core/tracking.test.ts). Every other available key needs an available switch.
  it("no available setting requires an unavailable one, but the tracking protections, which require the HTTPS switch", () => {
    for (const k of SETTING_KEYS.filter(isAvailable)) {
      const req = settingDef(k).requires;
      if (!req) continue;
      if (settingDef(k).section === "tracking") expect(req, k).toBe(HTTPS_SWITCH);
      else expect(unavailable as string[], k).not.toContain(req);
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
