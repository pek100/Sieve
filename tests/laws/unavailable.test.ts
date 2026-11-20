/**
 * Law 11, unavailable settings. `unavailableUntil` stays as a mechanism (its
 * behaviour is pinned in src/core/settings/unavailable.test.ts, with real keys
 * mocked unavailable). No key carries it today: the HTTPS and content switches
 * carried it until the owner's decisions of 2026-11-20
 * (docs/tasks/2026-11-06-open-decisions.md), and with them the tracking
 * protections, which the engine carries out and which wait for the switch each
 * requires (registry `isAvailable`), are offered too. The DNS filter's keys
 * waited for engine slice 4, which retired `filtering.dns` and brought
 * `filtering.upstreams` back. Real registry here, never mocked. An unavailable
 * key must name a plan that exists and names it, and no available key may
 * require it.
 */
import { describe, expect, it } from "vitest";
import { CONTENT_SWITCH, HTTPS_SWITCH } from "@/core/engine";
import { normalizeDoc, readValue } from "@/core/settings/document";
import { migrate } from "@/core/settings/migrate";
import { REGISTRY, SETTINGS_SCHEMA, SETTING_KEYS, isAvailable, settingDef, unavailableUntil, type SettingKey } from "@/core/settings/registry";
import { exportText, resetPlan, searchSettings } from "@/core/settings/transfer";
import { TRACKING_KEYS, trackingInForce } from "@/core/tracking";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { ROOT, read } from "./files";

const RETIRED = ["filtering.dns", "filtering.perApp"];
const unavailable = SETTING_KEYS.filter((k) => !isAvailable(k));

describe("unavailable settings law", () => {
  it("no setting is unavailable: the HTTPS and content switches are offered, and with them the tracking protections that require them", () => {
    expect(unavailable).toEqual([]);
    expect(SETTING_KEYS.filter((k) => settingDef(k).unavailableUntil !== undefined), "no key waits for a plan step").toEqual([]);
    for (const k of [HTTPS_SWITCH, CONTENT_SWITCH, ...TRACKING_KEYS]) expect(unavailableUntil(k as SettingKey), k).toBeNull();
    for (const k of TRACKING_KEYS) expect(settingDef(k).requires, k).toMatch(/^filtering\.(https|content)$/);
    // Offered is not on: each is sent only once the switch it requires is on.
    expect(trackingInForce((k) => (k === HTTPS_SWITCH || k === CONTENT_SWITCH ? false : settingDef(k).default)), "with HTTPS off, none is sent").toEqual([]);
  });

  it("the switches are searched, exported and reset like any setting, and read what is stored", () => {
    const stored = { schema: SETTINGS_SCHEMA, values: { [CONTENT_SWITCH]: true, [HTTPS_SWITCH]: true, "appearance.theme": "light" } };
    expect(searchSettings("filter inside pages")).toContain(CONTENT_SWITCH);
    expect(searchSettings("decrypt https")).toContain(HTTPS_SWITCH);
    expect(JSON.parse(exportText(stored)).values).toEqual(stored.values);
    expect(resetPlan(stored).changes.map((c) => c.key).sort()).toEqual(["appearance.theme", CONTENT_SWITCH, HTTPS_SWITCH].sort());
    expect(readValue(stored, CONTENT_SWITCH)).toBe(true);
    expect(readValue({ schema: SETTINGS_SCHEMA, values: {} }, HTTPS_SWITCH), "off on a fresh install: it installs a root certificate").toBe(false);
  });

  it("every key unavailable of its own names a plan step whose plan exists and names the key", () => {
    for (const k of unavailable.filter((key) => settingDef(key).unavailableUntil !== undefined)) {
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
