/**
 * Law 4, settings registry: every data switch defaults to false and names a
 * live check; every `requires` points at a data switch; defaults are valid;
 * levels that need a switch need a data switch; settings are declared nowhere else.
 */
import { describe, expect, it } from "vitest";
import { LEVEL_REQUIRES } from "@/core/policy";
import { REGISTRY, SETTING_KEYS, isValidValue, settingDef, type SettingDef } from "@/core/settings/registry";
import { hits, walk } from "./files";

const defs = SETTING_KEYS.map((k) => [k, settingDef(k)] as const);
const isDataSwitch = (key: string) => (REGISTRY as Record<string, SettingDef>)[key]?.kind === "dataSwitch";

describe("registry law", () => {
  it("data switches default to off and name a live_ check", () => {
    for (const [key, def] of defs) {
      if (def.kind !== "dataSwitch") continue;
      expect(def.default, key).toBe(false);
      expect(def.liveCheck, key).toMatch(/^live_[a-z0-9_]+$/);
    }
  });

  it("every requires points at an existing data switch", () => {
    for (const [key, def] of defs) if (def.requires) expect(isDataSwitch(def.requires), key).toBe(true);
    for (const needs of Object.values(LEVEL_REQUIRES)) expect(isDataSwitch(needs!), needs).toBe(true);
  });

  it("every default is a valid value for its own entry", () => {
    for (const [key, def] of defs) expect(isValidValue(key, def.default), key).toBe(true);
  });

  it("keys are dotted section names and their section matches", () => {
    for (const [key, def] of defs) {
      expect(key, key).toMatch(/^[a-z]+\.[a-zA-Z.]+$/);
      expect(key.split(".")[0], key).toBe(def.section);
    }
  });

  it("no setting key is read from storage outside the registry seam", () => {
    // localStorage and the Tauri store are touched only by the settings seam.
    const files = walk("src", [".ts", ".tsx"]).filter((f) => f !== "src/data/settings-store.ts" && !f.endsWith(".test.ts") && !f.endsWith(".test.tsx"));
    expect(files.flatMap((f) => hits(f, /localStorage|plugin-store/))).toEqual([]);
  });
});
