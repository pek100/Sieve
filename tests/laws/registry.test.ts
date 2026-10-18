/**
 * Law 4, settings registry: every data switch defaults to false and names a
 * live check; every `requires` points at a data switch; defaults are valid;
 * settings are declared nowhere else.
 */
import { describe, expect, it } from "vitest";
import { normalizeDoc, readValue } from "@/core/settings/document";
import { REGISTRY, SECTIONS, SETTING_KEYS, isValidValue, settingDef, type SettingDef } from "@/core/settings/registry";
import { hits, read, walk } from "./files";

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

  it("every data switch's live check is an ignored Rust test of that name (the app's or the engine's)", () => {
    const rust = [...walk("src-tauri/src", [".rs"]), ...walk("engine/crates", [".rs"])].map(read).join("\n");
    for (const [key, def] of defs) {
      if (def.kind !== "dataSwitch") continue;
      const declared = new RegExp(`#\\[ignore[^\\]]*\\]\\s*(?:#\\[[^\\]]*\\]\\s*)*async fn ${def.liveCheck}\\(|#\\[ignore[^\\]]*\\]\\s*fn ${def.liveCheck}\\(`);
      expect(rust, key).toMatch(declared);
    }
  });

  it("every requires points at an existing data switch", () => {
    for (const [key, def] of defs) if (def.requires) expect(isDataSwitch(def.requires), key).toBe(true);
  });

  it("every default is a valid value for its own entry", () => {
    for (const [key, def] of defs) expect(isValidValue(key, def.default), key).toBe(true);
  });

  it("map and list values are checked element by element, so a corrupt stored value reads as the default", () => {
    expect(isValidValue("apps.levels", { chrome: "off", slack: "sieve" })).toBe(true);
    expect(isValidValue("apps.levels", { chrome: "loud" })).toBe(false);
    expect(isValidValue("apps.levels", { chrome: 3 })).toBe(false);
    expect(isValidValue("apps.levels", { chrome: null })).toBe(false);
    expect(isValidValue("apps.pinned", ["C:\\Tools\\a.exe"])).toBe(true);
    expect(isValidValue("apps.pinned", ["C:\\Tools\\a.exe", 7])).toBe(false);
    expect(isValidValue("apps.pinned", [{ path: "x" }])).toBe(false);
    expect(isValidValue("apps.pinned", [""])).toBe(false);
    // Through the stored document: the corrupt value is not used, the default is.
    const doc = normalizeDoc({ schema: 2, values: { "apps.levels": { chrome: 42 }, "apps.pinned": [null] } });
    expect(readValue(doc, "apps.levels")).toEqual({});
    expect(readValue(doc, "apps.pinned")).toEqual([]);
    // Every map and list declares the shape of its elements.
    for (const [key, def] of defs) if (def.kind === "map" || def.kind === "list") expect(def.of, key).toBeDefined();
  });

  it("every section a setting uses is declared once, and every declared section has a setting", () => {
    const ids = SECTIONS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const [key, def] of defs) expect(ids, key).toContain(def.section);
    for (const id of ids) expect(defs.some(([, d]) => d.section === id), id).toBe(true);
  });

  it("keys are dotted section names and their section matches", () => {
    for (const [key, def] of defs) {
      expect(key, key).toMatch(/^[a-z]+\.[a-zA-Z.]+$/);
      expect(key.split(".")[0], key).toBe(def.section);
    }
  });

  it("UI code never names a data switch key: it reads it from `requires` or src/core/dns.ts", () => {
    const switches = defs.filter(([, d]) => d.kind === "dataSwitch").map(([k]) => k);
    const files = walk("src/components", [".ts", ".tsx"]).filter((f) => !f.endsWith(".test.ts") && !f.endsWith(".test.tsx"));
    const re = new RegExp(`["'\`](${switches.map((k) => k.replace(".", "\\.")).join("|")})["'\`]`);
    expect(files.flatMap((f) => hits(f, re))).toEqual([]);
  });

  it("no setting key is read from storage outside the registry seam", () => {
    // localStorage and the Tauri store are touched only by the settings seam.
    const files = walk("src", [".ts", ".tsx"]).filter((f) => f !== "src/data/settings-store.ts" && !f.endsWith(".test.ts") && !f.endsWith(".test.tsx"));
    expect(files.flatMap((f) => hits(f, /localStorage|plugin-store/))).toEqual([]);
  });
});
