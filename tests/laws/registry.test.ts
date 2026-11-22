/**
 * Law 4, settings registry: every data switch defaults to false, but for those
 * the owner put on for a new install (`ON_FOR_NEW_INSTALLS`, 2026-11-22), and
 * names a live check; an install from before keeps those off, so nothing turns
 * on without a new install's default or a person's click; every `requires`
 * points at a data switch; defaults are valid; settings are declared nowhere else.
 */
import { describe, expect, it } from "vitest";
import { CONTENT_SWITCH, DNS_CLIENT_CAPTURE, DNS_ENCRYPTION, ENGINE_SWITCH, HTTPS_SWITCH } from "@/core/engine";
import { EMPTY_DOC, normalizeDoc, readValue } from "@/core/settings/document";
import { SCHEMA_BEFORE_ON_DEFAULTS } from "@/core/settings/migrate";
import { ON_FOR_NEW_INSTALLS, REGISTRY, SECTIONS, SETTING_KEYS, isSettingKey, isValidValue, needsEngine, settingDef, type SettingDef, type SettingKey } from "@/core/settings/registry";
import { hits, read, walk } from "./files";

const defs = SETTING_KEYS.map((k) => [k, settingDef(k)] as const);
const isDataSwitch = (key: string) => (REGISTRY as Record<string, SettingDef>)[key]?.kind === "dataSwitch";
const onForNew = ON_FOR_NEW_INSTALLS as readonly string[];

describe("registry law", () => {
  it("data switches default to off, but for those on for a new install, and name a live_ check", () => {
    for (const [key, def] of defs) {
      if (def.kind !== "dataSwitch") continue;
      expect(def.default, key).toBe(onForNew.includes(key));
      expect(def.liveCheck, key).toMatch(/^live_[a-z0-9_]+$/);
    }
    for (const key of onForNew) expect(isDataSwitch(key), key).toBe(true);
  });

  it("a data switch on for a new install is off for every install from before, unless its person turned it on", () => {
    for (let schema = 1; schema <= SCHEMA_BEFORE_ON_DEFAULTS; schema++) {
      const old = normalizeDoc({ schema, values: {} });
      for (const key of onForNew) expect(readValue(old, key as SettingKey), `${key}, schema ${schema}`).toBe(false);
      const chose = normalizeDoc({ schema, values: Object.fromEntries(onForNew.map((k) => [k, true])) });
      for (const key of onForNew) expect(readValue(chose, key as SettingKey), `${key} chosen on, schema ${schema}`).toBe(true);
    }
    for (const key of onForNew) expect(readValue(EMPTY_DOC, key as SettingKey), `${key}, a new install`).toBe(true);
  });

  it("every data switch's live check is an ignored Rust test of that name (the app's or the engine's)", () => {
    const rust = [...walk("src-tauri/src", [".rs"]), ...walk("engine/crates", [".rs"])].map(read).join("\n");
    for (const [key, def] of defs) {
      if (def.kind !== "dataSwitch") continue;
      const declared = new RegExp(`#\\[ignore[^\\]]*\\]\\s*(?:#\\[[^\\]]*\\]\\s*)*async fn ${def.liveCheck}\\(|#\\[ignore[^\\]]*\\]\\s*fn ${def.liveCheck}\\(`);
      expect(rust, key).toMatch(declared);
    }
  });

  // A data switch, whose live check gates what builds on it, or a plain on/off setting (DNS encryption for the capture switch).
  it("every requires points at an existing switch: a data switch or a boolean", () => {
    for (const [key, def] of defs) if (def.requires) expect(isDataSwitch(def.requires) || (isSettingKey(def.requires) && settingDef(def.requires).kind === "boolean"), key).toBe(true);
  });

  it("the needsEngine settings are the three switches SetPolicy carries: the controller sends exactly them", () => {
    expect(defs.filter(([k]) => needsEngine(k)).map(([k]) => k)).toEqual([ENGINE_SWITCH, HTTPS_SWITCH, CONTENT_SWITCH]);
  });

  it("the content switch is on for a new install, names its live check and needs the HTTPS switch", () => {
    const def = settingDef(CONTENT_SWITCH);
    expect(def.kind).toBe("dataSwitch");
    expect(def.default).toBe(true);
    expect(def.requires).toBe(HTTPS_SWITCH);
    if (def.kind === "dataSwitch") expect(def.liveCheck).toBe("live_content_injects_into_test_page");
  });

  it("DNS encryption defaults on and no data switch: plain DNS is only ever the user's choice", () => {
    const def = settingDef(DNS_ENCRYPTION as SettingKey);
    expect(def.kind).toBe("boolean");
    expect(def.default).toBe(true);
    expect(def.help).toMatch(/plain text/);
    expect(read("src/data/engine-controller.ts")).toContain("plain_dns: settings.get(DNS_ENCRYPTION) === false");
  });

  it("Windows' own lookups are encrypted by default, need DNS encryption, and only off is sent", () => {
    const def = settingDef(DNS_CLIENT_CAPTURE as SettingKey);
    expect(def.kind).toBe("boolean");
    expect(def.default).toBe(true);
    expect(def.requires).toBe(DNS_ENCRYPTION);
    expect(def.help).toMatch(/can't read them/);
    expect(def.breaks).toMatch(/7 s slower/);
    expect(def.breaks).toMatch(/sign-in page/);
    expect(read("src/data/engine-controller.ts")).toContain("...(settings.get(DNS_CLIENT_CAPTURE) === false ? { skip_dns_capture: true } : {})");
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

  it("UI code never names a data switch key: it reads it from `requires` or src/core/engine.ts", () => {
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
