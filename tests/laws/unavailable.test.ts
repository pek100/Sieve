/**
 * Law 11, unavailable settings (2026-10-18, the user: "Hide the DNS filter
 * switch and its card until the engine's slice 4 replaces it; keep the code
 * for now"). A registry entry with `unavailableUntil` has no row, search,
 * export, import or reset, reads as its default, and takes no other value; a
 * stored "on" of an unavailable data switch is dropped by the schema 4
 * migration, so the DNS controller never starts the filter for it. Every
 * unavailable key names the plan step that brings it back, and that plan
 * names the key. Real registry here, never mocked.
 */
import { describe, expect, it } from "vitest";
import { createPassedChecks } from "@/core/checks";
import { DNS_SWITCH, UPSTREAMS_KEY } from "@/core/dns";
import { HTTPS_SWITCH } from "@/core/engine";
import { createNoticeBus } from "@/core/notices";
import { EMPTY_DOC, knownValues, normalizeDoc, readValue, writeValue } from "@/core/settings/document";
import { migrate, offUnavailableSwitches } from "@/core/settings/migrate";
import { SETTINGS_SCHEMA, SETTING_KEYS, isAvailable, settingDef } from "@/core/settings/registry";
import { EXPORT_KIND, exportText, planImport, resetPlan, searchSettings } from "@/core/settings/transfer";
import { createStore } from "@/core/store";
import { createDnsController } from "@/data/dns-controller";
import { createMockDns } from "@/data/dns-mock";
import type { DnsSource } from "@/data/dns-source";
import type { Clock } from "@/data/poller";
import { createSettingsStore, memoryBackend } from "@/data/settings-store";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { ROOT, read } from "./files";

const exists = (rel: string) => existsSync(join(ROOT, rel));

const unavailable = SETTING_KEYS.filter((k) => !isAvailable(k));

const settle = async () => {
  for (let i = 0; i < 20; i++) await new Promise<void>((r) => setTimeout(r, 0));
};

/** A clock whose timers never fire: the law is about what happens at load. */
const still: Clock = { now: () => 1_760_000_000_000, setTimeout: () => 0, clearTimeout: () => {} };

describe("unavailable settings law", () => {
  it("the DNS filter's switch and the keys only its card edits are unavailable, together; and the HTTPS switch until interception exists", () => {
    expect(unavailable).toEqual([DNS_SWITCH, HTTPS_SWITCH, UPSTREAMS_KEY]);
  });

  it("every unavailable key names a plan step whose plan exists and names the key", () => {
    for (const k of unavailable) {
      const until = settingDef(k).unavailableUntil ?? "";
      const path = until.match(/docs\/[\w./-]+\.md/)?.[0];
      expect(path, k).toBeDefined();
      expect(exists(path!), `${k}: ${path}`).toBe(true);
      expect(read(path!), `${path} names ${k}`).toContain(k);
    }
  });

  it("no available setting requires an unavailable one", () => {
    for (const k of SETTING_KEYS.filter(isAvailable)) {
      const req = settingDef(k).requires;
      if (req) expect(unavailable as string[], k).not.toContain(req);
    }
  });

  it("an unavailable key reads as its default whatever is stored, and takes no other value", () => {
    const doc = { schema: SETTINGS_SCHEMA, values: { [DNS_SWITCH]: true, [UPSTREAMS_KEY]: ["9.9.9.9"] } };
    expect(readValue(doc, DNS_SWITCH)).toBe(false);
    expect(readValue(doc, UPSTREAMS_KEY)).toEqual(settingDef(UPSTREAMS_KEY).default);
    expect(() => writeValue(EMPTY_DOC, DNS_SWITCH, true)).toThrow(/not available/);
    expect(() => writeValue(EMPTY_DOC, UPSTREAMS_KEY, ["9.9.9.9"])).toThrow(/not available/);
    // Its default is still writable (it clears the stored value).
    expect(writeValue(doc, DNS_SWITCH, false).values).not.toHaveProperty(DNS_SWITCH);
  });

  it("schema 3 -> 4: a stored unavailable data switch is dropped, so it is off; other unavailable values are kept, unread", () => {
    expect(SETTINGS_SCHEMA).toBe(4);
    const v3 = { [DNS_SWITCH]: true, [UPSTREAMS_KEY]: ["9.9.9.9"], "appearance.theme": "light" };
    expect(offUnavailableSwitches(v3)).toEqual({ [UPSTREAMS_KEY]: ["9.9.9.9"], "appearance.theme": "light" });
    expect(migrate({ schema: 3, values: v3 })).toEqual({ schema: 4, values: { [UPSTREAMS_KEY]: ["9.9.9.9"], "appearance.theme": "light" } });
    // Every older schema too, through the stored document.
    for (const schema of [1, 2, 3]) {
      const doc = normalizeDoc({ schema, values: { [DNS_SWITCH]: true } });
      expect(doc.values, `from ${schema}`).not.toHaveProperty(DNS_SWITCH);
      expect(readValue(doc, DNS_SWITCH)).toBe(false);
    }
  });

  it("a stored 'on' from an old build never starts the DNS filter, and its safety banner offers no switch", async () => {
    const calls: string[] = [];
    const base = createMockDns({ seed: 1, scenario: "off", pointed: true });
    const dns = Object.fromEntries(
      Object.entries(base).map(([k, v]) => [k, typeof v === "function" ? (...a: unknown[]) => (calls.push(k), (v as (...x: unknown[]) => unknown)(...a)) : v]),
    ) as unknown as DnsSource;
    for (const schema of [2, 3]) {
      calls.length = 0;
      const store = createStore();
      const settings = createSettingsStore(memoryBackend({ schema, values: { [DNS_SWITCH]: true } }));
      const notices = createNoticeBus();
      const undo = createDnsController({ dns, store, settings, notices, checks: createPassedChecks(), clock: still }).bind();
      await settle();
      expect(settings.get(DNS_SWITCH)).toBe(false);
      expect(calls, `schema ${schema}`).not.toContain("start");
      expect(store.getState().dns.status?.running).toBe(false);
      // The read-only safety net still says Windows asks loopback, and points only to Windows' settings.
      const banner = notices.list().find((n) => n.surface === "banner");
      expect(banner?.text).toMatch(/Windows network settings/);
      expect(banner?.action).toBeUndefined();
      undo();
    }
  });

  it("not searched, exported, imported or reset; an import cannot reach them", () => {
    for (const k of unavailable) expect(searchSettings(""), k).not.toContain(k);
    // Nothing visible mentions DNS while the filter is unavailable, so the search finds nothing.
    expect(searchSettings("dns")).toEqual([]);
    const stored = { schema: SETTINGS_SCHEMA, values: { [UPSTREAMS_KEY]: ["9.9.9.9"], "appearance.theme": "light" } };
    expect(knownValues(stored)).toEqual({ "appearance.theme": "light" });
    expect(JSON.parse(exportText(stored)).values).toEqual({ "appearance.theme": "light" });
    const file = JSON.stringify({ kind: EXPORT_KIND, schema: SETTINGS_SCHEMA, values: { [DNS_SWITCH]: true, [UPSTREAMS_KEY]: ["1.0.0.1"] } });
    const plan = planImport(stored, file);
    if (!plan.ok) throw new Error(plan.error);
    expect(plan.refused.map((r) => [r.key, r.reason])).toEqual([
      [DNS_SWITCH, "Not available in this version of Sieve"],
      [UPSTREAMS_KEY, "Not available in this version of Sieve"],
    ]);
    // The stored, unread upstream list survives an import and a reset untouched.
    expect(plan.next.values[UPSTREAMS_KEY]).toEqual(["9.9.9.9"]);
    expect(plan.changes.map((c) => c.key)).toEqual(["appearance.theme"]);
    const reset = resetPlan(stored);
    expect(reset.next.values).toEqual({ [UPSTREAMS_KEY]: ["9.9.9.9"] });
    expect(reset.changes.map((c) => c.key)).toEqual(["appearance.theme"]);
  });
});
