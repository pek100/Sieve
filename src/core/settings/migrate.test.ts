import { describe, expect, it } from "vitest";
import { EMPTY_DOC, OLD_INSTALL_DOC, normalizeDoc, readValue } from "./document";
import { SCHEMA_BEFORE_ON_DEFAULTS, dropSystemDns, keepSwitchesAsTheyWere, levelsToOnOff, migrate, retireDnsProxy } from "./migrate";
import { ON_FOR_NEW_INSTALLS, SETTINGS_SCHEMA, defaultValue } from "./registry";

/** What step 5 -> 6 adds to any document from before it that never stored the switches: they stay off. */
const KEPT_OFF = Object.fromEntries(ON_FOR_NEW_INSTALLS.map((k) => [k, false]));

describe("settings migration law", () => {
  it("every schema below the current one has a step, so any old document reaches the current schema", () => {
    for (let s = 1; s < SETTINGS_SCHEMA; s++) expect(migrate({ schema: s, values: {} }).schema, `from ${s}`).toBe(SETTINGS_SCHEMA);
  });

  it("1 -> 2: off stays off, watch and sieve become the default (not stored)", () => {
    const v1 = { "apps.levels": { chrome: "off", slack: "watch", code: "sieve", teams: "off" }, "appearance.theme": "light" };
    expect(levelsToOnOff(v1)).toEqual({ "apps.levels": { chrome: "off", teams: "off" }, "appearance.theme": "light" });
    const out = migrate({ schema: 1, values: v1 });
    expect(out).toEqual({ schema: SETTINGS_SCHEMA, values: { "apps.levels": { chrome: "off", teams: "off" }, "appearance.theme": "light", ...KEPT_OFF } });
  });

  it("1 -> 2: nothing off leaves no apps.levels entry; a corrupt value is dropped too", () => {
    expect(levelsToOnOff({ "apps.levels": { slack: "watch", x: "sieve", y: 3 } })).toEqual({});
    // Not a map: left for readValue to treat as the default.
    expect(levelsToOnOff({ "apps.levels": "loud" })).toEqual({ "apps.levels": "loud" });
    expect(levelsToOnOff({})).toEqual({});
  });

  it("through the stored document: an old file reads the new model", () => {
    const doc = normalizeDoc({ schema: 1, values: { "apps.levels": { chrome: "off", slack: "watch" } } });
    expect(doc.schema).toBe(SETTINGS_SCHEMA);
    expect(readValue(doc, "apps.levels")).toEqual({ chrome: "off" });
  });

  it("2 -> 3: the retired Windows DNS switch is dropped, on or off; everything else stays", () => {
    const v2 = { "filtering.systemDns": true, "filtering.dns": true, "appearance.theme": "light" };
    expect(dropSystemDns(v2)).toEqual({ "filtering.dns": true, "appearance.theme": "light" });
    // Then 4 -> 5 deletes the DNS switch too: the proxy it ran is gone.
    expect(migrate({ schema: 2, values: v2 })).toEqual({ schema: SETTINGS_SCHEMA, values: { "appearance.theme": "light", ...KEPT_OFF } });
    expect(migrate({ schema: 2, values: { "filtering.systemDns": false } }).values).toEqual(KEPT_OFF);
    // A schema 1 file that had it goes through both steps.
    expect(migrate({ schema: 1, values: { "filtering.systemDns": true, "apps.levels": { a: "watch" } } }).values).toEqual(KEPT_OFF);
  });

  it("a newer document is kept as is", () => {
    const newer = { schema: SETTINGS_SCHEMA + 1, values: { "apps.levels": { a: "watch" } } };
    expect(migrate(newer)).toBe(newer);
  });
});

describe("4 -> 5: the DNS proxy is retired", () => {
  const DEFAULTS = defaultValue("filtering.upstreams");
  const UPSTREAMS = "filtering.upstreams";

  it("the new default is the two DoH templates of plan 1.4", () => {
    expect(DEFAULTS).toEqual(["https://cloudflare-dns.com/dns-query", "https://dns.quad9.net/dns-query"]);
  });

  it.each([1, 2, 3, 4])("filtering.dns on and off is gone from schema %i", (schema) => {
    for (const on of [true, false]) expect(migrate({ schema, values: { "filtering.dns": on } }).values).toEqual(KEPT_OFF);
  });

  it.each([1, 2, 3, 4])("filtering.perApp is gone from schema %i", (schema) => {
    expect(migrate({ schema, values: { "filtering.perApp": false } }).values).toEqual(KEPT_OFF);
  });

  it("a list of bare addresses is deleted, so the defaults read", () => {
    const doc = normalizeDoc({ schema: 4, values: { [UPSTREAMS]: ["1.1.1.1", "9.9.9.9"] } });
    expect(doc.values).toEqual(KEPT_OFF);
    expect(readValue(doc, UPSTREAMS)).toEqual(DEFAULTS);
  });

  it("entries that parse come first, then the defaults; plain addresses never carry forward", () => {
    expect(retireDnsProxy({ [UPSTREAMS]: ["https://a.example/dns-query", "1.1.1.1", "tls://b.example"] })).toEqual({
      [UPSTREAMS]: ["https://a.example/dns-query", "tls://b.example", ...DEFAULTS],
    });
  });

  it("a stored default is not listed twice", () => {
    expect(retireDnsProxy({ [UPSTREAMS]: [DEFAULTS[1], "tls://b.example"] })).toEqual({ [UPSTREAMS]: [DEFAULTS[1], "tls://b.example", DEFAULTS[0]] });
  });

  it("quic:// is kept, and the migrated list reads as the value in force", () => {
    const doc = normalizeDoc({ schema: 4, values: { [UPSTREAMS]: ["quic://c.example:853"] } });
    expect(readValue(doc, UPSTREAMS)).toEqual(["quic://c.example:853", ...DEFAULTS]);
  });

  it("a wrong-shaped value is deleted", () => {
    for (const bad of ["https://a.example/dns-query", 7, null, { a: 1 }, [3, null], []]) expect(retireDnsProxy({ [UPSTREAMS]: bad }), JSON.stringify(bad)).toEqual({});
  });

  it("apps.levels and the theme are untouched", () => {
    const values = { "apps.levels": { chrome: "off" }, "appearance.theme": "light", "filtering.dns": true };
    expect(migrate({ schema: 4, values })).toEqual({ schema: SETTINGS_SCHEMA, values: { "apps.levels": { chrome: "off" }, "appearance.theme": "light", ...KEPT_OFF } });
  });

  it("a newer schema keeps even the retired keys, as is", () => {
    const newer = { schema: SETTINGS_SCHEMA + 1, values: { "filtering.dns": true, [UPSTREAMS]: ["1.1.1.1"] } };
    expect(migrate(newer)).toBe(newer);
  });
});

/** The owner's decision of 2026-11-22: on for a new install; an install from before keeps what it had. */
describe("5 -> 6: routing, HTTPS and page filtering are on for a new install only", () => {
  it("they are the three switches the engine carries out, and default on", () => {
    expect(SETTINGS_SCHEMA).toBe(6);
    expect(SCHEMA_BEFORE_ON_DEFAULTS).toBe(5);
    expect([...ON_FOR_NEW_INSTALLS]).toEqual(["filtering.engine", "filtering.https", "filtering.content"]);
    for (const k of ON_FOR_NEW_INSTALLS) expect(defaultValue(k), k).toBe(true);
  });

  it("a new install (nothing stored) reads all three on", () => {
    const fresh = normalizeDoc(undefined);
    expect(fresh).toEqual(EMPTY_DOC);
    for (const k of ON_FOR_NEW_INSTALLS) expect(readValue(fresh, k), k).toBe(true);
  });

  it.each([1, 2, 3, 4, 5])("a schema %i document with none of them set keeps all three off after the upgrade", (schema) => {
    const doc = normalizeDoc({ schema, values: { "appearance.theme": "light" } });
    expect(doc.schema).toBe(SETTINGS_SCHEMA);
    for (const k of ON_FOR_NEW_INSTALLS) expect(readValue(doc, k), k).toBe(false);
    expect(readValue(doc, "appearance.theme")).toBe("light");
  });

  it("the owner's own install: routing off, nothing else set, stays exactly as it was", () => {
    const doc = normalizeDoc({ schema: 5, values: { "startup.welcomeDone": true, "filters.lists": { "adguard-dns": "on" } } });
    expect(doc.values).toEqual({ "startup.welcomeDone": true, "filters.lists": { "adguard-dns": "on" }, ...KEPT_OFF });
  });

  it("a person's explicit choice is kept either way: a stored on stays on (now the default, so not stored)", () => {
    expect(keepSwitchesAsTheyWere({ "filtering.engine": true, "filtering.https": true })).toEqual({ "filtering.content": false });
    const doc = normalizeDoc({ schema: 5, values: { "filtering.engine": true } });
    expect(readValue(doc, "filtering.engine")).toBe(true);
    expect(readValue(doc, "filtering.https")).toBe(false);
    expect(readValue(doc, "filtering.content")).toBe(false);
  });

  it("a stored off from before stays off, and a wrong-shaped value reads off as it did", () => {
    expect(keepSwitchesAsTheyWere({ "filtering.engine": false, "filtering.https": "yes", "filtering.content": 1 })).toEqual(KEPT_OFF);
  });

  it("a current document with a damaged switch value, or values that are not a record, reads the switches off", () => {
    const damaged = normalizeDoc({ schema: SETTINGS_SCHEMA, values: { "filtering.engine": "yes", "filtering.https": 1 } });
    expect(readValue(damaged, "filtering.engine")).toBe(false);
    expect(readValue(damaged, "filtering.https")).toBe(false);
    expect(readValue(damaged, "filtering.content")).toBe(true);
    for (const values of [[], "x", null]) {
      const doc = normalizeDoc({ schema: SETTINGS_SCHEMA, values });
      for (const k of ON_FOR_NEW_INSTALLS) expect(readValue(doc, k), `${JSON.stringify(values)} ${k}`).toBe(false);
    }
  });

  it("a current document keeps a person's off and reads absence as on", () => {
    const doc = normalizeDoc({ schema: SETTINGS_SCHEMA, values: { "filtering.https": false } });
    expect(readValue(doc, "filtering.engine")).toBe(true);
    expect(readValue(doc, "filtering.https")).toBe(false);
    expect(doc.values).toEqual({ "filtering.https": false });
  });

  it("something stored that is no document, or has no schema, is an old install: off, never guessed on", () => {
    for (const raw of [null, 7, "x", [], {}, { values: {} }, { values: { "appearance.theme": "light" } }]) {
      const doc = normalizeDoc(raw);
      for (const k of ON_FOR_NEW_INSTALLS) expect(readValue(doc, k), `${JSON.stringify(raw)}: ${k}`).toBe(false);
    }
    expect(OLD_INSTALL_DOC).toEqual({ schema: SETTINGS_SCHEMA, values: KEPT_OFF });
  });

  it("migrating twice changes nothing more", () => {
    const once = migrate({ schema: 5, values: { "filtering.engine": true } });
    expect(migrate(once)).toEqual(once);
  });
});
