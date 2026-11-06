import { describe, expect, it } from "vitest";
import { normalizeDoc, readValue } from "./document";
import { dropSystemDns, levelsToOnOff, migrate, retireDnsProxy } from "./migrate";
import { SETTINGS_SCHEMA, defaultValue } from "./registry";

describe("settings migration law", () => {
  it("every schema below the current one has a step, so any old document reaches the current schema", () => {
    for (let s = 1; s < SETTINGS_SCHEMA; s++) expect(migrate({ schema: s, values: {} }).schema, `from ${s}`).toBe(SETTINGS_SCHEMA);
  });

  it("1 -> 2: off stays off, watch and sieve become the default (not stored)", () => {
    const v1 = { "apps.levels": { chrome: "off", slack: "watch", code: "sieve", teams: "off" }, "appearance.theme": "light" };
    expect(levelsToOnOff(v1)).toEqual({ "apps.levels": { chrome: "off", teams: "off" }, "appearance.theme": "light" });
    const out = migrate({ schema: 1, values: v1 });
    expect(out).toEqual({ schema: SETTINGS_SCHEMA, values: { "apps.levels": { chrome: "off", teams: "off" }, "appearance.theme": "light" } });
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
    expect(migrate({ schema: 2, values: v2 })).toEqual({ schema: SETTINGS_SCHEMA, values: { "appearance.theme": "light" } });
    expect(migrate({ schema: 2, values: { "filtering.systemDns": false } }).values).toEqual({});
    // A schema 1 file that had it goes through both steps.
    expect(migrate({ schema: 1, values: { "filtering.systemDns": true, "apps.levels": { a: "watch" } } }).values).toEqual({});
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
    expect(SETTINGS_SCHEMA).toBe(5);
    expect(DEFAULTS).toEqual(["https://cloudflare-dns.com/dns-query", "https://dns.quad9.net/dns-query"]);
  });

  it.each([1, 2, 3, 4])("filtering.dns on and off is gone from schema %i", (schema) => {
    for (const on of [true, false]) expect(migrate({ schema, values: { "filtering.dns": on } }).values).toEqual({});
  });

  it.each([1, 2, 3, 4])("filtering.perApp is gone from schema %i", (schema) => {
    expect(migrate({ schema, values: { "filtering.perApp": false } }).values).toEqual({});
  });

  it("a list of bare addresses is deleted, so the defaults read", () => {
    const doc = normalizeDoc({ schema: 4, values: { [UPSTREAMS]: ["1.1.1.1", "9.9.9.9"] } });
    expect(doc.values).toEqual({});
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
    expect(migrate({ schema: 4, values })).toEqual({ schema: 5, values: { "apps.levels": { chrome: "off" }, "appearance.theme": "light" } });
  });

  it("a newer schema keeps even the retired keys, as is", () => {
    const newer = { schema: SETTINGS_SCHEMA + 1, values: { "filtering.dns": true, [UPSTREAMS]: ["1.1.1.1"] } };
    expect(migrate(newer)).toBe(newer);
  });
});
