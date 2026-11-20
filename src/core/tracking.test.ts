import { describe, expect, it } from "vitest";
import ipc from "@/data/fixtures/engine-ipc-v3.json";
import { CUSTOM } from "./profiles";
import { EMPTY_DOC, readValue, writeValue, type SettingsDoc } from "./settings/document";
import { TRACKING_LEVELS, defaultValue, isAvailable, settingDef, unavailableUntil, type SettingKey } from "./settings/registry";
import { RECOMMENDED_TRACKING, TRACKING_KEYS, TRACKING_TEXT, offeredTrackingKeys, trackingInForce, trackingLevel, trackingName, trackingOffered, trackingValues } from "./tracking";

const readOf = (doc: SettingsDoc) => (k: SettingKey) => readValue(doc, k);
const withValues = (values: Record<string, unknown>): SettingsDoc => ({ ...EMPTY_DOC, values });
const IN_PAGE = ["tracking.webRtc", "tracking.push", "tracking.location"];

describe("tracking protection's options", () => {
  it("are the registry's tracking section, named and ordered as the engine names them", () => {
    expect(TRACKING_KEYS.map(trackingName)).toEqual(ipc.trackingNames);
  });

  it("each says its effect, needs the switch that carries it, and says what it breaks when Balanced leaves it off", () => {
    for (const k of TRACKING_KEYS) {
      const d = settingDef(k);
      expect(d.kind, k).toBe("boolean");
      expect(d.requires, k).toBe(IN_PAGE.includes(k) ? "filtering.content" : "filtering.https");
      expect(d.help.endsWith("."), k).toBe(true);
      expect(d.unavailableUntil, `${k}: the engine carries it out, so only its switch gates it`).toBeUndefined();
      if (d.preset !== "minimal" && d.preset !== "balanced") expect(d.breaks, `${k} is off in Balanced: it says what it can break`).toMatch(/\.$/);
    }
    expect(settingDef("tracking.webRtc").preset, "WebRTC is never part of a level: it breaks calls").toBeNull();
    expect(settingDef("tracking.webRtc").breaks).toMatch(/call/i);
    expect(settingDef("tracking.firstPartyCookies").preset, "it signs you out of every site").toBeNull();
  });

  it("are the defaults the plan decided, level by level", () => {
    const on = (level: (typeof TRACKING_LEVELS)[number]) => TRACKING_KEYS.filter((k) => trackingValues(level)[k]).map(trackingName);
    expect(on("minimal")).toEqual(["gpc", "clientData"]);
    expect(on("balanced")).toEqual(["gpc", "searchQueries", "clientData", "queryParams"]);
    expect(on("strict")).toEqual(["gpc", "searchQueries", "clientData", "referrer", "thirdPartyCookies", "queryParams"]);
  });
});

describe("tracking level", () => {
  it("is Balanced, the recommended level, with nothing changed: the defaults are Balanced", () => {
    expect(RECOMMENDED_TRACKING).toBe("balanced");
    expect(TRACKING_LEVELS).toEqual(["minimal", "balanced", "strict"]);
    expect(trackingLevel(readOf(EMPTY_DOC))).toBe("balanced");
    for (const k of TRACKING_KEYS) expect(defaultValue(k), k).toBe(trackingValues("balanced")[k]);
    for (const l of TRACKING_LEVELS) expect(TRACKING_TEXT[l].label.toLowerCase()).toBe(l);
  });

  it.each(TRACKING_LEVELS)("%s maps to exactly its options", (level) => {
    const values = trackingValues(level);
    expect(trackingLevel((k) => values[k])).toBe(level);
    const on = TRACKING_KEYS.filter((k) => values[k]);
    const rank = (p: string | null | undefined) => (p ? TRACKING_LEVELS.indexOf(p as (typeof TRACKING_LEVELS)[number]) : Infinity);
    expect(on).toEqual(TRACKING_KEYS.filter((k) => rank(settingDef(k).preset) <= TRACKING_LEVELS.indexOf(level)));
  });

  it("each level adds to the one before, and nothing reaches the options no level turns on", () => {
    for (let i = 1; i < TRACKING_LEVELS.length; i++) {
      const before = trackingValues(TRACKING_LEVELS[i - 1]);
      const now = trackingValues(TRACKING_LEVELS[i]);
      expect(TRACKING_KEYS.filter((k) => now[k] && !before[k]).length, TRACKING_LEVELS[i]).toBeGreaterThan(0);
      for (const k of TRACKING_KEYS) if (before[k]) expect(now[k], k).toBe(true);
    }
    const strict = trackingValues("strict");
    for (const k of TRACKING_KEYS) if (settingDef(k).preset === null) expect(strict[k], k).toBe(false);
  });

  it("any one change shows Custom; back to Balanced restores it", () => {
    for (const level of TRACKING_LEVELS) {
      for (const k of TRACKING_KEYS) {
        const values = { ...trackingValues(level), [k]: !trackingValues(level)[k] };
        expect(trackingLevel((key) => values[key]), `${level}, ${k}`).toBe(CUSTOM);
      }
    }
    const custom: Record<string, boolean> = { ...trackingValues("strict"), "tracking.webRtc": true };
    expect(trackingLevel((k) => custom[k])).toBe(CUSTOM);
    expect(trackingLevel((k) => trackingValues(RECOMMENDED_TRACKING)[k])).toBe("balanced");
  });
});

/** The HTTPS and content switches are available since 2026-11-20, so every option is offered. */
describe("once offered, a locked option is never sent as on", () => {
  it("every option is offered, waiting for no plan step of its own", () => {
    expect(isAvailable("filtering.https")).toBe(true);
    expect(TRACKING_KEYS.filter(isAvailable)).toEqual(TRACKING_KEYS);
    expect(trackingOffered()).toBe(true);
    for (const k of TRACKING_KEYS) expect(unavailableUntil(k), k).toBeNull();
  });

  it("is shown by level, mildest first, those in no level last", () => {
    expect(offeredTrackingKeys().map(trackingName)).toEqual(["gpc", "clientData", "searchQueries", "queryParams", "referrer", "thirdPartyCookies", "webRtc", "push", "location", "firstPartyCookies"]);
  });

  it("is not sent while HTTPS filtering is off, whatever is stored, and the default is off", () => {
    const doc = withValues(Object.fromEntries(TRACKING_KEYS.map((k) => [k, true])));
    expect(readValue(doc, "filtering.https"), "a fresh install: off").toBe(false);
    expect(readValue(doc, "tracking.webRtc"), "the wish is kept").toBe(true);
    expect(trackingInForce(readOf(doc))).toEqual([]);
    expect(defaultValue("tracking.gpc"), "on by default: so the switch, not the value, keeps it out").toBe(true);
  });

  it("is sent only with the switch it requires on", () => {
    const values: Record<string, boolean> = { ...trackingValues("balanced"), "tracking.webRtc": true };
    const with_ = (on: Record<string, boolean>) => trackingInForce((k) => (k in on ? on[k] : values[k]));
    expect(with_({ "filtering.https": false })).toEqual([]);
    expect(with_({ "filtering.https": true }), "WebRTC lives in the page: it waits for page filtering").toEqual(["gpc", "searchQueries", "clientData", "queryParams"]);
    expect(with_({ "filtering.https": true, "filtering.content": true })).toEqual(["gpc", "searchQueries", "clientData", "webRtc", "queryParams"]);
  });

  it("an option stays writable while locked, so a wish is kept for later", () => {
    expect(readValue(writeValue(EMPTY_DOC, "tracking.webRtc", true), "tracking.webRtc")).toBe(true);
  });
});
