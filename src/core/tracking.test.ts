import { afterEach, describe, expect, it, vi } from "vitest";

/** The options wait for the HTTPS switch in this build; `offer.tracking` makes them available, as the build with that switch will. */
const offer = vi.hoisted(() => ({ tracking: false }));
vi.mock("./settings/registry", async (importOriginal) => {
  const real = await importOriginal<typeof import("./settings/registry")>();
  return { ...real, isAvailable: (k: string) => (k.startsWith("tracking.") ? offer.tracking : real.isAvailable(k as never)) };
});

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

describe("while the HTTPS switch waits for its live check", () => {
  it("no option is offered, each waits for that switch, and none is in force whatever its default", () => {
    expect(TRACKING_KEYS.filter(isAvailable)).toEqual([]);
    expect(trackingOffered()).toBe(false);
    expect(offeredTrackingKeys()).toEqual([]);
    for (const k of TRACKING_KEYS) expect(unavailableUntil(k), k).toBe(unavailableUntil(IN_PAGE.includes(k) ? "filtering.content" : "filtering.https"));
    expect(defaultValue("tracking.gpc"), "on by default: so availability, not the value, keeps it out").toBe(true);
    const values: Record<string, boolean> = { ...trackingValues("strict"), "filtering.https": true };
    expect(trackingInForce((k) => values[k])).toEqual([]);
  });

  it("a stored wish is kept unread and no new one is written", () => {
    const doc = withValues({ "tracking.webRtc": true });
    expect(readValue(doc, "tracking.webRtc")).toBe(false);
    expect(doc.values["tracking.webRtc"]).toBe(true);
    expect(() => writeValue(EMPTY_DOC, "tracking.webRtc", true)).toThrow(/not available.*slice 9/);
    expect(() => writeValue(EMPTY_DOC, "tracking.referrer", true)).toThrow(/not available.*slice 6/);
  });
});

describe("once offered, a locked option is never sent as on", () => {
  const offered = () => {
    offer.tracking = true;
  };
  afterEach(() => {
    offer.tracking = false;
  });

  it("is shown by level, mildest first, those in no level last", () => {
    offered();
    expect(offeredTrackingKeys().map(trackingName)).toEqual(["gpc", "clientData", "searchQueries", "queryParams", "referrer", "thirdPartyCookies", "webRtc", "push", "location", "firstPartyCookies"]);
  });

  it("is not sent while the HTTPS switch is unavailable, whatever is stored", () => {
    offered();
    expect(isAvailable("filtering.https")).toBe(false);
    const doc = withValues({ "filtering.https": true, ...Object.fromEntries(TRACKING_KEYS.map((k) => [k, true])) });
    expect(readValue(doc, "tracking.webRtc"), "the wish is kept").toBe(true);
    expect(trackingInForce(readOf(doc))).toEqual([]);
  });

  it("is sent only with the switch it requires on", () => {
    offered();
    const values: Record<string, boolean> = { ...trackingValues("balanced"), "tracking.webRtc": true };
    const with_ = (on: Record<string, boolean>) => trackingInForce((k) => (k in on ? on[k] : values[k]));
    expect(with_({ "filtering.https": false })).toEqual([]);
    expect(with_({ "filtering.https": true }), "WebRTC lives in the page: it waits for page filtering").toEqual(["gpc", "searchQueries", "clientData", "queryParams"]);
    expect(with_({ "filtering.https": true, "filtering.content": true })).toEqual(["gpc", "searchQueries", "clientData", "webRtc", "queryParams"]);
  });

  it("an option stays writable while locked, so a wish is kept for later", () => {
    offered();
    expect(readValue(writeValue(EMPTY_DOC, "tracking.webRtc", true), "tracking.webRtc")).toBe(true);
  });
});
