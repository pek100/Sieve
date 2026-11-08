import { afterEach, describe, expect, it, vi } from "vitest";

/** The options are unavailable in this build; `offer.tracking` makes them available, as a later build will. */
const offer = vi.hoisted(() => ({ tracking: false }));
vi.mock("./settings/registry", async (importOriginal) => {
  const real = await importOriginal<typeof import("./settings/registry")>();
  return { ...real, isAvailable: (k: string) => (k.startsWith("tracking.") ? offer.tracking : real.isAvailable(k as never)) };
});

import ipc from "@/data/fixtures/engine-ipc-v3.json";
import { CUSTOM } from "./profiles";
import { EMPTY_DOC, readValue, writeValue, type SettingsDoc } from "./settings/document";
import { TRACKING_LEVELS, defaultValue, isAvailable, settingDef, type SettingKey } from "./settings/registry";
import { RECOMMENDED_TRACKING, TRACKING_KEYS, trackingInForce, trackingLevel, trackingName, trackingOffered, trackingValues } from "./tracking";

const readOf = (doc: SettingsDoc) => (k: SettingKey) => readValue(doc, k);
const withValues = (values: Record<string, unknown>): SettingsDoc => ({ ...EMPTY_DOC, values });

describe("tracking protection's options", () => {
  it("are the registry's tracking section, named as the engine names them", () => {
    expect(TRACKING_KEYS.map(trackingName)).toEqual(ipc.trackingNames);
  });

  it("each says its effect, needs the HTTPS switch, and says what it breaks when Standard leaves it off", () => {
    for (const k of TRACKING_KEYS) {
      const d = settingDef(k);
      expect(d.kind, k).toBe("boolean");
      expect(d.requires, k).toBe("filtering.https");
      expect(d.help.endsWith("."), k).toBe(true);
      if (d.preset !== "standard") expect(d.breaks, `${k} is off in Standard: it says what it can break`).toMatch(/\.$/);
    }
    expect(settingDef("tracking.webRtc").preset, "WebRTC is never part of a level: it breaks calls").toBeNull();
    expect(settingDef("tracking.webRtc").breaks).toMatch(/call/i);
  });
});

describe("tracking level", () => {
  it("is Standard, the recommended level, with nothing changed: the defaults are Standard", () => {
    expect(RECOMMENDED_TRACKING).toBe("standard");
    expect(trackingLevel(readOf(EMPTY_DOC))).toBe("standard");
    for (const k of TRACKING_KEYS) expect(defaultValue(k), k).toBe(trackingValues("standard")[k]);
  });

  it.each(TRACKING_LEVELS)("%s maps to exactly its options", (level) => {
    const values = trackingValues(level);
    expect(trackingLevel((k) => values[k])).toBe(level);
    const on = TRACKING_KEYS.filter((k) => values[k]);
    const rank = (p: string | null | undefined) => (p ? TRACKING_LEVELS.indexOf(p as (typeof TRACKING_LEVELS)[number]) : Infinity);
    expect(on).toEqual(TRACKING_KEYS.filter((k) => rank(settingDef(k).preset) <= TRACKING_LEVELS.indexOf(level)));
  });

  it("Strict adds to Standard and nothing reaches the options no level turns on", () => {
    const standard = trackingValues("standard");
    const strict = trackingValues("strict");
    expect(TRACKING_KEYS.filter((k) => strict[k] && !standard[k]).length).toBeGreaterThan(0);
    for (const k of TRACKING_KEYS) if (standard[k]) expect(strict[k], k).toBe(true);
    for (const k of TRACKING_KEYS) if (settingDef(k).preset === null) expect(strict[k], k).toBe(false);
  });

  it("any one change shows Custom; back to Standard restores it", () => {
    for (const level of TRACKING_LEVELS) {
      for (const k of TRACKING_KEYS) {
        const values = { ...trackingValues(level), [k]: !trackingValues(level)[k] };
        expect(trackingLevel((key) => values[key]), `${level}, ${k}`).toBe(CUSTOM);
      }
    }
    const custom: Record<string, boolean> = { ...trackingValues("strict"), "tracking.webRtc": true };
    expect(trackingLevel((k) => custom[k])).toBe(CUSTOM);
    expect(trackingLevel((k) => trackingValues(RECOMMENDED_TRACKING)[k])).toBe("standard");
  });
});

describe("while the engine does not carry them out", () => {
  it("no option is offered, and none is in force whatever its default or the HTTPS switch says", () => {
    expect(TRACKING_KEYS.filter(isAvailable)).toEqual([]);
    expect(trackingOffered()).toBe(false);
    expect(defaultValue("tracking.gpc"), "on by default: so availability, not the value, keeps it out").toBe(true);
    const values: Record<string, boolean> = { ...trackingValues("strict"), "filtering.https": true };
    expect(trackingInForce((k) => values[k])).toEqual([]);
  });

  it("a stored wish is kept unread and no new one is written", () => {
    const doc = withValues({ "tracking.webRtc": true });
    expect(readValue(doc, "tracking.webRtc")).toBe(false);
    expect(doc.values["tracking.webRtc"]).toBe(true);
    expect(() => writeValue(EMPTY_DOC, "tracking.webRtc", true)).toThrow(/not available/);
  });
});

describe("once offered, a locked option is never sent as on", () => {
  const offered = () => {
    offer.tracking = true;
  };
  afterEach(() => {
    offer.tracking = false;
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
    const values: Record<string, boolean> = { ...trackingValues("standard"), "tracking.webRtc": true };
    expect(trackingInForce((k) => (k === "filtering.https" ? false : values[k]))).toEqual([]);
    expect(trackingInForce((k) => (k === "filtering.https" ? true : values[k]))).toEqual(["gpc", "searchQueries", "clientData", "webRtc"]);
  });

  it("an option stays writable while locked, so a wish is kept for later", () => {
    offered();
    expect(readValue(writeValue(EMPTY_DOC, "tracking.webRtc", true), "tracking.webRtc")).toBe(true);
  });
});
