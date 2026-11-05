import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/engine-probe-v2.json";
import { parseEngineProbe } from "@/data/protocol";
import type { EngineSlice } from "./engine";
import { SETTING_KEYS, isAvailable, settingDef } from "./settings/registry";
import { dataSwitchSummary, switchesState, welcomeAdguard, welcomeSteps } from "./welcome";

const slice = (name: keyof typeof fixture.examples): EngineSlice => ({ probe: parseEngineProbe(fixture.examples[name]), error: null });
const ids = (e: EngineSlice, keep = false) => welcomeSteps(e, keep, "off").map((s) => s.id);
const unknown: EngineSlice = { probe: null, error: null };

describe("welcome steps", () => {
  it("offers AdGuard only with AdGuard running and the engine installed", () => {
    expect(ids(slice("adguard"))).toEqual(["what", "switches", "adguard"]);
    // The engine's service is installed but stopped: AdGuard still runs.
    expect(welcomeAdguard(slice("stopped"))).toBe(true);
    for (const e of [slice("missing"), slice("idle"), slice("filtering"), unknown]) {
      expect(ids(e)).toEqual(["what", "switches"]);
      expect(welcomeAdguard(e)).toBe(false);
    }
    expect(welcomeAdguard({ probe: { ...parseEngineProbe(fixture.examples.missing), adguard: "running" }, error: null })).toBe(false);
  });

  it("keeps the AdGuard step for the person on it after their pause ends the offer", () => {
    expect(ids(slice("filtering"), true)).toEqual(["what", "switches", "adguard"]);
  });

  it("says nothing is blocked", () => {
    expect(welcomeSteps(unknown, false, "off")[0].body).toContain("blocks nothing yet");
  });

  it("words the switches step by what is in force", () => {
    const body = (s: Parameters<typeof welcomeSteps>[2]) => welcomeSteps(unknown, false, s)[1].body;
    expect(body("off")).toContain("They are off");
    for (const s of ["on", "unknown"] as const) expect(body(s), s).not.toContain("They are off");
  });
});

describe("switchesState", () => {
  it("any switch on is on, whatever the engine says", () => {
    expect(switchesState([false, true], slice("missing"))).toBe("on");
    expect(switchesState([true], unknown)).toBe("on");
  });

  it("all off reads off only where the engine's state is known", () => {
    for (const name of ["missing", "stopped", "idle"] as const) expect(switchesState([false], slice(name)), name).toBe("off");
    for (const name of ["refused", "incompatible"] as const) expect(switchesState([false], slice(name)), name).toBe("unknown");
    expect(switchesState([false], unknown)).toBe("unknown");
    expect(switchesState([false], { probe: null, error: "denied" })).toBe("unknown");
  });
});

describe("dataSwitchSummary", () => {
  it("lists exactly the registry's available data switches", () => {
    const want = SETTING_KEYS.filter((k) => settingDef(k).kind === "dataSwitch" && isAvailable(k));
    expect(want.length).toBeGreaterThan(0);
    expect(dataSwitchSummary().map((s) => s.key)).toEqual(want);
    for (const s of dataSwitchSummary()) expect(s.label).toBe(settingDef(s.key).label);
  });
});
