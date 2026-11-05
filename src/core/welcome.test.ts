import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/engine-probe-v2.json";
import { parseEngineProbe } from "@/data/protocol";
import type { EngineSlice } from "./engine";
import { SETTING_KEYS, isAvailable, settingDef } from "./settings/registry";
import { dataSwitchSummary, welcomeAdguard, welcomeSteps } from "./welcome";

const slice = (name: keyof typeof fixture.examples): EngineSlice => ({ probe: parseEngineProbe(fixture.examples[name]), error: null });
const ids = (e: EngineSlice, keep?: boolean) => welcomeSteps(e, keep).map((s) => s.id);
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
    expect(welcomeSteps(unknown)[0].body).toContain("blocks nothing yet");
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
