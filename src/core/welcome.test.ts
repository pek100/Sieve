import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/engine-probe-v3.json";
import { parseEngineProbe } from "@/data/protocol";
import type { EngineSlice } from "./engine";
import { SETTING_KEYS, isAvailable, settingDef } from "./settings/registry";
import { dataSwitchSummary, switchesState, welcomeAdguard, welcomeSteps } from "./welcome";

const slice = (name: keyof typeof fixture.examples): EngineSlice => ({ probe: parseEngineProbe(fixture.examples[name]), error: null });
const ids = (e: EngineSlice, keep = false, httpsShown = false) => welcomeSteps(e, keep, "off", httpsShown).map((s) => s.id);
const unknown: EngineSlice = { probe: null, error: null };

describe("welcome steps", () => {
  it("offers AdGuard only with AdGuard running and the engine installed", () => {
    expect(ids(slice("adguard"))).toEqual(["what", "switches", "https", "adguard"]);
    // The engine's service is installed but stopped: AdGuard still runs.
    expect(welcomeAdguard(slice("stopped"))).toBe(true);
    for (const e of [slice("missing"), slice("idle"), slice("filtering"), unknown]) {
      expect(ids(e)).toEqual(["what", "switches", "https"]);
      expect(welcomeAdguard(e)).toBe(false);
    }
    expect(welcomeAdguard({ probe: { ...parseEngineProbe(fixture.examples.missing), adguard: "running" }, error: null })).toBe(false);
  });

  it("keeps the AdGuard step for the person on it after their pause ends the offer", () => {
    expect(ids(slice("filtering"), true)).toEqual(["what", "switches", "https", "adguard"]);
  });

  it("explains HTTPS filtering and where to turn it on, unless it is on: shown on in the switches step, or held on by the engine", () => {
    expect(ids(slice("idle"), false, true), "a new install: shown on").toEqual(["what", "switches"]);
    const https = welcomeSteps(unknown, false, "off", false).find((s) => s.id === "https");
    expect(https?.body).toMatch(/here on this computer/);
    expect(https?.body).toMatch(/turn it off at any time/);
    const probe = parseEngineProbe(fixture.examples.filtering);
    if (probe.pipe?.kind !== "welcome") throw new Error("the fixture's engine answers");
    const on: EngineSlice = { probe: { ...probe, pipe: { ...probe.pipe, status: { ...probe.pipe.status, policy: { ...probe.pipe.status.policy, https: true } } } }, error: null };
    expect(ids(on)).toEqual(["what", "switches"]);
  });

  it("says what the engine does only while it routes, and claims nothing was blocked", () => {
    const what = welcomeSteps(unknown, false, "off", false)[0].body;
    expect(what).toContain("While its engine routes your traffic, it also closes connections");
    expect(what).not.toMatch(/blocked/);
  });

  it("words the switches step by what is in force, says each can be changed here, and that off returns that part to normal", () => {
    const body = (s: Parameters<typeof welcomeSteps>[2]) => welcomeSteps(unknown, false, s, false)[1].body;
    expect(body("off")).toContain("and they are off");
    for (const s of ["on", "unknown"] as const) expect(body(s), s).not.toContain("they are off");
    for (const s of ["on", "off"] as const) {
      expect(body(s), s).toMatch(/here or later in Settings/);
      expect(body(s), s).toMatch(/returns that part to normal/);
    }
    expect(body("unknown")).toMatch(/Sieve cannot read the engine/);
    // The guide never says it leaves the switches alone: they are the person's to change.
    for (const s of ["on", "off", "unknown"] as const) expect(body(s), s).not.toMatch(/leaves them|changes none/);
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
