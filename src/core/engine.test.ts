import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/engine-probe-v2.json";
import { parseEngineProbe } from "@/data/protocol";
import {
  EMPTY_ENGINE,
  ENGINE_PHASES,
  ENGINE_STATE_TEXT,
  attribution,
  engineDetail,
  enginePhase,
  engineRoutes,
  engineVersion,
  splitTunnelText,
  type EngineSlice,
} from "./engine";

type Example = keyof typeof fixture.examples;
const facts = (name: Example): EngineSlice => ({ probe: parseEngineProbe(fixture.examples[name]), error: null });
const ALL = Object.keys(fixture.examples) as Example[];

describe("engine phase", () => {
  it("derives every phase from the fixture's facts", () => {
    expect(enginePhase(EMPTY_ENGINE)).toBe("checking");
    expect(enginePhase({ probe: null, error: "denied" })).toBe("unreadable");
    const want: Record<Example, string> = {
      missing: "not_installed",
      stopped: "not_running",
      starting: "not_running",
      unreachable: "not_running",
      refused: "refused",
      incompatible: "incompatible",
      idle: "idle",
      filtering: "routing",
      adguard: "adguard",
      vpn: "vpn",
      crash_loop: "crash_loop",
      setup: "setup_failed",
    };
    for (const name of ALL) expect(enginePhase(facts(name)), name).toBe(want[name]);
  });

  it("the switch on with no blocker and no routes yet is starting", () => {
    const s = facts("adguard");
    const pipe = s.probe!.pipe as Extract<NonNullable<NonNullable<EngineSlice["probe"]>["pipe"]>, { kind: "welcome" }>;
    const starting: EngineSlice = { ...s, probe: { ...s.probe!, pipe: { ...pipe, status: { ...pipe.status, blocker: null } } } };
    expect(enginePhase(starting)).toBe("starting");
  });

  it("never claims filtering or blocking: slice 3 relays every flow", () => {
    for (const s of [EMPTY_ENGINE, { probe: null, error: "e" }, ...ALL.map(facts)]) {
      expect(ENGINE_STATE_TEXT[enginePhase(s)]).not.toMatch(/filtering|blocked|blocking/i);
      expect(engineDetail(s)).not.toMatch(/is filtering|blocks |are blocked|blocked for/i);
    }
    expect(engineDetail(facts("filtering"))).toContain("Nothing is blocked yet");
  });

  it("names the blocker: AdGuard's service, the VPN adapter, the restarts, the setup error", () => {
    expect(engineDetail(facts("adguard"))).toMatch(/AdGuard's service runs/);
    expect(engineDetail(facts("vpn"))).toBe(
      "Paused while AdGuard VPN is connected. Sieve steps aside for a VPN that carries all traffic and resumes when it disconnects.",
    );
    expect(engineDetail(facts("crash_loop"))).toMatch(/restarted 3 times within an hour/);
    expect(engineDetail(facts("setup"))).toMatch(/SHA-256 does not match/);
  });

  it("states split tunnels and attribution from the engine's own facts", () => {
    expect(splitTunnelText(facts("filtering"))).toBe("Corp VPN sends some traffic around Sieve (a split-tunnel VPN). That traffic is not shown.");
    expect(splitTunnelText(facts("idle"))).toBeNull();
    expect(attribution(facts("filtering"))).toBeCloseTo(1188 / 1200);
    expect(attribution(facts("idle"))).toBeNull();
    expect(attribution(EMPTY_ENGINE)).toBeNull();
  });

  it("the app reads engine flows only while the engine routes", () => {
    expect(ALL.filter((n) => engineRoutes(facts(n)))).toEqual(["filtering"]);
    expect(engineRoutes({ ...facts("filtering"), error: "x" })).toBe(false);
  });

  it("a running service with no pipe answer is not running, and an error wins over old facts", () => {
    const running: EngineSlice = { probe: { v: 2, service: "running", adguard: "missing", pipe: null }, error: null };
    expect(enginePhase(running)).toBe("not_running");
    expect(enginePhase({ ...facts("idle"), error: "x" })).toBe("unreadable");
  });

  it("every phase has words and a detail sentence; the version only from a welcome", () => {
    expect(Object.keys(ENGINE_STATE_TEXT).sort()).toEqual([...ENGINE_PHASES].sort());
    for (const s of [EMPTY_ENGINE, { probe: null, error: "e" }, ...ALL.map(facts)]) {
      expect(engineDetail(s).length).toBeGreaterThan(10);
    }
    expect(engineVersion(facts("idle"))).toBe("0.1.0");
    expect(engineVersion(facts("refused"))).toBeNull();
    expect(engineVersion(EMPTY_ENGINE)).toBeNull();
  });
});
