import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/engine-probe-v2.json";
import { parseEngineProbe } from "@/data/protocol";
import {
  ADGUARD_PAUSE_TEXT,
  EMPTY_ENGINE,
  ENGINE_LOCK_TEXT,
  ENGINE_PHASES,
  ENGINE_STATE_TEXT,
  ENGINE_UNREACHED,
  adguardOffer,
  attribution,
  engineDetail,
  engineInForce,
  engineLockReason,
  enginePhase,
  engineRoutes,
  engineStatus,
  engineTakesPolicy,
  engineVersion,
  splitTunnelText,
  type EngineSlice,
  type EngineUnreached,
} from "./engine";

type Example = keyof typeof fixture.examples;
const facts = (name: Example): EngineSlice => ({ probe: parseEngineProbe(fixture.examples[name]), error: null });
const ALL = Object.keys(fixture.examples) as Example[];
// The fixture has no example of a switched-on engine still bringing its routes up: the idle one, told to route.
const startingEngine = (): EngineSlice => {
  const idle = facts("idle");
  const pipe = idle.probe!.pipe!;
  if (pipe.kind !== "welcome") throw new Error("idle is a welcome");
  const status = { ...pipe.status, policy: { ...pipe.status.policy, engine: true } };
  return { ...idle, probe: { ...idle.probe!, pipe: { ...pipe, status } } };
};

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
      adguard_paused: "routing",
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
      // AdGuard's filtering is a fact the refusal states; Sieve's own never is claimed.
      expect(engineDetail(s).replace("AdGuard is filtering", "")).not.toMatch(/is filtering|blocks |are blocked|blocked for/i);
    }
    expect(engineDetail(facts("filtering"))).toContain("Nothing is blocked yet");
  });

  it("names the blocker: AdGuard filtering, the VPN adapter, the restarts, the setup error", () => {
    expect(engineDetail(facts("adguard"))).toBe(
      "AdGuard is filtering this computer, and two filters would capture each other's connections. Sieve routes nothing while AdGuard filters; your network works as usual.",
    );
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
    expect(ALL.filter((n) => engineRoutes(facts(n)))).toEqual(["filtering", "adguard_paused"]);
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

describe("the AdGuard offer", () => {
  type Service = NonNullable<EngineSlice["probe"]>["adguard"];
  /** An example's engine facts, with AdGuard's service in another state. */
  const withService = (name: Example, adguard: Service): EngineSlice => {
    const s = facts(name);
    return { ...s, probe: { ...s.probe!, adguard } };
  };
  const SERVICES: readonly Service[] = ["missing", "stopped", "starting", "stopping", "running", "other"];

  it("follows the table: service state beside the engine's verdict", () => {
    const table: [Example, Service, ReturnType<typeof adguardOffer>][] = [
      ["adguard", "running", "pause"],
      ["filtering", "running", null], // protection off in AdGuard's own window: nothing to pause
      ["idle", "running", null],
      ["filtering", "stopped", "start"],
      ["adguard", "stopped", "start"],
      ["idle", "stopped", "start"],
      ["adguard_paused", "stopping", "paused"],
      ["vpn", "stopping", "paused"], // AdGuard wins over a VPN, so a VPN blocker means it is not intercepting
      ["idle", "stopping", null], // the switch is off: the engine gave no verdict
      ["adguard", "stopping", null], // still intercepting: the detail line says Sieve re-checks
      ["crash_loop", "stopping", null], // no check ran
      ["setup", "stopping", null], // the check may be what failed
      ["refused", "stopping", null],
    ];
    for (const [name, service, want] of table) expect(adguardOffer(withService(name, service)), `${name} ${service}`).toBe(want);
    // The switch just went on: the engine answers before its first check, so there is no verdict yet.
    const starting = startingEngine();
    expect(enginePhase(starting)).toBe("starting");
    expect(adguardOffer({ ...starting, probe: { ...starting.probe!, adguard: "stopping" } }), "starting stopping").toBeNull();
    for (const service of ["missing", "starting", "other"] as const) {
      for (const name of ALL) expect(adguardOffer(withService(name, service)), `${name} ${service}`).toBeNull();
    }
  });

  it("a switch going off takes the paused claim with it, even while routes are still up", () => {
    const s = facts("adguard_paused");
    const pipe = s.probe!.pipe!;
    if (pipe.kind !== "welcome") throw new Error("adguard_paused is a welcome");
    const off = { ...pipe, status: { ...pipe.status, policy: { ...pipe.status.policy, engine: false } } };
    expect(adguardOffer({ ...s, probe: { ...s.probe!, pipe: off } })).toBeNull();
  });

  it("says it re-checks only while a stopping service still intercepts", () => {
    expect(engineDetail(withService("adguard", "stopping"))).toBe(
      "AdGuard is filtering this computer, and two filters would capture each other's connections. Sieve routes nothing while AdGuard filters; your network works as usual. Sieve checks again every few seconds. If this stays, turn protection off in AdGuard's own window.",
    );
    expect(engineDetail(withService("adguard", "running"))).not.toMatch(/checks again/);
  });

  it("the pause text promises no resume it cannot do", () => {
    expect(ADGUARD_PAUSE_TEXT).not.toMatch(/start it again here/);
    expect(ADGUARD_PAUSE_TEXT).toMatch(/AdGuard's own window or restart the computer/);
  });

  it("degraded facts offer nothing and never throw", () => {
    const unreadable: EngineSlice = { probe: null, error: "denied" };
    expect(adguardOffer(EMPTY_ENGINE)).toBeNull();
    expect(adguardOffer(unreadable)).toBeNull();
    for (const service of SERVICES.filter((v) => v !== "stopped")) {
      expect(adguardOffer({ ...withService("adguard_paused", service), error: "read failed" }), service).toBeNull();
    }
    // Old or partial probes reach the render path only past the boundary; the guard holds anyway.
    const partial = { ...facts("adguard_paused"), probe: { v: 2, service: "running", pipe: null } } as unknown as EngineSlice;
    expect(adguardOffer(partial)).toBeNull();
    expect(() => engineDetail(partial)).not.toThrow();
    const noPipe: EngineSlice = { probe: { v: 2, service: "running", adguard: "stopping", pipe: null }, error: null };
    expect(adguardOffer(noPipe)).toBeNull();
    expect(adguardOffer(withService("adguard_paused", "other"))).toBeNull();
  });
});

describe("engine lock (the switch the engine carries out)", () => {
  const slices = (): EngineSlice[] => [EMPTY_ENGINE, { probe: null, error: "denied" }, startingEngine(), ...ALL.map(facts)];

  it("law: the engine takes a policy exactly when it answered with its Status; every other phase locks with one line", () => {
    const seen = new Set<string>();
    for (const s of slices()) {
      const phase = enginePhase(s);
      seen.add(phase);
      const answered = engineStatus(s) !== null;
      expect(engineTakesPolicy(s), phase).toBe(answered);
      expect((ENGINE_UNREACHED as readonly string[]).includes(phase), phase).toBe(!answered);
      const reason = engineLockReason(s);
      if (answered) expect(reason, phase).toBeNull();
      else expect(reason, phase).toBe(ENGINE_LOCK_TEXT[phase as EngineUnreached]);
      // The value in force is the engine's own, and unknown without a Status.
      expect(engineInForce(s), phase).toBe(answered ? engineStatus(s)!.policy.engine : null);
    }
    // Every phase is reached by these facts, so a new phase must be classified here.
    expect([...seen].sort()).toEqual([...ENGINE_PHASES].sort());
  });

  it("the refused copy says it is not the installed one and where to open Sieve", () => {
    expect(engineLockReason(facts("refused"))).toBe(
      "This copy of Sieve is not the installed one, so it cannot control the engine. Open Sieve from the Start menu.",
    );
  });

  it("a retained Status supplies the known value but cannot override a failed read or stopped service", () => {
    const e = facts("filtering");
    for (const s of [{ ...e, error: "read failed" }, { ...e, probe: { ...e.probe!, service: "stopped" as const } }]) {
      expect(engineTakesPolicy(s)).toBe(false);
      expect(engineLockReason(s)).toBeTruthy();
      expect(engineInForce(s)).toBe(true);
    }
  });
});
