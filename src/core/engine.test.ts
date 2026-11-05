import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/engine-probe-v2.json";
import { parseEngineProbe } from "@/data/protocol";
import {
  CHECK_AGAIN,
  EMPTY_ENGINE,
  ENGINE_LOCK_TEXT,
  ENGINE_PHASES,
  ENGINE_STATE_TEXT,
  ENGINE_UNREACHED,
  INSTALL_UPDATE,
  NO_UPDATE_NEWS,
  attribution,
  engineDetail,
  engineInForce,
  engineLockReason,
  enginePhase,
  engineRoutes,
  engineStatus,
  engineTakesPolicy,
  engineUpdate,
  engineVersion,
  splitTunnelText,
  updateBanner,
  updateNotice,
  type EngineSlice,
  type EngineUnreached,
} from "./engine";

type Example = keyof typeof fixture.examples;
const facts = (name: Example): EngineSlice => ({ probe: parseEngineProbe(fixture.examples[name]), error: null });
const ALL = Object.keys(fixture.examples) as Example[];

describe("engine updates", () => {
  const quiet = ["not_configured", "idle", "checking"] as const;

  it("shows nothing for the quiet states, and the engine that did not answer says nothing", () => {
    for (const kind of quiet) expect(updateNotice({ kind })).toBeNull();
    expect(engineUpdate(EMPTY_ENGINE)).toEqual(NO_UPDATE_NEWS);
    expect(engineUpdate(facts("missing"))).toEqual(NO_UPDATE_NEWS);
    expect(updateNotice(engineUpdate(facts("idle")))).toBeNull();
  });

  it("only an offered release installs; every other button only checks; applying has none", () => {
    const available = updateNotice(engineUpdate(facts("update_available")));
    expect(available?.action).toBe(INSTALL_UPDATE);
    // An engine release never closes the app and the status does not carry the kind.
    expect(available?.text).toContain("may close");
    expect(available?.text).not.toContain("closes Sieve");
    expect(updateNotice(engineUpdate(facts("update_applying")))?.action).toBeNull();
    for (const name of ["update_current", "update_stale", "update_failed", "update_refused", "update_rolled_back"] as const) {
      expect(updateNotice(engineUpdate(facts(name)))?.action, name).toBe(CHECK_AGAIN);
    }
  });

  it("says the reason, and never claims filtering or blocking", () => {
    expect(updateNotice(engineUpdate(facts("update_refused")))?.text).toContain("the signature does not verify");
    expect(updateNotice(engineUpdate(facts("update_failed")))?.text).toContain("could not reach the update host");
    expect(updateNotice(engineUpdate(facts("update_rolled_back")))?.text).toContain("0.2.0");
    for (const name of ALL) {
      const notice = updateNotice(engineUpdate(facts(name)));
      expect(notice?.text ?? "").not.toMatch(/is filtering|blocked/i);
    }
  });

  it("a banner only for an offered release and a rolled back one", () => {
    const banners = ALL.filter((n) => updateBanner(engineUpdate(facts(n))) !== null);
    expect(banners).toEqual(["update_available", "update_rolled_back"]);
  });
});

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
      update_current: "idle",
      update_available: "idle",
      update_applying: "idle",
      update_stale: "idle",
      update_failed: "idle",
      update_refused: "idle",
      update_rolled_back: "idle",
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
    const running: EngineSlice = { probe: { v: 3, service: "running", adguard: "missing", pipe: null }, error: null };
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

describe("engine lock (the switch the engine carries out)", () => {
  // The fixture has no example of a switched-on engine still bringing its routes up: the idle one, told to route.
  const starting = (): EngineSlice => {
    const idle = facts("idle");
    const pipe = idle.probe!.pipe!;
    if (pipe.kind !== "welcome") throw new Error("idle is a welcome");
    const status = { ...pipe.status, policy: { ...pipe.status.policy, engine: true } };
    return { ...idle, probe: { ...idle.probe!, pipe: { ...pipe, status } } };
  };
  const slices = (): EngineSlice[] => [EMPTY_ENGINE, { probe: null, error: "denied" }, starting(), ...ALL.map(facts)];

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
