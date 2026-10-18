import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/engine-probe-v1.json";
import { parseEngineProbe, type EngineProbe } from "@/data/protocol";
import { EMPTY_ENGINE, ENGINE_PHASES, ENGINE_STATE_TEXT, engineDetail, enginePhase, engineVersion, type EngineSlice } from "./engine";

const facts = (name: keyof typeof fixture.examples): EngineSlice => ({ probe: parseEngineProbe(fixture.examples[name]), error: null });

describe("engine phase", () => {
  it("derives every phase from the fixture's facts", () => {
    expect(enginePhase(EMPTY_ENGINE)).toBe("checking");
    expect(enginePhase({ probe: null, error: "denied" })).toBe("unreadable");
    expect(enginePhase(facts("missing"))).toBe("not_installed");
    expect(enginePhase(facts("stopped"))).toBe("not_running");
    expect(enginePhase(facts("starting"))).toBe("not_running");
    expect(enginePhase(facts("unreachable"))).toBe("not_running");
    expect(enginePhase(facts("refused"))).toBe("refused");
    expect(enginePhase(facts("incompatible"))).toBe("incompatible");
    expect(enginePhase(facts("idle"))).toBe("idle");
  });

  it("says filtering only when the engine itself reports filtering", () => {
    const idle = facts("idle").probe as EngineProbe;
    const pipe = idle.pipe as Extract<NonNullable<EngineProbe["pipe"]>, { kind: "welcome" }>;
    const on: EngineSlice = { probe: { ...idle, pipe: { ...pipe, status: { ...pipe.status, filtering: true } } }, error: null };
    expect(enginePhase(on)).toBe("filtering");
    for (const name of Object.keys(fixture.examples) as (keyof typeof fixture.examples)[]) {
      const s = facts(name);
      expect(ENGINE_STATE_TEXT[enginePhase(s)]).not.toBe("Filtering");
      expect(engineDetail(s)).not.toMatch(/is filtering/);
    }
  });

  it("a running service with no pipe answer is not running, and an error wins over old facts", () => {
    const running: EngineSlice = { probe: { v: 1, service: "running", pipe: null }, error: null };
    expect(enginePhase(running)).toBe("not_running");
    expect(enginePhase({ ...facts("idle"), error: "x" })).toBe("unreadable");
  });

  it("every phase has words and a detail sentence; the version only from a welcome", () => {
    expect(Object.keys(ENGINE_STATE_TEXT).sort()).toEqual([...ENGINE_PHASES].sort());
    for (const s of [EMPTY_ENGINE, { probe: null, error: "e" }, ...Object.keys(fixture.examples).map((k) => facts(k as keyof typeof fixture.examples))]) {
      expect(engineDetail(s).length).toBeGreaterThan(10);
    }
    expect(engineVersion(facts("idle"))).toBe("0.1.0");
    expect(engineVersion(facts("refused"))).toBeNull();
    expect(engineVersion(EMPTY_ENGINE)).toBeNull();
  });
});
