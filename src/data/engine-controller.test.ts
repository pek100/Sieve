import { describe, expect, it } from "vitest";
import { ENGINE_POLL_MS, enginePhase } from "@/core/engine";
import { createStore } from "@/core/store";
import { createEngineController } from "./engine-controller";
import { createMockEngine, MOCK_ENGINE_ERROR, type EngineScenario } from "./engine-mock";
import type { EngineSource } from "./engine-source";
import type { Clock } from "./poller";
import type { EngineProbe } from "./protocol";

function fakeClock() {
  let now = 0;
  let seq = 0;
  const timers = new Map<number, { at: number; fn: () => void }>();
  const clock: Clock = {
    now: () => now,
    setTimeout: (fn, ms) => {
      const id = ++seq;
      timers.set(id, { at: now + ms, fn });
      return id;
    },
    clearTimeout: (h) => void timers.delete(h as number),
  };
  const flush = () => new Promise<void>((r) => setTimeout(r, 0));
  return {
    clock,
    flush,
    pending: () => timers.size,
    async advance(ms: number) {
      const target = now + ms;
      for (;;) {
        const due = [...timers.entries()].filter(([, t]) => t.at <= target).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        timers.delete(due[0]);
        now = due[1].at;
        due[1].fn();
        await flush();
      }
      now = target;
    },
  };
}

/** A fake source whose scenario the test changes between probes, counting calls. */
function fakeEngine(start: EngineScenario) {
  let scenario = start;
  let calls = 0;
  const source: EngineSource = {
    kind: "mock",
    probe: () => {
      calls++;
      return createMockEngine(scenario).probe();
    },
  };
  return { source, set: (s: EngineScenario) => void (scenario = s), calls: () => calls };
}

function setup(start: EngineScenario) {
  const fc = fakeClock();
  const store = createStore();
  const fake = fakeEngine(start);
  const undo = createEngineController({ engine: fake.source, store, clock: fc.clock }).bind();
  const phase = () => enginePhase(store.getState().engine);
  return { fc, store, fake, undo, phase };
}

describe("engine controller", () => {
  it("probes at bind and writes the facts to the store", async () => {
    const s = setup("idle");
    expect(s.phase()).toBe("checking");
    await s.fc.flush();
    expect(s.phase()).toBe("idle");
    expect(s.store.getState().engine.error).toBeNull();
    s.undo();
  });

  it("follows the engine on the poll cadence, from facts only", async () => {
    const s = setup("missing");
    await s.fc.flush();
    expect(s.phase()).toBe("not_installed");
    s.fake.set("stopped");
    await s.fc.advance(ENGINE_POLL_MS - 1);
    expect(s.phase()).toBe("not_installed");
    await s.fc.advance(1);
    expect(s.phase()).toBe("not_running");
    s.fake.set("idle");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.phase()).toBe("idle");
    s.fake.set("incompatible");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.phase()).toBe("incompatible");
    s.fake.set("unreachable");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.phase()).toBe("not_running");
    expect(s.fake.calls()).toBe(5);
    s.undo();
  });

  it("a failed read clears the facts and says why; the next good read restores them", async () => {
    const s = setup("idle");
    await s.fc.flush();
    s.fake.set("error");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.store.getState().engine).toEqual({ probe: null, error: MOCK_ENGINE_ERROR });
    expect(s.phase()).toBe("unreadable");
    s.fake.set("idle");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.phase()).toBe("idle");
    expect(s.store.getState().engine.error).toBeNull();
    s.undo();
  });

  it("never overlaps probes: the next is scheduled after the previous settled", async () => {
    const fc = fakeClock();
    const store = createStore();
    let resolve: ((p: EngineProbe) => void) | null = null;
    let calls = 0;
    const slow: EngineSource = {
      kind: "mock",
      probe: () => {
        calls++;
        return new Promise((r) => (resolve = r));
      },
    };
    const undo = createEngineController({ engine: slow, store, clock: fc.clock }).bind();
    await fc.advance(ENGINE_POLL_MS * 5);
    expect(calls).toBe(1);
    expect(fc.pending()).toBe(0);
    const answer = await createMockEngine("idle").probe();
    resolve!(answer);
    await fc.flush();
    expect(enginePhase(store.getState().engine)).toBe("idle");
    expect(fc.pending()).toBe(1);
    undo();
  });

  it("stops polling on undo, and a probe in flight then writes nothing", async () => {
    const s = setup("idle");
    await s.fc.flush();
    s.undo();
    expect(s.fc.pending()).toBe(0);
    const before = s.fake.calls();
    await s.fc.advance(ENGINE_POLL_MS * 3);
    expect(s.fake.calls()).toBe(before);

    const fc = fakeClock();
    const store = createStore();
    let resolve: ((p: EngineProbe) => void) | null = null;
    const undo = createEngineController({ engine: { kind: "mock", probe: () => new Promise((r) => (resolve = r)) }, store, clock: fc.clock }).bind();
    undo();
    resolve!(await createMockEngine("idle").probe());
    await fc.flush();
    expect(store.getState().engine).toEqual({ probe: null, error: null });
    expect(fc.pending()).toBe(0);
  });
});
