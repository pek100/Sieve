import { describe, expect, it } from "vitest";
import { createPassedChecks } from "@/core/checks";
import { ENGINE_POLL_MS, ENGINE_SWITCH, engineLockReason, enginePhase } from "@/core/engine";
import { createNoticeBus } from "@/core/notices";
import type { SettingKey } from "@/core/settings/registry";
import { createStore } from "@/core/store";
import { CRASH_LOOP_BANNER, createEngineController } from "./engine-controller";
import { createMockEngine, MOCK_ADGUARD_ERROR, MOCK_ENGINE_ERROR, type EngineScenario } from "./engine-mock";
import type { EngineSource } from "./engine-source";
import type { Clock } from "./poller";
import type { EnginePolicy, EngineProbe } from "./protocol";
import { createSettingsStore, memoryBackend, type SettingsBackend } from "./settings-store";

const SWITCH = ENGINE_SWITCH as SettingKey;

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
  const flush = async () => {
    for (let i = 0; i < 5; i++) await new Promise<void>((r) => setTimeout(r, 0));
  };
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

/** The mock engine, with its scenario changeable between probes and every call recorded. */
function fakeEngine(start: EngineScenario) {
  let mock = createMockEngine(start);
  const policies: EnginePolicy[] = [];
  let probes = 0;
  const source: EngineSource = {
    kind: "mock",
    probe: () => {
      probes++;
      return mock.probe();
    },
    setPolicy: (p) => {
      policies.push(p);
      return mock.setPolicy(p);
    },
    stopAdguard: () => mock.stopAdguard(),
    startAdguard: () => mock.startAdguard(),
  };
  return { source, set: (s: EngineScenario) => void (mock = createMockEngine(s)), probes: () => probes, policies };
}

function setup(start: EngineScenario, backend: SettingsBackend = memoryBackend()) {
  const fc = fakeClock();
  const store = createStore();
  const fake = fakeEngine(start);
  const settings = createSettingsStore(backend);
  const checks = createPassedChecks();
  const notices = createNoticeBus();
  const controller = createEngineController({ engine: fake.source, store, clock: fc.clock, settings, checks, notices });
  const undo = controller.bind();
  const phase = () => enginePhase(store.getState().engine);
  return { fc, store, fake, settings, checks, notices, controller, undo, phase };
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
    expect(s.fake.probes()).toBe(5);
    s.undo();
  });

  it("a failed read clears the facts and says why; the next good read restores them", async () => {
    const s = setup("idle");
    await s.fc.flush();
    s.fake.set("error");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.store.getState().engine.probe).toBeNull();
    expect(s.store.getState().engine.error).toBe(MOCK_ENGINE_ERROR);
    expect(s.phase()).toBe("unreadable");
    s.fake.set("idle");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.phase()).toBe("idle");
    expect(s.store.getState().engine.error).toBeNull();
    s.undo();
  });

  it("the switch defaults off: an idle engine is never told to route", async () => {
    const s = setup("idle");
    await s.fc.flush();
    await s.fc.advance(ENGINE_POLL_MS * 3);
    expect(s.fake.policies).toEqual([]);
    expect(s.phase()).toBe("idle");
    s.undo();
  });

  it("turning the switch on sends it once with the next revision, and the engine routes", async () => {
    const s = setup("idle");
    await s.fc.flush();
    await s.settings.set(SWITCH, true);
    await s.fc.flush();
    expect(s.fake.policies).toEqual([{ revision: 1, engine: true }]);
    expect(s.phase()).toBe("routing");
    expect(s.checks.has(ENGINE_SWITCH)).toBe(true);
    await s.fc.advance(ENGINE_POLL_MS * 2);
    expect(s.fake.policies).toHaveLength(1);
    await s.settings.set(SWITCH, false);
    await s.fc.flush();
    expect(s.fake.policies[1]).toEqual({ revision: 3, engine: false });
    expect(s.phase()).toBe("idle");
    expect(s.checks.has(ENGINE_SWITCH)).toBe(false);
    s.undo();
  });

  it("an engine that routes while the user's switch is off is told to stop, but only after the settings loaded", async () => {
    let release: (doc: unknown) => void = () => {};
    const slow: SettingsBackend = { kind: "memory", load: () => new Promise((r) => (release = r)), save: async () => {} };
    const s = setup("filtering", slow);
    await s.fc.flush();
    expect(s.fake.policies).toEqual([]);
    release({ schema: 4, values: {} });
    await s.fc.flush();
    expect(s.fake.policies).toEqual([{ revision: 3, engine: false }]);
    s.undo();
  });

  it("a stored on reaches an idle engine after load", async () => {
    const s = setup("idle", memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true } }));
    await s.fc.flush();
    expect(s.fake.policies).toEqual([{ revision: 1, engine: true }]);
    s.undo();
  });

  it("refused (this copy is not the installed one): a flip sends nothing, and nothing claims routing", async () => {
    const s = setup("refused");
    await s.fc.flush();
    expect(s.phase()).toBe("refused");
    expect(engineLockReason(s.store.getState().engine)).not.toBeNull();
    // The Settings row is locked; even a write that got past it (another window, an old file) is not sent.
    await s.settings.set(SWITCH, true);
    await s.fc.flush();
    await s.fc.advance(ENGINE_POLL_MS * 3);
    expect(s.fake.policies).toEqual([]);
    expect(s.checks.has(ENGINE_SWITCH)).toBe(false);
    expect(s.store.getState().engine.actionError ?? null).toBeNull();
    s.undo();
  });

  it("law: no policy is sent in any phase that cannot take one, a stored on included; it waits untouched until the engine can", async () => {
    for (const scenario of ["missing", "stopped", "starting", "unreachable", "refused", "incompatible", "error"] as const) {
      const s = setup(scenario, memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true } }));
      await s.fc.flush();
      await s.fc.advance(ENGINE_POLL_MS * 2);
      expect(s.fake.policies, scenario).toEqual([]);
      expect(s.settings.get(SWITCH), scenario).toBe(true);
      s.undo();
    }
    const s = setup("refused", memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true } }));
    await s.fc.flush();
    expect(s.fake.policies).toEqual([]);
    // The installed copy's turn: the engine answers, and the stored value goes once.
    s.fake.set("idle");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.fake.policies).toEqual([{ revision: 1, engine: true }]);
    expect(s.phase()).toBe("routing");
    s.undo();
  });

  it("a retained Status cannot send a saved change after a failed read", async () => {
    const s = setup("idle");
    await s.fc.flush();
    s.store.setEngine({ ...s.store.getState().engine, error: "read failed" });
    await s.settings.set(SWITCH, true);
    await s.fc.flush();
    expect(s.phase()).toBe("unreadable");
    expect(s.fake.policies).toEqual([]);
    expect(s.settings.get(SWITCH)).toBe(true);
    s.undo();
  });

  it("a crash loop shows one Home banner, gone when the user turns routing off and on", async () => {
    const s = setup("crash_loop", memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true } }));
    const banners = () => s.notices.list().filter((n) => n.surface === "banner").map((n) => n.text);
    await s.fc.flush();
    expect(s.phase()).toBe("crash_loop");
    expect(banners()).toEqual([CRASH_LOOP_BANNER]);
    await s.fc.advance(ENGINE_POLL_MS);
    expect(banners()).toHaveLength(1);
    await s.settings.set(SWITCH, false);
    await s.fc.flush();
    await s.settings.set(SWITCH, true);
    await s.fc.flush();
    expect(s.phase()).toBe("routing");
    expect(banners()).toEqual([]);
    s.undo();
  });

  it("pausing AdGuard runs only on request, then probes: the waiting engine routes with the service left stopping", async () => {
    const s = setup("adguard", memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true } }));
    await s.fc.flush();
    expect(s.phase()).toBe("adguard");
    const probes = s.fake.probes();
    await s.controller.stopAdguard();
    expect(s.fake.probes()).toBe(probes + 1);
    expect(s.phase()).toBe("routing");
    expect(s.store.getState().engine.probe?.adguard).toBe("stopping");
    expect(s.store.getState().engine.adguard).toBeNull();
    await s.controller.startAdguard();
    expect(s.store.getState().engine.actionError).toMatch(/AdGuard/);
    expect(s.phase()).toBe("routing");
    s.undo();
  });

  it("starting AdGuard's stopped service makes the routing engine wait", async () => {
    const s = setup("filtering", memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true } }));
    await s.fc.flush();
    expect(s.phase()).toBe("routing");
    await s.controller.startAdguard();
    expect(s.phase()).toBe("adguard");
    s.undo();
  });

  it("a refused AdGuard action is said, and the facts stay the engine's", async () => {
    const s = setup("idle");
    await s.fc.flush();
    await s.controller.stopAdguard();
    expect(s.store.getState().engine.actionError).toBe(`AdGuard was not paused: ${MOCK_ADGUARD_ERROR}`);
    expect(s.phase()).toBe("idle");
    s.undo();
  });

  it("never overlaps probes: the next is scheduled after the previous settled", async () => {
    const fc = fakeClock();
    const store = createStore();
    let resolve: ((p: EngineProbe) => void) | null = null;
    let calls = 0;
    const mock = createMockEngine("idle");
    const slow: EngineSource = {
      ...mock,
      probe: () => {
        calls++;
        return new Promise((r) => (resolve = r));
      },
    };
    const deps = { settings: createSettingsStore(memoryBackend()), checks: createPassedChecks(), notices: createNoticeBus() };
    const undo = createEngineController({ engine: slow, store, clock: fc.clock, ...deps }).bind();
    await fc.advance(ENGINE_POLL_MS * 5);
    expect(calls).toBe(1);
    expect(fc.pending()).toBe(0);
    resolve!(await mock.probe());
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
    const before = s.fake.probes();
    await s.fc.advance(ENGINE_POLL_MS * 3);
    expect(s.fake.probes()).toBe(before);

    const fc = fakeClock();
    const store = createStore();
    let resolve: ((p: EngineProbe) => void) | null = null;
    const mock = createMockEngine("idle");
    const deps = { settings: createSettingsStore(memoryBackend()), checks: createPassedChecks(), notices: createNoticeBus() };
    const undo = createEngineController({ engine: { ...mock, probe: () => new Promise((r) => (resolve = r)) }, store, clock: fc.clock, ...deps }).bind();
    undo();
    resolve!(await mock.probe());
    await fc.flush();
    expect(store.getState().engine.probe).toBeNull();
    expect(fc.pending()).toBe(0);
  });
});
