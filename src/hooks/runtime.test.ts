import { describe, expect, it, vi } from "vitest";
import type { TrayAction, TrayState } from "@/core/tray";
import type { Desktop } from "@/data/desktop";
import { createMockDns } from "@/data/dns-mock";
import { createMockSource } from "@/data/mock-source";
import type { Clock } from "@/data/poller";
import { memoryBackend } from "@/data/settings-store";
import { bindDesktop, bindDns, bindSampling, createRuntime } from "./runtime";

const flush = () => new Promise<void>((r) => setTimeout(r, 0));
/** Timers never fire: only explicit poller calls change the status. */
const still: Clock = { now: () => 1_000_000, setTimeout: () => 0, clearTimeout: () => undefined };

function fakeDesktop(startEnabled = false) {
  const trays: TrayState[] = [];
  const autostartCalls: boolean[] = [];
  let enabled = startEnabled;
  let fire: (a: TrayAction) => void = () => {};
  let hold: () => boolean = () => false;
  let failNext = false;
  let quits = 0;
  const desktop: Desktop = {
    setTray: async (s) => void trays.push(s),
    onTrayAction: async (cb) => {
      fire = cb;
      return () => (fire = () => {});
    },
    autostart: {
      isEnabled: async () => enabled,
      set: async (on) => {
        if (failNext) {
          failNext = false;
          throw new Error("access denied");
        }
        autostartCalls.push(on);
        enabled = on;
      },
    },
    onCloseRequested: async (h) => {
      hold = h;
      return () => (hold = () => false);
    },
    quit: async () => void (quits += 1),
  };
  return {
    desktop,
    trays,
    autostartCalls,
    fire: (a: TrayAction) => fire(a),
    /** The window's close button: true when the window stays open. */
    close: () => hold(),
    quits: () => quits,
    failOnce: () => (failNext = true),
    enabled: () => enabled,
  };
}

function setup(d: ReturnType<typeof fakeDesktop>, stored?: unknown) {
  const rt = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend(stored), clock: still, desktop: d.desktop });
  const undo = bindDesktop(rt, () => "14:05");
  return { rt, undo };
}

describe("desktop binding: tray", () => {
  it("the tray follows the phase and its Pause and Resume drive the same poller actions as the pill", async () => {
    const d = fakeDesktop();
    const { rt, undo } = setup(d);
    await flush();
    expect(d.trays.at(-1)).toMatchObject({ tooltip: "Sieve: off", canPause: false });

    rt.poller.start();
    d.fire({ kind: "pause", minutes: 5 });
    expect(rt.store.getState().status.pausedUntil).toBe(1_000_000 + 5 * 60_000);
    expect(d.trays.at(-1)).toEqual({ tooltip: "Sieve: paused until 14:05", canPause: false, canResume: true, dim: true });

    d.fire({ kind: "resume" });
    expect(rt.store.getState().status.pausedUntil).toBeNull();
    expect(d.trays.at(-1)?.canPause).toBe(true);

    // The same state is not sent twice.
    const n = d.trays.length;
    rt.store.setStatus({});
    expect(d.trays.length).toBe(n);

    undo();
    rt.poller.pauseFor(5);
    expect(d.trays.length).toBe(n);
  });
});

describe("desktop binding: quit and close while Windows points at Sieve", () => {
  async function bound(dnsScenario: "off" | "running") {
    const d = fakeDesktop();
    const rt = createRuntime({
      source: createMockSource({ seed: 1 }),
      settings: memoryBackend(),
      clock: still,
      desktop: d.desktop,
      dns: createMockDns({ seed: 1, scenario: dnsScenario }),
    });
    const undo = bindDesktop(rt, () => "14:05");
    const undoDns = bindDns(rt);
    await rt.settings.ready;
    await vi.waitFor(() => expect(rt.store.getState().dns.system).not.toBeNull());
    await flush();
    return { d, rt, undo: () => (undo(), undoDns()) };
  }

  it("not pointed: tray Quit quits and the close button closes", async () => {
    const { d, rt, undo } = await bound("off");
    expect(d.close()).toBe(false);
    d.fire({ kind: "quit" });
    expect(d.quits()).toBe(1);
    expect(rt.store.getState().dns.quitAsked).toBe(false);
    undo();
  });

  it("pointed: close and tray Quit ask first; Cancel stays, Keep quits, Restore restores then quits", async () => {
    const { d, rt, undo } = await bound("running");
    expect(rt.store.getState().dns.system?.pointed).toBe(true);
    // The close button is held and the question is asked.
    expect(d.close()).toBe(true);
    expect(rt.store.getState().dns.quitAsked).toBe(true);
    rt.dnsController.cancelQuit();
    expect(rt.store.getState().dns.quitAsked).toBe(false);
    expect(d.quits()).toBe(0);

    d.fire({ kind: "quit" });
    expect(rt.store.getState().dns.quitAsked).toBe(true);
    await rt.dnsController.quit("restore");
    expect(rt.store.getState().dns.system?.pointed).toBe(false);
    expect(rt.store.getState().dns.system?.backup).toBe(false);
    expect(d.quits()).toBe(1);
    undo();
  });

  it("pointed: Keep filtering quits without touching Windows DNS", async () => {
    const { d, rt, undo } = await bound("running");
    d.fire({ kind: "quit" });
    await rt.dnsController.quit("keep");
    expect(d.quits()).toBe(1);
    expect(rt.store.getState().dns.system?.pointed).toBe(true);
    undo();
  });
});

describe("desktop binding: launch at startup", () => {
  it("the setting is the truth: reconciled on load, applied on change, never touched while equal", async () => {
    const d = fakeDesktop(true);
    const { rt } = setup(d);
    await rt.settings.ready;
    await flush();
    // Default off, OS on: reconciled off.
    expect(d.autostartCalls).toEqual([false]);
    await rt.settings.set("startup.launchAtLogin", true);
    await flush();
    expect(d.autostartCalls).toEqual([false, true]);
    await rt.settings.set("appearance.theme", "light");
    await flush();
    expect(d.autostartCalls).toEqual([false, true]);
  });

  it("a failure is said in a toast and retried on the next change", async () => {
    const d = fakeDesktop(false);
    const { rt } = setup(d);
    await rt.settings.ready;
    await flush();
    expect(d.autostartCalls).toEqual([]);
    d.failOnce();
    await rt.settings.set("startup.launchAtLogin", true);
    await flush();
    expect(rt.notices.list().at(-1)?.text).toMatch(/Could not change launch at startup: access denied/);
    await rt.settings.set("startup.launchAtLogin", false);
    await rt.settings.set("startup.launchAtLogin", true);
    await flush();
    expect(d.enabled()).toBe(true);
  });

  it("does nothing without a desktop (browser, tests)", () => {
    const rt = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend() });
    expect(rt.desktop).toBeNull();
    expect(() => bindDesktop(rt)()).not.toThrow();
  });
});

describe("sampling binding: the poller follows sampling.enabled and sampling.intervalMs", () => {
  function sampling(stored?: unknown) {
    const rt = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend(stored), clock: still });
    const undo = bindSampling(rt);
    return { rt, undo, status: () => rt.store.getState().status };
  }

  it("nothing starts before the settings load; then the stored values are applied", async () => {
    const { rt, status } = sampling({ schema: 1, values: { "sampling.intervalMs": 5000 } });
    expect(status().running).toBe(false);
    await rt.settings.ready;
    await flush();
    expect(status().running).toBe(true);
    expect(rt.store.getState().intervalMs).toBe(5000);
  });

  it("stored off stays off; turning it on starts, turning it off stops", async () => {
    const { rt, status } = sampling({ schema: 1, values: { "sampling.enabled": false } });
    await rt.settings.ready;
    await flush();
    expect(status().running).toBe(false);
    await rt.settings.set("sampling.enabled", true);
    expect(status().running).toBe(true);
    await rt.settings.set("sampling.enabled", false);
    expect(status()).toMatchObject({ running: false, pausedUntil: null });
  });

  it("a new interval changes the cadence without restarting, and an unrelated change keeps a pause", async () => {
    const { rt, status } = sampling();
    await rt.settings.ready;
    await flush();
    rt.poller.pauseFor(5);
    await rt.settings.set("sampling.intervalMs", 2000);
    expect(rt.store.getState().intervalMs).toBe(2000);
    await rt.settings.set("appearance.theme", "light");
    expect(status().pausedUntil).toBe(1_000_000 + 5 * 60_000);
  });

  it("the undo stops the poller and later setting changes are ignored", async () => {
    const { rt, undo, status } = sampling();
    await rt.settings.ready;
    await flush();
    undo();
    expect(status().running).toBe(false);
    await rt.settings.set("sampling.intervalMs", 2000);
    await rt.settings.set("sampling.enabled", false);
    await rt.settings.set("sampling.enabled", true);
    expect(status().running).toBe(false);
    expect(rt.store.getState().intervalMs).toBe(1000);
  });
});
