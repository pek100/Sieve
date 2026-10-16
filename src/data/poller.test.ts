import { describe, expect, it } from "vitest";
import { createStore, phase } from "@/core/store";
import fixture from "./fixtures/snapshot-v1.json";
import { createPoller, type Clock } from "./poller";
import type { SieveSource } from "./source";
import type { Snapshot } from "./protocol";

/** Manual clock: timers fire only when the test advances time. */
function fakeClock(start = 1_000_000) {
  let now = start;
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
      await flush();
    },
    flush,
  };
}

function scriptedSource(results: Array<Snapshot | Error>): SieveSource & { calls: number } {
  const src = {
    kind: "mock" as const,
    calls: 0,
    async sample() {
      const r = results[Math.min(src.calls, results.length - 1)];
      src.calls += 1;
      if (r instanceof Error) throw r;
      return r;
    },
    async history() {
      return [];
    },
  };
  return src;
}

const snap = (t: number): Snapshot => ({ ...(fixture as Snapshot), t });

describe("poller (seam law: single writer, cadence, pause, errors keep data)", () => {
  it("samples at once, then every interval, into the store", async () => {
    const fc = fakeClock();
    const store = createStore(1000);
    store.declareWindow(10_000);
    const src = scriptedSource([snap(1)]);
    const p = createPoller({ source: src, store, clock: fc.clock });
    p.start();
    await fc.flush();
    expect(src.calls).toBe(1);
    expect(store.getState().snapshots).toHaveLength(1);
    await fc.advance(3000);
    expect(src.calls).toBe(4);
    expect(phase(store.getState())).toBe("live");
  });

  it("a failed sample records the error and keeps previous snapshots; the next good one clears it", async () => {
    const fc = fakeClock();
    const store = createStore(1000);
    store.declareWindow(10_000);
    const p = createPoller({ source: scriptedSource([snap(1), new Error("boom"), snap(3)]), store, clock: fc.clock });
    p.start();
    await fc.flush();
    await fc.advance(1000);
    expect(store.getState().status.error).toBe("boom");
    expect(store.getState().snapshots).toHaveLength(1);
    expect(phase(store.getState())).toBe("error");
    await fc.advance(1000);
    expect(store.getState().status.error).toBeNull();
    expect(store.getState().snapshots).toHaveLength(2);
  });

  it("pauseFor stops sampling until the time, then resumes by itself", async () => {
    const fc = fakeClock();
    const store = createStore(1000);
    const src = scriptedSource([snap(1)]);
    const p = createPoller({ source: src, store, clock: fc.clock });
    p.start();
    await fc.flush();
    p.pauseFor(5);
    expect(store.getState().status.pausedUntil).toBe(1_000_000 + 5 * 60_000);
    expect(phase(store.getState())).toBe("paused");
    const before = src.calls;
    await fc.advance(4 * 60_000);
    expect(src.calls).toBe(before);
    await fc.advance(60_000);
    expect(store.getState().status.pausedUntil).toBeNull();
    expect(src.calls).toBe(before + 1);
  });

  it("resume ends a pause early; stop leaves no timers", async () => {
    const fc = fakeClock();
    const store = createStore(1000);
    const src = scriptedSource([snap(1)]);
    const p = createPoller({ source: src, store, clock: fc.clock });
    p.start();
    await fc.flush();
    p.pauseFor(15);
    p.resume();
    await fc.flush();
    expect(phase(store.getState())).toBe("live");
    p.stop();
    expect(fc.pending()).toBe(0);
    expect(phase(store.getState())).toBe("off");
  });

  it("a sample in flight when the user stops is dropped", async () => {
    const fc = fakeClock();
    const store = createStore(1000);
    let release: (s: Snapshot) => void = () => {};
    const slow: SieveSource = {
      kind: "mock",
      sample: () => new Promise<Snapshot>((r) => (release = r)),
      history: async () => [],
    };
    const p = createPoller({ source: slow, store, clock: fc.clock });
    p.start();
    p.stop();
    release(snap(9));
    await fc.flush();
    expect(store.getState().snapshots).toHaveLength(0);
    expect(fc.pending()).toBe(0);
  });
});
