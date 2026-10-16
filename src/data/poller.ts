/**
 * The poller: the only writer of the store and the only owner of sampling
 * cadence. Samples are chained with setTimeout (never setInterval), so a
 * slow sample delays the next one instead of piling up. A failed sample
 * records the error and keeps the previous snapshots; the next good sample
 * clears it.
 */
import type { SieveStore } from "@/core/store";
import type { SieveSource } from "./source";

export interface Clock {
  now(): number;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export const realClock: Clock = {
  now: () => Date.now(),
  setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimeout: (h) => globalThis.clearTimeout(h as ReturnType<typeof globalThis.setTimeout>),
};

export interface Poller {
  /** Start sampling now and then every interval. No-op when already running. */
  start(): void;
  /** Stop sampling and forget any pause. */
  stop(): void;
  /** Stop sampling until now + minutes, then resume by itself. */
  pauseFor(minutes: number): void;
  /** End a pause early. */
  resume(): void;
  setIntervalMs(ms: number): void;
  /** Stop and drop timers; the poller is unusable afterwards. */
  dispose(): void;
}

export function createPoller(opts: { source: SieveSource; store: SieveStore; clock?: Clock }): Poller {
  const { source, store } = opts;
  const clock = opts.clock ?? realClock;
  let timer: unknown = null;
  // Bumped on every stop/pause/resume so a sample in flight from an older
  // generation cannot write after the user stopped sampling.
  let generation = 0;
  let disposed = false;

  store.setSource(source.kind);

  const clear = () => {
    if (timer !== null) clock.clearTimeout(timer);
    timer = null;
  };

  const schedule = (ms: number, fn: () => void) => {
    clear();
    timer = clock.setTimeout(() => {
      timer = null;
      fn();
    }, ms);
  };

  const tick = async (gen: number) => {
    try {
      const snap = await source.sample();
      if (gen !== generation) return;
      store.push(snap);
    } catch (e) {
      if (gen !== generation) return;
      store.setStatus({ error: e instanceof Error ? e.message : String(e) });
    }
    if (gen !== generation) return;
    schedule(store.getState().intervalMs, () => void tick(gen));
  };

  const run = () => {
    clear();
    generation += 1;
    void tick(generation);
  };

  return {
    start() {
      const s = store.getState().status;
      if (disposed || (s.running && s.pausedUntil === null)) return;
      store.setStatus({ running: true, pausedUntil: null });
      run();
    },
    stop() {
      clear();
      generation += 1;
      store.setStatus({ running: false, pausedUntil: null });
    },
    pauseFor(minutes) {
      if (disposed) return;
      clear();
      generation += 1;
      const until = clock.now() + minutes * 60_000;
      store.setStatus({ running: true, pausedUntil: until });
      schedule(until - clock.now(), () => {
        store.setStatus({ pausedUntil: null });
        run();
      });
    },
    resume() {
      if (disposed || store.getState().status.pausedUntil === null) return;
      store.setStatus({ running: true, pausedUntil: null });
      run();
    },
    setIntervalMs(ms) {
      store.setInterval(ms);
    },
    dispose() {
      disposed = true;
      clear();
      generation += 1;
    },
  };
}
