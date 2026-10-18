/**
 * The engine controller: the one owner of the store's `engine` part and the
 * only caller of the engine source. It asks at load and then every
 * ENGINE_POLL_MS (plan 1.6.5), one probe at a time; a probe that fails
 * clears the facts and records why, so nothing is ever shown from a stale
 * or assumed state. It never changes the engine: in slice 2 the app only
 * reads it. Time comes from the injected clock.
 */
import { ENGINE_POLL_MS } from "@/core/engine";
import type { SieveStore } from "@/core/store";
import type { EngineSource } from "./engine-source";
import type { Clock } from "./poller";

export interface EngineController {
  /** Probe now and on the cadence. Returns the undo. */
  bind(): () => void;
}

export interface EngineControllerDeps {
  engine: EngineSource;
  store: SieveStore;
  clock: Clock;
}

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

export function createEngineController({ engine, store, clock }: EngineControllerDeps): EngineController {
  return {
    bind() {
      let disposed = false;
      let timer: unknown = null;

      const probe = async () => {
        try {
          const facts = await engine.probe();
          if (!disposed) store.setEngine({ probe: facts, error: null });
        } catch (e) {
          if (!disposed) store.setEngine({ probe: null, error: message(e) });
        }
      };

      // The next probe is scheduled only after the previous one settled.
      const cycle = async () => {
        await probe();
        if (disposed) return;
        timer = clock.setTimeout(() => {
          timer = null;
          void cycle();
        }, ENGINE_POLL_MS);
      };

      void cycle();
      return () => {
        disposed = true;
        if (timer !== null) clock.clearTimeout(timer);
        timer = null;
      };
    },
  };
}
