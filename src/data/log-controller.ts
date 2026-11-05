/**
 * The log controller: the one owner of the store's `log` part and the only
 * caller of `logTail`. It reads the tail every LOG_POLL_MS, one read at a
 * time, only while the engine routes and the user has not paused, and writes
 * only when something changed, so an idle or absent engine costs no IPC and
 * no rerender. It reads the engine part of the store and writes nothing to it.
 * A failed read records why and keeps the rows. Time comes from the injected clock.
 */
import { engineRoutes } from "@/core/engine";
import { EMPTY_LOG, LOG_POLL_MS, appendRows, type LogSlice } from "@/core/log";
import type { SieveStore } from "@/core/store";
import type { EngineSource } from "./engine-source";
import type { Clock } from "./poller";

export interface LogController {
  /** Follow the engine and read while it routes. Returns the undo. */
  bind(): () => void;
  /** Stop reading; the rows stay. */
  pause(): void;
  /** Read again, from where the last read ended. */
  resume(): void;
  /** Empty the ring. The cursor stays, so nothing comes back. */
  clear(): void;
}

export interface LogControllerDeps {
  engine: Pick<EngineSource, "logTail">;
  store: SieveStore;
  clock: Clock;
}

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

export function createLogController({ engine, store, clock }: LogControllerDeps): LogController {
  let disposed = true;
  let timer: unknown = null;
  let reading = false;
  let follow: () => void = () => {};

  const get = () => store.getState().log;
  const set = (patch: Partial<LogSlice>) => store.setLog({ ...get(), ...patch });
  const wanted = () => !disposed && !get().paused && engineRoutes(store.getState().engine);

  const read = async () => {
    reading = true;
    try {
      const tail = await engine.logTail(get().cursor);
      if (disposed) return;
      const log = get();
      // Seqs only rise, so the cursor does too: a rewind would read the whole ring again as duplicates.
      const cursor = Math.max(log.cursor, tail.next);
      const changed = tail.rows.length > 0 || tail.skipped > 0 || tail.dropped > 0 || cursor !== log.cursor || log.error !== null;
      if (changed) {
        set({
          rows: tail.rows.length > 0 ? appendRows(log.rows, tail.rows) : log.rows,
          cursor,
          dropped: log.dropped + tail.dropped,
          skipped: log.skipped + tail.skipped,
          error: null,
        });
      }
    } catch (e) {
      if (!disposed) set({ error: message(e) });
    } finally {
      reading = false;
    }
    follow();
  };

  const stopTimer = () => {
    if (timer !== null) clock.clearTimeout(timer);
    timer = null;
  };

  return {
    bind() {
      disposed = false;
      follow = () => {
        if (!wanted()) {
          stopTimer();
          return;
        }
        if (timer !== null || reading) return;
        timer = clock.setTimeout(() => {
          timer = null;
          if (wanted()) void read();
        }, LOG_POLL_MS);
      };
      const unsubscribe = store.subscribe(follow);
      follow();
      return () => {
        disposed = true;
        unsubscribe();
        stopTimer();
        follow = () => {};
      };
    },
    pause() {
      if (!get().paused) set({ paused: true });
    },
    resume() {
      if (get().paused) set({ paused: false });
    },
    clear() {
      const { cursor, paused } = get();
      store.setLog({ ...EMPTY_LOG, cursor, paused });
    },
  };
}
