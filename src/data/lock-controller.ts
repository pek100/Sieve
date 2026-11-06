/**
 * The lock controller: the one owner of the settings password's state and the
 * one write gate (plan D10). `guard(fn)` runs `fn` when writes are allowed.
 * Otherwise it parks `fn`, asks for the password, and runs it on success or drops
 * it on cancel. It keeps its own observable, like passedChecks, so the store
 * stays out of it. Time comes from the injected clock.
 *
 * Internal safety writes (the DNS controller turning a failed switch off) do not
 * come through here: they only ever turn things off.
 */
import { WRONG_PASSWORD_TEXT, LOCK_UNREADABLE_TEXT, canWrite, retryText, type LockPhase } from "@/core/lock";
import type { NoticeBus } from "@/core/notices";
import type { LockSource } from "./lock-source";
import type { Clock } from "./poller";
import type { SettingsStore } from "./settings-store";

export interface LockState {
  phase: LockPhase;
  /** The unlock prompt is up. */
  asking: boolean;
  /** Why the last answer was refused, for the prompt. */
  error: string | null;
  /** An answer is being checked. */
  busy: boolean;
}

export interface LockController {
  state(): LockState;
  subscribe(listener: () => void): () => void;
  /** Read the status and watch for idleness. Returns the undo. */
  bind(): () => void;
  guard<T>(fn: () => T | Promise<T>): Promise<T | undefined>;
  /** Open the unlock prompt, with nothing parked. */
  ask(): void;
  unlock(password: string): Promise<void>;
  /** Close the prompt; what was parked is dropped. */
  cancel(): void;
  lockNow(): void;
  /** A click or key press: pushes the idle relock back. */
  activity(): void;
  /** Set or change. Rejects with a sentence for the person. */
  setPassword(current: string | null, next: string): Promise<void>;
  /** Remove. Rejects with a sentence for the person. */
  clearPassword(current: string): Promise<void>;
}

export interface LockControllerDeps {
  source: LockSource;
  clock: Clock;
  settings: SettingsStore;
  notices: NoticeBus;
}

const IDLE_KEY = "password.idleMinutes";
const MINUTE_MS = 60_000;
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

export function createLockController({ source, clock, settings, notices }: LockControllerDeps): LockController {
  let state: LockState = { phase: "checking", asking: false, error: null, busy: false };
  const listeners = new Set<() => void>();
  let parked: { run: () => void; drop: () => void }[] = [];
  let lastActive = clock.now();
  let timer: unknown = null;

  const set = (patch: Partial<LockState>) => {
    state = { ...state, ...patch };
    listeners.forEach((l) => l());
  };
  const take = () => {
    const all = parked;
    parked = [];
    return all;
  };
  const flush = () => take().forEach((p) => p.run());
  const drop = () => take().forEach((p) => p.drop());

  const stopIdle = () => {
    if (timer !== null) clock.clearTimeout(timer);
    timer = null;
  };
  const idleWait = () => settings.get(IDLE_KEY) * MINUTE_MS - (clock.now() - lastActive);
  const watchIdle = () => {
    stopIdle();
    if (state.phase !== "unlocked") return;
    const wait = idleWait();
    if (wait <= 0) return lock();
    timer = clock.setTimeout(() => {
      timer = null;
      watchIdle();
    }, wait);
  };
  const lock = () => {
    stopIdle();
    set({ phase: "locked", error: null });
  };

  const opened = () => {
    lastActive = clock.now();
    set({ phase: "unlocked", asking: false, error: null, busy: false });
    watchIdle();
    flush();
  };

  const refuseUnreadable = () => notices.push({ kind: "error", text: LOCK_UNREADABLE_TEXT });

  return {
    state: () => state,
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    bind() {
      let cancelled = false;
      const unSettings = settings.subscribe(watchIdle);
      void source.status().then(
        (s) => {
          if (cancelled || state.phase !== "checking") return;
          if (s.state === "none") {
            set({ phase: "none" });
            flush();
          } else if (s.state === "set") {
            set({ phase: "locked", asking: parked.length > 0 });
          } else {
            set({ phase: "unreadable" });
            if (parked.length > 0) refuseUnreadable();
            drop();
          }
        },
        () => {
          // Not knowing is not "no password": settings stay locked.
          if (cancelled || state.phase !== "checking") return;
          set({ phase: "unreadable" });
          drop();
        },
      );
      return () => {
        cancelled = true;
        unSettings();
        stopIdle();
      };
    },
    guard(fn) {
      if (canWrite(state.phase)) return Promise.resolve(fn());
      if (state.phase === "unreadable") {
        refuseUnreadable();
        return Promise.resolve(undefined);
      }
      return new Promise((resolve, reject) => {
        parked.push({
          run: () => {
            try {
              resolve(fn());
            } catch (e) {
              reject(e);
            }
          },
          drop: () => resolve(undefined),
        });
        if (state.phase === "locked" && !state.asking) set({ asking: true, error: null });
      });
    },
    ask() {
      if (state.phase === "locked") set({ asking: true, error: null });
    },
    async unlock(password) {
      if (state.phase !== "locked" || state.busy) return;
      set({ busy: true, error: null });
      try {
        const verdict = await source.verify(password);
        if (verdict.ok) return opened();
        set({ busy: false, error: verdict.retry_after_secs > 0 ? retryText(verdict.retry_after_secs) : WRONG_PASSWORD_TEXT });
      } catch (e) {
        set({ busy: false, error: message(e) });
      }
    },
    cancel() {
      drop();
      set({ asking: false, error: null });
    },
    lockNow() {
      if (state.phase === "unlocked") lock();
    },
    activity() {
      lastActive = clock.now();
    },
    async setPassword(current, next) {
      await source.set(current, next);
      opened();
    },
    async clearPassword(current) {
      await source.clear(current);
      stopIdle();
      set({ phase: "none", asking: false, error: null });
      flush();
    },
  };
}
