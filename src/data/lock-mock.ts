/**
 * Mock settings password, for the browser, tests and e2e: memory only, never
 * persisted, gone on reload. Query string `?lock=none|set` (default `none`,
 * `set` starts with MOCK_PASSWORD; `unreadable` for that state).
 */
import { MIN_PASSWORD_CHARS } from "@/core/lock";
import type { LockSource } from "./lock-source";

export const LOCK_SCENARIOS = ["none", "set", "unreadable"] as const;
export type LockScenario = (typeof LOCK_SCENARIOS)[number];

/** Not a secret: the mock's own test value. */
export const MOCK_PASSWORD = "mock-password";
export const MOCK_TRIES = 5;
export const MOCK_RETRY_SECS = 30;

export function createMockLock(start: LockScenario = "none"): LockSource {
  let password: string | null = start === "set" ? MOCK_PASSWORD : null;
  let wrong = 0;
  const unreadable = () => {
    if (start === "unreadable") throw new Error("The password file could not be read, so it was left as it is.");
  };
  const check = (given: string | null) => {
    if (given !== password) throw new Error("That is not the current password.");
  };
  return {
    kind: "mock",
    status: async () => ({ state: start === "unreadable" ? "unreadable" : password === null ? "none" : "set", retry_after_secs: 0 }),
    verify: async (given) => {
      unreadable();
      if (given === password) {
        wrong = 0;
        return { ok: true, retry_after_secs: 0 };
      }
      wrong += 1;
      if (wrong < MOCK_TRIES) return { ok: false, retry_after_secs: 0 };
      wrong = 0;
      return { ok: false, retry_after_secs: MOCK_RETRY_SECS };
    },
    set: async (current, next) => {
      unreadable();
      if ([...next].length < MIN_PASSWORD_CHARS) throw new Error(`Use at least ${MIN_PASSWORD_CHARS} characters.`);
      if (password !== null) check(current);
      password = next;
    },
    clear: async (current) => {
      unreadable();
      check(current);
      password = null;
    },
  };
}
