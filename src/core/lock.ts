/**
 * The settings password, the pure part: its phases and its words. The check
 * itself lives in Rust (src-tauri/src/lock.rs), and the hash never reaches the
 * webview. It is a gate in the UI: it stops a person at the open app, not code
 * or anyone who can edit files in this Windows account. It covers settings only
 * and never the network (plan D8, D9).
 */

export const LOCK_PHASES = ["checking", "none", "locked", "unlocked", "unreadable"] as const;
export type LockPhase = (typeof LOCK_PHASES)[number];

/** Agrees with MIN_PASSWORD_CHARS in src-tauri/src/lock.rs (law 14). */
export const MIN_PASSWORD_CHARS = 8;

/** A write runs now only with no password, or after it was given. */
export const canWrite = (phase: LockPhase) => phase === "none" || phase === "unlocked";

/** Rows and the log stay shut in these; `checking` lasts a moment and shows no lock. */
export const isShut = (phase: LockPhase) => phase === "locked" || phase === "unreadable";

/** There is a password to lock or unlock with. */
export const hasPassword = (phase: LockPhase) => phase === "locked" || phase === "unlocked";

/** What is wrong with a new password, or null. */
export function passwordProblem(next: string, repeat: string): string | null {
  if ([...next].length < MIN_PASSWORD_CHARS) return `Use at least ${MIN_PASSWORD_CHARS} characters.`;
  if (next !== repeat) return "The two passwords are not the same.";
  return null;
}

export const LOCK_SCOPE_TEXT =
  "A password stops someone using this open app from changing settings or reading the log. It does not stop anyone who can edit files in your Windows account, and it never affects your network.";
export const LOCK_UNREADABLE_TEXT = "Sieve could not read its password file, so settings stay locked. Your network is not affected.";
export const LOCKED_ROW_TEXT = "Settings are locked.";
export const WRONG_PASSWORD_TEXT = "That is not the password.";

export const retryText = (secs: number) => `Too many tries. Try again in ${secs} s.`;

export const LOCK_PHASE_TEXT: Record<LockPhase, string> = {
  checking: "Checking",
  none: "No password is set.",
  locked: "Locked.",
  unlocked: "Unlocked.",
  unreadable: "The password file could not be read.",
};
