/**
 * The tray's state, derived from the sampling phase (plan row 74). Rust only
 * applies it (src-tauri/src/tray.rs, TrayState); the words live here, next
 * to the phase they describe.
 */
import type { Phase } from "./store";

export interface TrayState {
  tooltip: string;
  canPause: boolean;
  canResume: boolean;
  /** Faded icon: sampling is not live. */
  dim: boolean;
}

/**
 * What a tray menu item asks the window to do (Rust TrayAction, minus open,
 * which Rust does itself). Quit reaches the window only while Sieve's DNS
 * backup exists (Windows may point at Sieve), so the window can ask first;
 * otherwise Rust quits by itself.
 */
export type TrayAction = { kind: "pause"; minutes: number } | { kind: "resume" } | { kind: "quit" };

/**
 * @param fmt formats an epoch ms as a clock time (the caller owns the locale)
 */
export function trayState(p: Phase, pausedUntil: number | null, fmt: (ms: number) => string): TrayState {
  const words: Record<Phase, string> = {
    starting: "starting",
    live: "live",
    paused: pausedUntil === null ? "paused" : `paused until ${fmt(pausedUntil)}`,
    off: "off",
    error: "no data",
  };
  return {
    tooltip: `Sieve: ${words[p]}`,
    canPause: p === "live" || p === "starting" || p === "error",
    canResume: p === "paused",
    dim: p !== "live",
  };
}

/** Normalize an event payload from Rust; anything unexpected is ignored (null). */
export function parseTrayAction(x: unknown): TrayAction | null {
  if (typeof x !== "object" || x === null) return null;
  const r = x as { kind?: unknown; minutes?: unknown };
  if (r.kind === "resume") return { kind: "resume" };
  if (r.kind === "quit") return { kind: "quit" };
  if (r.kind === "pause" && typeof r.minutes === "number" && Number.isFinite(r.minutes) && r.minutes > 0) {
    return { kind: "pause", minutes: r.minutes };
  }
  return null;
}
