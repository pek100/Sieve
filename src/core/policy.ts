/**
 * What Sieve does per app (primitive B4): every app is sieved unless the
 * user turned it off, and nothing is sieved while the global Sieving switch
 * is off. Effective = global on AND app not off.
 *
 * Off means Sieve leaves the app out of its tracking (the chart, the counts
 * and the saved history) and, while the engine routes, relays its flows
 * untouched. The engine decides per flow and never blocks a DNS lookup, because
 * Windows sends every lookup through one service that cannot say which app asked.
 */
import type { SettingKey } from "./settings/registry";

export const APP_STATES = ["sieve", "off"] as const;
export type AppState = (typeof APP_STATES)[number];

/** What an app gets when the user never chose. */
export const DEFAULT_APP_STATE: AppState = "sieve";

/**
 * The global Sieving switch (top bar). Off pauses sampling, and the engine
 * relays every flow.
 */
export const GLOBAL_SWITCH = "sampling.enabled" satisfies SettingKey;

/** Stored per-app choices (settings `apps.levels`): only apps turned off are listed. */
export type AppStates = Readonly<Record<string, AppState>>;

export function appState(states: AppStates, appKey: string): AppState {
  return states[appKey] ?? DEFAULT_APP_STATE;
}

/** The user has not turned this app off. */
export function isAppOn(states: AppStates, appKey: string): boolean {
  return appState(states, appKey) !== "off";
}

/** Sieve tracks this app now: the global switch is on and the app is not off. */
export function effectiveOn(globalOn: boolean, states: AppStates, appKey: string): boolean {
  return globalOn && isAppOn(states, appKey);
}

/** Keys of the apps the user turned off (left out of charts, counts and history). */
export function offKeys(states: AppStates): ReadonlySet<string> {
  return new Set(Object.entries(states).filter(([, s]) => s === "off").map(([k]) => k));
}
