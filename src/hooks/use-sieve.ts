"use client";

import { useCallback, useMemo, useSyncExternalStore } from "react";
import type { EngineSlice } from "@/core/engine";
import type { LogSlice } from "@/core/log";
import type { Notice } from "@/core/notices";
import { effectiveOn, GLOBAL_SWITCH, offKeys, type AppStates } from "@/core/policy";
import { readValue } from "@/core/settings/document";
import { isSettingKey, type SettingKey, type SettingValue } from "@/core/settings/registry";
import type { SieveState } from "@/core/store";
import { useRuntime } from "./sieve-provider";

/**
 * Read from the store. The selector runs once per store change, so it may
 * build objects (derivations) without causing re-render loops.
 */
export function useSieve<T>(selector: (s: SieveState) => T): T {
  const { store } = useRuntime();
  // The state object only changes identity when the store emits, so the
  // derivation reruns once per change. Pass a module-level selector to also
  // skip recomputing on unrelated renders.
  const state = useSyncExternalStore(store.subscribe, store.getState, store.getState);
  return useMemo(() => selector(state), [state, selector]);
}

/** One setting's value and its setter. */
export function useSetting<K extends SettingKey>(key: K): [SettingValue<K>, (v: SettingValue<K>) => Promise<void>] {
  const { settings } = useRuntime();
  const get = useCallback(() => settings.get(key), [settings, key]);
  const value = useSyncExternalStore(settings.subscribe, get, get);
  const set = useCallback((v: SettingValue<K>) => settings.set(key, v), [settings, key]);
  return [value, set];
}

/** Whether a setting (by key) is on, for data switches named by data (`requires`). */
export function useSwitchOn(): (key: string) => boolean {
  const { settings } = useRuntime();
  const doc = useSyncExternalStore(settings.subscribe, settings.doc, settings.doc);
  return useCallback((k: string) => isSettingKey(k) && readValue(doc, k) === true, [doc]);
}

/** Whether a data switch's live check passed this session; rerenders when one passes or is forgotten. */
export function useCheckPassed(): (key: string) => boolean {
  const { passedChecks } = useRuntime();
  const version = useSyncExternalStore(passedChecks.subscribe, passedChecks.version, passedChecks.version);
  // `version` is the dependency that makes a new function on every change.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  return useCallback((k: string) => passedChecks.has(k), [passedChecks, version]);
}

export interface Tracking {
  /** The global Sieving switch. */
  globalOn: boolean;
  /** Stored per-app choices (only apps turned off). */
  states: AppStates;
  /** Keys of the apps turned off; same identity while the setting is unchanged (trackedSnapshot caches on it). */
  off: ReadonlySet<string>;
  /** policy.effectiveOn for one app key. */
  isOn: (appKey: string) => boolean;
}

/** What Sieve tracks: the global switch and the per-app on/off (policy.ts). */
export function useTracking(): Tracking {
  const [globalOn] = useSetting(GLOBAL_SWITCH);
  const [states] = useSetting("apps.levels");
  return useMemo(
    () => ({ globalOn, states, off: offKeys(states), isOn: (k: string) => effectiveOn(globalOn, states, k) }),
    [globalOn, states],
  );
}

const selectEngine = (s: SieveState): EngineSlice => s.engine;

/** The filtering engine's facts (owner: the engine controller). */
export function useEngine(): EngineSlice {
  return useSieve(selectEngine);
}

/** The engine's user actions: the AdGuard pause offer and its undo, the certificate's Reinstall, the update button (through the engine controller). */
export function useEngineActions(): { stopAdguard: () => Promise<void>; startAdguard: () => Promise<void>; installRoot: () => Promise<void>; requestUpdate: () => Promise<void> } {
  const { engineController } = useRuntime();
  return useMemo(
    () => ({
      stopAdguard: () => engineController.stopAdguard(),
      startAdguard: () => engineController.startAdguard(),
      installRoot: () => engineController.installRoot(),
      requestUpdate: () => engineController.requestUpdate(),
    }),
    [engineController],
  );
}

const selectLog = (s: SieveState): LogSlice => s.log;

/** The filtering log (owner: the log controller). */
export function useLog(): LogSlice {
  return useSieve(selectLog);
}

/** The log's user actions: pause, resume and clear (through the log controller). */
export function useLogActions(): { pause: () => void; resume: () => void; clear: () => void } {
  const { logController } = useRuntime();
  return useMemo(
    () => ({ pause: () => logController.pause(), resume: () => logController.resume(), clear: () => logController.clear() }),
    [logController],
  );
}

export function useNotices(): readonly Notice[] {
  const { notices } = useRuntime();
  return useSyncExternalStore(notices.subscribe, notices.list, notices.list);
}
