"use client";

import { useCallback, useMemo, useSyncExternalStore } from "react";
import type { Notice } from "@/core/notices";
import { ceiling, type Level } from "@/core/policy";
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

/** The highest per-app level reachable now (from data switches and passed live checks). */
export function useLevelCeiling(): Level {
  const { settings, passedChecks } = useRuntime();
  const doc = useSyncExternalStore(settings.subscribe, settings.doc, settings.doc);
  return useMemo(
    () =>
      ceiling(
        (k) => isSettingKey(k) && readValue(doc, k) === true,
        (k) => passedChecks.has(k),
      ),
    [doc, passedChecks],
  );
}

export function useNotices(): readonly Notice[] {
  const { notices } = useRuntime();
  return useSyncExternalStore(notices.subscribe, notices.list, notices.list);
}
