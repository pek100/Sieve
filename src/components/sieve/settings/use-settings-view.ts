"use client";

import { useCallback, useMemo, useSyncExternalStore } from "react";
import { LEVEL_REQUIRES, LEVELS } from "@/core/policy";
import { ROUTES, type RouteDef } from "@/core/routes";
import { readValue, type SettingsDoc } from "@/core/settings/document";
import { REGISTRY, SECTIONS, SETTING_KEYS, isSettingKey, settingDef, type Section, type SettingKey } from "@/core/settings/registry";
import { planImport, resetPlan, searchSettings, type ImportPlan } from "@/core/settings/transfer";
import { useRuntime } from "@/hooks/sieve-provider";
import { useHydrated } from "@/hooks/use-hydrated";
import { useCheckPassed, useSwitchOn } from "@/hooks/use-sieve";

/** Why a setting cannot be changed here and now. */
export type Lock =
  | { kind: "unavailable"; reason: string; check: string; neededBy: string[] }
  | { kind: "desktop" }
  /** `checking`: the switch it needs is on but its live check has not passed (yet). */
  | { kind: "requires"; label: string; checking: boolean };

export interface SettingsView {
  doc: SettingsDoc;
  /** Sections in registry order with the keys that match the search; sections with none are left out. */
  sections: { id: Section; label: string; keys: SettingKey[]; route: RouteDef | undefined }[];
  lockOf: (key: SettingKey) => Lock | null;
  set: (key: SettingKey, value: unknown) => void;
  reset: (key: SettingKey) => void;
  planImport: (text: string) => ImportPlan;
  resetAll: () => ReturnType<typeof resetPlan>;
  apply: (next: SettingsDoc, said: string) => void;
}

/** What needs a data switch, in words: levels (LEVEL_REQUIRES) and settings (`requires`). */
function neededBy(key: string): string[] {
  const levels = LEVELS.filter((l) => LEVEL_REQUIRES[l] === key).map((l) => `the ${l} level for apps`);
  const settings = SETTING_KEYS.filter((k) => settingDef(k).requires === key).map((k) => settingDef(k).label);
  return [...levels, ...settings];
}

/**
 * Everything the Settings view reads and writes, derived from the registry:
 * which rows exist, how each is locked, search, import, reset. Writes go
 * through the settings store; whole-document changes say what they did in a
 * toast with Undo (notice bus).
 */
export function useSettingsView(query: string): SettingsView {
  const { settings, notices, isTauri } = useRuntime();
  const doc = useSyncExternalStore(settings.subscribe, settings.doc, settings.doc);
  const hydrated = useHydrated();
  const switchOn = useSwitchOn();
  const passed = useCheckPassed();

  const sections = useMemo(() => {
    const hits = new Set(searchSettings(query));
    return SECTIONS.map((s) => ({
      id: s.id,
      label: s.label,
      keys: SETTING_KEYS.filter((k) => settingDef(k).section === s.id && hits.has(k)),
      route: ROUTES.find((r) => r.href === `/${s.id}`),
    })).filter((s) => s.keys.length > 0);
  }, [query]);

  const lockOf = useCallback(
    (key: SettingKey): Lock | null => {
      const d = settingDef(key);
      if (d.kind === "dataSwitch" && d.unavailable) {
        return { kind: "unavailable", reason: d.unavailable, check: d.liveCheck, neededBy: neededBy(key) };
      }
      if (d.desktopOnly && !(hydrated && isTauri)) return { kind: "desktop" };
      if (d.requires) {
        const label = isSettingKey(d.requires) ? REGISTRY[d.requires].label : d.requires;
        if (!switchOn(d.requires)) return { kind: "requires", label, checking: false };
        // A data switch is proven by its live check; what builds on it waits for that.
        if (isSettingKey(d.requires) && settingDef(d.requires).kind === "dataSwitch" && !passed(d.requires)) {
          return { kind: "requires", label, checking: true };
        }
      }
      return null;
    },
    [passed, hydrated, isTauri, switchOn],
  );

  const apply = useCallback(
    (next: SettingsDoc, said: string) => {
      const before = settings.doc();
      void settings.replace(next);
      notices.push({ kind: "success", text: said, action: { label: "Undo", run: () => void settings.replace(before) } });
    },
    [settings, notices],
  );

  return {
    doc,
    sections,
    lockOf,
    set: (key, value) => {
      // The control offered only valid values; a locked row offers none.
      if (lockOf(key) !== null) return;
      void settings.set(key, value as never);
    },
    reset: (key) => {
      const before = readValue(settings.doc(), key);
      void settings.reset(key);
      notices.push({
        kind: "info",
        text: `${settingDef(key).label} is back to its default`,
        action: { label: "Undo", run: () => void settings.set(key, before as never) },
      });
    },
    planImport: (text) => planImport(settings.doc(), text),
    resetAll: () => resetPlan(settings.doc()),
    apply,
  };
}
