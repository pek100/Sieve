"use client";

import { useCallback, useMemo, useSyncExternalStore } from "react";
import { engineInForce, engineLockReason } from "@/core/engine";
import { ROUTES, type RouteDef } from "@/core/routes";
import { readValue, type SettingsDoc } from "@/core/settings/document";
import { REGISTRY, SECTIONS, SETTING_KEYS, isSettingKey, needsEngine, settingDef, type Section, type SettingKey } from "@/core/settings/registry";
import { planImport, resetPlan, searchSettings, type ImportPlan } from "@/core/settings/transfer";
import { useRuntime } from "@/hooks/sieve-provider";
import { useHydrated } from "@/hooks/use-hydrated";
import { useCheckPassed, useEngine, useSwitchOn } from "@/hooks/use-sieve";

/** Why a setting cannot be changed here and now. */
export type Lock =
  | { kind: "desktop" }
  /** `checking`: the switch it needs is on but its live check has not passed (yet). */
  | { kind: "requires"; label: string; checking: boolean }
  /**
   * The engine carries it out (registry `needsEngine`) and cannot take a
   * policy now. `reason` is one line from the engine's phase; `inForce` is
   * the engine's own value, null when it did not say (the row shows off).
   */
  | { kind: "engine"; reason: string; inForce: boolean | null };

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

/**
 * Everything the Settings view reads and writes, derived from the registry:
 * which rows exist (available keys only: searchSettings), how each is locked,
 * search, import, reset. Writes go through the settings store; whole-document
 * changes say what they did in a toast with Undo (notice bus).
 *
 * `blocks`: sections that carry blocks of their own under their rows (the
 * Engine). With no search such a section is listed even when none of its
 * keys is available; a search lists only sections with a matching key.
 */
export function useSettingsView(query: string, blocks: ReadonlySet<Section>): SettingsView {
  const { settings, notices, isTauri } = useRuntime();
  const doc = useSyncExternalStore(settings.subscribe, settings.doc, settings.doc);
  const hydrated = useHydrated();
  const switchOn = useSwitchOn();
  const passed = useCheckPassed();
  const engine = useEngine();

  const sections = useMemo(() => {
    const hits = new Set(searchSettings(query));
    const searching = query.trim() !== "";
    return SECTIONS.map((s) => ({
      id: s.id,
      label: s.label,
      keys: SETTING_KEYS.filter((k) => settingDef(k).section === s.id && hits.has(k)),
      route: ROUTES.find((r) => r.href === `/${s.id}`),
    })).filter((s) => s.keys.length > 0 || (!searching && blocks.has(s.id)));
  }, [query, blocks]);

  const lockOf = useCallback(
    (key: SettingKey): Lock | null => {
      const d = settingDef(key);
      if (d.desktopOnly && !(hydrated && isTauri)) return { kind: "desktop" };
      if (needsEngine(key)) {
        const reason = engineLockReason(engine);
        if (reason !== null) return { kind: "engine", reason, inForce: engineInForce(engine) };
      }
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
    [passed, hydrated, isTauri, switchOn, engine],
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
