"use client";

import { useCallback, useMemo, useSyncExternalStore } from "react";
import { engineInForce, engineLockReason } from "@/core/engine";
import { isShut, type LockPhase } from "@/core/lock";
import { ROUTES, type RouteDef } from "@/core/routes";
import { readValue, type SettingsDoc } from "@/core/settings/document";
import { REGISTRY, SECTIONS, SETTING_KEYS, isAvailable, isSettingKey, needsEngine, settingDef, type Section, type SettingKey } from "@/core/settings/registry";
import { planImport, resetPlan, searchSettings, type ImportPlan } from "@/core/settings/transfer";
import { useRuntime } from "@/hooks/sieve-provider";
import { useHydrated } from "@/hooks/use-hydrated";
import { useLock } from "@/hooks/use-lock";
import { useCheckPassed, useEngine, useSwitchOn } from "@/hooks/use-sieve";

/** Why a setting cannot be changed here and now. */
export type Lock =
  /**
   * The settings password holds (`locked`, or `unreadable`: then nothing opens
   * it). Checked first. `beneath`: what would still lock the row without it, so
   * a row the engine carries out shows the engine's value here too.
   */
  | { kind: "password"; phase: LockPhase; beneath: Lock | null }
  | { kind: "desktop" }
  /**
   * `checking`: the switch it needs is on but its live check has not passed (yet).
   * `unavailable`: the switch it needs is not offered in this build, so nothing here can turn it on.
   */
  | { kind: "requires"; label: string; checking: boolean; unavailable?: boolean }
  /**
   * The engine carries it out (registry `needsEngine`) and cannot take a
   * policy now. `reason` is one line from the engine's phase; `inForce` is
   * the engine's own value, null when it did not say (the row shows off).
   */
  | { kind: "engine"; reason: string; inForce: boolean | null };

/**
 * A setting's value in force: what the engine itself holds for a setting it
 * carries out but cannot take now (off when it did not say), else the stored value.
 */
export function valueInForce(key: SettingKey, doc: SettingsDoc, lock: Lock | null): unknown {
  const engineLock = lock?.kind === "password" ? lock.beneath : lock;
  return engineLock?.kind === "engine" ? engineLock.inForce === true : readValue(doc, key);
}

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
 * search, import, reset. Every write goes through the lock's write gate
 * (`guard`) and then the settings store; whole-document changes say what they
 * did in a toast with Undo (notice bus).
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
  const { state: lockState, lock } = useLock();
  const { guard } = lock;
  const lockPhase = lockState.phase;

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

  const unpasswordedLock = useCallback(
    (key: SettingKey): Lock | null => {
      const d = settingDef(key);
      if (d.desktopOnly && !(hydrated && isTauri)) return { kind: "desktop" };
      if (needsEngine(key)) {
        const reason = engineLockReason(engine);
        if (reason !== null) return { kind: "engine", reason, inForce: engineInForce(engine) };
      }
      if (d.requires) {
        const label = isSettingKey(d.requires) ? REGISTRY[d.requires].label : d.requires;
        if (!switchOn(d.requires)) return { kind: "requires", label, checking: false, unavailable: isSettingKey(d.requires) && !isAvailable(d.requires) };
        // A data switch is proven by its live check; what builds on it waits for that.
        if (isSettingKey(d.requires) && settingDef(d.requires).kind === "dataSwitch" && !passed(d.requires)) {
          return { kind: "requires", label, checking: true };
        }
      }
      return null;
    },
    [passed, hydrated, isTauri, switchOn, engine],
  );

  const lockOf = useCallback(
    (key: SettingKey): Lock | null => (isShut(lockPhase) ? { kind: "password", phase: lockPhase, beneath: unpasswordedLock(key) } : unpasswordedLock(key)),
    [lockPhase, unpasswordedLock],
  );

  const apply = useCallback(
    (next: SettingsDoc, said: string) => {
      void guard(() => {
        const before = settings.doc();
        void settings.replace(next);
        notices.push({ kind: "success", text: said, action: { label: "Undo", run: () => void guard(() => settings.replace(before)) } });
      });
    },
    [settings, notices, guard],
  );

  return {
    doc,
    sections,
    lockOf,
    set: (key, value) => {
      // The control offered only valid values; a locked row offers none. A
      // password is the gate's to ask for, so the write waits for it.
      if (unpasswordedLock(key) !== null) return;
      void guard(() => settings.set(key, value as never));
    },
    reset: (key) => {
      void guard(() => {
        const before = readValue(settings.doc(), key);
        void settings.reset(key);
        notices.push({
          kind: "info",
          text: `${settingDef(key).label} is back to its default`,
          action: { label: "Undo", run: () => void guard(() => settings.set(key, before as never)) },
        });
      });
    },
    planImport: (text) => planImport(settings.doc(), text),
    resetAll: () => resetPlan(settings.doc()),
    apply,
  };
}
