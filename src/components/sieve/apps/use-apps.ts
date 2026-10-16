"use client";

import { useCallback, useMemo } from "react";
import {
  levelOf,
  listApps,
  pin,
  resetLevels,
  setLevel,
  sievedCount,
  stopAll,
  unpin,
  watchAll,
  type AppEntry,
} from "@/core/apps-actions";
import { exeStem } from "@/core/apps";
import { LEVEL_REQUIRES, levelRank, type Level } from "@/core/policy";
import { settingDef, type SettingKey } from "@/core/settings/registry";
import { newest, phase, type Phase } from "@/core/store";
import { useRuntime } from "@/hooks/sieve-provider";
import { useLevelCeiling, useSetting, useSieve } from "@/hooks/use-sieve";

export interface AppsModel {
  apps: AppEntry[];
  phase: Phase;
  error: string | null;
  /** Highest level reachable now. */
  top: Level;
  sievedNow: number;
  levelOf: (key: string) => Level;
  /** Why a level above the ceiling is not available, or null when it is. */
  lockedReason: (level: Level) => string | null;
  setLevel: (key: string, level: Level) => void;
  watchAll: () => void;
  stopAll: () => void;
  resetLevels: () => void;
  pin: (path: string) => void;
  unpin: (key: string) => void;
}

/**
 * Everything the Apps screen reads and writes, in one place. Reads come from
 * the store and the settings; writes go through the pure reducers in
 * core/apps-actions and land in apps.levels / apps.pinned. Notices go through
 * the notice bus, never sonner directly.
 */
export function useApps(): AppsModel {
  const { settings, notices } = useRuntime();
  const snapshot = useSieve(newest);
  const p = useSieve(phase);
  const error = useSieve((s) => s.status.error);
  const [levels, writeLevels] = useSetting("apps.levels");
  const [pinned, writePinned] = useSetting("apps.pinned");
  const [dnsOn] = useSetting("filtering.dns");
  const top = useLevelCeiling();

  const apps = useMemo(() => listApps(snapshot, pinned), [snapshot, pinned]);
  const sievedNow = useMemo(() => sievedCount(snapshot, levels, top), [snapshot, levels, top]);

  const lockedReason = useCallback(
    (level: Level) => {
      const needs = LEVEL_REQUIRES[level];
      if (!needs || levelRank(level) <= levelRank(top)) return null;
      const label = settingDef(needs as SettingKey).label;
      // Only one data switch exists today; its state is read for the copy.
      return dnsOn ? `Needs ${label} to pass its live check` : `Needs ${label}, which is off`;
    },
    [top, dnsOn],
  );

  // Writers read the latest stored value at call time, so undo after other edits stays correct.
  const levelsNow = useCallback(() => settings.get("apps.levels"), [settings]);
  const pinnedNow = useCallback(() => settings.get("apps.pinned"), [settings]);

  const undoLevels = useCallback(
    (text: string, before: ReturnType<typeof levelsNow>) =>
      notices.push({ kind: "info", text, action: { label: "Undo", run: () => void writeLevels(before) } }),
    [notices, writeLevels],
  );

  return {
    apps,
    phase: p,
    error,
    top,
    sievedNow,
    levelOf: (key) => levelOf(levels, key, top),
    lockedReason,
    setLevel: (key, level) => void writeLevels(setLevel(levelsNow(), key, level, top)),
    watchAll: () => {
      const before = levelsNow();
      void writeLevels(watchAll(before));
      undoLevels("Every app is watched", before);
    },
    stopAll: () => {
      const before = levelsNow();
      void writeLevels(stopAll(before, apps.map((a) => a.key)));
      undoLevels("Stopped watching every app", before);
    },
    resetLevels: () => {
      const before = levelsNow();
      void writeLevels(resetLevels());
      undoLevels("Levels reset to watch", before);
    },
    pin: (path) => {
      const before = pinnedNow();
      const next = pin(before, path);
      if (next === before) {
        notices.push({ kind: "info", text: `${exeStem(path.trim())} is already in your apps` });
        return;
      }
      void writePinned(next);
      notices.push({ kind: "success", text: `Added ${exeStem(path.trim())}` });
    },
    unpin: (key) => {
      const app = apps.find((a) => a.key === key);
      if (!app || app.pinnedPaths.length === 0) return;
      const removed = app.pinnedPaths;
      void writePinned(unpin(pinnedNow(), key, apps));
      notices.push({
        kind: "info",
        text: `Removed ${app.name} from your apps`,
        action: {
          label: "Undo",
          run: () => void writePinned(removed.reduce((acc, path) => pin(acc, path), pinnedNow())),
        },
      });
    },
  };
}
