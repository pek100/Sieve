"use client";

import { useMemo } from "react";
import { listApps, offAll, pin, setAppState, sieveAll, sievedCount, unpin, type AppEntry } from "@/core/apps-actions";
import { exeStem } from "@/core/apps";
import { engineStatus } from "@/core/engine";
import { guestRows, type GuestRow } from "@/core/guests";
import { isAppOn } from "@/core/policy";
import { newest, phase, type Phase } from "@/core/store";
import { useRuntime } from "@/hooks/sieve-provider";
import { useEngine, useSetting, useSieve, useTracking } from "@/hooks/use-sieve";

export interface AppsModel {
  apps: AppEntry[];
  /** "Virtual machines and WSL": empty until the engine saw forwarded traffic. */
  guests: GuestRow[];
  phase: Phase;
  error: string | null;
  /** The global Sieving switch. */
  globalOn: boolean;
  sievedNow: number;
  /** The user has not turned this app off (the global switch is shown on its own). */
  isOn: (key: string) => boolean;
  setOn: (key: string, on: boolean) => void;
  sieveAll: () => void;
  offAll: () => void;
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
  const { globalOn, states } = useTracking();
  const [, writeStates] = useSetting("apps.levels");
  const [pinned, writePinned] = useSetting("apps.pinned");

  // The list is the whole snapshot (an app turned off must stay listed to be turned back on).
  const apps = useMemo(() => listApps(snapshot, pinned), [snapshot, pinned]);
  const engineGuests = engineStatus(useEngine())?.guests;
  const guests = useMemo(() => guestRows(engineGuests), [engineGuests]);
  const sievedNow = useMemo(() => sievedCount(snapshot, states, globalOn), [snapshot, states, globalOn]);

  // Writers read the latest stored value at call time, so undo after other edits stays correct.
  const statesNow = () => settings.get("apps.levels");
  const pinnedNow = () => settings.get("apps.pinned");
  // A toast says only what happened: it waits for the write, which the lock may park or drop.
  const writeAllStates = (next: ReturnType<typeof statesNow>, text: string) => {
    const before = statesNow();
    void writeStates(next).then((ran) => {
      if (ran) notices.push({ kind: "info", text, action: { label: "Undo", run: () => void writeStates(before) } });
    });
  };

  return {
    apps,
    guests,
    phase: p,
    error,
    globalOn,
    sievedNow,
    isOn: (key) => isAppOn(states, key),
    setOn: (key, on) => void writeStates(setAppState(statesNow(), key, on ? "sieve" : "off")),
    sieveAll: () => writeAllStates(sieveAll(), "Every app is sieved"),
    offAll: () => writeAllStates(offAll(statesNow(), [...apps, ...guests].map((a) => a.key)), "Every app is off"),
    pin: (path) => {
      const before = pinnedNow();
      const next = pin(before, path);
      if (next === before) {
        notices.push({ kind: "info", text: `${exeStem(path.trim())} is already in your apps` });
        return;
      }
      void writePinned(next).then((ran) => {
        if (ran) notices.push({ kind: "success", text: `Added ${exeStem(path.trim())}` });
      });
    },
    unpin: (key) => {
      const app = apps.find((a) => a.key === key);
      if (!app || app.pinnedPaths.length === 0) return;
      const removed = app.pinnedPaths;
      void writePinned(unpin(pinnedNow(), key, apps)).then((ran) => {
        if (!ran) return;
        notices.push({
          kind: "info",
          text: `Removed ${app.name} from your apps`,
          action: {
            label: "Undo",
            run: () => void writePinned(removed.reduce((acc, path) => pin(acc, path), pinnedNow())),
          },
        });
      });
    },
  };
}
