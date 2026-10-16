"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { heatGrid, type HeatGrid } from "@/core/heat";
import { kpis, type Kpi } from "@/core/kpis";
import { effectiveLevel, requestedLevel, type Level } from "@/core/policy";
import { createSlotKeeper, windowSnapshots, type SeriesModel } from "@/core/series";
import type { SieveState } from "@/core/store";
import { useRuntime } from "@/hooks/sieve-provider";
import { useLevelCeiling, useSetting, useSieve } from "@/hooks/use-sieve";

/** The chart's window choices. Session keeps at most SESSION_MAX_MS so memory stays bounded. */
export const SESSION_MAX_MS = 2 * 3_600_000;
export const WINDOWS = [
  { value: "5m", label: "5 min", ms: 5 * 60_000 },
  { value: "1h", label: "1 h", ms: 3_600_000 },
  { value: "session", label: "Session", ms: SESSION_MAX_MS },
] as const;
export type WindowChoice = (typeof WINDOWS)[number]["value"];

export function windowMs(choice: WindowChoice): number {
  return WINDOWS.find((w) => w.value === choice)?.ms ?? WINDOWS[0].ms;
}

const VIEW_STEP_MS = 5 * 60_000;

/**
 * The span the chart shows. Fixed windows show their length; Session shows
 * the data kept so far, rounded up to 5 minutes (so the scale changes once
 * every 5 minutes, not every tick), up to SESSION_MAX_MS.
 */
export function viewMs(choice: WindowChoice, dataSpanMs: number): number {
  if (choice !== "session") return windowMs(choice);
  return Math.min(SESSION_MAX_MS, Math.max(VIEW_STEP_MS, Math.ceil(dataSpanMs / VIEW_STEP_MS) * VIEW_STEP_MS));
}

const selectSpan = (s: SieveState) => (s.snapshots.length ? s.snapshots[s.snapshots.length - 1].t - s.snapshots[0].t : 0);

/** The chart and KPI span for a window choice. */
export function useViewMs(choice: WindowChoice): number {
  const span = useSieve(selectSpan);
  return viewMs(choice, span);
}

const selectSnapshots = (s: SieveState) => s.snapshots;
const selectInterval = (s: SieveState) => s.intervalMs;

/** Declare the window to the store (sizes the ring) for as long as Home shows it. */
export function useDeclaredWindow(choice: WindowChoice) {
  const { store } = useRuntime();
  const ms = windowMs(choice);
  useEffect(() => store.declareWindow(ms), [store, ms]);
}

/** The per-app series for the window; colours stay sticky across ticks. */
export function useSeriesModel(ms: number): SeriesModel {
  const snapshots = useSieve(selectSnapshots);
  const intervalMs = useSieve(selectInterval);
  const [keeper] = useState(createSlotKeeper);
  return useMemo(() => keeper.build(snapshots, { windowMs: ms, intervalMs }), [keeper, snapshots, ms, intervalMs]);
}

/** Effective level of an app, from apps.levels and the current ceiling. */
export function useLevelOf(): (appKey: string) => Level {
  const [levels] = useSetting("apps.levels");
  const top = useLevelCeiling();
  return useCallback((k: string) => effectiveLevel(requestedLevel(levels, k), top), [levels, top]);
}

export function useKpis(ms: number): Kpi[] | null {
  const snapshots = useSieve(selectSnapshots);
  const levelOf = useLevelOf();
  return useMemo(() => kpis(windowSnapshots(snapshots, ms), levelOf), [snapshots, ms, levelOf]);
}

export type HistoryState =
  | { kind: "loading" }
  | { kind: "ready"; grid: HeatGrid }
  | { kind: "error"; message: string };

const DAY = 86_400_000;
const HISTORY_REFRESH_MS = 60_000;

/** Four weeks of hourly activity from the source, refreshed every minute. */
export function useHeat(): HistoryState {
  const { source } = useRuntime();
  const [state, setState] = useState<HistoryState>({ kind: "loading" });
  useEffect(() => {
    let alive = true;
    const load = () => {
      const to = Date.now();
      source.history({ from: to - 28 * DAY, to }).then(
        (b) => alive && setState({ kind: "ready", grid: heatGrid(b) }),
        (e: unknown) => alive && setState({ kind: "error", message: e instanceof Error ? e.message : String(e) }),
      );
    };
    load();
    const id = setInterval(load, HISTORY_REFRESH_MS);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [source]);
  return state;
}

function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true;
}

const raf = (cb: (t: number) => void): number =>
  typeof requestAnimationFrame === "function"
    ? requestAnimationFrame(cb)
    : (setTimeout(() => cb(Date.now()), 16) as unknown as number);
const caf = (id: number) =>
  typeof cancelAnimationFrame === "function" ? cancelAnimationFrame(id) : clearTimeout(id);

/**
 * KPI number ticker: counts from the shown value to the new one over `ms`
 * (motion base, 200). The first value shows at once, never counting up from
 * zero. Reduced motion jumps straight to the value.
 */
export function useTicker(value: number, ms = 200): number {
  const [shown, setShown] = useState(value);
  const shownRef = useRef(value);
  useEffect(() => {
    const from = shownRef.current;
    if (from === value) return;
    let frame = 0;
    let start: number | null = null;
    const step = (now: number) => {
      start ??= now;
      const k = prefersReducedMotion() ? 1 : Math.min(1, (now - start) / ms);
      const v = k >= 1 ? value : Math.round(from + (value - from) * (1 - (1 - k) * (1 - k)));
      shownRef.current = v;
      setShown(v);
      if (k < 1) frame = raf(step);
    };
    frame = raf(step);
    return () => caf(frame);
  }, [value, ms]);
  return shown;
}
