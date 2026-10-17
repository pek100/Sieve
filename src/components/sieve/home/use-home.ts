"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { heatCaption, heatGrid, type HeatGrid } from "@/core/heat";
import { trackedSnapshot } from "@/core/apps";
import { historySeries, hourActivity, periodQuery, trackedHistory, type HistoryQuery } from "@/core/history";
import type { History, Snapshot } from "@/data/protocol";
import { kpis, type Kpi } from "@/core/kpis";
import { buildSeries, createSlotKeeper, windowSnapshots, type SeriesModel, type SeriesSet } from "@/core/series";
import type { SieveState } from "@/core/store";
import { useRuntime } from "@/hooks/sieve-provider";
import { useSieve, useTracking } from "@/hooks/use-sieve";

/**
 * The chart's window choices. Live windows draw the store's snapshot ring
 * (Session keeps at most SESSION_MAX_MS so memory stays bounded); history
 * periods read the source's persisted history (plan row 77).
 */
export const SESSION_MAX_MS = 2 * 3_600_000;
const DAY = 86_400_000;
export const WINDOWS = [
  { value: "5m", label: "5 min", ms: 5 * 60_000, history: false },
  { value: "1h", label: "1 h", ms: 3_600_000, history: false },
  { value: "session", label: "Session", ms: SESSION_MAX_MS, history: false },
  { value: "24h", label: "24 h", ms: DAY, history: true },
  { value: "7d", label: "7 d", ms: 7 * DAY, history: true },
  { value: "14d", label: "14 d", ms: 14 * DAY, history: true },
] as const;
export type WindowChoice = (typeof WINDOWS)[number]["value"];

export function windowMs(choice: WindowChoice): number {
  return WINDOWS.find((w) => w.value === choice)?.ms ?? WINDOWS[0].ms;
}

export function isHistoryWindow(choice: WindowChoice): boolean {
  return WINDOWS.find((w) => w.value === choice)?.history ?? false;
}

/** The live window behind a choice: itself, or the whole session for a history period (KPIs stay live). */
export function liveWindow(choice: WindowChoice): WindowChoice {
  return isHistoryWindow(choice) ? "session" : choice;
}

const selectSnapshots = (s: SieveState) => s.snapshots;
const selectInterval = (s: SieveState) => s.intervalMs;

/** Declare the window to the store (sizes the ring) for as long as Home shows it. */
export function useDeclaredWindow(choice: WindowChoice) {
  const { store } = useRuntime();
  const ms = windowMs(choice);
  useEffect(() => store.declareWindow(ms), [store, ms]);
}

/** The snapshot ring as Sieve tracks it: apps turned off left out (apps.trackedSnapshot). */
export function useTrackedSnapshots(): readonly Snapshot[] {
  const snapshots = useSieve(selectSnapshots);
  const { off } = useTracking();
  return useMemo(() => (off.size === 0 ? snapshots : snapshots.map((s) => trackedSnapshot(s, off))), [snapshots, off]);
}

/**
 * The chart's series set, derived once from what every window shares: the
 * live session (Home keeps the whole session in the ring). Every window, live
 * or history, draws this set, so switching the window changes only the time
 * range. Colours stay sticky across ticks.
 */
export function useSeriesSet(): SeriesSet {
  const snapshots = useTrackedSnapshots();
  const [keeper] = useState(createSlotKeeper);
  return useMemo(() => keeper.set(snapshots), [keeper, snapshots]);
}

/** The live chart model for a window, drawing `set`. */
export function useSeriesModel(ms: number, set: SeriesSet): SeriesModel {
  const snapshots = useTrackedSnapshots();
  const intervalMs = useSieve(selectInterval);
  return useMemo(() => buildSeries(snapshots, { windowMs: ms, intervalMs }, set), [snapshots, ms, intervalMs, set]);
}

export function useKpis(ms: number): Kpi[] | null {
  const snapshots = useTrackedSnapshots();
  const { isOn } = useTracking();
  return useMemo(() => kpis(windowSnapshots(snapshots, ms), isOn), [snapshots, ms, isOn]);
}

export type Loaded<T> = { kind: "loading" } | ({ kind: "ready" } & T) | { kind: "error"; message: string };
export type HistoryState = Loaded<{ grid: HeatGrid; caption: string }>;

const HOUR = 3_600_000;
const HISTORY_REFRESH_MS = 60_000;
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/**
 * Read the source's history now and every minute while `query` is not null,
 * folding each answer with `fold`. The fold runs in the effect, so a broken
 * answer becomes an error state, never a crash.
 */
function useHistory<T>(query: ((to: number) => HistoryQuery) | null, fold: (h: History, q: HistoryQuery) => T): Loaded<T> {
  const { source, clock } = useRuntime();
  // The answer is pinned to the query it answers: a new query shows loading, never the old period.
  const [answer, setAnswer] = useState<{ for: unknown; state: Loaded<T> }>({ for: null, state: { kind: "loading" } });
  useEffect(() => {
    if (query === null) return;
    let alive = true;
    const set = (state: Loaded<T>) => alive && setAnswer({ for: query, state });
    const load = () => {
      const q = query(clock.now());
      source.history(q).then(
        (h) => {
          try {
            set({ kind: "ready", ...fold(h, q) });
          } catch (e) {
            set({ kind: "error", message: message(e) });
          }
        },
        (e: unknown) => set({ kind: "error", message: message(e) }),
      );
    };
    load();
    const id = setInterval(load, HISTORY_REFRESH_MS);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [source, clock, query, fold]);
  return query !== null && answer.for === query ? answer.state : { kind: "loading" };
}

const heatQuery = (to: number): HistoryQuery => ({ from: to - 28 * DAY, to, grain: "hour", step: HOUR });
/** Up to four weeks of hourly activity from the source (apps turned off left out), refreshed every minute; the caption says how far back it goes. */
export function useHeat(): HistoryState {
  const { off } = useTracking();
  const fold = useCallback(
    (h: History, q: HistoryQuery) => {
      const grid = heatGrid(hourActivity(trackedHistory(h, off)));
      return { grid, caption: heatCaption(grid, q) };
    },
    [off],
  );
  return useHistory(heatQuery, fold);
}

/**
 * The chart model for a history period (24 h, 7 d, 14 d), drawing `set`. The
 * fold keeps the raw answer; the model is made from it and the current set,
 * so a new set (a live tick that reranks) never needs a new read.
 */
export function useHistoryModel(choice: WindowChoice, set: SeriesSet): Loaded<{ model: SeriesModel }> {
  const history = isHistoryWindow(choice);
  const ms = windowMs(choice);
  const query = useMemo(() => (history ? (to: number) => periodQuery(ms, to) : null), [history, ms]);
  const { off } = useTracking();
  const fold = useCallback((h: History, q: HistoryQuery) => ({ history: trackedHistory(h, off), to: q.to }), [off]);
  const read = useHistory(query, fold);
  return useMemo<Loaded<{ model: SeriesModel }>>(
    () => (read.kind === "ready" ? { kind: "ready", model: historySeries(read.history, { periodMs: ms, to: read.to }, set) } : read),
    [read, ms, set],
  );
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
