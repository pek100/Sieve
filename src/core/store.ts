/**
 * The single Sieve store, many readers (React through useSieve). One writer
 * per part: the poller (src/data/poller.ts) owns snapshots and sampling
 * status; the engine controller (src/data/engine-controller.ts) owns `engine`
 * through setEngine; the log controller (src/data/log-controller.ts) owns
 * `log` through setLog. Snapshots live in a ring buffer whose size is derived from the
 * longest window any consumer declared, so nothing keeps more history than
 * someone actually reads.
 */
import type { Snapshot } from "@/data/protocol";
import { EMPTY_ENGINE, type EngineSlice } from "./engine";
import { EMPTY_LOG, type LogSlice } from "./log";

export type SourceKind = "mock" | "tauri";

export interface SamplingStatus {
  /** The poller is scheduled to sample. */
  running: boolean;
  /** Epoch ms until which sampling is paused, or null. */
  pausedUntil: number | null;
  /** Message of the last failed sample, cleared by the next good one. */
  error: string | null;
}

export interface SieveState {
  source: SourceKind | null;
  intervalMs: number;
  /** Oldest first. Never longer than `capacity`. */
  snapshots: readonly Snapshot[];
  capacity: number;
  status: SamplingStatus;
  /** Filtering engine facts (writer: the engine controller). */
  engine: EngineSlice;
  /** The filtering log, session only (writer: the log controller). */
  log: LogSlice;
}

export type Phase = "starting" | "live" | "paused" | "off" | "error";

/** The sampling phase (the master switch's data-phase and spoken status), derived from status and data, never stored. */
export function phase(s: Pick<SieveState, "status" | "snapshots">): Phase {
  if (s.status.pausedUntil !== null) return "paused";
  if (!s.status.running) return "off";
  if (s.status.error !== null) return "error";
  if (s.snapshots.length === 0) return "starting";
  return "live";
}

export function newest(s: Pick<SieveState, "snapshots">): Snapshot | null {
  return s.snapshots.length ? s.snapshots[s.snapshots.length - 1] : null;
}

/** Ring size for a window: enough samples to span it, plus the anchor sample. */
export function capacityFor(windowMs: number, intervalMs: number): number {
  return Math.max(1, Math.ceil(windowMs / Math.max(1, intervalMs)) + 1);
}

export interface SieveStore {
  getState(): SieveState;
  subscribe(listener: () => void): () => void;
  /** Declare that a consumer reads `windowMs` of history. Returns the undo. */
  declareWindow(windowMs: number): () => void;
  // Writer API: only the poller calls these.
  setSource(kind: SourceKind): void;
  setInterval(intervalMs: number): void;
  push(snapshot: Snapshot): void;
  setStatus(patch: Partial<SamplingStatus>): void;
  clear(): void;
  // Writer API of the engine part: only the engine controller calls this.
  setEngine(next: EngineSlice): void;
  // Writer API of the log part: only the log controller calls this.
  setLog(next: LogSlice): void;
}

export const DEFAULT_INTERVAL_MS = 1000;

export function createStore(intervalMs = DEFAULT_INTERVAL_MS): SieveStore {
  const windows = new Map<number, number>();
  let nextWindowId = 1;
  let state: SieveState = {
    source: null,
    intervalMs,
    snapshots: [],
    capacity: 1,
    status: { running: false, pausedUntil: null, error: null },
    engine: EMPTY_ENGINE,
    log: EMPTY_LOG,
  };
  const listeners = new Set<() => void>();

  const emit = (next: SieveState) => {
    state = next;
    for (const l of listeners) l();
  };

  const recapacity = (s: SieveState): SieveState => {
    const longest = Math.max(0, ...windows.values());
    const capacity = capacityFor(longest, s.intervalMs);
    const snapshots =
      s.snapshots.length > capacity ? s.snapshots.slice(s.snapshots.length - capacity) : s.snapshots;
    return { ...s, capacity, snapshots };
  };

  return {
    getState: () => state,
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    declareWindow(windowMs) {
      const id = nextWindowId++;
      windows.set(id, windowMs);
      emit(recapacity(state));
      return () => {
        windows.delete(id);
        emit(recapacity(state));
      };
    },
    setSource(kind) {
      if (state.source !== kind) emit({ ...state, source: kind });
    },
    setInterval(ms) {
      if (state.intervalMs !== ms) emit(recapacity({ ...state, intervalMs: ms }));
    },
    push(snapshot) {
      const snapshots = [...state.snapshots, snapshot];
      if (snapshots.length > state.capacity) snapshots.splice(0, snapshots.length - state.capacity);
      emit({ ...state, snapshots, status: { ...state.status, error: null } });
    },
    setStatus(patch) {
      emit({ ...state, status: { ...state.status, ...patch } });
    },
    clear() {
      emit({ ...state, snapshots: [] });
    },
    setEngine(next) {
      emit({ ...state, engine: next });
    },
    setLog(next) {
      emit({ ...state, log: next });
    },
  };
}
