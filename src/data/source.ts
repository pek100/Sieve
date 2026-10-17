/**
 * The data seam (primitive B2). Every byte of machine data enters Sieve
 * through one SieveSource. Two implementations: `tauri` (Rust reads the
 * OS connection tables, read only) and `mock` (seeded, for the browser and
 * tests). A Tauri failure surfaces as an error; it never falls back to the
 * mock silently.
 */
import type { SourceKind } from "@/core/store";
import { createMockSource, MOCK_SCENARIOS, type MockScenario } from "./mock-source";
import type { HistoryQuery } from "@/core/history";
import type { History, Snapshot } from "./protocol";
import { createTauriSource } from "./tauri-source";

export type { SourceKind };

export type { HistoryQuery };

export interface SieveSource {
  readonly kind: SourceKind;
  /** Take one sample of the machine now. Rejects on failure. */
  sample(): Promise<Snapshot>;
  /**
   * Per-app activity in [from, to) at one grain, summed into `step` buckets,
   * oldest first. Tauri reads the persisted store; the mock computes the same
   * shape. Rejects on failure.
   */
  history(query: HistoryQuery): Promise<History>;
}

export interface SourceOptions {
  kind: SourceKind;
  seed: number;
  scenario: MockScenario;
}

/** Read the source choice from the environment: query string and Tauri presence. */
export function sourceOptions(env: { search: string; isTauri: boolean }): SourceOptions {
  const q = new URLSearchParams(env.search);
  const forced = q.get("source");
  const kind: SourceKind = forced === "mock" ? "mock" : env.isTauri ? "tauri" : "mock";
  const seedRaw = Number(q.get("seed"));
  const seed = Number.isInteger(seedRaw) && seedRaw > 0 ? seedRaw : 1;
  const sc = q.get("scenario");
  const scenario = (MOCK_SCENARIOS as readonly string[]).includes(sc ?? "") ? (sc as MockScenario) : "steady";
  return { kind, seed, scenario };
}

export function createSource(o: SourceOptions): SieveSource {
  return o.kind === "tauri" ? createTauriSource() : createMockSource({ seed: o.seed, scenario: o.scenario });
}

/** Pick the source for this window. */
export function resolveSource(env: { search: string; isTauri: boolean }): SieveSource {
  return createSource(sourceOptions(env));
}

export function isTauriWindow(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
