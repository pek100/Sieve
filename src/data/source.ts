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
import type { AppIcon, History, Snapshot } from "./protocol";
import { createTauriSource } from "./tauri-source";
import { CERT_SCENARIOS, createMockEngine, ENGINE_SCENARIOS, type CertScenario, type EngineScenario } from "./engine-mock";
import { createTauriEngine, type EngineSource } from "./engine-source";
import { createMockWindowsDns, createTauriWindowsDns, type WindowsDnsSource } from "./safety-net";

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
  /**
   * The icon of one exe (an app's first exe), or null when it has none to
   * show (Windows hides the path, no icon, the mock without ?icons=1). Never
   * part of a snapshot. Rejects only when the source itself failed.
   */
  appIcon(exe: string): Promise<AppIcon | null>;
}

export interface SourceOptions {
  kind: SourceKind;
  seed: number;
  scenario: MockScenario;
  /** Mock: one Windows adapter asks 127.0.0.1 and ::1 for DNS (?pointed=1). */
  pointed: boolean;
  /** Mock: generated app icons (?icons=1); without it the mock has none, as for unreadable exes. */
  icons: boolean;
  /** Mock engine scenario (?engine=missing|stopped|idle|..., default missing). */
  engine: EngineScenario;
  /** Mock: every read of the engine's log fails (?log=error). */
  logError: boolean;
  /** Mock certificate scenario (?cert=installed|expires_soon|not_installed|policy_off|error, default not_installed). */
  cert: CertScenario;
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
  const e = q.get("engine");
  const engine = (ENGINE_SCENARIOS as readonly string[]).includes(e ?? "") ? (e as EngineScenario) : "missing";
  const c = q.get("cert");
  const cert = (CERT_SCENARIOS as readonly string[]).includes(c ?? "") ? (c as CertScenario) : "not_installed";
  return { kind, seed, scenario, pointed: q.get("pointed") === "1", icons: q.get("icons") === "1", engine, logError: q.get("log") === "error", cert };
}

/**
 * @param untracked the app keys the user turned off, read at every sample;
 *   the Tauri source does not save their counts. (The mock keeps no history
 *   of its own: its history is computed, and the window filters what it shows.)
 */
export function createSource(o: SourceOptions, untracked: () => ReadonlySet<string>): SieveSource {
  return o.kind === "tauri" ? createTauriSource(undefined, untracked) : createMockSource({ seed: o.seed, scenario: o.scenario, icons: o.icons });
}

/** The safety net's read follows the same choice: the Tauri command, or the mock. */
export function createWindowsDnsSource(o: SourceOptions): WindowsDnsSource {
  return o.kind === "tauri" ? createTauriWindowsDns() : createMockWindowsDns({ pointed: o.pointed });
}

/** The engine seam follows the same choice: the Tauri command, or the mock. */
export function createEngineSource(o: SourceOptions): EngineSource {
  return o.kind === "tauri" ? createTauriEngine() : createMockEngine(o.engine, { seed: o.seed, logError: o.logError, cert: o.cert });
}

export function isTauriWindow(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
