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
import { createMockDns, DNS_SCENARIOS, type DnsScenario } from "./dns-mock";
import { createTauriDns, type DnsSource } from "./dns-source";

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
  /** Mock DNS scenario (?dns=off|running|error, default off). */
  dns: DnsScenario;
  /** Mock: report AdGuard as running (?adguard=1). */
  adguard: boolean;
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
  const d = q.get("dns");
  const dns = (DNS_SCENARIOS as readonly string[]).includes(d ?? "") ? (d as DnsScenario) : "off";
  return { kind, seed, scenario, dns, adguard: q.get("adguard") === "1" };
}

export function createSource(o: SourceOptions): SieveSource {
  return o.kind === "tauri" ? createTauriSource() : createMockSource({ seed: o.seed, scenario: o.scenario });
}

/** The DNS seam follows the same choice: Tauri commands, or the mock. */
export function createDnsSource(o: SourceOptions): DnsSource {
  return o.kind === "tauri" ? createTauriDns() : createMockDns({ seed: o.seed, scenario: o.dns, adguard: o.adguard });
}

/** Pick the source for this window. */
export function resolveSource(env: { search: string; isTauri: boolean }): SieveSource {
  return createSource(sourceOptions(env));
}

export function isTauriWindow(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
