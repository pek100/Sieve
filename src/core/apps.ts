/**
 * App identity and grouping (primitive B3, starter set).
 * An app is identified by its product name, else its exe stem; executables
 * and pids are its children. Nothing here is stored: it is recomputed from
 * the newest snapshot every time (S23).
 */
import type { Flow, ProcessInfo, Snapshot } from "@/data/protocol";
import { levelRank, type Level } from "./policy";

export type Category = "mine" | "apps" | "system";

export interface AppGroup {
  /** Stable identity, lower case. Used as the settings key in apps.levels. */
  key: string;
  /** Display name. */
  name: string;
  /** Distinct exe paths, sorted. */
  exes: string[];
  pids: number[];
  flows: Flow[];
}

/** File name without directory and extension: "C:\\x\\Code.exe" -> "Code". */
export function exeStem(path: string): string {
  const base = path.split(/[\\/]/).pop() ?? path;
  return base.replace(/\.[^.]+$/, "");
}

export function appIdentity(p: ProcessInfo): { key: string; name: string } {
  const product = p.product?.trim();
  if (product) return { key: product.toLowerCase(), name: product };
  if (p.exe) {
    const stem = exeStem(p.exe);
    return { key: stem.toLowerCase(), name: stem };
  }
  return { key: p.name.toLowerCase(), name: p.name };
}

export function groupApps(snapshot: Snapshot): AppGroup[] {
  const byKey = new Map<string, AppGroup>();
  const keyOfPid = new Map<number, string>();
  for (const p of snapshot.processes) {
    const { key, name } = appIdentity(p);
    keyOfPid.set(p.pid, key);
    let g = byKey.get(key);
    if (!g) {
      g = { key, name, exes: [], pids: [], flows: [] };
      byKey.set(key, g);
    }
    g.pids.push(p.pid);
    if (p.exe && !g.exes.includes(p.exe)) g.exes.push(p.exe);
  }
  for (const f of snapshot.flows) {
    const key = keyOfPid.get(f.pid);
    if (key !== undefined) byKey.get(key)?.flows.push(f);
  }
  const out = [...byKey.values()];
  for (const g of out) {
    g.exes.sort();
    g.pids.sort((a, b) => a - b);
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

const WINDOWS_DIR = /^[a-z]:\\windows\\/i;

function samePath(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

/**
 * Category derived from paths, never from a list of app names.
 * Pinned by the user -> mine; every exe under the Windows dir (or unreadable,
 * which only happens for protected system processes) -> system; else apps.
 */
export function category(app: Pick<AppGroup, "exes">, pinned: readonly string[]): Category {
  if (app.exes.some((e) => pinned.some((p) => samePath(e, p)))) return "mine";
  if (app.exes.length === 0 || app.exes.every((e) => WINDOWS_DIR.test(e))) return "system";
  return "apps";
}

/** A flow that talks to something: anything but a listening or unbound socket. */
export function isActiveFlow(f: Flow): boolean {
  return f.remote !== null && f.state !== "listen";
}

/** "Being sieved": effective level at least watch and at least one active flow now. */
export function isSieved(app: Pick<AppGroup, "flows">, effective: Level): boolean {
  return levelRank(effective) >= levelRank("watch") && app.flows.some(isActiveFlow);
}
