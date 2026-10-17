/**
 * App identity and grouping (primitive B3, starter set).
 * An app is identified by its product name, else its exe stem; executables
 * and pids are its children. Nothing here is stored: it is recomputed from
 * the newest snapshot every time (S23).
 */
import type { Flow, ProcessInfo, Snapshot } from "@/data/protocol";

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

/** "Being sieved": effectively on (policy.effectiveOn) and at least one active flow now. */
export function isSieved(app: Pick<AppGroup, "flows">, on: boolean): boolean {
  return on && app.flows.some(isActiveFlow);
}

// Snapshots are immutable once pushed; the tracked view is computed once per (snapshot, off set).
const trackedCache = new WeakMap<Snapshot, { off: ReadonlySet<string>; out: Snapshot }>();

/**
 * What Sieve tracks of a snapshot: the snapshot without the processes (and
 * their flows) of the apps the user turned off, by app key. The one place
 * per-app Off is applied; the chart, the counts and the saved history all
 * read through it. With nothing off it is the snapshot itself.
 */
export function trackedSnapshot(s: Snapshot, off: ReadonlySet<string>): Snapshot {
  if (off.size === 0) return s;
  const hit = trackedCache.get(s);
  if (hit && hit.off === off) return hit.out;
  const dropped = new Set(s.processes.filter((p) => off.has(appIdentity(p).key)).map((p) => p.pid));
  const out: Snapshot =
    dropped.size === 0
      ? s
      : { ...s, processes: s.processes.filter((p) => !dropped.has(p.pid)), flows: s.flows.filter((f) => !dropped.has(f.pid)) };
  trackedCache.set(s, { off, out });
  return out;
}
