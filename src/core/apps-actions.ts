/**
 * Apps screen data (slice S3): pure reducers over the two settings values
 * `apps.levels` (map app key -> "off", only apps the user turned off) and
 * `apps.pinned` (exe paths the user added), plus the derived app list.
 */
import type { Snapshot } from "@/data/protocol";
import { appIdentity, category, exeStem, groupApps, isActiveFlow, isSieved, trackedSnapshot, type AppGroup, type Category } from "./apps";
import { DEFAULT_APP_STATE, canTurnOff, effectiveOn, offKeys, type AppState, type AppStates } from "./policy";

export type Pinned = readonly string[];

/** Set one app on or off. Only "off" is stored, so "on" and "never touched" read the same. */
export function setAppState(states: AppStates, key: string, state: AppState): AppStates {
  const next: Record<string, AppState> = { ...states };
  if (state === DEFAULT_APP_STATE || !canTurnOff(key)) delete next[key];
  else next[key] = state;
  return next;
}

/** Turn every app on: forget every Off. */
export function sieveAll(): AppStates {
  return {};
}

/** Turn every listed app off. */
export function offAll(states: AppStates, keys: readonly string[]): AppStates {
  return keys.reduce((acc, k) => setAppState(acc, k, "off"), states);
}

function samePath(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

/** Add an exe path. Blank paths and paths already pinned (any letter case) are absorbed. */
export function pin(pinned: Pinned, path: string): Pinned {
  const p = path.trim();
  if (!p || pinned.some((x) => samePath(x, p))) return pinned;
  return [...pinned, p];
}

/** Remove every pinned path that belongs to the app with this key. */
export function unpin(pinned: Pinned, key: string, apps: readonly Pick<AppEntry, "key" | "pinnedPaths">[]): Pinned {
  const paths = apps.find((a) => a.key === key)?.pinnedPaths ?? [];
  return pinned.filter((p) => !paths.some((x) => samePath(x, p)));
}

/** A path the user can pin: ends in .exe after trimming. */
export function isPinnablePath(path: string): boolean {
  return /\.exe$/i.test(path.trim()) && exeStem(path.trim()).length > 0;
}

export interface AppEntry extends AppGroup {
  category: Category;
  /** Pinned paths that belong to this app (empty when not pinned). */
  pinnedPaths: string[];
  /** Flows that talk to something now (see isActiveFlow). */
  activeCount: number;
}

/**
 * The Apps screen list: every app in the newest snapshot, plus pinned exes
 * that are not running (they show under Mine with zero connections).
 */
export function listApps(snapshot: Snapshot | null, pinned: Pinned): AppEntry[] {
  const groups = snapshot ? groupApps(snapshot) : [];
  const byKey = new Map(groups.map((g) => [g.key, { ...g, exes: [...g.exes] }]));
  for (const path of pinned) {
    if ([...byKey.values()].some((g) => g.exes.some((e) => samePath(e, path)))) continue;
    const { key, name } = appIdentity({ pid: 0, exe: path, name: exeStem(path), product: null });
    const existing = byKey.get(key);
    if (existing) existing.exes.push(path);
    else byKey.set(key, { key, name, exes: [path], pids: [], flows: [] });
  }
  return [...byKey.values()]
    .map((g) => ({
      ...g,
      category: category(g, pinned),
      pinnedPaths: pinned.filter((p) => g.exes.some((e) => samePath(e, p))),
      activeCount: g.flows.filter(isActiveFlow).length,
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export const CATEGORY_ORDER: readonly Category[] = ["mine", "apps", "system"];

export interface AppSection {
  category: Category;
  apps: AppEntry[];
}

/** Sections in fixed order (Mine, Apps, System), each sorted by name. Empty sections are kept. */
export function sections(apps: readonly AppEntry[]): AppSection[] {
  return CATEGORY_ORDER.map((c) => ({ category: c, apps: apps.filter((a) => a.category === c) }));
}

/** Search over name, key and exe paths, case-insensitive. Blank matches everything. */
export function matchesQuery(app: Pick<AppEntry, "name" | "key" | "exes">, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return app.name.toLowerCase().includes(q) || app.key.includes(q) || app.exes.some((e) => e.toLowerCase().includes(q));
}

/** How many apps are being sieved now: effectively on (global and app) with an active flow. */
export function sievedCount(snapshot: Snapshot | null, states: AppStates, globalOn: boolean): number {
  if (!snapshot) return 0;
  return groupApps(trackedSnapshot(snapshot, offKeys(states))).filter((a) => isSieved(a, effectiveOn(globalOn, states, a.key))).length;
}
