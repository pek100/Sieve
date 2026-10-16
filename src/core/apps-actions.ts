/**
 * Apps screen data (slice S3): pure reducers over the two settings values
 * `apps.levels` (map app key -> level, only non-default entries) and
 * `apps.pinned` (exe paths the user added), plus the derived app list.
 *
 * Nothing here reads a level above the ceiling: setLevel clamps on write and
 * every read goes through policy.effectiveLevel, so a stored value from a
 * time when the ceiling was higher is still shown and counted as clamped.
 */
import type { Snapshot } from "@/data/protocol";
import { appIdentity, category, exeStem, groupApps, isActiveFlow, isSieved, type AppGroup, type Category } from "./apps";
import { DEFAULT_LEVEL, effectiveLevel, minLevel, requestedLevel, type Level } from "./policy";

export type Levels = Readonly<Record<string, Level>>;
export type Pinned = readonly string[];

/** Store only what differs from the default, so "reset" and "never touched" read the same. */
function withLevel(levels: Levels, key: string, level: Level): Levels {
  const next: Record<string, Level> = { ...levels };
  if (level === DEFAULT_LEVEL) delete next[key];
  else next[key] = level;
  return next;
}

/** Set one app's level, clamped to the ceiling (`top`) so nothing above it is ever stored. */
export function setLevel(levels: Levels, key: string, level: Level, top: Level): Levels {
  return withLevel(levels, key, minLevel(level, top));
}

/** Every app that was off goes back to watch. Apps at sieve keep it. */
export function watchAll(levels: Levels): Levels {
  const next: Record<string, Level> = {};
  for (const [k, v] of Object.entries(levels)) if (v !== "off") next[k] = v;
  return next;
}

/** Every listed app goes to off. */
export function stopAll(levels: Levels, keys: readonly string[]): Levels {
  return keys.reduce((acc, k) => withLevel(acc, k, "off"), levels);
}

/** Forget every choice: all apps read the default level again. */
export function resetLevels(): Levels {
  return {};
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

/** The level an app actually runs at: its stored choice clamped to the ceiling. */
export function levelOf(levels: Levels, key: string, top: Level): Level {
  return effectiveLevel(requestedLevel(levels, key), top);
}

/** How many apps are being sieved now (effective level at least watch and an active flow). */
export function sievedCount(snapshot: Snapshot | null, levels: Levels, top: Level): number {
  if (!snapshot) return 0;
  return groupApps(snapshot).filter((a) => isSieved(a, levelOf(levels, a.key, top))).length;
}
