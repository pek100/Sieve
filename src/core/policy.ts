/**
 * Per-app level (primitive B4): one ordered quantity off < watch < sieve.
 * Replaces AdGuard's three dependent switches (route, filter, HTTPS); the
 * "muted when the parent is off" rule falls out of the ordering.
 *
 * Effective level = min(requested, ceiling). The ceiling is derived from the
 * data switches: a level that needs a switch is reachable only when that
 * switch is on AND its live check has passed this session.
 */

export const LEVELS = ["off", "watch", "sieve"] as const;
export type Level = (typeof LEVELS)[number];

/** What an app gets when the user never chose: watching is read-only and safe. */
export const DEFAULT_LEVEL: Level = "watch";

/** Which data switch (settings key) each level needs. Levels absent here need nothing. */
export const LEVEL_REQUIRES: Partial<Record<Level, string>> = {
  sieve: "filtering.dns",
};

export function levelRank(level: Level): number {
  return LEVELS.indexOf(level);
}

export function minLevel(a: Level, b: Level): Level {
  return levelRank(a) <= levelRank(b) ? a : b;
}

/**
 * The highest level currently reachable.
 * @param switchOn  whether a data switch (by settings key) is on
 * @param checkPassed whether that switch's live check passed this session
 */
export function ceiling(
  switchOn: (key: string) => boolean,
  checkPassed: (key: string) => boolean,
): Level {
  let top: Level = LEVELS[0];
  for (const level of LEVELS) {
    const needs = LEVEL_REQUIRES[level];
    if (needs !== undefined && !(switchOn(needs) && checkPassed(needs))) break;
    top = level;
  }
  return top;
}

/**
 * Why `level` is out of reach, or null when it is reachable. Reads the switch
 * LEVEL_REQUIRES names for that level (never a hardcoded key), so a new
 * level or a new switch gets the right words for free.
 * @param switchOn whether a data switch (by settings key) is on
 * @param labelOf  a settings key's label
 */
export function lockedReason(
  level: Level,
  top: Level,
  switchOn: (key: string) => boolean,
  labelOf: (key: string) => string,
): string | null {
  const needs = LEVEL_REQUIRES[level];
  if (needs === undefined || levelRank(level) <= levelRank(top)) return null;
  const label = labelOf(needs);
  return switchOn(needs) ? `Needs ${label} to pass its live check` : `Needs ${label}, which is off`;
}

export function requestedLevel(levels: Readonly<Record<string, Level>>, appKey: string): Level {
  return levels[appKey] ?? DEFAULT_LEVEL;
}

export function effectiveLevel(requested: Level, top: Level): Level {
  return minLevel(requested, top);
}
