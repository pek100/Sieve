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

export function requestedLevel(levels: Readonly<Record<string, Level>>, appKey: string): Level {
  return levels[appKey] ?? DEFAULT_LEVEL;
}

export function effectiveLevel(requested: Level, top: Level): Level {
  return minLevel(requested, top);
}
