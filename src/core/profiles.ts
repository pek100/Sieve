/**
 * Profiles, the one law behind both pickers (Filters' Balanced, Strict and
 * Minimal; Tracking protection's Standard and Strict). A scale is an ordered
 * list of levels. Every item names the lowest level that turns it on, or null
 * for none. A level is in force exactly when every item is on at its own level
 * and every stricter one, and off below it; anything else is Custom. Nothing
 * here is stored: the profile is derived from the items' on and off, so it
 * can never disagree with them (S23).
 */

export const CUSTOM = "custom" as const;

export interface PresetItem<L extends string> {
  /** The lowest level that turns it on; null: no level does. */
  level: L | null;
  on: boolean;
}

/** Whether `level` turns on an item whose own level is `own`. */
export function inPreset<L extends string>(scale: readonly L[], level: L, own: L | null): boolean {
  return own !== null && scale.indexOf(own) >= 0 && scale.indexOf(own) <= scale.indexOf(level);
}

/** The level these items are at, or Custom. */
export function presetOf<L extends string>(scale: readonly L[], items: readonly PresetItem<L>[]): L | typeof CUSTOM {
  return scale.find((level) => items.every((i) => i.on === inPreset(scale, level, i.level))) ?? CUSTOM;
}
