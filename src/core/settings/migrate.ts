/**
 * Settings migrations. Adding a key with a default never bumps the schema.
 * Renaming or retyping a key does: bump SETTINGS_SCHEMA and add a step here
 * that maps documents of schema N to N + 1.
 */
import { SETTINGS_SCHEMA } from "./registry";

type Values = Record<string, unknown>;

/**
 * 1 -> 2: per-app levels (off < watch < sieve, default watch) became on/off
 * per app (default sieve). An app the user turned off stays off; every other
 * entry ("watch", "sieve", or anything unreadable) is the new default, so it
 * is dropped (defaults are never stored). `filtering.perApp` is gone from the
 * registry; its stored value is left as an unknown key (kept, ignored).
 */
export function levelsToOnOff(values: Values): Values {
  const levels = values["apps.levels"];
  if (typeof levels !== "object" || levels === null || Array.isArray(levels)) return values;
  const off = Object.fromEntries(Object.entries(levels).filter(([, v]) => v === "off"));
  const next: Values = { ...values };
  if (Object.keys(off).length === 0) delete next["apps.levels"];
  else next["apps.levels"] = off;
  return next;
}

/** Keys a step removes for good: a stored value would mean something Sieve no longer does. */
export const RETIRED_KEYS = ["filtering.systemDns"] as const;

/**
 * 2 -> 3: "Point Windows at Sieve" is gone (2026-10-18). It set every
 * adapter's DNS to 127.0.0.1 and ::1, and a reboot with Sieve not running
 * left the computer with no DNS. Sieve never writes Windows DNS now, so its
 * switch `filtering.systemDns` is dropped, not kept as an unknown key: no
 * build may ever read an old "on" back.
 */
export function dropSystemDns(values: Values): Values {
  const next: Values = { ...values };
  for (const k of RETIRED_KEYS) delete next[k];
  return next;
}

/** STEPS[n] upgrades a schema-n document to schema n + 1. */
const STEPS: Record<number, (values: Values) => Values> = {
  1: levelsToOnOff,
  2: dropSystemDns,
};

export function migrate(doc: { schema: number; values: Values }): { schema: number; values: Values } {
  if (doc.schema > SETTINGS_SCHEMA) {
    // Written by a newer Sieve: keep everything, read what we understand.
    return doc;
  }
  let { schema, values } = doc;
  while (schema < SETTINGS_SCHEMA) {
    const step = STEPS[schema];
    if (!step) throw new Error(`Settings: no migration from schema ${schema}`);
    values = step(values);
    schema += 1;
  }
  return { schema, values };
}
