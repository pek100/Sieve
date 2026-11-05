/**
 * Settings migrations. Adding a key with a default never bumps the schema.
 * Renaming or retyping a key does: bump SETTINGS_SCHEMA and add a step here
 * that maps documents of schema N to N + 1.
 */
import { parseUpstream } from "../upstream";
import { SETTINGS_SCHEMA, SETTING_KEYS, defaultValue, isAvailable, settingDef, type SettingKey } from "./registry";

type Values = Record<string, unknown>;

/**
 * 1 -> 2: per-app levels (off < watch < sieve, default watch) became on/off
 * per app (default sieve). An app the user turned off stays off; every other
 * entry ("watch", "sieve", or anything unreadable) is the new default, so it
 * is dropped (defaults are never stored).
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

/**
 * 3 -> 4: a stored value of any data switch that is unavailable (registry
 * `unavailableUntil`) is dropped, so a stored "on" is off (off is the default,
 * never stored) and stays off when the switch comes back: the user turns it
 * on again where its checks run. Derived from the registry rather than a key
 * list, so the step and the attribute cannot disagree. Other unavailable keys
 * are kept: they hold no traffic change and read as their default while
 * unavailable. No key is unavailable today; the old decoder stays.
 */
export function offUnavailableSwitches(values: Values): Values {
  const next: Values = { ...values };
  for (const k of SETTING_KEYS) if (settingDef(k).kind === "dataSwitch" && !isAvailable(k)) delete next[k];
  return next;
}

const UPSTREAMS = "filtering.upstreams" satisfies SettingKey;

/**
 * 4 -> 5: the app-hosted DNS proxy is gone (engine slice 4). `filtering.dns`
 * and the never-available `filtering.perApp` are deleted. `filtering.upstreams`
 * now holds encrypted upstreams: of a stored list, the entries that parse as
 * DoH, DoT or DoQ come first, followed by the defaults not already present;
 * none parses (every list an old build could store, bare addresses): the key
 * goes, so the defaults apply. A plain address is never carried forward,
 * because the engine sends no plain DNS.
 */
export function retireDnsProxy(values: Values): Values {
  const next: Values = { ...values };
  delete next["filtering.dns"];
  delete next["filtering.perApp"];
  const stored = next[UPSTREAMS];
  delete next[UPSTREAMS];
  if (!Array.isArray(stored)) return next;
  const kept = stored.filter((v): v is string => typeof v === "string" && parseUpstream(v) !== null);
  if (kept.length > 0) next[UPSTREAMS] = [...new Set([...kept, ...defaultValue(UPSTREAMS)])];
  return next;
}

/** STEPS[n] upgrades a schema-n document to schema n + 1. */
const STEPS: Record<number, (values: Values) => Values> = {
  1: levelsToOnOff,
  2: dropSystemDns,
  3: offUnavailableSwitches,
  4: retireDnsProxy,
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
