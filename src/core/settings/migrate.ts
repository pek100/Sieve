/**
 * Settings migrations. Adding a key with a default never bumps the schema.
 * Renaming or retyping a key does, and so does changing a default that a stored
 * document relies on (absence reads as the default): bump SETTINGS_SCHEMA and
 * add a step here that maps documents of schema N to N + 1.
 */
import { parseUpstream } from "../upstream";
import { ON_FOR_NEW_INSTALLS, SETTINGS_SCHEMA, SETTING_KEYS, defaultValue, isAvailable, settingDef, type SettingKey } from "./registry";

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
 * unavailable. None is today: `filtering.https` and `filtering.content` became
 * available on 2026-11-20 (the owner's decisions, docs/tasks/2026-11-06-open-decisions.md),
 * and no stored "on" of either could exist, since a write of one was refused
 * while it was unavailable. The old decoder stays.
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
 * goes, so the defaults apply. A plain address is never carried forward: the
 * list is only ever encrypted, and plain DNS is the user's own later choice
 * (`filtering.dnsEncryption`, a new key with a default, so no step of its own).
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

/** The last schema whose documents read routing, HTTPS and page filtering as off when nothing was stored. */
export const SCHEMA_BEFORE_ON_DEFAULTS = 5;

/**
 * 5 -> 6: routing, HTTPS and page filtering became on for a new install (the
 * owner's decision of 2026-11-22, registry `ON_FOR_NEW_INSTALLS`). A document
 * from before was written by an install that had them off unless its person
 * turned one on, and absence read as off. So absence, or anything that is not a
 * stored boolean, becomes a stored off (off is no longer the default, so it is
 * stored), and a stored on is the new default, so it goes. The install reads
 * exactly what it read before: an upgrade never turns one on.
 */
export function keepSwitchesAsTheyWere(values: Values): Values {
  const next: Values = { ...values };
  for (const k of ON_FOR_NEW_INSTALLS) {
    if (next[k] === true) delete next[k];
    else next[k] = false;
  }
  return next;
}

/** STEPS[n] upgrades a schema-n document to schema n + 1. */
const STEPS: Record<number, (values: Values) => Values> = {
  1: levelsToOnOff,
  2: dropSystemDns,
  3: offUnavailableSwitches,
  4: retireDnsProxy,
  [SCHEMA_BEFORE_ON_DEFAULTS]: keepSwitchesAsTheyWere,
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
