/**
 * The stored settings document: { schema, values } where values holds only
 * non-default entries. Missing keys read as defaults; unknown keys are kept
 * (a newer Sieve may have written them) and ignored; a value with the wrong
 * shape reads as the default instead of crashing the UI.
 */
import { SCHEMA_BEFORE_ON_DEFAULTS, migrate } from "./migrate";
import {
  POLICY_BUDGETS,
  SETTINGS_SCHEMA,
  budgetBytes,
  budgetProblem,
  defaultValue,
  isAvailable,
  isSettingKey,
  isValidValue,
  settingDef,
  unavailableUntil,
  type SettingKey,
  type SettingValue,
} from "./registry";

export interface SettingsDoc {
  schema: number;
  values: Readonly<Record<string, unknown>>;
}

export const EMPTY_DOC: SettingsDoc = { schema: SETTINGS_SCHEMA, values: {} };

/**
 * What an install from before schema 6 reads when nothing is stored: the
 * switches on for a new install (`ON_FOR_NEW_INSTALLS`) off. Also what the
 * settings store reads until its document is loaded, so nothing shows one on
 * before the stored answer is in.
 */
export const OLD_INSTALL_DOC: SettingsDoc = migrate({ schema: SCHEMA_BEFORE_ON_DEFAULTS, values: {} });

function sameValue(a: unknown, b: unknown): boolean {
  return a === b || JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Turn whatever storage returned into a current-schema document. Only nothing
 * stored at all is a new install (`EMPTY_DOC`, today's defaults). Anything else
 * was written by some Sieve: one that is not a document, or carries no schema,
 * reads as a document from before schema 6, so it keeps the switches on for a
 * new install off rather than guessing them on.
 */
export function normalizeDoc(raw: unknown): SettingsDoc {
  if (raw === undefined) return EMPTY_DOC;
  if (typeof raw !== "object" || raw === null) return OLD_INSTALL_DOC;
  const r = raw as { schema?: unknown; values?: unknown };
  const values = typeof r.values === "object" && r.values !== null && !Array.isArray(r.values) ? r.values : {};
  const schema = typeof r.schema === "number" ? r.schema : SCHEMA_BEFORE_ON_DEFAULTS;
  return migrate({ schema, values: values as Record<string, unknown> });
}

/** What an unavailable setting reads: its default, but off for a data switch, whose default may be on. */
function unavailableValue<K extends SettingKey>(key: K): SettingValue<K> {
  return (settingDef(key).kind === "dataSwitch" ? false : defaultValue(key)) as SettingValue<K>;
}

/**
 * The value in force. An unavailable setting reads as its default whatever is
 * stored, and an unavailable data switch reads off, so it is never on; its
 * stored value is kept (not read) for the build that makes it available again.
 */
export function readValue<K extends SettingKey>(doc: SettingsDoc, key: K): SettingValue<K> {
  if (!isAvailable(key)) return unavailableValue(key);
  const v = doc.values[key];
  return v !== undefined && isValidValue(key, v) ? (v as SettingValue<K>) : defaultValue(key);
}

/**
 * Store a value. An unavailable setting takes only what it reads (which clears it).
 * A value that would put its group over the engine's budget is refused with a
 * sentence the person reads; one that makes an oversized group smaller is not.
 */
export function writeValue<K extends SettingKey>(doc: SettingsDoc, key: K, value: SettingValue<K>): SettingsDoc {
  if (!isValidValue(key, value)) throw new Error(`Setting ${key}: invalid value ${JSON.stringify(value)}`);
  const available = isAvailable(key);
  if (!available && !sameValue(value, unavailableValue(key))) {
    throw new Error(`Setting ${key} is not available in this version of Sieve (until ${unavailableUntil(key)})`);
  }
  const values: Record<string, unknown> = { ...doc.values };
  if (!available || sameValue(value, defaultValue(key))) delete values[key];
  else values[key] = value;
  const next = { schema: doc.schema, values };
  const budget = POLICY_BUDGETS.find((b) => b.keys.includes(key));
  if (budget) {
    const after = budgetBytes(budget, (k) => readValue(next, k));
    if (after > budget.bytes && after > budgetBytes(budget, (k) => readValue(doc, k))) throw new Error(budgetProblem(budget, after));
  }
  return next;
}

export function resetValue(doc: SettingsDoc, key: SettingKey): SettingsDoc {
  const values: Record<string, unknown> = { ...doc.values };
  delete values[key];
  return { schema: doc.schema, values };
}

/** Only the known, available, non-default values: what export writes. */
export function knownValues(doc: SettingsDoc): Partial<Record<SettingKey, unknown>> {
  const out: Partial<Record<SettingKey, unknown>> = {};
  for (const [k, v] of Object.entries(doc.values)) if (isSettingKey(k) && isAvailable(k)) out[k] = v;
  return out;
}
