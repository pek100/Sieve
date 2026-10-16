/**
 * The stored settings document: { schema, values } where values holds only
 * non-default entries. Missing keys read as defaults; unknown keys are kept
 * (a newer Sieve may have written them) and ignored; a value with the wrong
 * shape reads as the default instead of crashing the UI.
 */
import { migrate } from "./migrate";
import {
  SETTINGS_SCHEMA,
  defaultValue,
  isSettingKey,
  isValidValue,
  type SettingKey,
  type SettingValue,
} from "./registry";

export interface SettingsDoc {
  schema: number;
  values: Readonly<Record<string, unknown>>;
}

export const EMPTY_DOC: SettingsDoc = { schema: SETTINGS_SCHEMA, values: {} };

function sameValue(a: unknown, b: unknown): boolean {
  return a === b || JSON.stringify(a) === JSON.stringify(b);
}

/** Turn whatever storage returned into a current-schema document. */
export function normalizeDoc(raw: unknown): SettingsDoc {
  if (typeof raw !== "object" || raw === null) return EMPTY_DOC;
  const r = raw as { schema?: unknown; values?: unknown };
  const values = typeof r.values === "object" && r.values !== null && !Array.isArray(r.values) ? r.values : {};
  const schema = typeof r.schema === "number" ? r.schema : SETTINGS_SCHEMA;
  return migrate({ schema, values: values as Record<string, unknown> });
}

export function readValue<K extends SettingKey>(doc: SettingsDoc, key: K): SettingValue<K> {
  const v = doc.values[key];
  return v !== undefined && isValidValue(key, v) ? (v as SettingValue<K>) : defaultValue(key);
}

export function writeValue<K extends SettingKey>(doc: SettingsDoc, key: K, value: SettingValue<K>): SettingsDoc {
  if (!isValidValue(key, value)) throw new Error(`Setting ${key}: invalid value ${JSON.stringify(value)}`);
  const values: Record<string, unknown> = { ...doc.values };
  if (sameValue(value, defaultValue(key))) delete values[key];
  else values[key] = value;
  return { schema: doc.schema, values };
}

export function resetValue(doc: SettingsDoc, key: SettingKey): SettingsDoc {
  const values: Record<string, unknown> = { ...doc.values };
  delete values[key];
  return { schema: doc.schema, values };
}

/** Only the known, non-default values: what export writes. */
export function knownValues(doc: SettingsDoc): Partial<Record<SettingKey, unknown>> {
  const out: Partial<Record<SettingKey, unknown>> = {};
  for (const [k, v] of Object.entries(doc.values)) if (isSettingKey(k)) out[k] = v;
  return out;
}
