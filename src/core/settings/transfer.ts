/**
 * Export, import, reset and search, all derived from the registry (B5).
 * Pure: the settings view and the settings store do the I/O.
 *
 * Import replaces: the file is the whole truth, so a known key the file does
 * not carry goes back to its default. The preview lists every key that would
 * change and every entry that is refused, before anything is applied. A data
 * switch is never turned on by an import; that entry is refused with the reason.
 */
import { SETTINGS_SCHEMA, SECTIONS, SETTING_KEYS, defaultValue, isSettingKey, isValidValue, settingDef, type SettingKey } from "./registry";
import { knownValues, normalizeDoc, readValue, type SettingsDoc } from "./document";

/** Marks a file as Sieve settings, so a random JSON file is not read as one. */
export const EXPORT_KIND = "sieve.settings";

export interface Change {
  key: SettingKey;
  from: unknown;
  to: unknown;
}

export interface Refused {
  key: string;
  reason: string;
}

export type ImportPlan =
  | { ok: true; changes: Change[]; refused: Refused[]; next: SettingsDoc }
  | { ok: false; error: string };

function same(a: unknown, b: unknown): boolean {
  return a === b || JSON.stringify(a) === JSON.stringify(b);
}

/** The exported file: only known, non-default values (defaults travel as absence). */
export function exportText(doc: SettingsDoc): string {
  return `${JSON.stringify({ kind: EXPORT_KIND, schema: doc.schema, values: knownValues(doc) }, null, 2)}\n`;
}

/** The document with every known key at `values` (defaults dropped) plus the current doc's unknown keys. */
function docWith(current: SettingsDoc, values: Partial<Record<SettingKey, unknown>>): SettingsDoc {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(current.values)) if (!isSettingKey(k)) out[k] = v;
  for (const key of SETTING_KEYS) {
    const v = values[key];
    if (v !== undefined && !same(v, defaultValue(key))) out[key] = v;
  }
  return { schema: Math.max(current.schema, SETTINGS_SCHEMA), values: out };
}

function changesBetween(current: SettingsDoc, next: SettingsDoc): Change[] {
  return SETTING_KEYS.flatMap((key) => {
    const from = readValue(current, key);
    const to = readValue(next, key);
    return same(from, to) ? [] : [{ key, from, to }];
  });
}

/**
 * What importing `text` would do to `current`. A data switch is never turned
 * on by an import: it changes traffic or the system, so a person turns it on
 * where its checks run (safety asymmetry). Turning one off is imported.
 */
export function planImport(current: SettingsDoc, text: string): ImportPlan {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { ok: false, error: "This is not a settings file: it is not valid JSON." };
  }
  if (typeof raw !== "object" || raw === null || (raw as { kind?: unknown }).kind !== EXPORT_KIND) {
    return { ok: false, error: "This is not a Sieve settings file." };
  }
  let incoming: SettingsDoc;
  try {
    incoming = normalizeDoc(raw);
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
  const refused: Refused[] = [];
  const values: Partial<Record<SettingKey, unknown>> = {};
  for (const [key, v] of Object.entries(incoming.values)) {
    if (!isSettingKey(key)) {
      refused.push({ key, reason: "Not a setting in this version of Sieve" });
      continue;
    }
    if (!isValidValue(key, v)) {
      refused.push({ key, reason: "Not a valid value for this setting" });
      continue;
    }
    if (settingDef(key).kind === "dataSwitch" && v === true && readValue(current, key) !== true) {
      refused.push({ key, reason: "An import never turns this on; turn it on yourself in Settings" });
      continue;
    }
    values[key] = v;
  }
  // A refused known key keeps its current value rather than dropping to the default.
  for (const r of refused) if (isSettingKey(r.key)) values[r.key] = readValue(current, r.key);
  const next = docWith(current, values);
  return { ok: true, changes: changesBetween(current, next), refused, next };
}

/** Every known key back to its default; unknown keys (from a newer Sieve) are kept. */
export function resetPlan(current: SettingsDoc): { changes: Change[]; next: SettingsDoc } {
  const next = docWith(current, {});
  return { changes: changesBetween(current, next), next };
}

const sectionLabel = (id: string) => SECTIONS.find((s) => s.id === id)?.label ?? id;

/** Keys whose key, label, help, section or option names contain every word of `query`, in registry order. */
export function searchSettings(query: string): SettingKey[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return [...SETTING_KEYS];
  return SETTING_KEYS.filter((key) => {
    const d = settingDef(key);
    const options = d.kind === "enum" ? d.options.join(" ") : "";
    const hay = `${key} ${d.label} ${d.help} ${sectionLabel(d.section)} ${options}`.toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}

const capital = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/** A number with its unit, said the way a person reads it (1500 ms reads 1.5 s). */
export function formatNumber(value: number, unit: string): string {
  if (unit === "ms" && value >= 1000) return `${Math.round(value / 100) / 10} s`;
  return `${value} ${unit}`;
}

/** A value as words, for previews and summaries. */
export function formatValue(key: SettingKey, value: unknown): string {
  const d = settingDef(key);
  switch (d.kind) {
    case "enum":
      return typeof value === "string" ? capital(value) : String(value);
    case "boolean":
    case "dataSwitch":
      return value === true ? "On" : "Off";
    case "number":
      return typeof value === "number" ? formatNumber(value, d.unit) : String(value);
    case "map": {
      const n = typeof value === "object" && value !== null ? Object.keys(value).length : 0;
      return n === 0 ? "None set" : n === 1 ? "1 app set" : `${n} apps set`;
    }
    case "list": {
      const n = Array.isArray(value) ? value.length : 0;
      // Server addresses are short and are the point: say them.
      if (d.of.type === "upstream" && Array.isArray(value)) return n === 0 ? "None" : value.join(", ");
      return n === 0 ? "None" : n === 1 ? "1 item" : `${n} items`;
    }
  }
}

/** The choices a number setting offers: min to max in steps. */
export function numberChoices(key: SettingKey): number[] {
  const d = settingDef(key);
  if (d.kind !== "number") return [];
  const out: number[] = [];
  for (let v = d.min; v <= d.max; v += d.step) out.push(v);
  return out;
}
