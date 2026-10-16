/**
 * Settings migrations. Adding a key with a default never bumps the schema.
 * Renaming or retyping a key does: bump SETTINGS_SCHEMA and add a step here
 * that maps documents of schema N to N + 1.
 */
import { SETTINGS_SCHEMA } from "./registry";

type Values = Record<string, unknown>;

/** STEPS[n] upgrades a schema-n document to schema n + 1. */
const STEPS: Record<number, (values: Values) => Values> = {};

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
