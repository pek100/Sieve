/**
 * Settings storage seam. The document format and rules live in
 * src/core/settings; this file only moves the document in and out of
 * storage: localStorage in the browser, tauri-plugin-store (settings.json
 * in the app's data dir) in Tauri.
 */
import { EMPTY_DOC, normalizeDoc, readValue, resetValue, writeValue, type SettingsDoc } from "@/core/settings/document";
import type { SettingKey, SettingValue } from "@/core/settings/registry";

export interface SettingsBackend {
  readonly kind: "memory" | "local" | "tauri";
  load(): Promise<unknown>;
  save(doc: SettingsDoc): Promise<void>;
}

export const LOCAL_KEY = "sieve.settings";

export function memoryBackend(initial?: unknown): SettingsBackend {
  let stored: unknown = initial;
  return {
    kind: "memory",
    load: async () => stored,
    save: async (doc) => {
      stored = JSON.parse(JSON.stringify(doc));
    },
  };
}

export function localBackend(storage: Storage = window.localStorage): SettingsBackend {
  return {
    kind: "local",
    async load() {
      const raw = storage.getItem(LOCAL_KEY);
      if (raw === null) return undefined;
      try {
        return JSON.parse(raw);
      } catch {
        return undefined;
      }
    },
    async save(doc) {
      storage.setItem(LOCAL_KEY, JSON.stringify(doc));
    },
  };
}

export function tauriBackend(): SettingsBackend {
  const open = import("@tauri-apps/plugin-store").then((m) => m.load("settings.json", { autoSave: false, defaults: {} }));
  return {
    kind: "tauri",
    async load() {
      const store = await open;
      return store.get("doc");
    },
    async save(doc) {
      const store = await open;
      await store.set("doc", doc);
      await store.save();
    },
  };
}

export interface SettingsStore {
  readonly backend: SettingsBackend["kind"];
  /** Resolves once the stored document has been read (defaults until then). */
  ready: Promise<void>;
  doc(): SettingsDoc;
  get<K extends SettingKey>(key: K): SettingValue<K>;
  set<K extends SettingKey>(key: K, value: SettingValue<K>): Promise<void>;
  reset(key: SettingKey): Promise<void>;
  subscribe(listener: () => void): () => void;
}

export function createSettingsStore(backend: SettingsBackend): SettingsStore {
  let doc: SettingsDoc = EMPTY_DOC;
  const listeners = new Set<() => void>();
  const emit = () => listeners.forEach((l) => l());
  let saving: Promise<void> = Promise.resolve();

  const commit = (next: SettingsDoc) => {
    doc = next;
    emit();
    const snapshot = next;
    saving = saving.then(() => backend.save(snapshot));
    return saving;
  };

  const ready = backend.load().then((raw) => {
    doc = normalizeDoc(raw);
    emit();
  });

  return {
    backend: backend.kind,
    ready,
    doc: () => doc,
    get: (key) => readValue(doc, key),
    // Writes wait for the first load so a stored document never overwrites them.
    set: async (key, value) => {
      await ready;
      return commit(writeValue(doc, key, value));
    },
    reset: async (key) => {
      await ready;
      return commit(resetValue(doc, key));
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}
