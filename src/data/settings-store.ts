/**
 * Settings storage seam. The document format and rules live in
 * src/core/settings; this file only moves the document in and out of
 * storage: localStorage in the browser, tauri-plugin-store (settings.json
 * in the app's data dir) in Tauri.
 */
import { OLD_INSTALL_DOC, normalizeDoc, readValue, resetValue, writeValue, type SettingsDoc } from "@/core/settings/document";
import { ON_FOR_NEW_INSTALLS, type SettingKey, type SettingValue } from "@/core/settings/registry";

export interface SettingsBackend {
  readonly kind: "memory" | "local" | "tauri";
  /** The stored document; undefined only when nothing is stored (a new install). */
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
        // Something was stored, so this is no new install: it reads as an old one (normalizeDoc).
        return null;
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
  /** Swap in a whole document (import, reset all, their undo) in one write. */
  replace(doc: SettingsDoc): Promise<void>;
  subscribe(listener: () => void): () => void;
  /**
   * A new install whose engine has not been read yet (`NEW_INSTALL_MARK`): the
   * switches on for a new install read on, but whether this is a new install is
   * settled only by the engine's first answer (the engine controller).
   */
  unsettled(): boolean;
  /**
   * The engine controller's one write, once, at the engine's first answer: the
   * engine was set up by an older Sieve (a lost settings file, another Windows
   * account), so `held` are its switches as the engine holds them, stored here;
   * or the engine is new too (`held` null) and the defaults stand. It changes
   * nothing the engine holds, so it needs no password.
   */
  settle(held: Partial<Record<(typeof ON_FOR_NEW_INSTALLS)[number], boolean>> | null): Promise<void>;
}

/**
 * Saved beside the document while the store is unsettled, so a write before
 * the engine's first answer (the guide's Skip) cannot make a new-looking
 * document of an install the engine already knows.
 */
export const NEW_INSTALL_MARK = "newInstall";

export function createSettingsStore(backend: SettingsBackend): SettingsStore {
  // Until the stored document is read, the switches on for a new install read off.
  let doc: SettingsDoc = OLD_INSTALL_DOC;
  let unsettled = false;
  const listeners = new Set<() => void>();
  const emit = () => listeners.forEach((l) => l());
  let saving: Promise<void> = Promise.resolve();

  const commit = (next: SettingsDoc) => {
    doc = next;
    emit();
    const snapshot: SettingsDoc = unsettled ? { ...next, [NEW_INSTALL_MARK]: true } as SettingsDoc : next;
    const written = saving.then(() => backend.save(snapshot));
    // This write's failure is its caller's; the next write still goes to the disk.
    saving = written.catch(() => undefined);
    return written;
  };

  const ready = backend.load().then((raw) => {
    doc = normalizeDoc(raw);
    // Nothing stored, or a document saved before the engine's first answer.
    unsettled = raw === undefined || (typeof raw === "object" && raw !== null && (raw as Record<string, unknown>)[NEW_INSTALL_MARK] === true);
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
    replace: async (next) => {
      await ready;
      return commit(normalizeDoc(next));
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    unsettled: () => unsettled,
    settle: async (held) => {
      await ready;
      if (!unsettled) return;
      unsettled = false;
      let next = doc;
      for (const k of ON_FOR_NEW_INSTALLS) {
        const v = held?.[k];
        if (typeof v === "boolean") next = writeValue(next, k, v);
      }
      return commit(next);
    },
  };
}
