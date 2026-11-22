import { describe, expect, it } from "vitest";
import { ON_FOR_NEW_INSTALLS, SETTINGS_SCHEMA } from "@/core/settings/registry";
import { createSettingsStore, LOCAL_KEY, NEW_INSTALL_MARK, localBackend, memoryBackend } from "./settings-store";

describe("settings store (seam law: only non-default values are stored, defaults read back)", () => {
  it("reads defaults before and after an empty load; the switches on for a new install read off until the load", async () => {
    const s = createSettingsStore(memoryBackend());
    expect(s.get("sampling.enabled")).toBe(true);
    for (const k of ON_FOR_NEW_INSTALLS) expect(s.get(k), `${k} before the load`).toBe(false);
    await s.ready;
    expect(s.get("appearance.theme")).toBe("dark");
    for (const k of ON_FOR_NEW_INSTALLS) expect(s.get(k), `${k}: a new install`).toBe(true);
  });

  it("stores only non-default values and drops a value set back to its default", async () => {
    const backend = memoryBackend({ schema: SETTINGS_SCHEMA, values: {} });
    const s = createSettingsStore(backend);
    await s.set("appearance.theme", "light");
    expect(await backend.load()).toEqual({ schema: SETTINGS_SCHEMA, values: { "appearance.theme": "light" } });
    await s.set("appearance.theme", "dark");
    expect(await backend.load()).toEqual({ schema: SETTINGS_SCHEMA, values: {} });
  });

  describe("a new install is settled by the engine's first answer", () => {
    it("nothing stored: unsettled, and a write before the answer keeps the mark, so the next run is unsettled too", async () => {
      const backend = memoryBackend();
      const s = createSettingsStore(backend);
      await s.ready;
      expect(s.unsettled()).toBe(true);
      await s.set("startup.welcomeDone", true);
      expect(await backend.load()).toEqual({ schema: SETTINGS_SCHEMA, values: { "startup.welcomeDone": true }, [NEW_INSTALL_MARK]: true });
      const next = createSettingsStore(backend);
      await next.ready;
      expect(next.unsettled()).toBe(true);
      for (const k of ON_FOR_NEW_INSTALLS) expect(next.get(k), k).toBe(true);
    });

    it("a new engine too: the defaults stand and the mark goes", async () => {
      const backend = memoryBackend();
      const s = createSettingsStore(backend);
      await s.settle(null);
      expect(s.unsettled()).toBe(false);
      expect(await backend.load()).toEqual({ schema: SETTINGS_SCHEMA, values: {} });
      const next = createSettingsStore(backend);
      await next.ready;
      expect(next.unsettled()).toBe(false);
      for (const k of ON_FOR_NEW_INSTALLS) expect(next.get(k), k).toBe(true);
    });

    it("an engine an older Sieve set up: its switches are stored as it holds them, and stay so", async () => {
      const backend = memoryBackend();
      const s = createSettingsStore(backend);
      await s.settle({ "filtering.engine": false, "filtering.https": false, "filtering.content": false });
      for (const k of ON_FOR_NEW_INSTALLS) expect(s.get(k), k).toBe(false);
      const next = createSettingsStore(backend);
      await next.ready;
      expect(next.unsettled()).toBe(false);
      for (const k of ON_FOR_NEW_INSTALLS) expect(next.get(k), k).toBe(false);
      // Settling happens once: a later call changes nothing.
      await next.settle({ "filtering.engine": true });
      expect(next.get("filtering.engine")).toBe(false);
    });

    it("a stored document, old or current, is never unsettled", async () => {
      for (const stored of [{ schema: 5, values: {} }, { schema: SETTINGS_SCHEMA, values: {} }, null, "garbage"]) {
        const s = createSettingsStore(memoryBackend(stored));
        await s.ready;
        expect(s.unsettled(), JSON.stringify(stored)).toBe(false);
      }
      const old = createSettingsStore(memoryBackend({ schema: 5, values: {} }));
      await old.settle({ "filtering.engine": true });
      expect(old.get("filtering.engine"), "an old install keeps its off").toBe(false);
    });
  });

  it("replace swaps the whole document in one write, after the first load", async () => {
    const backend = memoryBackend({ schema: SETTINGS_SCHEMA, values: { "appearance.theme": "light" } });
    const s = createSettingsStore(backend);
    let emits = 0;
    s.subscribe(() => (emits += 1));
    await s.replace({ schema: SETTINGS_SCHEMA, values: { "sampling.intervalMs": 2000 } });
    expect(s.get("appearance.theme")).toBe("dark");
    expect(s.get("sampling.intervalMs")).toBe(2000);
    expect(await backend.load()).toEqual({ schema: SETTINGS_SCHEMA, values: { "sampling.intervalMs": 2000 } });
    // One emit for the load, one for the replace.
    expect(emits).toBe(2);
  });

  it("keeps unknown keys and reads a wrong-shaped value as the default", async () => {
    const s = createSettingsStore(
      memoryBackend({ schema: SETTINGS_SCHEMA, values: { "future.key": 3, "sampling.intervalMs": "fast" } }),
    );
    await s.ready;
    expect(s.get("sampling.intervalMs")).toBe(1000);
    expect(s.doc().values["future.key"]).toBe(3);
  });

  it("rejects a value outside the registry's shape", async () => {
    const s = createSettingsStore(memoryBackend());
    // @ts-expect-error: not one of the options
    await expect(s.set("appearance.theme", "neon")).rejects.toThrow(/invalid value/);
  });

  it("a failed save is its caller's to hear of, and the next write still reaches the disk", async () => {
    const inner = memoryBackend({ schema: SETTINGS_SCHEMA, values: {} });
    let fail = true;
    const s = createSettingsStore({
      ...inner,
      save: async (doc) => {
        if (fail) throw new Error("disk full");
        await inner.save(doc);
      },
    });
    await expect(s.set("appearance.theme", "light")).rejects.toThrow("disk full");
    fail = false;
    await s.set("sampling.intervalMs", 2000);
    expect(await inner.load()).toEqual({ schema: SETTINGS_SCHEMA, values: { "appearance.theme": "light", "sampling.intervalMs": 2000 } });
  });

  it("round-trips through localStorage and absorbs garbage", async () => {
    const a = createSettingsStore(localBackend(window.localStorage));
    await a.set("sampling.intervalMs", 2000);
    const b = createSettingsStore(localBackend(window.localStorage));
    await b.ready;
    expect(b.get("sampling.intervalMs")).toBe(2000);
    window.localStorage.setItem(LOCAL_KEY, "{not json");
    const c = createSettingsStore(localBackend(window.localStorage));
    await c.ready;
    expect(c.get("sampling.intervalMs")).toBe(1000);
    // Garbage is something stored, so not a new install: the switches on for one read off.
    expect(c.unsettled()).toBe(false);
    for (const k of ON_FOR_NEW_INSTALLS) expect(c.get(k), k).toBe(false);
  });

  it("notifies subscribers on change", async () => {
    const s = createSettingsStore(memoryBackend());
    let n = 0;
    s.subscribe(() => n++);
    await s.set("sampling.enabled", false);
    expect(n).toBeGreaterThan(0);
    expect(s.get("sampling.enabled")).toBe(false);
  });
});
