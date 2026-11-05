import { describe, expect, it } from "vitest";
import { SETTINGS_SCHEMA } from "@/core/settings/registry";
import { createSettingsStore, LOCAL_KEY, localBackend, memoryBackend } from "./settings-store";

describe("settings store (seam law: only non-default values are stored, defaults read back)", () => {
  it("reads defaults before and after an empty load", async () => {
    const s = createSettingsStore(memoryBackend());
    expect(s.get("sampling.enabled")).toBe(true);
    await s.ready;
    expect(s.get("appearance.theme")).toBe("dark");
    expect(s.get("filtering.engine")).toBe(false);
  });

  it("stores only non-default values and drops a value set back to its default", async () => {
    const backend = memoryBackend();
    const s = createSettingsStore(backend);
    await s.set("appearance.theme", "light");
    expect(await backend.load()).toEqual({ schema: SETTINGS_SCHEMA, values: { "appearance.theme": "light" } });
    await s.set("appearance.theme", "dark");
    expect(await backend.load()).toEqual({ schema: SETTINGS_SCHEMA, values: {} });
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
