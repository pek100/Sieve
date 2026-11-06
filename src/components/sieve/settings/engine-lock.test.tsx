import { act, render, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ENGINE_LOCK_TEXT, ENGINE_UNREACHED, enginePhase, engineStatus, type EngineUnreached } from "@/core/engine";
import { SETTING_KEYS, isAvailable, needsEngine, type SettingKey } from "@/core/settings/registry";
import { createMockEngine, ENGINE_SCENARIOS, type EngineScenario } from "@/data/engine-mock";
import type { EngineSource } from "@/data/engine-source";
import { createMockSource } from "@/data/mock-source";
import type { EnginePolicy } from "@/data/protocol";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { SettingsScreen } from "./settings-screen";

vi.mock("next/navigation", () => ({ usePathname: () => "/settings/" }));

/** Every setting the engine carries out, from the registry (never a key spelled here). */
const ENGINE_KEYS: SettingKey[] = SETTING_KEYS.filter((k) => isAvailable(k) && needsEngine(k));

/** The mock engine with every SetPolicy recorded; `checking` never answers. */
function recorded(scenario: EngineScenario | "checking") {
  const mock = createMockEngine(scenario === "checking" ? "idle" : scenario);
  const policies: EnginePolicy[] = [];
  const source: EngineSource = {
    ...mock,
    probe: scenario === "checking" ? () => new Promise(() => {}) : mock.probe,
    setPolicy: (p) => {
      policies.push(p);
      return mock.setPolicy(p);
    },
  };
  return { source, policies };
}

async function setup(scenario: EngineScenario | "checking", storedOn: boolean) {
  const engine = recorded(scenario);
  const values = Object.fromEntries(ENGINE_KEYS.map((k) => [k, storedOn]));
  const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend({ schema: 4, values }), engine: engine.source });
  render(
    <SieveProvider runtime={runtime}>
      <SettingsScreen />
    </SieveProvider>,
  );
  await act(async () => {
    await runtime.settings.ready;
  });
  if (scenario !== "checking") await vi.waitFor(() => expect(runtime.store.getState().engine.probe ?? runtime.store.getState().engine.error).not.toBeNull());
  return { runtime, policies: engine.policies, phase: () => enginePhase(runtime.store.getState().engine) };
}

const row = (key: SettingKey) => document.querySelector<HTMLElement>(`[data-setting="${key}"]`)!;

describe("a setting the engine carries out is locked while the engine cannot take it", () => {
  it("the registry names at least one such setting (so the law below cannot pass empty)", () => {
    expect(ENGINE_KEYS.length).toBeGreaterThan(0);
  });

  it.each(["checking", ...ENGINE_SCENARIOS] as const)("law: every needsEngine switch follows the engine lock in %s", async (scenario) => {
    // Stored on, as an old file or another window would leave it: the row must not show it as in force.
    const s = await setup(scenario, true);
    const phase = s.phase();
    const unreached = (ENGINE_UNREACHED as readonly string[]).includes(phase);
    for (const key of ENGINE_KEYS) {
      const r = row(key);
      const sw = within(r).getByRole("switch");
      const lock = r.querySelector("[data-lock=engine]");
      if (unreached) {
        expect(sw, `${scenario} ${key}`).toBeDisabled();
        expect(sw, `${scenario} ${key}`).not.toBeChecked();
        expect(lock, `${scenario} ${key}`).toHaveTextContent(ENGINE_LOCK_TEXT[phase as EngineUnreached]);
        expect(s.runtime.settings.get(key), `${scenario} ${key}`).toBe(true);
      } else {
        expect(lock, `${scenario} ${key}`).toBeNull();
        expect(sw, `${scenario} ${key}`).toBeEnabled();
      }
    }
    if (unreached) expect(s.policies, scenario).toEqual([]);
  });

  it("refused: the switch is disabled with the reason, a click changes nothing and sends nothing", async () => {
    const s = await setup("refused", false);
    expect(s.phase()).toBe("refused");
    for (const key of ENGINE_KEYS) {
      const r = row(key);
      const sw = within(r).getByRole("switch");
      expect(sw).toBeDisabled();
      expect(r.querySelector("[data-lock=engine]")).toHaveTextContent(
        "This copy of Sieve is not the installed one, so it cannot control the engine. Open Sieve from the Start menu.",
      );
      await userEvent.click(sw);
      expect(s.runtime.settings.get(key)).toBe(false);
      expect(sw).not.toBeChecked();
    }
    expect(s.policies).toEqual([]);
  });

  it("a locked row uses the known engine policy even when the saved wish differs", async () => {
    const s = await setup("idle", false);
    const e = s.runtime.store.getState().engine;
    const pipe = e.probe!.pipe!;
    if (pipe.kind !== "welcome") throw new Error("idle must answer with Status");
    await act(async () => {
      s.runtime.store.setEngine({
        ...e,
        error: "read failed",
        probe: { ...e.probe!, pipe: { ...pipe, status: { ...pipe.status, policy: { ...pipe.status.policy, engine: true } } } },
      });
    });
    expect(engineStatus(s.runtime.store.getState().engine)!.policy.engine).toBe(true);
    for (const key of ENGINE_KEYS) {
      const sw = within(row(key)).getByRole("switch");
      expect(sw).toBeDisabled();
      expect(sw).toBeChecked();
      await userEvent.click(sw);
      expect(s.runtime.settings.get(key)).toBe(false);
    }
    expect(s.policies).toEqual([]);
  });

  it("idle: unlocked, and a flip reaches the engine", async () => {
    const s = await setup("idle", false);
    for (const key of ENGINE_KEYS) {
      const sw = within(row(key)).getByRole("switch");
      expect(sw).toBeEnabled();
      await userEvent.click(sw);
      await vi.waitFor(() => expect(s.phase()).toBe("routing"));
      expect(sw).toBeChecked();
    }
    expect(s.policies).toEqual([{ revision: 1, engine: true, sieving: true, off_apps: [], lists: null, domain_lists: [], https: false }]);
  });
});
