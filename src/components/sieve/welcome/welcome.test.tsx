import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AppShell } from "@/components/sieve/shell/app-shell";
import { SETTING_KEYS, isAvailable, settingDef } from "@/core/settings/registry";
import { dataSwitchSummary } from "@/core/welcome";
import { createMockEngine, type EngineScenario } from "@/data/engine-mock";
import type { EngineSource } from "@/data/engine-source";
import { createMockSource } from "@/data/mock-source";
import type { EnginePolicy } from "@/data/protocol";
import { memoryBackend, type SettingsBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";

vi.mock("next/navigation", () => ({ usePathname: () => "/" }));
vi.setConfig({ testTimeout: 20_000 });

const DONE = { schema: 4, values: { "startup.welcomeDone": true } };
const PAGE = "the routed screen";

const settle = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });

function spyEngine(start: EngineScenario) {
  const mock = createMockEngine(start);
  const policies: EnginePolicy[] = [];
  const stop = vi.fn(mock.stopAdguard);
  const startAdguard = vi.fn(mock.startAdguard);
  const engine: EngineSource = {
    ...mock,
    setPolicy: (p) => {
      policies.push(p);
      return mock.setPolicy(p);
    },
    stopAdguard: stop,
    startAdguard,
  };
  return { engine, policies, stop, startAdguard };
}

async function setup(o: { isTauri?: boolean; welcomeOnFirstRun?: boolean; stored?: unknown; engine?: EngineSource } = {}) {
  const runtime = createRuntime({
    source: createMockSource({ seed: 1 }),
    settings: memoryBackend(o.stored),
    isTauri: o.isTauri ?? true,
    welcomeOnFirstRun: o.welcomeOnFirstRun,
    engine: o.engine,
  });
  render(<AppShell runtime={runtime}>{PAGE}</AppShell>);
  await act(async () => {
    await runtime.settings.ready;
  });
  await settle();
  return runtime;
}

const shown = () => document.querySelector("[data-welcome-step]") !== null;
const step = () => document.querySelector("[data-welcome-step]")?.getAttribute("data-welcome-step");
const press = (name: string) => userEvent.click(screen.getByRole("button", { name }));

describe("when the guide shows", () => {
  it("the desktop app with a fresh doc shows it, in place of the routed screen", async () => {
    await setup();
    expect(shown()).toBe(true);
    expect(screen.queryByText(PAGE)).toBeNull();
  });

  it("a stored done flag never renders it, not even for one frame before the settings are read", async () => {
    let release: () => void = () => {};
    const slow: SettingsBackend = {
      ...memoryBackend(DONE),
      load: () =>
        new Promise((resolve) => {
          release = () => resolve(DONE);
        }),
    };
    const rt = createRuntime({ source: createMockSource({ seed: 1 }), settings: slow, isTauri: true });
    const frames: boolean[] = [];
    const seen = new MutationObserver(() => frames.push(shown()));
    seen.observe(document.body, { childList: true, subtree: true, attributes: true });
    render(<AppShell runtime={rt}>{PAGE}</AppShell>);
    await settle();
    expect(shown()).toBe(false);
    await act(async () => {
      release();
      await rt.settings.ready;
    });
    await settle();
    seen.disconnect();
    expect(shown()).toBe(false);
    expect(frames).not.toContain(true);
    expect(screen.getByText(PAGE)).toBeInTheDocument();
  });

  it("a browser never shows it without ?welcome=1", async () => {
    await setup({ isTauri: false });
    expect(shown()).toBe(false);
    expect(screen.getByText(PAGE)).toBeInTheDocument();
  });

  it("?welcome=1 is the same predicate", async () => {
    await setup({ isTauri: false, welcomeOnFirstRun: true });
    expect(shown()).toBe(true);
  });

  it("Skip and Finish both set the flag and bring the screen back", async () => {
    const a = await setup();
    await press("Skip");
    await settle();
    expect(a.settings.get("startup.welcomeDone")).toBe(true);
    expect(shown()).toBe(false);
    expect(screen.getByText(PAGE)).toBeInTheDocument();
    document.body.innerHTML = "";

    const b = await setup();
    await press("Next");
    await press("Finish");
    await settle();
    expect(b.settings.get("startup.welcomeDone")).toBe(true);
    expect(shown()).toBe(false);
  });
});

describe("the steps", () => {
  it("the data-switch step lists the registry's available switches, read only and off", async () => {
    await setup();
    await press("Next");
    expect(step()).toBe("switches");
    const switches = [...document.querySelectorAll("[data-welcome-switch]")].map((e) => e.getAttribute("data-welcome-switch"));
    expect(switches).toEqual(SETTING_KEYS.filter((k) => settingDef(k).kind === "dataSwitch" && isAvailable(k)));
    for (const s of dataSwitchSummary()) {
      const sw = screen.getByRole("switch", { name: s.label });
      expect(sw).toBeDisabled();
      expect(sw).not.toBeChecked();
    }
  });
});

describe("the network proof", () => {
  async function walkToEnd() {
    await press("Next");
    await press("Next");
    expect(step()).toBe("adguard");
  }

  it("running the guide to the end while skipping the offer changes nothing", async () => {
    const spy = spyEngine("adguard");
    const rt = await setup({ engine: spy.engine });
    await walkToEnd();
    await press("Finish");
    await settle();
    // The controller reconciles an engine holding routing on toward the user's switch: off. Never on.
    expect(spy.policies.filter((p) => p.engine)).toEqual([]);
    expect(spy.stop).not.toHaveBeenCalled();
    expect(spy.startAdguard).not.toHaveBeenCalled();
    for (const s of dataSwitchSummary()) expect(rt.settings.get(s.key), s.key).toBe(false);
    expect(Object.keys(rt.settings.doc().values)).toEqual(["startup.welcomeDone"]);
  });

  it("stopAdguard is called exactly once, only on its click, and the step stays", async () => {
    const spy = spyEngine("adguard");
    const rt = await setup({ engine: spy.engine });
    await walkToEnd();
    expect(spy.stop).not.toHaveBeenCalled();
    await press("Pause AdGuard");
    await settle();
    expect(spy.stop).toHaveBeenCalledOnce();
    expect(step()).toBe("adguard");
    expect(screen.getByText(/AdGuard is not running now/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Pause AdGuard" })).toBeNull();
    await press("Finish");
    await settle();
    expect(spy.stop).toHaveBeenCalledOnce();
    expect(spy.policies.filter((p) => p.engine)).toEqual([]);
    for (const s of dataSwitchSummary()) expect(rt.settings.get(s.key), s.key).toBe(false);
  });

  it("with no AdGuard there is no such step", async () => {
    const spy = spyEngine("idle");
    await setup({ engine: spy.engine });
    await press("Next");
    await press("Finish");
    await settle();
    expect(spy.stop).not.toHaveBeenCalled();
  });

  it("a stopping failure is said on the step", async () => {
    const spy = spyEngine("adguard");
    spy.stop.mockRejectedValueOnce(new Error("The user declined"));
    await setup({ engine: spy.engine });
    await walkToEnd();
    await press("Pause AdGuard");
    await settle();
    expect(screen.getByRole("alert")).toHaveTextContent("The user declined");
  });
});
