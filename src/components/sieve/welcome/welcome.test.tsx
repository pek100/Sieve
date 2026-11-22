import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AppShell } from "@/components/sieve/shell/app-shell";
import { ENGINE_SWITCH, HTTPS_HREF, HTTPS_INVITE, HTTPS_SWITCH } from "@/core/engine";
import { SETTING_KEYS, isAvailable, settingDef } from "@/core/settings/registry";
import { resetPlan } from "@/core/settings/transfer";
import { dataSwitchSummary } from "@/core/welcome";
import { createMockEngine, type EngineScenario } from "@/data/engine-mock";
import type { EngineSource } from "@/data/engine-source";
import { createMockLock, type LockScenario } from "@/data/lock-mock";
import { createMockSource } from "@/data/mock-source";
import type { EnginePolicy } from "@/data/protocol";
import { memoryBackend, type SettingsBackend } from "@/data/settings-store";
import { createRuntime, type Runtime } from "@/hooks/runtime";

vi.mock("next/navigation", () => ({ usePathname: () => "/", useRouter: () => ({ push: () => {} }) }));
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

async function setup(o: { isTauri?: boolean; welcomeOnFirstRun?: boolean; stored?: unknown; engine?: EngineSource; lock?: LockScenario } = {}) {
  const runtime = createRuntime({
    source: createMockSource({ seed: 1 }),
    settings: memoryBackend(o.stored),
    isTauri: o.isTauri ?? true,
    welcomeOnFirstRun: o.welcomeOnFirstRun,
    engine: o.engine,
    lock: o.lock ? createMockLock(o.lock) : undefined,
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
    await press("Next");
    await press("Finish");
    await settle();
    expect(b.settings.get("startup.welcomeDone")).toBe(true);
    expect(shown()).toBe(false);
  });

  describe("the row's words: off shows it the next time Sieve opens", () => {
    const open = (settings: SettingsBackend) => {
      const rt = createRuntime({ source: createMockSource({ seed: 1 }), settings, isTauri: true });
      const view = render(<AppShell runtime={rt}>{PAGE}</AppShell>);
      return { rt, view };
    };
    const opened = async (rt: Runtime) => {
      await act(async () => {
        await rt.settings.ready;
      });
      await settle();
    };

    it("turning the flag off leaves the screen alone, and the next open shows the guide", async () => {
      const backend = memoryBackend(DONE);
      const first = open(backend);
      await opened(first.rt);
      expect(shown()).toBe(false);
      await act(async () => {
        await first.rt.settings.set("startup.welcomeDone", false);
      });
      await settle();
      expect(shown()).toBe(false);
      expect(screen.getByText(PAGE)).toBeInTheDocument();
      first.view.unmount();

      const second = open(backend);
      await opened(second.rt);
      expect(shown()).toBe(true);
    });

    it("so does turning it off after the guide was finished in this same run", async () => {
      const first = open(memoryBackend());
      await opened(first.rt);
      expect(shown()).toBe(true);
      await press("Skip");
      await settle();
      expect(shown()).toBe(false);
      await act(async () => {
        await first.rt.settings.set("startup.welcomeDone", false);
      });
      await settle();
      expect(shown()).toBe(false);
      expect(screen.getByText(PAGE)).toBeInTheDocument();
    });

    it("Reset all neither drops the person into the guide nor brings it back at the next open", async () => {
      const backend = memoryBackend({ schema: 4, values: { "startup.welcomeDone": true, "appearance.theme": "light" } });
      const first = open(backend);
      await opened(first.rt);
      await act(async () => {
        await first.rt.settings.replace(resetPlan(first.rt.settings.doc()).next);
      });
      await settle();
      expect(first.rt.settings.get("appearance.theme")).toBe("dark");
      expect(first.rt.settings.get("startup.welcomeDone")).toBe(true);
      expect(shown()).toBe(false);
      first.view.unmount();

      const second = open(backend);
      await opened(second.rt);
      expect(shown()).toBe(false);
    });
  });

  // The flag was turned off or lost while a password file stayed: the guide must still let the person out.
  it.each(["set", "unreadable"] as const)("with a password %s, Skip and Finish dismiss it in one click and open nothing", async (lock) => {
    const a = await setup({ lock });
    const phase = a.lockController.state().phase;
    expect(["locked", "unreadable"]).toContain(phase);
    expect(shown()).toBe(true);
    await press("Skip");
    await settle();
    expect(a.settings.get("startup.welcomeDone")).toBe(true);
    expect(shown()).toBe(false);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(a.lockController.state().phase).toBe(phase);
    expect(screen.getByText(PAGE)).toBeInTheDocument();
    document.body.innerHTML = "";

    const b = await setup({ lock });
    await press("Next");
    await press("Next");
    await press("Finish");
    await settle();
    expect(b.settings.get("startup.welcomeDone")).toBe(true);
    expect(shown()).toBe(false);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(b.lockController.state().phase).toBe(phase);
  });

  it("the password still holds every other write, the guide's AdGuard pause among them", async () => {
    const spy = spyEngine("adguard");
    const rt = await setup({ lock: "set", engine: spy.engine });
    await press("Next");
    await press("Next");
    await press("Next");
    await press("Pause AdGuard");
    await settle();
    expect(screen.getByRole("dialog", { name: "Unlock settings" })).toBeInTheDocument();
    expect(spy.stop).not.toHaveBeenCalled();
    expect(rt.lockController.state().phase).toBe("locked");
  });
});

/** An install from before 2026-11-22 with nothing set: routing, HTTPS and page filtering off. */
const OLD_INSTALL = { schema: 5, values: {} };
const ROUTE = settingDef(ENGINE_SWITCH).label;

describe("the steps", () => {
  it("the data-switch step lists the registry's available switches at their value in force; an engine that cannot take them locks each, with the reason", async () => {
    await setup();
    await press("Next");
    expect(step()).toBe("switches");
    const switches = [...document.querySelectorAll("[data-welcome-switch]")].map((e) => e.getAttribute("data-welcome-switch"));
    expect(switches).toEqual(SETTING_KEYS.filter((k) => settingDef(k).kind === "dataSwitch" && isAvailable(k)));
    // No engine installed: as on the Settings row, the saved choice (a new install's: on), locked,
    // moving, and why; the step's words say what is in force (off).
    for (const s of dataSwitchSummary()) {
      const sw = screen.getByRole("switch", { name: s.label });
      expect(sw).toBeDisabled();
      expect(sw).toBeChecked();
      expect(sw).toHaveAttribute("data-pending");
      expect(document.querySelector(`[data-welcome-switch="${s.key}"] [data-lock=engine]`), s.key).not.toBeNull();
    }
    expect(screen.getByText(/and they are off/)).toBeInTheDocument();
  });

  describe("a new install: the switches are on and the person can turn them off", () => {
    it("routing shows on and is a real switch; a click turns it off through Settings' write, and the engine is told", async () => {
      const spy = spyEngine("idle");
      const rt = await setup({ engine: spy.engine });
      await settle();
      await press("Next");
      expect(step()).toBe("switches");
      expect(screen.getByText("What Sieve changes on your network")).toBeInTheDocument();
      expect(screen.getByText(/Turning one off returns that part to normal/)).toBeInTheDocument();
      const sw = screen.getByRole("switch", { name: ROUTE });
      expect(sw).toBeChecked();
      expect(sw).toBeEnabled();
      // The defaults were the engine's first policy; the guide sent nothing of its own.
      expect(spy.policies[0]).toMatchObject({ engine: true, https: true, content: true });
      await userEvent.click(sw);
      await settle();
      expect(rt.settings.get(ENGINE_SWITCH)).toBe(false);
      expect(spy.policies.at(-1)?.engine).toBe(false);
      expect(screen.getByRole("switch", { name: ROUTE })).not.toBeChecked();
    });

    it("with HTTPS on there is no step inviting the person to turn it on", async () => {
      await setup({ engine: spyEngine("idle").engine });
      await settle();
      await press("Next");
      expect(screen.getByRole("switch", { name: settingDef(HTTPS_SWITCH).label })).toBeChecked();
      expect(screen.getByRole("button", { name: "Finish" })).toBeInTheDocument();
      expect(screen.queryByText(HTTPS_INVITE.title)).toBeNull();
    });

    it("walking the guide without a click changes no setting but its flag", async () => {
      const spy = spyEngine("idle");
      const rt = await setup({ engine: spy.engine });
      await settle();
      const before = JSON.stringify(rt.settings.doc().values);
      const sent = spy.policies.length;
      await press("Next");
      await press("Finish");
      await settle();
      expect(rt.settings.doc().values).toEqual({ ...JSON.parse(before), "startup.welcomeDone": true });
      expect(spy.policies.length, "nothing more was sent").toBe(sent);
    });
  });

  it("an install from before keeps them off; turning one on is the person's click, and it is sent", async () => {
    const spy = spyEngine("idle");
    const rt = await setup({ stored: OLD_INSTALL, engine: spy.engine });
    await press("Next");
    expect(screen.getByText("Your network is as it was")).toBeInTheDocument();
    expect(spy.policies.filter((p) => p.engine || p.https || p.content)).toEqual([]);
    const sw = screen.getByRole("switch", { name: ROUTE });
    expect(sw).not.toBeChecked();
    await userEvent.click(sw);
    await settle();
    expect(rt.settings.get(ENGINE_SWITCH)).toBe(true);
    expect(spy.policies.at(-1)?.engine).toBe(true);
    // Still off until routing is on and checked: as on the Settings row, locked with the reason.
    expect(rt.settings.get(HTTPS_SWITCH)).toBe(false);
  });

  it("a switch whose prerequisite is off is locked with Settings' reason", async () => {
    await setup({ stored: OLD_INSTALL, engine: spyEngine("idle").engine });
    await press("Next");
    const https = document.querySelector(`[data-welcome-switch="${HTTPS_SWITCH}"]`)!;
    expect(within(https as HTMLElement).getByRole("switch")).toBeDisabled();
    expect(https).toHaveTextContent(`Needs ${ROUTE}, which is off.`);
  });

  it("with a password set the switches wait for it: locked, with the way to unlock, and nothing written", async () => {
    const spy = spyEngine("idle");
    const rt = await setup({ engine: spy.engine, lock: "set" });
    await settle();
    await press("Next");
    const sw = screen.getByRole("switch", { name: ROUTE });
    expect(sw).toBeDisabled();
    expect(document.querySelector(`[data-welcome-switch="${ENGINE_SWITCH}"] [data-lock=password]`)).not.toBeNull();
    expect(within(document.querySelector(`[data-welcome-switch="${ENGINE_SWITCH}"]`) as HTMLElement).getByRole("button", { name: "Unlock" })).toBeInTheDocument();
    await userEvent.click(sw);
    expect(rt.settings.get(ENGINE_SWITCH)).toBe(true);
  });

  describe("an existing install, with the engine's switch stored on", () => {
    const ON = { schema: 4, values: { "filtering.engine": true } };
    const walk = async (scenario: EngineScenario) => {
      await setup({ stored: ON, engine: spyEngine(scenario).engine });
      await press("Next");
      expect(step()).toBe("switches");
      return screen.getByRole("switch", { name: ROUTE });
    };

    it("routing: the switch shows on and can be changed, and the step does not say the network is untouched", async () => {
      const sw = await walk("filtering");
      expect(sw).toBeChecked();
      expect(sw).toBeEnabled();
      expect(screen.getByText(/Each is on or off as shown/)).toBeInTheDocument();
      expect(screen.queryByText(/and they are off/)).toBeNull();
      expect(screen.queryByText("Your network is as it was")).toBeNull();
    });

    it("the engine stopped: the switch shows the saved choice, waiting; the step says off, the engine's own", async () => {
      const sw = await walk("stopped");
      expect(sw).toBeChecked();
      expect(sw).toHaveAttribute("data-pending");
      expect(sw).toBeDisabled();
      expect(screen.getByText(/and they are off/)).toBeInTheDocument();
    });

    it.each(["refused", "error"] as const)("%s: the engine did not say, so the step does not claim off", async (scenario) => {
      expect(await walk(scenario)).toHaveAttribute("data-pending");
      expect(screen.queryByText(/and they are off/)).toBeNull();
      expect(screen.getByText(/Sieve cannot read the engine/)).toBeInTheDocument();
    });
  });
});

/** On an install from before, whose switches are off: what a walk without a switch click leaves. */
describe("the network proof", () => {
  const OFF_SWITCHES = dataSwitchSummary().map((s) => s.key);
  async function walkToEnd() {
    await press("Next");
    await press("Next");
    expect(step()).toBe("https");
    await press("Next");
    expect(step()).toBe("adguard");
  }

  it("running the guide to the end while skipping the offer changes nothing", async () => {
    const spy = spyEngine("adguard");
    const rt = await setup({ stored: OLD_INSTALL, engine: spy.engine });
    await walkToEnd();
    await press("Finish");
    await settle();
    // The controller reconciles an engine holding routing on toward the user's switch: off. Never on.
    expect(spy.policies.filter((p) => p.engine)).toEqual([]);
    expect(spy.stop).not.toHaveBeenCalled();
    expect(spy.startAdguard).not.toHaveBeenCalled();
    for (const s of dataSwitchSummary()) expect(rt.settings.get(s.key), s.key).toBe(false);
    // The switches' stored offs are the upgrade's (migrate 5 -> 6); the guide added its flag only.
    expect(Object.keys(rt.settings.doc().values).sort()).toEqual([...OFF_SWITCHES, "startup.welcomeDone"].sort());
  });

  it("stopAdguard is called exactly once, only on its click, and the step stays", async () => {
    const spy = spyEngine("adguard");
    const rt = await setup({ stored: OLD_INSTALL, engine: spy.engine });
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
    await setup({ stored: OLD_INSTALL, engine: spy.engine });
    await press("Next");
    await press("Next");
    expect(step()).toBe("https");
    await press("Finish");
    await settle();
    expect(spy.stop).not.toHaveBeenCalled();
  });

  it("the HTTPS step explains in plain words and links to the switch, which it never turns on", async () => {
    const spy = spyEngine("idle");
    const rt = await setup({ stored: OLD_INSTALL, engine: spy.engine });
    await press("Next");
    await press("Next");
    expect(step()).toBe("https");
    expect(screen.getByText(HTTPS_INVITE.title)).toBeInTheDocument();
    expect(screen.getByText(/opens your browsers' encrypted traffic here on this computer/)).toBeInTheDocument();
    expect(screen.getByText(/Only browsers are decrypted: other apps are never opened/)).toBeInTheDocument();
    expect(screen.getByText(/such as many banks and payment, health, government/)).toBeInTheDocument();
    expect(screen.getByText(/turn it off at any time/)).toBeInTheDocument();
    expect(screen.getByText(/removes Sieve's own certificate once Windows allows it, which can take a moment, and leaves every other certificate as it was/)).toBeInTheDocument();
    expect(HTTPS_HREF).toBe("/settings/#setting-filtering.https");
    expect(screen.getByRole("link", { name: HTTPS_INVITE.link })).toHaveAttribute("href", expect.stringMatching(/^\/settings\/?#setting-filtering\.https$/));
    expect(rt.settings.get(HTTPS_SWITCH)).toBe(false);
    expect(spy.policies.filter((p) => p.https)).toEqual([]);
  });

  it("a stopping failure is said on the step", async () => {
    const spy = spyEngine("adguard");
    spy.stop.mockRejectedValueOnce(new Error("The user declined"));
    await setup({ stored: OLD_INSTALL, engine: spy.engine });
    await walkToEnd();
    await press("Pause AdGuard");
    await settle();
    expect(screen.getByRole("alert")).toHaveTextContent("The user declined");
  });
});
