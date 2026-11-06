import { act, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ADGUARD_PAUSE_TEXT, ADGUARD_PAUSED_TEXT, ADGUARD_START_TEXT, ENGINE_SWITCH } from "@/core/engine";
import { createMockEngine, MOCK_ADGUARD_ERROR, MOCK_ENGINE_ERROR, type EngineScenario } from "@/data/engine-mock";
import type { EngineSource } from "@/data/engine-source";
import fixture from "@/data/fixtures/engine-probe-v2.json";
import { createMockSource } from "@/data/mock-source";
import { parseEngineProbe } from "@/data/protocol";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { SettingsScreen } from "./settings-screen";

vi.mock("next/navigation", () => ({ usePathname: () => "/settings/" }));
vi.setConfig({ testTimeout: 20_000 });

/** The user's engine switch as the fixture's welcome examples hold it (on for every example the engine routes or explains). */
const SWITCHED_ON = new Set<EngineScenario>(["filtering", "hosts", "adguard", "adguard_paused", "vpn", "crash_loop", "setup"]);

async function setup(engine: EngineSource, on = false) {
  const settings = memoryBackend(on ? { schema: 4, values: { [ENGINE_SWITCH]: true } } : undefined);
  const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings, engine });
  render(
    <SieveProvider runtime={runtime}>
      <SettingsScreen />
    </SieveProvider>,
  );
  await act(async () => {
    await runtime.settings.ready;
  });
  return runtime;
}

const block = () => screen.getByRole("region", { name: "Engine" });
const phase = () => block().querySelector("[data-engine-phase]")!.getAttribute("data-engine-phase");
const state = () => block().querySelector("[data-engine-state]")!.textContent;

describe("Engine block", () => {
  const cases: [EngineScenario, string, string, RegExp][] = [
    ["missing", "not_installed", "Not installed", /not installed on this computer/],
    ["stopped", "not_running", "Not running", /service is not running/],
    ["unreachable", "not_running", "Not running", /does not answer: The system cannot find the file specified/],
    ["idle", "idle", "Installed, not routing", /changes nothing: no traffic goes through it/],
    ["filtering", "routing", "Routing traffic", /Nothing is blocked yet/],
    ["hosts", "filtering", "Filtering hosts", /applies 142,000 rules from 2 lists to host names only/],
    ["adguard", "adguard", "Waiting for AdGuard", /AdGuard is filtering this computer/],
    ["vpn", "vpn", "Paused for a VPN", /Paused while AdGuard VPN is connected/],
    ["crash_loop", "crash_loop", "Stopped after repeated failures", /restarted 3 times within an hour/],
    ["setup", "setup_failed", "Could not start", /SHA-256 does not match/],
    ["incompatible", "incompatible", "Installed, needs an update", /supports 4 to 4/],
    ["refused", "refused", "Installed", /not the installed one/],
  ];

  it.each(cases)("%s: says %s from the facts", async (scenario, wantPhase, wantState, detail) => {
    await setup(createMockEngine(scenario), SWITCHED_ON.has(scenario));
    await vi.waitFor(() => expect(phase()).toBe(wantPhase));
    expect(state()).toBe(wantState);
    expect(block().querySelector("[data-engine-detail]")).toHaveTextContent(detail);
  });

  it("routing: states split tunnels and attribution from the engine's own counters", async () => {
    await setup(createMockEngine("filtering"), true);
    await vi.waitFor(() => expect(phase()).toBe("routing"));
    expect(block().querySelector("[data-engine-split]")).toHaveTextContent("Corp VPN sends some traffic around Sieve");
    expect(block().querySelector("[data-engine-attribution]")).toHaveTextContent("1,200 flows relayed since the engine started, 99% tied to an app.");
  });

  it("forwarded flows: both rates are said; with none, the sentence is exactly the old one", async () => {
    await setup(createMockEngine("filtering"), true);
    await vi.waitFor(() => expect(phase()).toBe("routing"));
    // 1188 of 1200 is the gate; 1184 of 1194 is this computer's own, floored to a tenth.
    expect(block().querySelector("[data-engine-attribution]")).toHaveTextContent(
      "1,200 flows relayed since the engine started, 99% tied to an app. 6 came from virtual machines; 99.1% of this computer's own flows are tied to an app.",
    );
  });

  it("no forwarded flow: the attribution sentence does not mention them", async () => {
    const example = fixture.examples.filtering as unknown as { pipe: { status: { counters: Record<string, number> } } };
    const counters = { ...example.pipe.status.counters, forwarded: 0, forwarded_named: 0 };
    const engine: EngineSource = {
      ...createMockEngine("filtering"),
      probe: async () => parseEngineProbe({ ...example, pipe: { ...example.pipe, status: { ...example.pipe.status, counters } } }),
    };
    await setup(engine, true);
    await vi.waitFor(() => expect(phase()).toBe("routing"));
    expect(block().querySelector("[data-engine-attribution]")?.textContent).toBe("1,200 flows relayed since the engine started, 99% tied to an app.");
  });

  it("filtering: each list's applied and skipped rules, from the engine's facts; no lists, no block", async () => {
    await setup(createMockEngine("hosts"), true);
    await vi.waitFor(() => expect(phase()).toBe("filtering"));
    const lists = screen.getByRole("list", { name: "Filter lists" });
    expect(lists.querySelector('[data-engine-list="adguard-base"]')).toHaveTextContent("AdGuard Base filter: 90,000 rules applied, 120 skipped");
    expect(lists.querySelector('[data-engine-list="ubo-filters"]')).toHaveTextContent("uBlock filters: 52,000 rules applied, 7 skipped");
  });

  it("routing with no facts lists nothing", async () => {
    await setup(createMockEngine("filtering"), true);
    await vi.waitFor(() => expect(phase()).toBe("routing"));
    expect(screen.queryByRole("list", { name: "Filter lists" })).toBeNull();
  });

  it("AdGuard filtering: the pause offer says what it does, and pausing lets the engine route with the service left stopping", async () => {
    await setup(createMockEngine("adguard"), true);
    await vi.waitFor(() => expect(phase()).toBe("adguard"));
    const offer = () => block().querySelector("[data-adguard-offer]")!;
    expect(offer().getAttribute("data-adguard-offer")).toBe("pause");
    expect(offer()).toHaveTextContent(ADGUARD_PAUSE_TEXT);
    expect(offer()).toHaveTextContent(/asks its Windows service \(Adguard Service\) to stop\. Windows asks you to approve it/);
    await act(async () => screen.getByRole("button", { name: "Pause AdGuard" }).click());
    await vi.waitFor(() => expect(phase()).toBe("routing"));
    expect(offer().getAttribute("data-adguard-offer")).toBe("paused");
    expect(offer()).toHaveTextContent(ADGUARD_PAUSED_TEXT);
    expect(screen.queryByRole("button", { name: "Start AdGuard again" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Pause AdGuard" })).toBeNull();
  });

  it("the mock's pause leaves AdGuard stopping, never stopped", async () => {
    const engine = createMockEngine("adguard");
    await engine.stopAdguard();
    expect((await engine.probe()).adguard).toBe("stopping");
    await expect(engine.startAdguard()).rejects.toThrow(MOCK_ADGUARD_ERROR);
  });

  it("AdGuard's service really stopped: Start is offered and makes the engine wait", async () => {
    await setup(createMockEngine("filtering"), true);
    await vi.waitFor(() => expect(phase()).toBe("routing"));
    expect(block().querySelector("[data-adguard-offer]")!.getAttribute("data-adguard-offer")).toBe("start");
    expect(block().querySelector("[data-adguard-offer]")).toHaveTextContent(ADGUARD_START_TEXT);
    await act(async () => screen.getByRole("button", { name: "Start AdGuard again" }).click());
    await vi.waitFor(() => expect(phase()).toBe("adguard"));
  });

  it("no AdGuard: no offer; a failed action is said", async () => {
    const rt = await setup(createMockEngine("idle"));
    await vi.waitFor(() => expect(phase()).toBe("idle"));
    expect(block().querySelector("[data-adguard-offer]")).toBeNull();
    await act(async () => rt.engineController.stopAdguard());
    expect(block().querySelector("[data-engine-action-error]")).toHaveTextContent("AdGuard was not paused");
  });

  describe("updates", () => {
    const update = () => block().querySelector("[data-engine-update]");

    it("offered: plain text and one button; installing sends the request and shows it applying", async () => {
      await setup(createMockEngine("update_available"));
      await vi.waitFor(() => expect(update()?.getAttribute("data-engine-update")).toBe("available"));
      expect(update()).toHaveTextContent("Sieve 0.2.0 is available. Installing it stops the engine");
      await act(async () => screen.getByRole("button", { name: "Install update" }).click());
      await vi.waitFor(() => expect(update()?.getAttribute("data-engine-update")).toBe("applying"));
      expect(screen.queryByRole("button", { name: "Install update" })).toBeNull();
    });

    it("a refusal and a rollback read as problems with their reason; current is one quiet line", async () => {
      await setup(createMockEngine("update_refused"));
      await vi.waitFor(() => expect(update()).toHaveTextContent("the signature does not verify"));
      expect(update()!.querySelector("p")!.getAttribute("role")).toBe("alert");
      expect(screen.getByRole("button", { name: "Check again" })).toBeEnabled();
    });

    it("current says so quietly and is no alert", async () => {
      await setup(createMockEngine("update_current"));
      await vi.waitFor(() => expect(update()).toHaveTextContent("Sieve is up to date."));
      expect(update()!.querySelector("p")!.getAttribute("role")).toBeNull();
    });

    it.each(["idle", "missing", "refused"] as const)("%s: nothing about updates", async (scenario) => {
      await setup(createMockEngine(scenario));
      await vi.waitFor(() => expect(phase()).not.toBe("checking"));
      expect(update()).toBeNull();
    });

    /** frontend-resilience, step 6: what an older or broken engine could send. */
    it.each([
      ["missing", undefined],
      ["null", null],
      ["partial", { kind: "available" }],
      ["partial message", { kind: "refused" }],
      ["wrong type", "available"],
      ["unknown kind", { kind: "sign", version: "9" }],
    ])("degraded update (%s): no crash, no notice, the engine's facts stand", async (_, degraded) => {
      const { parseEngineProbe } = await import("@/data/protocol");
      const fixture = (await import("@/data/fixtures/engine-probe-v2.json")).default;
      const idle = fixture.examples.idle;
      const answer = { ...idle, pipe: { ...idle.pipe, status: { ...idle.pipe.status, update: degraded } } };
      await setup({ ...createMockEngine("idle"), probe: async () => parseEngineProbe(answer) });
      await vi.waitFor(() => expect(phase()).toBe("idle"));
      expect(update()).toBeNull();
      expect(state()).toBe("Installed, not routing");
    });
  });

  it("shows the engine's version only when the engine said it", async () => {
    await setup(createMockEngine("idle"));
    await vi.waitFor(() => expect(block()).toHaveTextContent("Engine version 0.1.0"));
  });

  it("an unreadable state is said as such, never as a guess", async () => {
    await setup(createMockEngine("error"));
    await vi.waitFor(() => expect(phase()).toBe("unreadable"));
    expect(state()).toBe("Unknown");
    expect(block().querySelector("[data-engine-detail]")!.getAttribute("role")).toBe("alert");
    expect(block()).toHaveTextContent(MOCK_ENGINE_ERROR);
  });

  it("before the first answer it says it is checking, and never claims filtering", async () => {
    await setup({ ...createMockEngine("idle"), probe: () => new Promise(() => {}) });
    expect(phase()).toBe("checking");
    expect(block()).not.toHaveTextContent(/filtering this computer|blocked/i);
  });

  it("degraded answers are refused at the boundary and shown as unreadable, not crashed", async () => {
    const partial = async () => ({ v: 3, service: "running", adguard: "missing", pipe: { kind: "welcome" } });
    const { parseEngineProbe } = await import("@/data/protocol");
    await setup({ ...createMockEngine("idle"), probe: async () => parseEngineProbe(await partial()) });
    await vi.waitFor(() => expect(phase()).toBe("unreadable"));
    expect(block()).toHaveTextContent(/pipe\.engine_version must be a string/);
  });
});
