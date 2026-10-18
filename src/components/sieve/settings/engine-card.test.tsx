import { act, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { createMockEngine, MOCK_ENGINE_ERROR, type EngineScenario } from "@/data/engine-mock";
import type { EngineSource } from "@/data/engine-source";
import { createMockSource } from "@/data/mock-source";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { SettingsScreen } from "./settings-screen";

vi.mock("next/navigation", () => ({ usePathname: () => "/settings/" }));
vi.setConfig({ testTimeout: 20_000 });

async function setup(engine: EngineSource) {
  const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend(), engine });
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
    ["idle", "idle", "Installed, not filtering", /changes nothing: no traffic goes through it/],
    ["incompatible", "incompatible", "Installed, needs an update", /supports 2 to 2/],
    ["refused", "refused", "Installed", /not the installed one/],
  ];

  it.each(cases)("%s: says %s from the facts", async (scenario, wantPhase, wantState, detail) => {
    await setup(createMockEngine(scenario));
    await vi.waitFor(() => expect(phase()).toBe(wantPhase));
    expect(state()).toBe(wantState);
    expect(block().querySelector("[data-engine-detail]")).toHaveTextContent(detail);
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
    await setup({ kind: "mock", probe: () => new Promise(() => {}) });
    expect(phase()).toBe("checking");
    expect(block()).not.toHaveTextContent(/filtering this computer|blocked/i);
  });

  it("degraded answers are refused at the boundary and shown as unreadable, not crashed", async () => {
    const partial = { kind: "mock" as const, probe: async () => ({ v: 1, service: "running", pipe: { kind: "welcome" } }) };
    const { parseEngineProbe } = await import("@/data/protocol");
    await setup({ kind: "mock", probe: async () => parseEngineProbe(await partial.probe()) });
    await vi.waitFor(() => expect(phase()).toBe("unreadable"));
    expect(block()).toHaveTextContent(/pipe\.status must be an object/);
  });
});
