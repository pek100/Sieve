import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ENGINE_SWITCH } from "@/core/engine";
import { VERDICT_TEXT } from "@/core/issues";
import { createMockEngine, type IssuesScenario } from "@/data/engine-mock";
import type { EngineSource } from "@/data/engine-source";
import { createMockSource } from "@/data/mock-source";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime, type Runtime } from "@/hooks/runtime";
import { AppShell } from "@/components/sieve/shell/app-shell";
import { AppsScreen } from "./apps-screen";

vi.mock("next/navigation", () => ({ usePathname: () => "/apps/", useRouter: () => ({ push: () => {} }) }));

for (const m of ["setPointerCapture", "releasePointerCapture"] as const) {
  if (!(m in Element.prototype)) Object.defineProperty(Element.prototype, m, { value: () => {}, configurable: true });
}
if (!("hasPointerCapture" in Element.prototype)) {
  Object.defineProperty(Element.prototype, "hasPointerCapture", { value: () => false, configurable: true });
}

async function setup(engine: EngineSource, routes = true) {
  window.history.replaceState(null, "", "/apps/");
  const runtime: Runtime = createRuntime({
    source: createMockSource({ seed: 1 }),
    settings: memoryBackend({ schema: 5, values: routes ? { [ENGINE_SWITCH]: true } : {} }),
    engine,
  });
  render(
    <AppShell runtime={runtime}>
      <AppsScreen />
    </AppShell>,
  );
  await act(async () => {
    await runtime.settings.ready;
  });
  await screen.findAllByTestId("app-row");
  return { runtime, user: userEvent.setup() };
}

const engineWith = (issues: IssuesScenario) => createMockEngine("filtering", { issues });
const troubleRows = () => screen.queryAllByTestId("trouble-row");

afterEach(() => {
  cleanup();
  window.history.replaceState(null, "", "/");
});

describe("apps having trouble", () => {
  it("lists each failing app with its likely cause in words, and its sheet shows the problems even after it exited", async () => {
    const { user } = await setup(engineWith("some"));
    await waitFor(() => expect(troubleRows()).toHaveLength(2));
    const game = troubleRows()[0];
    expect(game.dataset.app).toBe("game launcher");
    expect(game).toHaveTextContent("9 of 40 connections had trouble, 6 blocked by a filter rule");
    expect(game).toHaveTextContent(VERDICT_TEXT.sieve);
    await user.click(within(game).getByRole("button"));
    const sheet = await screen.findByTestId("app-problems");
    expect(within(sheet).getByTestId("app-verdict")).toHaveTextContent(VERDICT_TEXT.sieve);
    const signals = within(sheet).getAllByTestId("problem").map((p) => p.dataset.signal);
    expect(signals).toEqual(["app_refused_certificate", "blocked", "connect_timeout", "connect_refused", "unreachable", "stall"]);
    expect(within(sheet).getByText(/Sieve tried 3 connections again before the app noticed; 2 then worked/)).toBeInTheDocument();
  });

  it("a fix shows its exact line first, then writes it to the user's own list", async () => {
    const { runtime, user } = await setup(engineWith("some"));
    await waitFor(() => expect(troubleRows()).toHaveLength(2));
    await user.click(within(troubleRows()[0]).getByRole("button"));
    const sheet = await screen.findByTestId("app-problems");
    await user.click(within(sheet).getByRole("button", { name: "Stop decrypting it for this app: cdn.game.example" }));
    const dialog = await screen.findByRole("dialog", { name: /Stop decrypting cdn.game.example/ });
    expect(within(dialog).getByText("cdn.game.example$app=launcher.exe")).toBeInTheDocument();
    expect(runtime.settings.get("filtering.exclusions"), "nothing before the confirm").toEqual([]);
    await user.click(within(dialog).getByRole("button", { name: "Add it" }));
    await waitFor(() => expect(runtime.settings.get("filtering.exclusions")).toEqual(["cdn.game.example$app=launcher.exe"]));
    await user.click(within(sheet).getByRole("button", { name: "Unblock this site: updates.game.example" }));
    await user.click(within(await screen.findByRole("dialog", { name: /Unblock updates.game.example/ })).getByRole("button", { name: "Add it" }));
    await waitFor(() => expect(runtime.settings.get("filtering.userRules")).toEqual(["@@||updates.game.example^"]));
  });

  it("Off for a running app is one click, and the report goes to the clipboard only", async () => {
    const engine = engineWith("some");
    const some = engine.issues;
    engine.issues = async (after) => {
      const answer = await some(after);
      return { ...answer, apps: answer.apps.map((a, i) => (i === 0 ? { ...a, key: "google chrome", exe: "chrome.exe" } : a)) };
    };
    const { runtime, user } = await setup(engine);
    await waitFor(() => expect(troubleRows()[0]?.dataset.app).toBe("google chrome"));
    expect(troubleRows()[0]).toHaveTextContent("Google Chrome");
    await user.click(within(troubleRows()[0]).getByRole("button"));
    const sheet = await screen.findByTestId("app-problems");
    await user.click(within(sheet).getByRole("button", { name: "Copy a report" }));
    await waitFor(async () => expect(await navigator.clipboard.readText()).toContain("Google Chrome (chrome.exe)"));
    await user.click(within(sheet).getByRole("button", { name: "Turn Sieve off for this app" }));
    await waitFor(() => expect(runtime.settings.get("apps.levels")).toEqual({ "google chrome": "off" }));
  });

  it("an app Sieve let through untouched says so, and keep or try again is one click", async () => {
    const engine = createMockEngine("filtering", { issues: "some", heal: true });
    const page = engine.exclusions;
    engine.exclusions = async (after) => {
      const p = await page(after);
      return { ...p, rows: [...p.rows, { line: "*", apps: ["launcher.exe"], reason: "auto:failing", created_ms: 1_793_000_000_000, retries: 0 }] };
    };
    const tried = vi.fn(engine.tryDecryptAgain);
    engine.tryDecryptAgain = tried;
    const { runtime, user } = await setup(engine);
    await waitFor(() => expect(troubleRows()).toHaveLength(2));
    await user.click(within(troubleRows()[0]).getByRole("button"));
    const sheet = await screen.findByTestId("app-problems");
    expect(await within(sheet).findByTestId("app-untouched")).toHaveTextContent("Sieve passes this app through untouched for a day");
    await user.click(within(sheet).getByRole("button", { name: "Keep it this way" }));
    await user.click(within(await screen.findByRole("dialog", { name: /Never decrypt launcher.exe/ })).getByRole("button", { name: "Add it" }));
    await waitFor(() => expect(runtime.settings.get("filtering.exclusions")).toEqual(["*$app=launcher.exe"]));
    await user.click(within(sheet).getByRole("button", { name: "Try decrypting again" }));
    expect(tried).toHaveBeenCalledWith("*", "launcher.exe", "auto:failing");
  });

  it("degraded answers render what can be read and never crash", async () => {
    await setup(engineWith("partial"));
    await waitFor(() => expect(troubleRows()).toHaveLength(1));
    expect(troubleRows()[0].dataset.app).toBe("game launcher");
    expect(troubleRows()[0]).toHaveTextContent("2 connections had trouble");
  });

  it("a failed read says so in words", async () => {
    await setup(engineWith("error"));
    expect(await screen.findByTestId("trouble-error")).toHaveTextContent("Sieve could not read the apps' problems just now");
  });

  it("with the engine not routing nothing is claimed", async () => {
    await setup(createMockEngine("idle", { issues: "some" }), false);
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(screen.queryByTestId("trouble")).toBeNull();
  });
});
