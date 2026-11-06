import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ENGINE_SWITCH } from "@/core/engine";
import { VM_GROUP_LABEL, VM_OFF_MEANS } from "@/core/guests";
import { GLOBAL_SWITCH } from "@/core/policy";
import { createMockEngine } from "@/data/engine-mock";
import type { EngineSource } from "@/data/engine-source";
import fixture from "@/data/fixtures/engine-probe-v2.json";
import { createMockSource } from "@/data/mock-source";
import { parseEngineProbe } from "@/data/protocol";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime, type Runtime } from "@/hooks/runtime";
import { AppShell } from "@/components/sieve/shell/app-shell";
import { APP_OFF_MEANS } from "./app-toggle";
import { AppsScreen } from "./apps-screen";

vi.mock("next/navigation", () => ({ usePathname: () => "/apps/" }));

// jsdom has no pointer capture; sonner's toast calls it when the toast is pressed.
for (const m of ["setPointerCapture", "releasePointerCapture"] as const) {
  if (!(m in Element.prototype)) Object.defineProperty(Element.prototype, m, { value: () => {}, configurable: true });
}
if (!("hasPointerCapture" in Element.prototype)) {
  Object.defineProperty(Element.prototype, "hasPointerCapture", { value: () => false, configurable: true });
}

const CHROME = "google chrome";

async function setup(stored?: Record<string, unknown>, search = "") {
  window.history.replaceState(null, "", `/apps/${search}`);
  const runtime: Runtime = createRuntime({
    source: createMockSource({ seed: 1 }),
    settings: memoryBackend(stored ? { schema: 1, values: stored } : undefined),
  });
  const view = render(
    <AppShell runtime={runtime}>
      <AppsScreen />
    </AppShell>,
  );
  await act(async () => {
    await runtime.settings.ready;
  });
  await screen.findAllByTestId("app-row");
  return { runtime, view, user: userEvent.setup() };
}

const row = (key: string) => document.querySelector<HTMLElement>(`[data-testid="app-row"][data-app="${key}"]`)!;

afterEach(() => {
  window.history.replaceState(null, "", "/");
});

describe("apps screen", () => {
  it("groups apps into Mine, Apps and System; a C:\\Windows\\ app lands in System", async () => {
    await setup({ "apps.pinned": ["D:\\Tools\\quiet.exe"] });
    const sections = screen.getAllByRole("button", { expanded: true }).map((b) => b.textContent);
    expect(sections.map((t) => t?.replace(/\d+$/, ""))).toEqual(["Mine", "Apps", "System"]);
    const system = screen.getByRole("region", { name: /System/ });
    expect(within(system).getByText("Microsoft Windows Operating System")).toBeInTheDocument();
    const mine = screen.getByRole("region", { name: /Mine/ });
    expect(within(mine).getByText("quiet")).toBeInTheDocument();
    expect(within(row("quiet")).getByText("0")).toBeInTheDocument();
  });

  it("every app is sieved by default; the toggle says once, plainly, what Off does and claims no blocking", async () => {
    await setup();
    const toggle = within(row(CHROME)).getByRole("switch", { name: "Sieve Google Chrome" });
    expect(toggle).toBeChecked();
    expect(toggle).toHaveAccessibleDescription(APP_OFF_MEANS);
    expect(APP_OFF_MEANS).toBe("Off: Sieve passes this app's traffic through untouched and stops charting it.");
    // Whether anything is blocked is the engine's fact, so this copy must not claim blocking.
    expect(APP_OFF_MEANS).not.toMatch(/block/i);
    // No Watch level and no locked per-app filtering anywhere.
    expect(document.body.textContent).not.toMatch(/Watch|network driver|Per-app filtering/);
    expect(screen.queryAllByRole("radio")).toHaveLength(0);
  });

  it("the app sheet opens the report dialog for that app, with no URL yet", async () => {
    const { user } = await setup();
    await user.click(within(row(CHROME)).getByRole("button", { name: /Open details/ }));
    await user.click(await screen.findByRole("button", { name: "Report a broken site" }));
    const report = await screen.findByRole<HTMLTextAreaElement>("textbox", { name: "The report" });
    expect(report.value).toContain("Page URL: not known");
    expect(report.value).toContain("Browser: chrome.exe");
    expect(screen.getByRole("textbox", { name: "Page URL" })).toHaveValue("");
    // No engine in this runtime: the reason, and no page to open.
    expect(screen.getByRole("button", { name: "Open issue page" })).toBeDisabled();
  });

  it("turning an app off stores it and drops it from the being-sieved count", async () => {
    const { runtime, user } = await setup();
    const count = () => Number(screen.getByTestId("sieved-count").textContent?.split(" ")[0]);
    // Freeze sampling so the count only moves because of the toggle.
    act(() => runtime.poller.stop());
    const before = count();
    expect(screen.getByTestId("sieved-count")).toHaveTextContent(`${before} being sieved`);
    await user.click(within(row(CHROME)).getByRole("switch", { name: "Sieve Google Chrome" }));
    expect(runtime.settings.get("apps.levels")).toEqual({ [CHROME]: "off" });
    expect(within(row(CHROME)).getByRole("switch", { name: "Sieve Google Chrome" })).not.toBeChecked();
    expect(row(CHROME)).toHaveAttribute("data-off");
    expect(count()).toBe(before - 1);
    // Back on: nothing stored.
    await user.click(within(row(CHROME)).getByRole("switch", { name: "Sieve Google Chrome" }));
    expect(runtime.settings.get("apps.levels")).toEqual({});
  });

  it("global Sieving off: nothing is being sieved and the screen says so", async () => {
    const { runtime } = await setup();
    await act(async () => {
      await runtime.settings.set(GLOBAL_SWITCH, false);
    });
    expect(screen.getByTestId("sieved-count")).toHaveTextContent("0 being sieved");
    expect(screen.getByTestId("sieving-off")).toHaveTextContent("Sieving is off for every app");
  });

  it("an old Watch level reads as on; an old off stays off (settings migration)", async () => {
    await setup({ "apps.levels": { [CHROME]: "watch", discord: "off" } });
    expect(within(row(CHROME)).getByRole("switch")).toBeChecked();
  });

  it("removing a pinned app shows an undo toast, and undo restores it", async () => {
    const { runtime, user } = await setup({ "apps.pinned": ["D:\\Tools\\quiet.exe"] });
    await user.click(screen.getByRole("button", { name: "Remove quiet from my apps" }));
    expect(runtime.settings.get("apps.pinned")).toEqual([]);
    await waitFor(() => expect(row("quiet")).toBeNull());
    expect(await screen.findByText("Removed quiet from your apps")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Undo" }));
    await waitFor(() => expect(runtime.settings.get("apps.pinned")).toEqual(["D:\\Tools\\quiet.exe"]));
    expect(await screen.findByText("quiet")).toBeInTheDocument();
  });

  it("search with no match shows the no-results state and Escape clears it", async () => {
    const { user } = await setup();
    const box = screen.getByRole("searchbox", { name: "Search apps" });
    await user.type(box, "zzzz-nothing");
    expect(screen.getByText("Nothing by that name")).toBeInTheDocument();
    expect(screen.queryAllByTestId("app-row")).toHaveLength(0);
    await user.keyboard("{Escape}");
    expect(box).toHaveValue("");
    expect(screen.getAllByTestId("app-row").length).toBeGreaterThan(10);
  });

  it("search narrows by name and the clear button empties it", async () => {
    const { user } = await setup();
    const box = screen.getByRole("searchbox", { name: "Search apps" });
    await user.type(box, "chrome");
    expect(screen.getAllByTestId("app-row").map((r) => r.dataset.app)).toEqual([CHROME]);
    await user.click(screen.getByRole("button", { name: "Clear search" }));
    expect(box).toHaveValue("");
  });

  it("?app=<key> opens that app's panel, with mono hosts and a copyable path", async () => {
    const { user } = await setup(undefined, `?app=${encodeURIComponent(CHROME)}`);
    const sheet = await screen.findByRole("dialog");
    expect(within(sheet).getByRole("heading", { name: "Google Chrome" })).toBeInTheDocument();
    const hosts = within(sheet).getAllByTestId("host");
    expect(hosts.length).toBeGreaterThan(0);
    for (const h of hosts) expect(h.className).toContain("font-mono");
    await user.click(within(sheet).getByRole("button", { name: /^Copy path / }));
    expect(within(sheet).getByRole("button", { name: /^Copied / })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(new URLSearchParams(window.location.search).get("app")).toBeNull();
  });

  it("a row opens the panel and writes ?app=", async () => {
    const { user } = await setup();
    await user.click(within(row(CHROME)).getByRole("button", { name: /^Google Chrome, / }));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(new URLSearchParams(window.location.search).get("app")).toBe(CHROME);
  });

  it("bulk: turn every app off, then sieve every app again, each with undo", async () => {
    const { runtime, user } = await setup();
    await user.click(screen.getByRole("button", { name: "More app actions" }));
    await user.click(await screen.findByRole("menuitem", { name: "Turn every app off" }));
    expect(runtime.settings.get("apps.levels")[CHROME]).toBe("off");
    await user.click(screen.getByRole("button", { name: "More app actions" }));
    await user.click(await screen.findByRole("menuitem", { name: "Sieve every app" }));
    expect(runtime.settings.get("apps.levels")).toEqual({});
  });

  it("the browser add-app dialog pins a typed .exe path and rejects others", async () => {
    const { runtime, user } = await setup();
    await user.click(screen.getByRole("button", { name: "Add app" }));
    const dialog = await screen.findByRole("dialog", { name: "Add an app" });
    const input = within(dialog).getByLabelText("Program path");
    await user.type(input, "C:\\Tools\\notes.txt");
    await user.click(within(dialog).getByRole("button", { name: "Add" }));
    expect(within(dialog).getByText("Enter a path that ends in .exe")).toBeInTheDocument();
    await user.clear(input);
    await user.type(input, "C:\\Tools\\thing.exe");
    await user.click(within(dialog).getByRole("button", { name: "Add" }));
    expect(runtime.settings.get("apps.pinned")).toEqual(["C:\\Tools\\thing.exe"]);
    expect(await screen.findByText("thing")).toBeInTheDocument();
  });

  it("every button has an accessible name", async () => {
    await setup({ "apps.pinned": ["D:\\Tools\\quiet.exe"] });
    for (const b of screen.getAllByRole("button")) expect(b).toHaveAccessibleName();
  });
});

describe("Virtual machines and WSL", () => {
  const vmRow = (key: string) => document.querySelector<HTMLElement>(`[data-testid="vm-row"][data-app="${key}"]`)!;
  const group = () => screen.queryByTestId("vm-group");

  // The user's engine switch is on: off, the engine controller would turn routing off.
  async function withEngine(engine: EngineSource, stored?: Record<string, unknown>) {
    const runtime: Runtime = createRuntime({
      source: createMockSource({ seed: 1 }),
      settings: memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true, ...stored } }),
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

  async function routing(stored?: Record<string, unknown>) {
    const ready = await withEngine(createMockEngine("filtering"), stored);
    await screen.findByTestId("vm-group");
    return ready;
  }

  it("is hidden with no status, a null pipe, or no guests", async () => {
    await withEngine(createMockEngine("missing"));
    expect(group()).toBeNull();
    cleanup();
    await withEngine(createMockEngine("idle"), { [ENGINE_SWITCH]: false });
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(group()).toBeNull();
  });

  it("stays hidden when the engine sends no guests or broken ones, and keeps the good rows", async () => {
    const example = fixture.examples.filtering as unknown as { pipe: { status: Record<string, unknown> } };
    const probing = (guests: unknown): EngineSource => ({
      ...createMockEngine("filtering"),
      probe: async () => parseEngineProbe({ ...example, pipe: { ...example.pipe, status: { ...example.pipe.status, guests } } }),
    });
    await withEngine(probing(undefined));
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(group()).toBeNull();
    cleanup();
    await withEngine(probing([{ key: 7 }, { key: "vm:devbox", vm: "DevBox", seen: 1, open: 0 }]));
    await screen.findByTestId("vm-group");
    expect(screen.getAllByTestId("vm-row").map((r) => r.dataset.app)).toEqual(["vm:devbox"]);
  });

  it("sits above Mine, one row per VM, with the note and the exact unidentified label", async () => {
    await routing({ "apps.pinned": ["D:\\Tools\\quiet.exe"] });
    const headers = screen.getAllByRole("button", { expanded: true }).map((b) => b.textContent?.replace(/\d+$/, ""));
    expect(headers).toEqual([VM_GROUP_LABEL, "Mine", "Apps", "System"]);
    expect(VM_GROUP_LABEL).toBe("Virtual machines and WSL");
    expect(screen.getAllByTestId("vm-row").map((r) => r.dataset.app)).toEqual(["vm:devbox", "vm:unidentified"]);
    expect(within(vmRow("vm:devbox")).getByText("DevBox")).toBeInTheDocument();
    expect(within(vmRow("vm:unidentified")).getByText("Unidentified virtual machine traffic")).toBeInTheDocument();
    for (const key of ["vm:devbox", "vm:unidentified"]) expect(within(vmRow(key)).getByText("Filtered by domain only")).toBeInTheDocument();
  });

  it("a row's switch writes its key into apps.levels and says what Off does there", async () => {
    const { runtime, user } = await routing();
    // Freeze sampling so the count can only move because of the toggle.
    act(() => runtime.poller.stop());
    const sieved = screen.getByTestId("sieved-count").textContent;
    const toggle = within(vmRow("vm:devbox")).getByRole("switch", { name: "Sieve DevBox" });
    expect(toggle).toBeChecked();
    expect(toggle).toHaveAccessibleDescription(VM_OFF_MEANS);
    expect(VM_OFF_MEANS).not.toBe(APP_OFF_MEANS);
    expect(VM_OFF_MEANS).not.toMatch(/chart|track/i);
    await user.click(toggle);
    expect(runtime.settings.get("apps.levels")).toEqual({ "vm:devbox": "off" });
    expect(vmRow("vm:devbox")).toHaveAttribute("data-off");
    expect(screen.getByTestId("sieved-count").textContent).toBe(sieved);
    await user.click(toggle);
    expect(runtime.settings.get("apps.levels")).toEqual({});
  });

  it("an Off stored earlier applies when the row returns", async () => {
    await routing({ "apps.levels": { "vm:unidentified": "off" } });
    expect(within(vmRow("vm:unidentified")).getByRole("switch")).not.toBeChecked();
    expect(within(vmRow("vm:devbox")).getByRole("switch")).toBeChecked();
  });

  it("search narrows it; a name only a VM has is not 'nothing by that name'", async () => {
    const { user } = await routing();
    const box = screen.getByRole("searchbox", { name: "Search apps" });
    await user.type(box, "devb");
    expect(screen.getAllByTestId("vm-row").map((r) => r.dataset.app)).toEqual(["vm:devbox"]);
    expect(screen.queryByText("Nothing by that name")).toBeNull();
    await user.clear(box);
    await user.type(box, "chrome");
    expect(group()).toBeNull();
  });

  it("bulk Off includes the rows, since its notice says every app; Sieve all clears them", async () => {
    const { runtime, user } = await routing();
    await user.click(screen.getByRole("button", { name: "More app actions" }));
    await user.click(await screen.findByRole("menuitem", { name: "Turn every app off" }));
    const levels = runtime.settings.get("apps.levels");
    expect(levels["vm:devbox"]).toBe("off");
    expect(levels["vm:unidentified"]).toBe("off");
    await user.click(screen.getByRole("button", { name: "More app actions" }));
    await user.click(await screen.findByRole("menuitem", { name: "Sieve every app" }));
    expect(runtime.settings.get("apps.levels")).toEqual({});
  });
});
