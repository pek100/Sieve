import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createMockSource } from "@/data/mock-source";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime, type Runtime } from "@/hooks/runtime";
import { AppShell } from "@/components/sieve/shell/app-shell";
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

  it("sieve is disabled and says it needs DNS filtering while the data switch is off", async () => {
    await setup();
    const group = within(row(CHROME)).getByRole("radiogroup", { name: "Level for Google Chrome" });
    const sieve = within(group).getByRole("radio", { name: "Sieve" });
    expect(sieve).toBeDisabled();
    expect(sieve).toHaveAccessibleDescription("Needs DNS filtering, which is off");
    expect(within(group).getByRole("radio", { name: "Watch" })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByTestId("sieve-locked")).toHaveTextContent("Needs DNS filtering, which is off");
  });

  it("setting an app to off stores it and drops it from the being-sieved count", async () => {
    const { runtime, user } = await setup();
    const count = () => Number(screen.getByTestId("sieved-count").textContent?.split(" ")[0]);
    // Freeze sampling so the count only moves because of the level.
    act(() => runtime.poller.stop());
    const before = count();
    await user.click(within(row(CHROME)).getByRole("radio", { name: "Off" }));
    expect(runtime.settings.get("apps.levels")).toEqual({ [CHROME]: "off" });
    expect(within(row(CHROME)).getByRole("radio", { name: "Off" })).toHaveAttribute("aria-checked", "true");
    expect(count()).toBe(before - 1);
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

  it("reset asks first, then empties apps.levels", async () => {
    const { runtime, user } = await setup({ "apps.levels": { [CHROME]: "off" } });
    await user.click(screen.getByRole("button", { name: "More app actions" }));
    await user.click(await screen.findByRole("menuitem", { name: "Reset levels" }));
    const dialog = await screen.findByRole("dialog", { name: "Reset every app to watch?" });
    expect(runtime.settings.get("apps.levels")).toEqual({ [CHROME]: "off" });
    await user.click(within(dialog).getByRole("button", { name: "Reset levels" }));
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
