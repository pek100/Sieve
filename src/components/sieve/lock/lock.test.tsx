import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { AppsScreen } from "@/components/sieve/apps/apps-screen";
import { EngineCard } from "@/components/sieve/settings/engine-card";
import { SettingsScreen } from "@/components/sieve/settings/settings-screen";
import { AppShell } from "@/components/sieve/shell/app-shell";
import { exportText, resetPlan } from "@/core/settings/transfer";
import { createMockEngine } from "@/data/engine-mock";
import type { EngineSource } from "@/data/engine-source";
import { MOCK_PASSWORD, createMockLock, type LockScenario } from "@/data/lock-mock";
import { createMockSource } from "@/data/mock-source";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime, type Runtime } from "@/hooks/runtime";
import { FiltersScreen } from "@/components/sieve/filters/filters-screen";
import { LockGate } from "./lock-gate";

vi.mock("next/navigation", () => ({ usePathname: () => "/settings/" }));
vi.mock("next/link", () => ({ default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a> }));
vi.setConfig({ testTimeout: 30_000 });

const settle = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });

async function setup(children: ReactNode, o: { lock?: LockScenario; engine?: EngineSource; stored?: unknown } = {}) {
  const runtime = createRuntime({
    source: createMockSource({ seed: 1 }),
    settings: memoryBackend(o.stored),
    lock: createMockLock(o.lock ?? "set"),
    engine: o.engine,
  });
  render(<AppShell runtime={runtime}>{children}</AppShell>);
  await act(async () => {
    await runtime.settings.ready;
  });
  await settle();
  return runtime;
}

const dialog = () => screen.findByRole("dialog", { name: "Unlock settings" });

async function answerRight() {
  const d = await dialog();
  await userEvent.type(within(d).getByLabelText("Password"), MOCK_PASSWORD);
  await userEvent.click(within(d).getByRole("button", { name: "Unlock" }));
  await settle();
}

const row =(key: string) => document.querySelector<HTMLElement>(`[data-setting="${key}"]`)!;

/** Each writer: it asks and writes nothing; after unlock the write lands; on cancel it is dropped. */
describe("the write gate, one test per writer, while locked", () => {
  it("master switch", async () => {
    const rt = await setup(<p>page</p>);
    const sw = screen.getByRole("switch", { name: "Sieving" });
    await userEvent.click(sw);
    await dialog();
    expect(rt.settings.get("sampling.enabled")).toBe(true);
    await answerRight();
    expect(rt.settings.get("sampling.enabled")).toBe(false);
  });

  it("master switch: cancel drops the write", async () => {
    const rt = await setup(<p>page</p>);
    await userEvent.click(screen.getByRole("switch", { name: "Sieving" }));
    const d = await dialog();
    await userEvent.click(within(d).getByRole("button", { name: "Cancel" }));
    await settle();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(rt.settings.get("sampling.enabled")).toBe(true);
    screen.getByRole("button", { name: "Unlock settings" }).click();
    await answerRight();
    expect(rt.settings.get("sampling.enabled")).toBe(true);
  });

  it("theme", async () => {
    const rt = await setup(<p>page</p>);
    await userEvent.click(screen.getByRole("button", { name: /theme/i }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Light" }));
    await dialog();
    expect(rt.settings.get("appearance.theme")).toBe("dark");
    await answerRight();
    expect(rt.settings.get("appearance.theme")).toBe("light");
  });

  it("app toggle", async () => {
    const rt = await setup(<AppsScreen />);
    await act(async () => {
      rt.poller.start();
      await new Promise((r) => setTimeout(r, 50));
    });
    const row = await screen.findAllByTestId("app-row");
    await userEvent.click(within(row[0]).getByRole("switch"));
    await dialog();
    expect(rt.settings.get("apps.levels")).toEqual({});
    await answerRight();
    expect(Object.values(rt.settings.get("apps.levels"))).toEqual(["off"]);
  });

  it("pin", async () => {
    const rt = await setup(<AppsScreen />);
    await userEvent.click(await screen.findByRole("button", { name: /add app/i }));
    const box = await screen.findByRole("textbox", { name: /path/i });
    await userEvent.type(box, "C:\\Tools\\tool.exe{Enter}");
    await dialog();
    expect(rt.settings.get("apps.pinned")).toEqual([]);
    await answerRight();
    expect(rt.settings.get("apps.pinned")).toEqual(["C:\\Tools\\tool.exe"]);
  });

  it("setting row: disabled with the note, and Unlock opens it for the write", async () => {
    const rt = await setup(<SettingsScreen />);
    const theme = within(row("appearance.theme"));
    expect(theme.getByRole("radio", { name: "Light" })).toBeDisabled();
    expect(row("appearance.theme").querySelector("[data-lock=password]")).toHaveTextContent("Settings are locked.");
    await userEvent.click(theme.getByRole("button", { name: "Unlock" }));
    await answerRight();
    await userEvent.click(theme.getByRole("radio", { name: "Light" }));
    expect(rt.settings.get("appearance.theme")).toBe("light");
    expect(row("appearance.theme").querySelector("[data-lock=password]")).toBeNull();
  });

  it("a locked row the engine carries out still shows the engine's value, never the stored wish", async () => {
    await setup(<SettingsScreen />, { stored: { schema: 4, values: { "filtering.engine": true } } });
    const sw = within(row("filtering.engine")).getByRole("switch");
    expect(sw).toBeDisabled();
    expect(sw).not.toBeChecked();
    expect(row("filtering.engine").querySelector("[data-lock=password]")).toBeInTheDocument();
  });

  it("a list row's Clear is disabled while locked", async () => {
    await setup(<SettingsScreen />, { stored: { schema: 4, values: { "apps.pinned": ["C:\\a.exe"] } } });
    expect(within(row("apps.pinned")).getByRole("button", { name: /Clear/ })).toBeDisabled();
  });

  it("import", async () => {
    const rt = await setup(<SettingsScreen />);
    await userEvent.click(screen.getByRole("button", { name: "Settings actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Import settings" }));
    const box = await screen.findByRole("textbox", { name: "Settings file to import" });
    await act(async () => {
      await userEvent.click(box);
      await userEvent.paste(JSON.stringify({ kind: "sieve.settings", schema: 4, values: { "sampling.intervalMs": 2000 } }));
    });
    await userEvent.click(screen.getByRole("button", { name: "Preview changes" }));
    await userEvent.click(screen.getByRole("button", { name: "Apply 1 change" }));
    await dialog();
    expect(rt.settings.get("sampling.intervalMs")).toBe(1000);
    await answerRight();
    expect(rt.settings.get("sampling.intervalMs")).toBe(2000);
  });

  it("reset all", async () => {
    const rt = await setup(<SettingsScreen />, { stored: { schema: 4, values: { "sampling.intervalMs": 2000 } } });
    await userEvent.click(screen.getByRole("button", { name: "Settings actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Reset to defaults" }));
    await userEvent.click(await screen.findByRole("button", { name: "Reset to defaults" }));
    await dialog();
    expect(rt.settings.get("sampling.intervalMs")).toBe(2000);
    await answerRight();
    expect(rt.settings.get("sampling.intervalMs")).toBe(1000);
  });

  it("AdGuard pause", async () => {
    const mock = createMockEngine("adguard");
    const stopAdguard = vi.fn(mock.stopAdguard);
    const rt = await setup(<EngineCard />, { engine: { ...mock, stopAdguard }, stored: { schema: 4, values: { "filtering.engine": true } } });
    await act(async () => {
      await rt.settings.ready;
    });
    const button = await screen.findByRole("button", { name: "Pause AdGuard" });
    await userEvent.click(button);
    await dialog();
    expect(stopAdguard).not.toHaveBeenCalled();
    await answerRight();
    expect(stopAdguard).toHaveBeenCalledOnce();
  });

  it("the Filters screen stays readable and takes no change until unlocked", async () => {
    const rt = await setup(<FiltersScreen />);
    const sw = await screen.findByRole("switch", { name: "AdGuard Base filter" });
    expect(sw).toBeDisabled();
    expect(sw).toBeChecked();
    expect(screen.getByRole("textbox", { name: "User rules" })).toHaveAttribute("readonly");
    await userEvent.click(screen.getByRole("button", { name: "Unlock" }));
    await answerRight();
    await userEvent.click(sw);
    expect(rt.settings.get("filters.lists")).toEqual({ "adguard-base": "off" });
  });
});

describe("the prompt", () => {
  it("a wrong password says so and stays; the right one opens", async () => {
    const rt = await setup(<p>page</p>);
    screen.getByRole("button", { name: "Unlock settings" }).click();
    const d = await dialog();
    await userEvent.type(within(d).getByLabelText("Password"), "not the one");
    await userEvent.click(within(d).getByRole("button", { name: "Unlock" }));
    await settle();
    expect(within(d).getByRole("alert")).toHaveTextContent("That is not the password.");
    await userEvent.clear(within(d).getByLabelText("Password"));
    await userEvent.type(within(d).getByLabelText("Password"), MOCK_PASSWORD);
    await userEvent.click(within(d).getByRole("button", { name: "Unlock" }));
    await settle();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(rt.lockController.state().phase).toBe("unlocked");
  });
});

describe("the password block", () => {
  const block = () => document.querySelector<HTMLElement>("[data-password-block]")!;

  it("set, change, lock and remove, with the current password each time", async () => {
    const rt = await setup(<SettingsScreen />, { lock: "none" });
    const b = within(block());
    await userEvent.click(b.getByRole("button", { name: "Set a password" }));
    const d = await screen.findByRole("dialog", { name: "Set a password" });
    await userEvent.type(within(d).getByLabelText("New password"), "short");
    await userEvent.type(within(d).getByLabelText("New password again"), "short");
    await userEvent.click(within(d).getByRole("button", { name: "Set password" }));
    expect(within(d).getByRole("alert")).toHaveTextContent("at least 8");
    await userEvent.clear(within(d).getByLabelText("New password"));
    await userEvent.clear(within(d).getByLabelText("New password again"));
    await userEvent.type(within(d).getByLabelText("New password"), "a good password");
    await userEvent.type(within(d).getByLabelText("New password again"), "a good password");
    await userEvent.click(within(d).getByRole("button", { name: "Set password" }));
    await settle();
    expect(rt.lockController.state().phase).toBe("unlocked");
    expect(block()).toHaveAttribute("data-lock-phase", "unlocked");

    await userEvent.click(b.getByRole("button", { name: "Lock now" }));
    expect(rt.lockController.state().phase).toBe("locked");
    expect(within(block()).queryByRole("button", { name: "Change password" })).toBeNull();
    rt.lockController.ask();
    const u = await dialog();
    await userEvent.type(within(u).getByLabelText("Password"), "a good password");
    await userEvent.click(within(u).getByRole("button", { name: "Unlock" }));
    await settle();

    await userEvent.click(within(block()).getByRole("button", { name: "Remove password" }));
    const r = await screen.findByRole("dialog", { name: "Remove the password" });
    await userEvent.type(within(r).getByLabelText("Current password"), "wrong one");
    await userEvent.click(within(r).getByRole("button", { name: "Remove password" }));
    await settle();
    expect(within(r).getByRole("alert")).toHaveTextContent("not the current password");
    await userEvent.clear(within(r).getByLabelText("Current password"));
    await userEvent.type(within(r).getByLabelText("Current password"), "a good password");
    await userEvent.click(within(r).getByRole("button", { name: "Remove password" }));
    await settle();
    expect(rt.lockController.state().phase).toBe("none");
  });

  it("an unreadable file says why, and nothing opens", async () => {
    const rt = await setup(<SettingsScreen />, { lock: "unreadable" });
    expect(block()).toHaveTextContent("could not read its password file");
    expect(within(block()).queryByRole("button")).toBeNull();
    expect(row("appearance.theme").querySelector("[data-lock=password]")).toHaveTextContent("could not read its password file");
    // The top bar's switch comes first; the Settings row's is disabled.
    await userEvent.click(screen.getAllByRole("switch", { name: "Sieving" })[0]);
    await settle();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(rt.settings.get("sampling.enabled")).toBe(true);
  });
});

describe("LockGate", () => {
  const SECRET = "what was browsed";

  it("hides its children while locked, unreadable or still checking, and shows them unlocked or with no password", async () => {
    const shown = () => screen.queryByText(SECRET) !== null;
    const gate = <LockGate>{SECRET}</LockGate>;
    const rt = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend(), lock: createMockLock("set") });
    const view = render(<AppShell runtime={rt}>{gate}</AppShell>);
    expect(shown()).toBe(false);
    await settle();
    expect(rt.lockController.state().phase).toBe("locked");
    expect(shown()).toBe(false);
    await userEvent.click(screen.getByRole("button", { name: "Unlock" }));
    await answerRight();
    expect(shown()).toBe(true);
    act(() => rt.lockController.lockNow());
    expect(shown()).toBe(false);
    view.unmount();

    await setup(gate, { lock: "none" });
    expect(shown()).toBe(true);
  });

  it("unreadable stays shut", async () => {
    await setup(<LockGate>{SECRET}</LockGate>, { lock: "unreadable" });
    expect(screen.queryByText(SECRET)).toBeNull();
  });
});

describe("the password is not a setting", () => {
  it("export carries nothing of it, and a reset leaves it set", async () => {
    const rt: Runtime = await setup(<p>page</p>);
    const text = exportText(rt.settings.doc());
    expect(text).not.toMatch(/argon|phc|hash/i);
    const { next } = resetPlan(rt.settings.doc());
    await rt.settings.replace(next);
    expect((await rt.lock.status()).state).toBe("set");
    expect(rt.lockController.state().phase).toBe("locked");
  });
});
