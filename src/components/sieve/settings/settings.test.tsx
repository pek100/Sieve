import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SECTIONS, SETTING_KEYS, settingDef } from "@/core/settings/registry";
import { EXPORT_KIND } from "@/core/settings/transfer";
import type { Desktop } from "@/data/desktop";
import { createMockSource } from "@/data/mock-source";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { NoticeToaster } from "@/components/sieve/shell/notice-toaster";
import { SettingsScreen } from "./settings-screen";

vi.mock("next/navigation", () => ({ usePathname: () => "/settings/" }));
vi.setConfig({ testTimeout: 20_000 });

async function setup(stored?: unknown) {
  const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend(stored) });
  render(
    <SieveProvider runtime={runtime}>
      <SettingsScreen />
      <NoticeToaster />
    </SieveProvider>,
  );
  await act(async () => {
    await runtime.settings.ready;
  });
  return runtime;
}

const row = (key: string) => document.querySelector<HTMLElement>(`[data-setting="${key}"]`)!;

describe("settings view (rendered from the registry)", () => {
  it("shows one row per registry key under its section, and the rail lists the sections in order", async () => {
    await setup();
    for (const key of SETTING_KEYS) {
      const r = row(key);
      expect(r, key).not.toBeNull();
      expect(r).toHaveTextContent(settingDef(key).label);
    }
    const rail = screen.getByRole("navigation", { name: "Settings sections" });
    expect(within(rail).getAllByRole("link").map((a) => a.textContent)).toEqual(
      SECTIONS.filter((s) => SETTING_KEYS.some((k) => settingDef(k).section === s.id)).map((s) => s.label),
    );
  });

  it("there is no per-app filtering row: per-app DNS exemption would need a network driver", async () => {
    await setup({ schema: 1, values: { "filtering.perApp": true } });
    expect(document.querySelector('[data-setting="filtering.perApp"]')).toBeNull();
    expect(document.querySelector("[data-lock=unavailable]")).toBeNull();
    expect(row("apps.levels")).toHaveTextContent("Apps turned off");
  });

  it("DNS filtering is a live switch: on starts the filter and records its passed self check", async () => {
    const rt = await setup();
    const dns = row("filtering.dns");
    expect(dns.querySelector("[data-lock]")).toBeNull();
    expect(dns).toHaveTextContent(/every app on this computer/);
    // Pointing Windows waits for DNS filtering.
    expect(within(row("filtering.systemDns")).getByRole("switch")).toBeDisabled();
    expect(row("filtering.systemDns").querySelector("[data-lock=requires]")).toHaveTextContent("Needs DNS filtering, which is off.");
    await userEvent.click(within(dns).getByRole("switch"));
    await vi.waitFor(() => expect(rt.passedChecks.has("filtering.dns")).toBe(true));
    expect(rt.store.getState().dns.status?.running).toBe(true);
    expect(within(row("filtering.dns")).getByRole("switch")).toBeChecked();
    await vi.waitFor(() => expect(within(row("filtering.systemDns")).getByRole("switch")).toBeEnabled());
  });

  it("launch at startup is a switch only the desktop app can change", async () => {
    await setup();
    const r = row("startup.launchAtLogin");
    expect(within(r).getByRole("switch")).toBeDisabled();
    expect(r.querySelector("[data-lock=desktop]")).toBeInTheDocument();
  });

  it("in the desktop app, launch at startup is a live switch that the OS entry follows", async () => {
    const autostart: boolean[] = [];
    const desktop: Desktop = {
      setTray: async () => {},
      onTrayAction: async () => () => {},
      autostart: { isEnabled: async () => autostart.at(-1) ?? false, set: async (on) => void autostart.push(on) },
      onCloseRequested: async () => () => {},
      quit: async () => {},
    };
    const rt = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend(), isTauri: true, desktop });
    render(
      <SieveProvider runtime={rt}>
        <SettingsScreen />
      </SieveProvider>,
    );
    await act(async () => {
      await rt.settings.ready;
    });
    const r = row("startup.launchAtLogin");
    const sw = within(r).getByRole("switch");
    expect(sw).toBeEnabled();
    expect(sw).not.toBeChecked();
    expect(r.querySelector("[data-lock]")).toBeNull();
    // Default off and the OS entry is off: nothing is written.
    expect(autostart).toEqual([]);

    await userEvent.click(sw);
    expect(rt.settings.get("startup.launchAtLogin")).toBe(true);
    await vi.waitFor(() => expect(autostart).toEqual([true]));
    expect(within(row("startup.launchAtLogin")).getByRole("switch")).toBeChecked();
  });

  it("changing a control writes the setting", async () => {
    const rt = await setup();
    await userEvent.click(within(row("appearance.theme")).getByRole("radio", { name: "Light" }));
    expect(rt.settings.get("appearance.theme")).toBe("light");
    await userEvent.click(within(row("sampling.enabled")).getByRole("switch"));
    expect(rt.settings.get("sampling.enabled")).toBe(false);
  });

  it("search narrows the rows and sections; no match shows one empty state; Escape clears", async () => {
    await setup();
    const search = screen.getByRole("searchbox", { name: "Search settings" });
    // Keys are searched too: "intervalms" is only in the key sampling.intervalMs.
    fireEvent.change(search, { target: { value: "intervalms" } });
    expect([...document.querySelectorAll("[data-setting]")].map((e) => e.getAttribute("data-setting"))).toEqual(["sampling.intervalMs"]);
    expect(within(screen.getByRole("navigation", { name: "Settings sections" })).getAllByRole("link")).toHaveLength(1);
    fireEvent.change(search, { target: { value: "sample" } });
    expect([...document.querySelectorAll("[data-setting]")].map((e) => e.getAttribute("data-setting"))).toEqual(["sampling.intervalMs"]);
    fireEvent.change(search, { target: { value: "zzz" } });
    expect(screen.getByText("No setting matches")).toBeInTheDocument();
    fireEvent.keyDown(search, { key: "Escape" });
    expect(document.querySelectorAll("[data-setting]")).toHaveLength(SETTING_KEYS.length);
  });

  it("import previews every change before applying, never turns a data switch on, and undo restores", async () => {
    const rt = await setup();
    await userEvent.click(screen.getByRole("button", { name: "Settings actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Import settings" }));
    const file = JSON.stringify({ kind: EXPORT_KIND, schema: 1, values: { "appearance.theme": "light", "filtering.dns": true } });
    fireEvent.change(screen.getByRole("textbox", { name: "Settings file to import" }), { target: { value: file } });
    await userEvent.click(screen.getByRole("button", { name: "Preview changes" }));

    const changes = screen.getByRole("list", { name: "Changes" });
    expect(within(changes).getAllByRole("listitem")).toHaveLength(1);
    expect(changes).toHaveTextContent(/Theme\s*Dark.*Light/);
    expect(screen.getByRole("list", { name: "Not imported" })).toHaveTextContent(/filtering\.dns.*never turns this on/);
    // Nothing applied yet.
    expect(rt.settings.get("appearance.theme")).toBe("dark");

    await userEvent.click(screen.getByRole("button", { name: "Apply 1 change" }));
    expect(rt.settings.get("appearance.theme")).toBe("light");
    expect(rt.settings.get("filtering.dns")).toBe(false);
    const undo = await screen.findByRole("button", { name: "Undo" });
    await userEvent.click(undo);
    expect(rt.settings.get("appearance.theme")).toBe("dark");
  });

  it("a file that is not Sieve settings is refused with a reason", async () => {
    await setup();
    await userEvent.click(screen.getByRole("button", { name: "Settings actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Import settings" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Settings file to import" }), { target: { value: '{"a":1}' } });
    await userEvent.click(screen.getByRole("button", { name: "Preview changes" }));
    expect(screen.getByRole("alert")).toHaveTextContent("This is not a Sieve settings file.");
  });

  it("export shows only changed settings; reset to defaults confirms with the list, applies, and can be undone", async () => {
    const rt = await setup({ schema: 1, values: { "sampling.intervalMs": 2000 } });
    await userEvent.click(screen.getByRole("button", { name: "Settings actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Export settings" }));
    const text = (screen.getByRole("textbox", { name: "Exported settings" }) as HTMLTextAreaElement).value;
    expect(JSON.parse(text).values).toEqual({ "sampling.intervalMs": 2000 });
    await userEvent.click(screen.getByRole("button", { name: "Done" }));

    await userEvent.click(screen.getByRole("button", { name: "Settings actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Reset to defaults" }));
    expect(screen.getByRole("list", { name: "Changes" })).toHaveTextContent(/Sample every\s*2 s.*1 s/);
    await userEvent.click(screen.getByRole("button", { name: "Reset to defaults" }));
    expect(rt.settings.get("sampling.intervalMs")).toBe(1000);
    await userEvent.click(await screen.findByRole("button", { name: "Undo" }));
    expect(rt.settings.get("sampling.intervalMs")).toBe(2000);
  });

  it("every button on the screen has an accessible name", async () => {
    await setup({ schema: 1, values: { "apps.pinned": ["C:\\Tools\\a.exe"] } });
    for (const b of screen.getAllByRole("button")) expect(b).toHaveAccessibleName();
  });
});
