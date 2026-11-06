import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SECTIONS, SETTINGS_SCHEMA, SETTING_KEYS, isAvailable, settingDef } from "@/core/settings/registry";
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
  it("shows one row per available registry key under its section, none for an unavailable one, and the rail lists the sections in order", async () => {
    await setup();
    for (const key of SETTING_KEYS) {
      const r = row(key);
      if (!isAvailable(key)) {
        // Unavailable (unavailableUntil): no row, and nothing else on screen edits it.
        expect(r, key).toBeNull();
        expect(screen.queryAllByText(settingDef(key).label), key).toHaveLength(0);
        continue;
      }
      expect(r, key).not.toBeNull();
      expect(r).toHaveTextContent(settingDef(key).label);
    }
    const rail = screen.getByRole("navigation", { name: "Settings sections" });
    // Every section with an available key, and Filtering, which carries the engine.
    expect(within(rail).getAllByRole("link").map((a) => a.textContent)).toEqual(
      SECTIONS.filter((s) => s.id === "filtering" || SETTING_KEYS.some((k) => isAvailable(k) && settingDef(k).section === s.id)).map((s) => s.label),
    );
  });

  it("there is no per-app filtering row: an old file's value is gone", async () => {
    await setup({ schema: 1, values: { "filtering.perApp": true } });
    expect(document.querySelector('[data-setting="filtering.perApp"]')).toBeNull();
    expect(document.querySelector("[data-lock=unavailable]")).toBeNull();
    expect(row("apps.levels")).toHaveTextContent("Apps turned off");
  });

  it("the DNS filter is gone: no switch, no card; Filtering shows the engine and the encrypted upstreams", async () => {
    // Stored by an old build with DNS filtering on and bare upstreams.
    const rt = await setup({ schema: 3, values: { "filtering.dns": true, "filtering.upstreams": ["1.1.1.1"] } });
    expect(row("filtering.dns")).toBeNull();
    expect(screen.queryByRole("region", { name: "DNS filter" })).toBeNull();
    expect(screen.queryByRole("switch", { name: /DNS filtering/ })).toBeNull();
    // There is no switch that points Windows DNS anywhere (removed 2026-10-18).
    expect(document.querySelector('[data-setting="filtering.systemDns"]')).toBeNull();
    const filtering = document.getElementById("section-filtering")!;
    expect(within(filtering).getByRole("region", { name: "Engine" })).toBeInTheDocument();
    expect(filtering.querySelector("#engine")).not.toBeNull();
    // The upstream row is a summary of the defaults, no bare address, nothing to reset.
    expect(row("filtering.upstreams")).toHaveTextContent("https://cloudflare-dns.com/dns-query, https://dns.quad9.net/dns-query");
    expect(row("filtering.upstreams")).not.toHaveTextContent("1.1.1.1");
    expect(within(row("filtering.upstreams")).queryByRole("button")).toBeNull();
    expect(rt.passedChecks.has("filtering.dns")).toBe(false);
  });

  it("a migrated upstream list shows with a way back to the defaults", async () => {
    const rt = await setup({ schema: 4, values: { "filtering.upstreams": ["tls://a.example"] } });
    expect(row("filtering.upstreams")).toHaveTextContent("tls://a.example, https://cloudflare-dns.com/dns-query");
    await userEvent.click(within(row("filtering.upstreams")).getByRole("button", { name: "Reset Upstream DNS servers" }));
    expect(rt.settings.get("filtering.upstreams")).toEqual(settingDef("filtering.upstreams").default);
  });

  it("a search hides the engine's section unless a Filtering key matches; clearing it brings it back", async () => {
    await setup();
    const search = screen.getByRole("searchbox", { name: "Search settings" });
    fireEvent.change(search, { target: { value: "theme" } });
    expect(screen.queryByRole("region", { name: "Engine" })).toBeNull();
    fireEvent.change(search, { target: { value: "" } });
    expect(screen.getByRole("region", { name: "Engine" })).toBeInTheDocument();
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
    expect(document.querySelectorAll("[data-setting]")).toHaveLength(SETTING_KEYS.filter(isAvailable).length);
  });

  it("import previews every change before applying, refuses the retired DNS switch, and undo restores", async () => {
    const rt = await setup();
    await userEvent.click(screen.getByRole("button", { name: "Settings actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Import settings" }));
    // A current file (an older one loses the DNS switch to the migration before the preview).
    const file = JSON.stringify({ kind: EXPORT_KIND, schema: SETTINGS_SCHEMA, values: { "appearance.theme": "light", "filtering.dns": true } });
    fireEvent.change(screen.getByRole("textbox", { name: "Settings file to import" }), { target: { value: file } });
    await userEvent.click(screen.getByRole("button", { name: "Preview changes" }));

    const changes = screen.getByRole("list", { name: "Changes" });
    expect(within(changes).getAllByRole("listitem")).toHaveLength(1);
    expect(changes).toHaveTextContent(/Theme\s*Dark.*Light/);
    expect(screen.getByRole("list", { name: "Not imported" })).toHaveTextContent(/filtering\.dns.*Not a setting in this version of Sieve/);
    // Nothing applied yet.
    expect(rt.settings.get("appearance.theme")).toBe("dark");

    await userEvent.click(screen.getByRole("button", { name: "Apply 1 change" }));
    expect(rt.settings.get("appearance.theme")).toBe("light");
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
