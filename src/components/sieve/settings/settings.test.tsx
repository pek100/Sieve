import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SECTIONS, SETTING_KEYS, settingDef } from "@/core/settings/registry";
import { EXPORT_KIND } from "@/core/settings/transfer";
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

  it("a data switch is a locked, disabled switch that names its live check, and the value in force is off", async () => {
    await setup({ schema: 1, values: { "filtering.dns": true } });
    const dns = row("filtering.dns");
    const sw = within(dns).getByRole("switch");
    expect(sw).toBeDisabled();
    expect(sw).not.toBeChecked();
    expect(dns.querySelector("[data-lock=liveCheck]")).toHaveTextContent(/live_dns_filter_resolves_blocked_domain/);
    expect(dns).toHaveTextContent(/Needed by the sieve level for apps/);
  });

  it("launch at startup is a switch only the desktop app can change", async () => {
    await setup();
    const r = row("startup.launchAtLogin");
    expect(within(r).getByRole("switch")).toBeDisabled();
    expect(r.querySelector("[data-lock=desktop]")).toBeInTheDocument();
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

  it("import previews every change before applying, refuses a locked switch, and undo restores", async () => {
    const rt = await setup();
    await userEvent.click(screen.getByRole("button", { name: "Settings actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Import settings" }));
    const file = JSON.stringify({ kind: EXPORT_KIND, schema: 1, values: { "appearance.theme": "light", "filtering.dns": true } });
    fireEvent.change(screen.getByRole("textbox", { name: "Settings file to import" }), { target: { value: file } });
    await userEvent.click(screen.getByRole("button", { name: "Preview changes" }));

    const changes = screen.getByRole("list", { name: "Changes" });
    expect(within(changes).getAllByRole("listitem")).toHaveLength(1);
    expect(changes).toHaveTextContent(/Theme\s*Dark.*Light/);
    expect(screen.getByRole("list", { name: "Not imported" })).toHaveTextContent(/filtering\.dns.*live check/);
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
