import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { DNS_SWITCH } from "@/core/dns";
import { createMockDns, MOCK_PORT_BUSY, type DnsScenario } from "@/data/dns-mock";
import type { DnsSource } from "@/data/dns-source";
import { createMockSource } from "@/data/mock-source";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { SettingsScreen } from "./settings-screen";

vi.mock("next/navigation", () => ({ usePathname: () => "/settings/" }));
vi.setConfig({ testTimeout: 20_000 });

async function setup(
  scenario: DnsScenario,
  opts: { stored?: Record<string, unknown>; adguard?: boolean; over?: Partial<DnsSource>; systemReadable?: boolean } = {},
) {
  const dns = { ...createMockDns({ seed: 1, scenario, adguard: opts.adguard }), ...opts.over } as DnsSource;
  const runtime = createRuntime({
    source: createMockSource({ seed: 1 }),
    settings: memoryBackend({ schema: 1, values: opts.stored ?? {} }),
    dns,
  });
  render(
    <SieveProvider runtime={runtime}>
      <SettingsScreen />
    </SieveProvider>,
  );
  await act(async () => {
    await runtime.settings.ready;
  });
  if (opts.systemReadable !== false) await vi.waitFor(() => expect(runtime.store.getState().dns.system).not.toBeNull());
  return runtime;
}

const card = () => screen.getByRole("region", { name: "DNS filter" });
const phase = () => card().querySelector("[data-dns-phase]")!.getAttribute("data-dns-phase");

describe("DNS card", () => {
  it("off: says so, shows Windows' own DNS per adapter, and Point is disabled until the filter runs", async () => {
    await setup("off");
    expect(phase()).toBe("off");
    expect(card()).toHaveTextContent("Off. Lookups go to Windows' own DNS servers.");
    expect(card()).toHaveTextContent(/every app on this computer at once/);
    const adapters = within(card()).getByRole("list", { name: "Network adapters" });
    expect(within(adapters).getAllByRole("listitem")).toHaveLength(2);
    expect(adapters).toHaveTextContent("192.0.2.53 (DHCP)");
    expect(adapters).toHaveTextContent("198.51.100.53, 203.0.113.53 (set by hand)");
    expect(within(card()).getByRole("button", { name: "Point Windows at Sieve" })).toBeDisabled();
    expect(within(card()).getByRole("button", { name: "Restore my DNS" })).toBeDisabled();
    expect(within(card()).queryByRole("list", { name: "Most blocked domains" })).toBeNull();
  });

  it("on: running with counters, list info, the passed check, and Point becomes available; Point then Restore", async () => {
    const rt = await setup("off");
    await userEvent.click(within(card()).getByRole("switch", { name: "DNS filtering" }));
    await vi.waitFor(() => expect(phase()).toBe("running"));
    expect(card()).toHaveTextContent("Running on 127.0.0.1:53 and [::1]:53.");
    expect(card().querySelector("[data-dns-check=pass]")).toHaveTextContent(/Self check passed: doubleclick\.net is blocked on 127\.0\.0\.1:53 and \[::1\]:53/);
    expect(card()).toHaveTextContent("Windows does not use Sieve for DNS yet, so nothing is blocked.");
    expect(card().querySelector("[data-stat=queries] [data-numeric]")).toHaveTextContent("3");
    expect(card().querySelector("[data-dns-list]")).toHaveTextContent(/51,234 block rules, 812 allow rules, 97 lines skipped\. Updated/);
    const point = within(card()).getByRole("button", { name: "Point Windows at Sieve" });
    await vi.waitFor(() => expect(point).toBeEnabled());
    await userEvent.click(point);
    await vi.waitFor(() => expect(rt.store.getState().dns.system?.pointed).toBe(true));
    expect(card().querySelector("[data-system-dns]")).toHaveAttribute("data-system-dns", "pointed");
    expect(within(card()).getAllByText("Uses Sieve")).toHaveLength(2);
    expect(card()).toHaveTextContent(/restore-dns\.ps1/);
    await userEvent.click(within(card()).getByRole("button", { name: "Restore my DNS" }));
    await vi.waitFor(() => expect(rt.store.getState().dns.system?.pointed).toBe(false));
  });

  it("error: a busy port 53 turns the switch back off and the card says why", async () => {
    const rt = await setup("error", { stored: { [DNS_SWITCH]: true } });
    await vi.waitFor(() => expect(phase()).toBe("error"));
    expect(rt.settings.get(DNS_SWITCH)).toBe(false);
    expect(within(card()).getByRole("alert")).toHaveTextContent(MOCK_PORT_BUSY);
    expect(within(card()).getByRole("switch", { name: "DNS filtering" })).not.toBeChecked();
  });

  it("AdGuard running: a warning that its DNS protection must be paused for Sieve to decide", async () => {
    await setup("off", { adguard: true });
    await vi.waitFor(() => expect(within(card()).getByRole("note", { name: "AdGuard is running" })).toBeInTheDocument());
    expect(within(card()).getByRole("note", { name: "AdGuard is running" })).toHaveTextContent(/Pause AdGuard's DNS protection/);
  });

  it("degraded data never crashes the card: unreadable Windows DNS, no list, nothing blocked", async () => {
    const base = createMockDns({ seed: 1 });
    const noList = { url: null, fetched_at: null, rules: 0, allow: 0, skipped: 0, user_rules: false, error: "offline" };
    await setup("off", {
      stored: { [DNS_SWITCH]: true },
      systemReadable: false,
      over: {
        systemState: async () => {
          throw new Error("access denied");
        },
        status: async () => ({ ...(await base.status()), list: noList }),
        start: async (c) => ({ ...(await base.start(c)), list: noList }),
        selfCheck: () => base.selfCheck(),
      },
    });
    await vi.waitFor(() => expect(phase()).toBe("running"));
    // Windows DNS was never read: the card says so, and Point stays off (no adapters to back up).
    expect(card().querySelector("[data-system-dns]")).toHaveAttribute("data-system-dns", "unknown");
    expect(within(card()).getByRole("button", { name: "Point Windows at Sieve" })).toBeDisabled();
    // The next poll (2 s) reads Windows DNS again and says why it failed.
    await vi.waitFor(() => expect(within(card()).getByRole("alert")).toHaveTextContent("Windows DNS could not be read: access denied"), {
      timeout: 5000,
    });
    expect(card().querySelector("[data-dns-list]")).toHaveTextContent("No list is loaded, so nothing is blocked.");
    expect(card()).toHaveTextContent("The list could not be refreshed: offline");
  });
});
