import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { DNS_POLL_MS, DNS_SWITCH, STRANDED_DNS_TEXT } from "@/core/dns";
import { createMockDns, MOCK_PORT_BUSY, type DnsScenario } from "@/data/dns-mock";
import type { DnsSource } from "@/data/dns-source";
import { createMockSource } from "@/data/mock-source";
import type { Clock } from "@/data/poller";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { NoticeToaster } from "@/components/sieve/shell/notice-toaster";
import { DnsCard } from "./dns-card";

vi.mock("next/navigation", () => ({ usePathname: () => "/settings/" }));
vi.setConfig({ testTimeout: 20_000 });
// The DNS filter's settings are unavailable until the engine's slice 4 replaces it, so the
// Settings screen does not show this card (settings.test.tsx, settings.spec.ts and law 11
// hold that with the real registry). Its code stays: these tests render the card itself,
// as a build where its settings are available would.
vi.mock("@/core/settings/registry", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/core/settings/registry")>()),
  isAvailable: () => true,
}));

/** Manual clock: the controller's polls fire only when the test advances time. */
function fakeClock() {
  let now = 1_760_000_000_000;
  let seq = 0;
  const timers = new Map<number, { at: number; fn: () => void }>();
  const clock: Clock = {
    now: () => now,
    setTimeout: (fn, ms) => {
      timers.set(++seq, { at: now + ms, fn });
      return seq;
    },
    clearTimeout: (h) => void timers.delete(h as number),
  };
  const flush = () => new Promise<void>((r) => setTimeout(r, 0));
  return {
    clock,
    async advance(ms: number) {
      const target = now + ms;
      for (;;) {
        const due = [...timers.entries()].filter(([, t]) => t.at <= target).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        timers.delete(due[0]);
        now = due[1].at;
        due[1].fn();
        for (let i = 0; i < 10; i++) await flush();
      }
      now = target;
      await flush();
    },
  };
}

async function setup(
  scenario: DnsScenario,
  opts: {
    stored?: Record<string, unknown>;
    adguard?: boolean;
    pointed?: boolean;
    over?: Partial<DnsSource>;
    windowsReadable?: boolean;
    clock?: Clock;
  } = {},
) {
  const dns = { ...createMockDns({ seed: 1, scenario, adguard: opts.adguard, pointed: opts.pointed, now: opts.clock?.now }), ...opts.over } as DnsSource;
  const runtime = createRuntime({
    source: createMockSource({ seed: 1, now: opts.clock?.now }),
    settings: memoryBackend({ schema: 1, values: opts.stored ?? {} }),
    dns,
    clock: opts.clock,
  });
  render(
    <SieveProvider runtime={runtime}>
      <DnsCard lockOf={() => null} />
      <NoticeToaster />
    </SieveProvider>,
  );
  await act(async () => {
    await runtime.settings.ready;
  });
  if (opts.windowsReadable !== false) await vi.waitFor(() => expect(runtime.store.getState().dns.windows).not.toBeNull());
  return runtime;
}

const card = () => screen.getByRole("region", { name: "DNS filter" });
const phase = () => card().querySelector("[data-dns-phase]")!.getAttribute("data-dns-phase");

describe("DNS card", () => {
  it("off: says so in one honest line about what it covers, and there is no Windows DNS block", async () => {
    await setup("off");
    expect(phase()).toBe("off");
    expect(card()).toHaveTextContent("Off. Lookups go to Windows' own DNS servers.");
    expect(card().querySelector("[data-dns-scope]")).toHaveTextContent(
      "Only lookups sent straight to 127.0.0.1:53 are filtered for now; filtering for the whole computer comes later.",
    );
    expect(card()).not.toHaveTextContent(/every app on this computer|once Windows uses Sieve/);
    // Removed 2026-10-18: no adapter list, no Point or Restore, nothing that changes Windows DNS.
    expect(within(card()).queryByRole("list", { name: "Network adapters" })).toBeNull();
    expect(within(card()).queryByRole("button", { name: /Point Windows|Restore my DNS/ })).toBeNull();
    expect(card().querySelector("[data-system-dns], [data-dns-stranded]")).toBeNull();
    expect(within(card()).queryByRole("list", { name: "Most blocked domains" })).toBeNull();
  });

  it("an adapter still asks 127.0.0.1 and ::1 while the filter is off: the card says so until the filter answers", async () => {
    const rt = await setup("off", { pointed: true });
    await vi.waitFor(() => expect(card().querySelector("[data-dns-stranded]")).toHaveTextContent(STRANDED_DNS_TEXT));
    expect(within(card()).getByRole("alert", { name: "Windows DNS" })).toBeInTheDocument();
    await userEvent.click(within(card()).getByRole("switch", { name: "DNS filtering" }));
    await vi.waitFor(() => expect(phase()).toBe("running"));
    expect(card().querySelector("[data-dns-stranded]")).toBeNull();
    expect(rt.notices.list().some((n) => n.surface === "banner")).toBe(false);
  });

  it("on: running with counters, list info and the passed check", async () => {
    await setup("off");
    await userEvent.click(within(card()).getByRole("switch", { name: "DNS filtering" }));
    await vi.waitFor(() => expect(phase()).toBe("running"));
    expect(card()).toHaveTextContent("Running on 127.0.0.1:53 and [::1]:53.");
    expect(card().querySelector("[data-dns-check=pass]")).toHaveTextContent(
      /Self check passed: the test name is blocked on 127\.0\.0\.1:53 and \[::1\]:53, and a normal name resolves\./,
    );
    // The self check's normal name once per listener; its canary is never counted.
    expect(card().querySelector("[data-stat=queries] [data-numeric]")).toHaveTextContent("2");
    expect(card().querySelector("[data-stat=blocked] [data-numeric]")).toHaveTextContent("0");
    expect(within(card()).queryByText("selfcheck.sieve.invalid")).toBeNull();
    expect(card().querySelector("[data-dns-list]")).toHaveTextContent(/51,234 block rules, 812 allow rules, 97 lines skipped\. Updated/);
    expect(card().querySelector("[data-dns-scope]")).toBeInTheDocument();
    expect(card().querySelector("[data-dns-stranded]")).toBeNull();
  });

  // Moved from tests/e2e/dns.spec.ts when the card left the Settings screen (2026-10-18).
  it("lookups that reach a running filter fill the counters and the most blocked domains, in the mono font", async () => {
    const fc = fakeClock();
    await setup("off", { pointed: true, stored: { [DNS_SWITCH]: true }, clock: fc.clock });
    await vi.waitFor(() => expect(phase()).toBe("running"));
    expect(card().querySelector("[data-dns-stranded]")).toBeNull();
    await act(() => fc.advance(DNS_POLL_MS * 6));
    const top = within(card()).getByRole("list", { name: "Most blocked domains" });
    expect(within(top).getAllByRole("listitem").length).toBeGreaterThan(1);
    expect(top.querySelector(".font-mono")).not.toBeNull();
    expect(Number(card().querySelector("[data-stat=blocked] [data-numeric]")!.textContent!.replace(/\D/g, ""))).toBeGreaterThan(0);
    // The card never names an app, and its stranded note offers no way to change Windows DNS.
    expect(within(card()).queryByRole("button", { name: /Point Windows|Restore my DNS|Turn DNS filtering on/ })).toBeNull();
  });

  it("error: a busy port 53 turns the switch back off and the card says why", async () => {
    const rt = await setup("error", { stored: { [DNS_SWITCH]: true } });
    await vi.waitFor(() => expect(phase()).toBe("error"));
    expect(rt.settings.get(DNS_SWITCH)).toBe(false);
    expect(within(card()).getByRole("alert")).toHaveTextContent(MOCK_PORT_BUSY);
    expect(within(card()).getByRole("switch", { name: "DNS filtering" })).not.toBeChecked();
    expect(await screen.findByText(/DNS filtering could not start/)).toBeInTheDocument();
  });

  it("global Sieving off: a running filter passes everything through and says Paused, never stops", async () => {
    const rt = await setup("off", { stored: { [DNS_SWITCH]: true } });
    await vi.waitFor(() => expect(phase()).toBe("running"));
    await act(() => rt.settings.set("sampling.enabled", false));
    await vi.waitFor(() => expect(phase()).toBe("paused"));
    expect(card()).toHaveTextContent("Paused while Sieving is off");
    expect(within(card()).getByRole("switch", { name: "DNS filtering" })).toBeChecked();
    await act(() => rt.settings.set("sampling.enabled", true));
    await vi.waitFor(() => expect(phase()).toBe("running"));
  });

  it("failed self check: a short toast, one plain line in the card, the technical replies folded away and said once", async () => {
    // What the user hit: the same failure on both listeners, with a long technical reply.
    const bad = "no answer: bad name -tototix.gif: Malformed label: -tototix";
    const check = (kind: "canary" | "resolve", server: string, got: string, pass: boolean) => ({
      kind,
      server,
      name: kind === "canary" ? "selfcheck.sieve.invalid" : "example.com",
      expect: kind === "canary" ? "NOERROR 0.0.0.0 (blocked)" : "NOERROR with a real address",
      got,
      pass,
    });
    const rt = await setup("off", {
      stored: { [DNS_SWITCH]: true },
      over: {
        selfCheck: async () => ({
          pass: false,
          checks: [
            check("canary", "127.0.0.1:53", bad, false),
            check("resolve", "127.0.0.1:53", "NOERROR 192.0.2.10", true),
            check("canary", "[::1]:53", bad, false),
            check("resolve", "[::1]:53", "NOERROR 192.0.2.10", true),
          ],
        }),
      },
    });
    await vi.waitFor(() => expect(phase()).toBe("error"));
    expect(rt.settings.get(DNS_SWITCH)).toBe(false);

    const toastText =
      "DNS filtering could not start: its self check failed on 127.0.0.1:53 and [::1]:53 (the test name got no answer). Details in Settings > Filtering.";
    expect(await screen.findByText(toastText)).toBeInTheDocument();
    expect(rt.notices.list().map((n) => n.text)).toEqual([toastText]);

    // The card says it once, in plain words.
    const line = "The self check failed on 127.0.0.1:53 and [::1]:53 (the test name got no answer).";
    expect(within(card()).getAllByText(line)).toHaveLength(1);
    expect(within(card()).getByRole("alert")).toHaveTextContent(line);
    const technical = within(card()).getAllByText(/Malformed/);
    expect(technical).toHaveLength(2);
    for (const el of technical) expect(el).not.toBeVisible();

    // The detail row folds out with each listener's reply once.
    const details = card().querySelector("[data-dns-check-details]") as HTMLDetailsElement;
    expect(details.open).toBe(false);
    await userEvent.click(within(details).getByText("Self check details"));
    expect(details.open).toBe(true);
    const items = within(details).getAllByRole("listitem").map((li) => li.textContent);
    expect(items).toEqual([
      `127.0.0.1:53: selfcheck.sieve.invalid expected NOERROR 0.0.0.0 (blocked), got ${bad}`,
      `[::1]:53: selfcheck.sieve.invalid expected NOERROR 0.0.0.0 (blocked), got ${bad}`,
    ]);
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
      windowsReadable: false,
      over: {
        windowsDns: async () => {
          throw new Error("access denied");
        },
        status: async () => ({ ...(await base.status()), list: noList }),
        start: async (c) => ({ ...(await base.start(c)), list: noList }),
        selfCheck: () => base.selfCheck(),
      },
    });
    await vi.waitFor(() => expect(phase()).toBe("running"));
    // Windows DNS was never read: unknown decides nothing, so no safety notice and no error.
    expect(card().querySelector("[data-dns-stranded]")).toBeNull();
    expect(within(card()).queryByRole("alert")).toBeNull();
    expect(card().querySelector("[data-dns-list]")).toHaveTextContent("No list is loaded, so nothing is blocked.");
    expect(card()).toHaveTextContent("The list could not be refreshed: offline");
  });
});
