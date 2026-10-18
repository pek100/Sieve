import { describe, expect, it, vi } from "vitest";
import { createPassedChecks } from "@/core/checks";
import { DNS_POLL_MS, DNS_SWITCH, dnsPhase, isFiltering, STRANDED_DNS_TEXT, UPSTREAMS_KEY, WINDOWS_DNS_POLL_MS } from "@/core/dns";
import { createNoticeBus } from "@/core/notices";
import { GLOBAL_SWITCH } from "@/core/policy";
import { createStore } from "@/core/store";
import { createDnsController } from "./dns-controller";
import { createMockDns, MOCK_PORT_BUSY, type DnsScenario } from "./dns-mock";
import type { DnsSource } from "./dns-source";
import type { Clock } from "./poller";
import { createSettingsStore, memoryBackend } from "./settings-store";

// The DNS filter's settings are unavailable until the engine's slice 4 replaces it (law 11,
// tests/laws/unavailable.test.ts, holds the real registry). Its code stays, so these tests
// run it as a build where they are available would.
vi.mock("@/core/settings/registry", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/core/settings/registry")>()),
  isAvailable: () => true,
}));

/** Manual clock: timers fire only when the test advances time. */
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
  return {
    clock,
    pending: () => timers.size,
    async advance(ms: number) {
      const target = now + ms;
      for (;;) {
        const due = [...timers.entries()].filter(([, t]) => t.at <= target).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        timers.delete(due[0]);
        now = due[1].at;
        due[1].fn();
        await settle();
      }
      now = target;
      await settle();
    },
  };
}

const settle = async () => {
  for (let i = 0; i < 20; i++) await new Promise<void>((r) => setTimeout(r, 0));
};

/** The mock with every call counted, and any call replaceable. */
function spied(scenario: DnsScenario, over: Partial<DnsSource> = {}, pointed = false) {
  const base = createMockDns({ seed: 1, scenario, pointed });
  const calls: string[] = [];
  const src = { ...base, ...over } as DnsSource;
  const wrapped = Object.fromEntries(
    Object.entries(src).map(([k, v]) => [k, typeof v === "function" ? (...a: unknown[]) => (calls.push(k), (v as (...x: unknown[]) => unknown)(...a)) : v]),
  ) as unknown as DnsSource;
  return { dns: wrapped, calls, count: (name: string) => calls.filter((c) => c === name).length };
}

async function setup(scenario: DnsScenario, stored: Record<string, unknown> = {}, over: Partial<DnsSource> = {}, pointed = false) {
  const fc = fakeClock();
  const s = spied(scenario, over, pointed);
  const store = createStore();
  const settings = createSettingsStore(memoryBackend({ schema: 1, values: stored }));
  const notices = createNoticeBus();
  const checks = createPassedChecks();
  // Every banner ever shown, so a test can say one never flashed.
  const banners: string[] = [];
  notices.subscribe(() => {
    for (const n of notices.list()) if (n.surface === "banner" && !banners.includes(`${n.id}`)) banners.push(`${n.id}`);
  });
  const ctl = createDnsController({ dns: s.dns, store, settings, notices, checks, clock: fc.clock });
  const undo = ctl.bind();
  await settle();
  const dns = () => store.getState().dns;
  const banner = () => notices.list().find((n) => n.surface === "banner");
  return { ...s, source: s.dns, fc, store, settings, notices, checks, ctl, undo, dns, banner, bannersShown: () => banners.length, texts: () => notices.list().map((n) => n.text) };
}

describe("DNS controller: the filtering.dns switch", () => {
  it("on: dns_start with the upstreams setting, then the self check; a pass is recorded", async () => {
    const t = await setup("off", { [UPSTREAMS_KEY]: ["9.9.9.9", "2620:fe::fe"] });
    expect(t.count("start")).toBe(0);
    await t.settings.set(DNS_SWITCH, true);
    await settle();
    expect(t.calls.filter((c) => c === "start" || c === "selfCheck")).toEqual(["start", "selfCheck"]);
    expect(t.dns().status?.upstreams).toEqual(["9.9.9.9:53", "[2620:fe::fe]:53"]);
    expect(t.dns().status?.binds).toEqual(["127.0.0.1:53", "[::1]:53"]);
    expect(t.checks.has(DNS_SWITCH)).toBe(true);
    expect(t.dns().check?.pass).toBe(true);
    expect(t.dns().busy).toBeNull();
    t.undo();
  });

  it("polls dns_status every DNS_POLL_MS only while running", async () => {
    const t = await setup("off");
    await t.fc.advance(DNS_POLL_MS * 3);
    expect(t.count("status")).toBe(1); // the load read only
    await t.settings.set(DNS_SWITCH, true);
    await settle();
    const before = t.count("status");
    await t.fc.advance(DNS_POLL_MS * 3);
    expect(t.count("status") - before).toBe(3);
    await t.settings.set(DNS_SWITCH, false);
    await settle();
    expect(t.dns().status?.running).toBe(false);
    // Only the safety net's 30 s Windows DNS read is left.
    expect(t.fc.pending()).toBe(1);
    const after = t.count("status");
    await t.fc.advance(DNS_POLL_MS * 5);
    expect(t.count("status")).toBe(after);
    expect(t.checks.has(DNS_SWITCH)).toBe(false);
    t.undo();
  });

  it("a failed start (port 53 busy) turns the switch back off with the error said", async () => {
    const t = await setup("error");
    await t.settings.set(DNS_SWITCH, true);
    await settle();
    expect(t.settings.get(DNS_SWITCH)).toBe(false);
    expect(t.checks.has(DNS_SWITCH)).toBe(false);
    expect(t.dns().error).toBe(MOCK_PORT_BUSY);
    expect(t.texts().at(-1)).toBe(`DNS filtering could not start: ${MOCK_PORT_BUSY}`);
    expect(t.notices.list().at(-1)?.kind).toBe("error");
    expect(t.count("start")).toBe(1);
    t.undo();
  });

  it("a failed self check stops the filter and turns the switch back off with what failed", async () => {
    const t = await setup("off", {}, {
      selfCheck: async () => ({
        pass: false,
        checks: [
          { kind: "canary", server: "127.0.0.1:53", name: "selfcheck.sieve.invalid", expect: "NOERROR 0.0.0.0 (blocked)", got: "no answer: timed out", pass: false },
        ],
      }),
    });
    await t.settings.set(DNS_SWITCH, true);
    await settle();
    expect(t.count("stop")).toBe(1);
    expect(t.dns().status?.running).toBe(false);
    expect(t.settings.get(DNS_SWITCH)).toBe(false);
    expect(t.checks.has(DNS_SWITCH)).toBe(false);
    expect(t.texts().at(-1)).toBe(
      "DNS filtering could not start: its self check failed on 127.0.0.1:53 (the test name got no answer). Details in Settings > Filtering.",
    );
    expect(t.dns().error).toBe("The self check failed on 127.0.0.1:53 (the test name got no answer).");
    expect(t.dns().check?.pass).toBe(false);
    t.undo();
  });

  it("off stops the filter; the source has no call that could change Windows DNS", async () => {
    const t = await setup("off", { [DNS_SWITCH]: true });
    expect(t.dns().status?.running).toBe(true);
    expect(t.texts()).toContain("DNS filtering is on for lookups sent to 127.0.0.1:53.");
    await t.settings.set(DNS_SWITCH, false);
    await settle();
    expect(t.count("stop")).toBe(1);
    expect(t.dns().status?.running).toBe(false);
    // Reads and the filter's own start, stop and pass-through only (Sieve never writes Windows DNS).
    expect(Object.keys(t.source).sort()).toEqual(["adguardRunning", "kind", "selfCheck", "setPassThrough", "start", "status", "stop", "windowsDns"]);
    t.undo();
  });
});

describe("DNS controller: the read-only safety net", () => {
  it("an adapter asks 127.0.0.1 and ::1 while the filter is off: a banner says so, word for word", async () => {
    const t = await setup("off", {}, {}, true);
    expect(t.count("windowsDns")).toBe(1);
    expect(t.dns().windows?.adapters[0].servers).toEqual(["127.0.0.1", "::1"]);
    expect(t.banner()?.text).toBe(
      "Windows is set to use Sieve for DNS, but nothing of Sieve's answers there, so sites may not load. Set DNS back to automatic in Windows network settings.",
    );
    expect(t.banner()?.kind).toBe("error");
    // It points to Windows' own settings only: no action, nothing that turns the filter on.
    expect(t.banner()?.action).toBeUndefined();
    // Nothing is started by itself (no startup recovery) and nothing is written.
    expect(t.count("start")).toBe(0);
    expect(t.settings.get(DNS_SWITCH)).toBe(false);
    t.undo();
  });

  it("the banner goes once the filter answers there, and comes back when it stops", async () => {
    const t = await setup("off", {}, {}, true);
    expect(t.banner()?.text).toBe(STRANDED_DNS_TEXT);
    await t.settings.set(DNS_SWITCH, true);
    await settle();
    expect(t.settings.get(DNS_SWITCH)).toBe(true);
    expect(t.dns().status?.running).toBe(true);
    expect(t.banner()).toBeUndefined();
    // Lookups now reach it, so some get blocked on the next polls.
    await t.fc.advance(DNS_POLL_MS * 3);
    expect(t.dns().status?.counters.queries).toBeGreaterThan(0);
    // Off again: back.
    await t.settings.set(DNS_SWITCH, false);
    await settle();
    expect(t.banner()?.text).toBe(STRANDED_DNS_TEXT);
    t.undo();
  });

  it("filtering already on at load: the filter starts and the banner never flashes", async () => {
    const t = await setup("off", { [DNS_SWITCH]: true }, {}, true);
    expect(t.dns().status?.running).toBe(true);
    expect(t.bannersShown()).toBe(0);
    t.undo();
  });

  it("Windows' own DNS: no banner, and Windows DNS is read again every 30 s, read only", async () => {
    const t = await setup("off");
    expect(WINDOWS_DNS_POLL_MS).toBe(30_000);
    expect(t.banner()).toBeUndefined();
    await t.fc.advance(WINDOWS_DNS_POLL_MS * 3);
    expect(t.count("windowsDns")).toBe(4);
    expect(t.bannersShown()).toBe(0);
    t.undo();
    await t.fc.advance(WINDOWS_DNS_POLL_MS * 3);
    expect(t.count("windowsDns")).toBe(4);
  });

  it("follows Windows: pointed later shows the banner at the next read, reset by hand clears it", async () => {
    let pointed = false;
    const own = createMockDns({ seed: 1 });
    const set = createMockDns({ seed: 1, pointed: true });
    const t = await setup("off", {}, { windowsDns: () => (pointed ? set : own).windowsDns() });
    expect(t.banner()).toBeUndefined();
    pointed = true;
    await t.fc.advance(WINDOWS_DNS_POLL_MS);
    expect(t.banner()?.text).toBe(STRANDED_DNS_TEXT);
    pointed = false;
    await t.fc.advance(WINDOWS_DNS_POLL_MS);
    expect(t.banner()).toBeUndefined();
    t.undo();
  });

  it("the filter stopping by itself while Windows asks it brings the banner", async () => {
    const mock = createMockDns({ seed: 1, pointed: true });
    let dead = false;
    const t = await setup("off", { [DNS_SWITCH]: true }, {
      start: (c) => mock.start(c),
      selfCheck: () => mock.selfCheck(),
      // The proxy dies between two polls (say, it crashed).
      status: async () => (dead ? { ...(await mock.status()), running: false, binds: [] } : mock.status()),
    }, true);
    expect(t.dns().status?.running).toBe(true);
    expect(t.banner()).toBeUndefined();
    dead = true;
    await t.fc.advance(DNS_POLL_MS);
    expect(t.dns().status?.running).toBe(false);
    expect(t.banner()?.text).toBe(STRANDED_DNS_TEXT);
    t.undo();
  });

  it("a dismissed banner stays dismissed while nothing changes, and comes back after it was fixed and broke again", async () => {
    let pointed = true;
    const own = createMockDns({ seed: 1 });
    const set = createMockDns({ seed: 1, pointed: true });
    const t = await setup("off", {}, { windowsDns: () => (pointed ? set : own).windowsDns() });
    const first = t.banner();
    expect(first).toBeDefined();
    t.notices.dismiss(first!.id);
    await t.fc.advance(WINDOWS_DNS_POLL_MS * 2);
    expect(t.banner()).toBeUndefined();
    pointed = false;
    await t.fc.advance(WINDOWS_DNS_POLL_MS);
    pointed = true;
    await t.fc.advance(WINDOWS_DNS_POLL_MS);
    expect(t.banner()?.text).toBe(STRANDED_DNS_TEXT);
    t.undo();
    // The undo takes its banner with it.
    expect(t.banner()).toBeUndefined();
  });

  it("an unreadable Windows DNS decides nothing: no banner, no error", async () => {
    const t = await setup("off", {}, {
      windowsDns: async () => {
        throw new Error("GetAdaptersAddresses: error 8");
      },
    });
    expect(t.dns().windows).toBeNull();
    expect(t.dns().error).toBeNull();
    expect(t.banner()).toBeUndefined();
    t.undo();
  });
});

describe("DNS controller: AdGuard", () => {
  it("reads whether AdGuard runs on load", async () => {
    const fc = fakeClock();
    const store = createStore();
    const ctl = createDnsController({
      dns: createMockDns({ seed: 1, adguard: true }),
      store,
      settings: createSettingsStore(memoryBackend()),
      notices: createNoticeBus(),
      checks: createPassedChecks(),
      clock: fc.clock,
    });
    const undo = ctl.bind();
    await vi.waitFor(() => expect(store.getState().dns.adguard).toBe(true));
    undo();
  });
});

describe("DNS controller: the global Sieving switch", () => {
  it("off puts the running filter in pass-through instead of stopping it; on filters again", async () => {
    const t = await setup("off", { [DNS_SWITCH]: true });
    expect(t.dns().status?.running).toBe(true);
    expect(dnsPhase(t.dns())).toBe("running");
    await t.settings.set(GLOBAL_SWITCH, false);
    await settle();
    expect(t.count("setPassThrough")).toBe(1);
    expect(t.count("stop")).toBe(0);
    expect(t.dns().status).toMatchObject({ running: true, pass_through: true });
    expect(dnsPhase(t.dns())).toBe("paused");
    expect(isFiltering(t.dns())).toBe(false);
    await t.settings.set(GLOBAL_SWITCH, true);
    await settle();
    expect(t.dns().status).toMatchObject({ running: true, pass_through: false });
    expect(isFiltering(t.dns())).toBe(true);
    t.undo();
  });

  it("a filter started while Sieving is off passes its self check first, then passes through", async () => {
    const t = await setup("off", { [GLOBAL_SWITCH]: false });
    await t.settings.set(DNS_SWITCH, true);
    await settle();
    expect(t.calls.filter((c) => ["start", "selfCheck", "setPassThrough"].includes(c))).toEqual(["start", "selfCheck", "setPassThrough"]);
    expect(t.checks.has(DNS_SWITCH)).toBe(true);
    expect(t.dns().status?.pass_through).toBe(true);
    t.undo();
  });

  it("nothing is called while the filter is not running", async () => {
    const t = await setup("off");
    await t.settings.set(GLOBAL_SWITCH, false);
    await settle();
    expect(t.count("setPassThrough")).toBe(0);
    t.undo();
  });
});
