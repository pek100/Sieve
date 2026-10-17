import { describe, expect, it, vi } from "vitest";
import { createPassedChecks } from "@/core/checks";
import { DNS_POLL_MS, DNS_SWITCH, dnsPhase, isFiltering, SYSTEM_DNS_SWITCH, UPSTREAMS_KEY } from "@/core/dns";
import { createNoticeBus } from "@/core/notices";
import { GLOBAL_SWITCH } from "@/core/policy";
import { createStore } from "@/core/store";
import { createDnsController } from "./dns-controller";
import { createMockDns, MOCK_PORT_BUSY, type DnsScenario } from "./dns-mock";
import type { DnsSource } from "./dns-source";
import type { Clock } from "./poller";
import { createSettingsStore, memoryBackend } from "./settings-store";

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
function spied(scenario: DnsScenario, over: Partial<DnsSource> = {}) {
  const base = createMockDns({ seed: 1, scenario });
  const calls: string[] = [];
  const src = { ...base, ...over } as DnsSource;
  const wrapped = Object.fromEntries(
    Object.entries(src).map(([k, v]) => [k, typeof v === "function" ? (...a: unknown[]) => (calls.push(k), (v as (...x: unknown[]) => unknown)(...a)) : v]),
  ) as unknown as DnsSource;
  return { dns: wrapped, calls, count: (name: string) => calls.filter((c) => c === name).length };
}

async function setup(scenario: DnsScenario, stored: Record<string, unknown> = {}, over: Partial<DnsSource> = {}, exit = true) {
  const fc = fakeClock();
  const s = spied(scenario, over);
  const store = createStore();
  const settings = createSettingsStore(memoryBackend({ schema: 1, values: stored }));
  const notices = createNoticeBus();
  const checks = createPassedChecks();
  const exits: number[] = [];
  const ctl = createDnsController({
    dns: s.dns,
    store,
    settings,
    notices,
    checks,
    clock: fc.clock,
    exit: exit ? async () => void exits.push(1) : null,
  });
  const undo = ctl.bind();
  await settle();
  const dns = () => store.getState().dns;
  return { ...s, fc, store, settings, notices, checks, ctl, undo, dns, exits, texts: () => notices.list().map((n) => n.text) };
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
    expect(t.fc.pending()).toBe(0);
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
    expect(t.texts().at(-1)).toMatch(/DNS filtering was turned off: its self check failed \(selfcheck\.sieve\.invalid: expected .* got no answer: timed out\)/);
    t.undo();
  });

  it("off while Windows points at Sieve restores first, then stops", async () => {
    const t = await setup("running");
    expect(t.dns().status?.running).toBe(true);
    await t.settings.set(DNS_SWITCH, false);
    await settle();
    expect(t.calls.filter((c) => c === "restoreSystem" || c === "stop")).toEqual(["restoreSystem", "stop"]);
    expect(t.dns().system?.pointed).toBe(false);
    expect(t.settings.get(SYSTEM_DNS_SWITCH)).toBe(false);
    t.undo();
  });

  it("off while pointed, and the restore is declined: the filter stays on and the switch says so", async () => {
    const t = await setup("running", {}, {
      restoreSystem: async () => {
        throw new Error("you declined the Windows prompt, so nothing was changed");
      },
    });
    await t.settings.set(DNS_SWITCH, false);
    await settle();
    expect(t.count("stop")).toBe(0);
    expect(t.dns().status?.running).toBe(true);
    expect(t.settings.get(DNS_SWITCH)).toBe(true);
    expect(t.texts()).toContain("DNS filtering stays on: Windows still uses Sieve for DNS until it is restored.");
    t.undo();
  });
});

describe("DNS controller: safety on load", () => {
  it("Windows pointed at Sieve with a backup: the filter starts whatever the switch says, with a notice", async () => {
    const t = await setup("running", { [DNS_SWITCH]: false });
    expect(t.count("start")).toBe(1);
    expect(t.dns().status?.running).toBe(true);
    expect(t.settings.get(DNS_SWITCH)).toBe(true);
    expect(t.settings.get(SYSTEM_DNS_SWITCH)).toBe(true);
    expect(t.texts()).toContain("Windows uses Sieve for DNS, so Sieve started its DNS filter.");
    // Starting it again from the switch does not happen: it is running.
    await settle();
    expect(t.count("start")).toBe(1);
    t.undo();
  });

  it("pointed but the filter cannot start: a banner that stays, with Restore my DNS, which works", async () => {
    const t = await setup("running", {}, {
      start: async () => {
        throw new Error(MOCK_PORT_BUSY);
      },
    });
    const banner = t.notices.list().find((n) => n.surface === "banner");
    expect(banner?.kind).toBe("error");
    expect(banner?.text).toMatch(/could not start .*10048.*Nothing resolves until you restore your DNS/);
    expect(banner?.action?.label).toBe("Restore my DNS");
    banner?.action?.run();
    await settle();
    expect(t.count("restoreSystem")).toBe(1);
    expect(t.dns().system?.pointed).toBe(false);
    expect(t.notices.list().some((n) => n.surface === "banner")).toBe(false);
    t.undo();
  });

  it("the system switch mirrors Windows on load and never points it by itself", async () => {
    // Stored on from an earlier session, but Windows was restored meanwhile.
    const t = await setup("off", { [SYSTEM_DNS_SWITCH]: true, [DNS_SWITCH]: true });
    await settle();
    expect(t.count("pointSystem")).toBe(0);
    expect(t.settings.get(SYSTEM_DNS_SWITCH)).toBe(false);
    t.undo();
  });
});

describe("DNS controller: pointing Windows", () => {
  it("is refused until the filter runs and passed its check; then points and records its own check", async () => {
    const t = await setup("off");
    expect(await t.ctl.point()).toBe(false);
    expect(t.count("pointSystem")).toBe(0);
    await t.settings.set(DNS_SWITCH, true);
    await settle();
    await t.settings.set(SYSTEM_DNS_SWITCH, true);
    await settle();
    expect(t.count("pointSystem")).toBe(1);
    expect(t.dns().system?.pointed).toBe(true);
    expect(t.checks.has(SYSTEM_DNS_SWITCH)).toBe(true);
    expect(t.texts().at(-1)).toMatch(/Windows now uses Sieve for DNS\. Ads and trackers are blocked for every app on this computer\./);
    // Off restores.
    await t.settings.set(SYSTEM_DNS_SWITCH, false);
    await settle();
    expect(t.count("restoreSystem")).toBe(1);
    expect(t.dns().system?.pointed).toBe(false);
    expect(t.checks.has(SYSTEM_DNS_SWITCH)).toBe(false);
    t.undo();
  });

  it("Windows restored by hand (restore-dns.ps1) while Sieve runs: the switch follows and nothing is run", async () => {
    const before = createMockDns({ seed: 1, scenario: "running" });
    const after = createMockDns({ seed: 1, scenario: "off" });
    let byHand = false;
    const t = await setup("running", {}, { systemState: () => (byHand ? after : before).systemState() });
    expect(t.settings.get(SYSTEM_DNS_SWITCH)).toBe(true);
    byHand = true;
    await t.fc.advance(DNS_POLL_MS);
    await settle();
    expect(t.settings.get(SYSTEM_DNS_SWITCH)).toBe(false);
    expect(t.count("pointSystem") + t.count("restoreSystem")).toBe(0);
    t.undo();
  });

  it("a declined Windows prompt leaves the switch off with the reason", async () => {
    const t = await setup("off", { [DNS_SWITCH]: true }, {
      pointSystem: async () => {
        throw new Error("you declined the Windows prompt, so nothing was changed");
      },
    });
    await settle();
    await t.settings.set(SYSTEM_DNS_SWITCH, true);
    await settle();
    expect(t.settings.get(SYSTEM_DNS_SWITCH)).toBe(false);
    expect(t.texts().at(-1)).toBe("Windows was not pointed at Sieve: you declined the Windows prompt, so nothing was changed");
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
      exit: null,
    });
    const undo = ctl.bind();
    await vi.waitFor(() => expect(store.getState().dns.adguard).toBe(true));
    // No app to end in the browser: quit is a no-op.
    ctl.requestQuit();
    expect(store.getState().dns.quitAsked).toBe(false);
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
