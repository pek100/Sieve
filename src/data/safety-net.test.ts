import { describe, expect, it } from "vitest";
import { STRANDED_DNS_TEXT, WINDOWS_DNS_POLL_MS } from "@/core/dns";
import { createNoticeBus } from "@/core/notices";
import type { Clock } from "./poller";
import { createMockWindowsDns, createSafetyNet, createTauriWindowsDns, type WindowsDnsSource } from "./safety-net";

const settle = async () => {
  for (let i = 0; i < 10; i++) await new Promise<void>((r) => setTimeout(r, 0));
};

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

async function setup(windowsDns: WindowsDnsSource["windowsDns"]) {
  const fc = fakeClock();
  const notices = createNoticeBus();
  let reads = 0;
  const undo = createSafetyNet({
    source: {
      windowsDns: () => {
        reads += 1;
        return windowsDns();
      },
    },
    notices,
    clock: fc.clock,
  }).bind();
  await settle();
  return { fc, notices, undo, reads: () => reads, banner: () => notices.list().find((n) => n.surface === "banner") };
}

const own = createMockWindowsDns();
const pointed = createMockWindowsDns({ pointed: true });

describe("the read-only safety net", () => {
  it("an adapter asks 127.0.0.1 and ::1: a banner says so, word for word, with no action", async () => {
    const t = await setup(pointed.windowsDns);
    expect(t.reads()).toBe(1);
    expect(t.banner()?.text).toBe("Windows is set to use Sieve for DNS, but nothing of Sieve's answers there, so sites may not load. Set DNS back to automatic in Windows network settings.");
    expect(t.banner()?.kind).toBe("error");
    // It points to Windows' own settings only.
    expect(t.banner()?.action).toBeUndefined();
    t.undo();
  });

  it("Windows' own DNS: no banner, and it is read again every 30 s until the undo", async () => {
    const t = await setup(own.windowsDns);
    expect(WINDOWS_DNS_POLL_MS).toBe(30_000);
    expect(t.banner()).toBeUndefined();
    await t.fc.advance(WINDOWS_DNS_POLL_MS * 3);
    expect(t.reads()).toBe(4);
    expect(t.notices.list()).toEqual([]);
    t.undo();
    await t.fc.advance(WINDOWS_DNS_POLL_MS * 3);
    expect(t.reads()).toBe(4);
  });

  it("follows Windows: pointed later shows the banner at the next read, reset by hand clears it", async () => {
    let on = false;
    const t = await setup(() => (on ? pointed : own).windowsDns());
    expect(t.banner()).toBeUndefined();
    on = true;
    await t.fc.advance(WINDOWS_DNS_POLL_MS);
    expect(t.banner()?.text).toBe(STRANDED_DNS_TEXT);
    on = false;
    await t.fc.advance(WINDOWS_DNS_POLL_MS);
    expect(t.banner()).toBeUndefined();
    t.undo();
  });

  it("a dismissed banner stays dismissed while nothing changes, and comes back after it was fixed and broke again", async () => {
    let on = true;
    const t = await setup(() => (on ? pointed : own).windowsDns());
    t.notices.dismiss(t.banner()!.id);
    await t.fc.advance(WINDOWS_DNS_POLL_MS * 2);
    expect(t.banner()).toBeUndefined();
    on = false;
    await t.fc.advance(WINDOWS_DNS_POLL_MS);
    on = true;
    await t.fc.advance(WINDOWS_DNS_POLL_MS);
    expect(t.banner()?.text).toBe(STRANDED_DNS_TEXT);
    t.undo();
  });

  it("an unreadable first read decides nothing: no banner, and it keeps asking", async () => {
    const t = await setup(async () => {
      throw new Error("GetAdaptersAddresses failed");
    });
    expect(t.notices.list()).toEqual([]);
    await t.fc.advance(WINDOWS_DNS_POLL_MS);
    expect(t.reads()).toBe(2);
    t.undo();
  });

  it("a failed read keeps the last reading: the banner stays", async () => {
    let fail = false;
    const t = await setup(() => (fail ? Promise.reject(new Error("no")) : pointed.windowsDns()));
    fail = true;
    await t.fc.advance(WINDOWS_DNS_POLL_MS);
    expect(t.banner()?.text).toBe(STRANDED_DNS_TEXT);
    t.undo();
  });

  it("the undo clears the timer and takes its banner with it", async () => {
    const t = await setup(pointed.windowsDns);
    expect(t.fc.pending()).toBe(1);
    t.undo();
    expect(t.fc.pending()).toBe(0);
    expect(t.banner()).toBeUndefined();
  });

  it("the Tauri source asks windows_dns only, and validates the answer", async () => {
    const calls: string[] = [];
    const answer = await own.windowsDns();
    const source = createTauriWindowsDns(async <T,>(cmd: string) => {
      calls.push(cmd);
      return answer as T;
    });
    expect(Object.keys(source)).toEqual(["windowsDns"]);
    expect(await source.windowsDns()).toEqual(answer);
    expect(calls).toEqual(["windows_dns"]);
    await expect(createTauriWindowsDns(async <T,>() => ({ v: 9 }) as T).windowsDns()).rejects.toThrow(/version 9/);
  });
});
