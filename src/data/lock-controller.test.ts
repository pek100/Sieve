import { describe, expect, it, vi } from "vitest";
import { createNoticeBus } from "@/core/notices";
import { LOCK_UNREADABLE_TEXT, WRONG_PASSWORD_TEXT } from "@/core/lock";
import { createLockController } from "./lock-controller";
import { MOCK_PASSWORD, MOCK_RETRY_SECS, MOCK_TRIES, createMockLock, type LockScenario } from "./lock-mock";
import type { LockSource } from "./lock-source";
import type { Clock } from "./poller";
import { createSettingsStore, memoryBackend } from "./settings-store";

const flush = () => new Promise<void>((r) => setTimeout(r, 0));

function fakeClock() {
  let now = 1_000_000;
  const timers = new Map<number, { at: number; fn: () => void }>();
  let id = 0;
  const clock: Clock = {
    now: () => now,
    setTimeout: (fn, ms) => {
      timers.set(++id, { at: now + ms, fn });
      return id;
    },
    clearTimeout: (t) => void timers.delete(t as number),
  };
  const advance = (ms: number) => {
    const end = now + ms;
    for (;;) {
      const next = [...timers.entries()].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!next) break;
      timers.delete(next[0]);
      now = next[1].at;
      next[1].fn();
    }
    now = end;
  };
  return { clock, advance };
}

async function setup(start: LockScenario | LockSource = "set", stored?: unknown) {
  const { clock, advance } = fakeClock();
  const settings = createSettingsStore(memoryBackend(stored));
  await settings.ready;
  const notices = createNoticeBus();
  const source = typeof start === "string" ? createMockLock(start) : start;
  const c = createLockController({ source, clock, settings, notices });
  return { c, settings, notices, advance, undo: c.bind() };
}

/** A source whose status answers only on `release`, so `checking` can be seen. */
function heldSource(start: LockScenario) {
  const mock = createMockLock(start);
  let release: () => void = () => {};
  const source: LockSource = {
    ...mock,
    status: async () => {
      await new Promise<void>((r) => (release = r));
      return mock.status();
    },
  };
  return { source, release: () => release() };
}

describe("lock controller phases", () => {
  it("reads none, locked and unreadable from the source, and starts at checking", async () => {
    const held = heldSource("none");
    const none = await setup(held.source);
    expect(none.c.state().phase).toBe("checking");
    held.release();
    await flush();
    expect(none.c.state().phase).toBe("none");
    const set = await setup("set");
    await flush();
    expect(set.c.state().phase).toBe("locked");
    const bad = await setup("unreadable");
    await flush();
    expect(bad.c.state().phase).toBe("unreadable");
  });

  it("a status that cannot be read is unreadable, never open", async () => {
    const source: LockSource = { ...createMockLock(), status: async () => Promise.reject(new Error("no")) };
    const { c } = await setup(source);
    await flush();
    expect(c.state().phase).toBe("unreadable");
  });

  it("right and wrong answers; too many wrong says how long to wait", async () => {
    const { c } = await setup();
    await flush();
    c.ask();
    await c.unlock("wrong one");
    expect(c.state()).toMatchObject({ phase: "locked", asking: true, error: WRONG_PASSWORD_TEXT, busy: false });
    for (let i = 1; i < MOCK_TRIES; i++) await c.unlock("wrong one");
    expect(c.state().error).toContain(`${MOCK_RETRY_SECS} s`);
    await c.unlock(MOCK_PASSWORD);
    expect(c.state()).toMatchObject({ phase: "unlocked", asking: false, error: null });
    c.lockNow();
    expect(c.state().phase).toBe("locked");
  });

  it("setting a password leaves it unlocked; clearing goes back to none and needs the current one", async () => {
    const { c } = await setup("none");
    await flush();
    await c.setPassword(null, "a good password");
    expect(c.state().phase).toBe("unlocked");
    await expect(c.setPassword("wrong one", "another password")).rejects.toThrow("not the current password");
    await expect(c.clearPassword("wrong one")).rejects.toThrow("not the current password");
    expect(c.state().phase).toBe("unlocked");
    await c.clearPassword("a good password");
    expect(c.state().phase).toBe("none");
  });
});

describe("the write gate", () => {
  it("runs at once with no password", async () => {
    const { c } = await setup("none");
    await flush();
    const fn = vi.fn(() => 7);
    await expect(c.guard(fn)).resolves.toBe(7);
    expect(fn).toHaveBeenCalledOnce();
  });

  it("a parked write runs after unlock", async () => {
    const { c } = await setup();
    await flush();
    const fn = vi.fn(() => "written");
    const result = c.guard(fn);
    expect(fn).not.toHaveBeenCalled();
    expect(c.state().asking).toBe(true);
    await c.unlock(MOCK_PASSWORD);
    await expect(result).resolves.toBe("written");
    expect(fn).toHaveBeenCalledOnce();
  });

  it("a parked write is dropped on cancel, and does not come back on a later unlock", async () => {
    const { c } = await setup();
    await flush();
    const fn = vi.fn();
    const result = c.guard(fn);
    c.cancel();
    await expect(result).resolves.toBeUndefined();
    expect(c.state().asking).toBe(false);
    c.ask();
    await c.unlock(MOCK_PASSWORD);
    expect(fn).not.toHaveBeenCalled();
  });

  it("checking parks instead of dropping: no password runs it, a password asks", async () => {
    const heldNone = heldSource("none");
    const none = await setup(heldNone.source);
    const fn = vi.fn();
    void none.c.guard(fn);
    expect(fn).not.toHaveBeenCalled();
    expect(none.c.state().asking).toBe(false);
    heldNone.release();
    await flush();
    expect(fn).toHaveBeenCalledOnce();

    const heldSet = heldSource("set");
    const set = await setup(heldSet.source);
    const parked = vi.fn();
    void set.c.guard(parked);
    heldSet.release();
    await flush();
    expect(parked).not.toHaveBeenCalled();
    expect(set.c.state()).toMatchObject({ phase: "locked", asking: true });
  });

  it("an unreadable lock refuses every write and says why", async () => {
    const { c, notices } = await setup("unreadable");
    await flush();
    const fn = vi.fn();
    await expect(c.guard(fn)).resolves.toBeUndefined();
    expect(fn).not.toHaveBeenCalled();
    expect(notices.list().at(-1)?.text).toBe(LOCK_UNREADABLE_TEXT);
    expect(c.state().asking).toBe(false);
  });
});

describe("relock on idle", () => {
  const MIN = 60_000;

  it("happens at password.idleMinutes (default 15)", async () => {
    const { c, advance } = await setup();
    await flush();
    await c.unlock(MOCK_PASSWORD);
    advance(15 * MIN - 1);
    expect(c.state().phase).toBe("unlocked");
    advance(1);
    expect(c.state().phase).toBe("locked");
  });

  it("follows the stored dial", async () => {
    const { c, advance } = await setup("set", { schema: 4, values: { "password.idleMinutes": 5 } });
    await flush();
    await c.unlock(MOCK_PASSWORD);
    advance(5 * MIN);
    expect(c.state().phase).toBe("locked");
  });

  it("a shorter dial chosen while unlocked applies at once", async () => {
    const { c, advance, settings } = await setup();
    await flush();
    await c.unlock(MOCK_PASSWORD);
    advance(6 * MIN);
    await settings.set("password.idleMinutes", 5);
    expect(c.state().phase).toBe("locked");
  });

  it("activity pushes it back", async () => {
    const { c, advance } = await setup();
    await flush();
    await c.unlock(MOCK_PASSWORD);
    advance(14 * MIN);
    c.activity();
    advance(14 * MIN);
    expect(c.state().phase).toBe("unlocked");
    advance(MIN);
    expect(c.state().phase).toBe("locked");
  });

  it("does not run while locked, without a password or after the undo", async () => {
    const { c, advance, undo } = await setup();
    await flush();
    await c.unlock(MOCK_PASSWORD);
    undo();
    advance(60 * MIN);
    expect(c.state().phase).toBe("unlocked");
  });
});
