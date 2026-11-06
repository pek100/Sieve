import { describe, expect, it } from "vitest";
import { LOG_POLL_MS, LOG_RING } from "@/core/log";
import { createStore } from "@/core/store";
import fixture from "./fixtures/engine-probe-v3.json";
import { createLogController } from "./log-controller";
import type { Clock } from "./poller";
import { LOG_TAIL_VERSION, parseEngineProbe, parseLogTail, type LogEntry, type LogTail } from "./protocol";
import logFixture from "./fixtures/engine-log-v1.json";

const settle = async () => {
  for (let i = 0; i < 10; i++) await new Promise<void>((r) => setTimeout(r, 0));
};

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

const ROW = logFixture.rows[0].row as LogEntry["row"];
const facts = (name: keyof typeof fixture.examples) => ({ probe: parseEngineProbe(fixture.examples[name]), error: null });

/** An engine whose tail is scripted: every read takes the next answer, or an empty one. */
function setup(start: keyof typeof fixture.examples | null = "hosts") {
  const fc = fakeClock();
  const store = createStore();
  if (start) store.setEngine(facts(start));
  const asked: number[] = [];
  const queue: (LogTail | Error)[] = [];
  const engine = {
    logTail: async (since: number): Promise<LogTail> => {
      asked.push(since);
      const next = queue.shift();
      if (next instanceof Error) throw next;
      return next ?? { v: LOG_TAIL_VERSION, next: since, dropped: 0, rows: [], skipped: 0 };
    },
  };
  const ctl = createLogController({ engine, store, clock: fc.clock });
  let emits = 0;
  store.subscribe(() => (emits += 1));
  const undo = ctl.bind();
  const tail = (from: number, n: number, extra: Partial<LogTail> = {}): LogTail => ({
    v: LOG_TAIL_VERSION,
    next: from + n - 1,
    dropped: 0,
    skipped: 0,
    rows: Array.from({ length: n }, (_, i) => ({ seq: from + i, row: ROW })),
    ...extra,
  });
  return { fc, store, ctl, undo, asked, queue, tail, log: () => store.getState().log, emits: () => emits };
}

describe("the log controller", () => {
  it("makes no call while the engine does not route", async () => {
    for (const start of [null, "missing", "idle", "adguard"] as const) {
      const t = setup(start);
      await t.fc.advance(LOG_POLL_MS * 5);
      expect(t.asked, String(start)).toEqual([]);
      expect(t.fc.pending(), String(start)).toBe(0);
      t.undo();
    }
  });

  it("polling starts when the engine routes and stops when it ends", async () => {
    const t = setup("idle");
    await t.fc.advance(LOG_POLL_MS * 3);
    expect(t.asked).toEqual([]);
    t.store.setEngine(facts("filtering"));
    await t.fc.advance(LOG_POLL_MS * 3);
    expect(t.asked).toHaveLength(3);
    t.store.setEngine(facts("idle"));
    await t.fc.advance(LOG_POLL_MS * 3);
    expect(t.asked).toHaveLength(3);
    expect(t.fc.pending()).toBe(0);
    t.undo();
  });

  it("reads one at a time, from the cursor, and appends", async () => {
    const t = setup();
    t.queue.push(t.tail(1, 2), t.tail(3, 1));
    await t.fc.advance(LOG_POLL_MS * 2);
    expect(t.asked).toEqual([0, 2]);
    expect(t.log().rows.map((e) => e.seq)).toEqual([1, 2, 3]);
    expect(t.log().cursor).toBe(3);
    t.undo();
  });

  it("pause stops calls; resume continues from the cursor", async () => {
    const t = setup();
    t.queue.push(t.tail(1, 2));
    await t.fc.advance(LOG_POLL_MS);
    t.ctl.pause();
    expect(t.log().paused).toBe(true);
    expect(t.fc.pending()).toBe(0);
    await t.fc.advance(LOG_POLL_MS * 5);
    expect(t.asked).toEqual([0]);
    t.ctl.resume();
    await t.fc.advance(LOG_POLL_MS);
    expect(t.asked).toEqual([0, 2]);
    t.undo();
  });

  it("clear empties the ring and does not rewind", async () => {
    const t = setup();
    t.queue.push(t.tail(1, 3, { dropped: 1, skipped: 1 }));
    await t.fc.advance(LOG_POLL_MS);
    t.ctl.clear();
    expect(t.log()).toMatchObject({ rows: [], cursor: 3, dropped: 0, skipped: 0 });
    await t.fc.advance(LOG_POLL_MS);
    expect(t.asked).toEqual([0, 3]);
    t.undo();
  });

  describe("a read held open", () => {
    /** The controller with its next read waiting for `release`. */
    function held() {
      const fc = fakeClock();
      const store = createStore();
      store.setEngine(facts("hosts"));
      const asked: number[] = [];
      const waiting: ((t: LogTail) => void)[] = [];
      const engine = {
        logTail: (since: number) => {
          asked.push(since);
          return new Promise<LogTail>((resolve) => waiting.push(resolve));
        },
      };
      const ctl = createLogController({ engine, store, clock: fc.clock });
      const row = (seq: number): LogTail => ({ v: LOG_TAIL_VERSION, next: seq, dropped: 0, skipped: 0, rows: [{ seq, row: ROW }] });
      return { fc, store, ctl, undo: ctl.bind(), asked, row, release: async (t: LogTail) => (waiting.shift()!(t), settle()), log: () => store.getState().log };
    }

    it("across a pause lands nothing; resume reads those rows again", async () => {
      const t = held();
      await t.fc.advance(LOG_POLL_MS);
      expect(t.asked).toEqual([0]);
      t.ctl.pause();
      await t.release(t.row(1));
      expect(t.log()).toMatchObject({ paused: true, rows: [], cursor: 0 });
      t.ctl.resume();
      await t.fc.advance(LOG_POLL_MS);
      expect(t.asked, "the same rows, from the same cursor").toEqual([0, 0]);
      await t.release(t.row(1));
      expect(t.log().rows.map((e) => e.seq)).toEqual([1]);
      t.undo();
    });

    it("across a clear lands nothing in the emptied list, and reading goes on by itself", async () => {
      const t = held();
      await t.fc.advance(LOG_POLL_MS);
      t.ctl.clear();
      await t.release(t.row(1));
      expect(t.log()).toMatchObject({ rows: [], cursor: 0 });
      await t.fc.advance(LOG_POLL_MS);
      expect(t.asked).toEqual([0, 0]);
      t.undo();
    });
  });

  it("a malformed answer cannot rewind the cursor, so the ring is not read again", async () => {
    const t = setup();
    t.queue.push(t.tail(1, 3), parseLogTail({ v: LOG_TAIL_VERSION, rows: [] }), parseLogTail({ v: LOG_TAIL_VERSION, next: 1, rows: [] }));
    await t.fc.advance(LOG_POLL_MS);
    const before = t.emits();
    await t.fc.advance(LOG_POLL_MS * 3);
    expect(t.asked).toEqual([0, 3, 3, 3]);
    expect(t.log().cursor).toBe(3);
    expect(t.emits()).toBe(before);
    t.undo();
  });

  it("a failed read sets the error and keeps the rows; the next good read clears it", async () => {
    const t = setup();
    t.queue.push(t.tail(1, 2), new Error("pipe broke"));
    await t.fc.advance(LOG_POLL_MS * 2);
    expect(t.log().error).toBe("pipe broke");
    expect(t.log().rows).toHaveLength(2);
    await t.fc.advance(LOG_POLL_MS);
    expect(t.log().error).toBeNull();
    expect(t.log().rows).toHaveLength(2);
    t.undo();
  });

  it("an empty tail emits nothing", async () => {
    const t = setup();
    await t.fc.advance(LOG_POLL_MS);
    const before = t.emits();
    await t.fc.advance(LOG_POLL_MS * 5);
    expect(t.emits()).toBe(before);
    t.undo();
  });

  it("the ring never exceeds LOG_RING, and dropped and skipped add up", async () => {
    const t = setup();
    t.queue.push(t.tail(1, LOG_RING, { dropped: 2 }), t.tail(LOG_RING + 1, 50, { dropped: 3, skipped: 4 }));
    await t.fc.advance(LOG_POLL_MS * 2);
    expect(t.log().rows).toHaveLength(LOG_RING);
    expect(t.log().rows.at(-1)?.seq).toBe(LOG_RING + 50);
    expect(t.log().dropped).toBe(5);
    expect(t.log().skipped).toBe(4);
    t.undo();
  });

  it("the undo stops reading and clears the timer", async () => {
    const t = setup();
    expect(t.fc.pending()).toBe(1);
    t.undo();
    expect(t.fc.pending()).toBe(0);
    await t.fc.advance(LOG_POLL_MS * 3);
    expect(t.asked).toEqual([]);
    expect(t.fc.pending()).toBe(0);
  });
});
