import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { createStore, phase } from "@/core/store";
import historyFixture from "./fixtures/history-v1.json";
import fixture from "./fixtures/snapshot-v1.json";
import { createPoller, type Clock } from "./poller";
import { parseSnapshot, ProtocolError, type HistoryRecord } from "./protocol";
import { createTauriSource, historyRecord } from "./tauri-source";

type Invoke = Parameters<typeof createTauriSource>[0];

const fake = (impl: (cmd: string) => Promise<unknown>): Invoke => ((cmd: string) => impl(cmd)) as Invoke;

/** A clock whose timers never fire: only the poller's first, immediate sample runs. */
const stillClock: Clock = { now: () => 1_000_000, setTimeout: () => 0, clearTimeout: () => undefined };
const flush = () => new Promise<void>((r) => setTimeout(r, 0));

describe("tauri source (seam law: validated, never silently empty)", () => {
  it("calls net_snapshot and returns the validated snapshot", async () => {
    const calls: string[] = [];
    const src = createTauriSource(fake(async (cmd) => (calls.push(cmd), fixture)));
    await expect(src.sample()).resolves.toEqual(fixture);
    expect(calls).toEqual(["net_snapshot", "history_record"]);
  });

  it("throws a ProtocolError naming both versions on a version mismatch", async () => {
    const src = createTauriSource(fake(async () => ({ ...fixture, v: 2 })));
    const err = await src.sample().then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ProtocolError);
    expect((err as Error).message).toMatch(/version 2 is not 1/);
    expect((err as Error).message).toMatch(/Restart Sieve/);
  });

  it("treats a missing version or a non-object answer as a mismatch", async () => {
    const noVersion: Record<string, unknown> = { ...fixture };
    delete noVersion.v;
    await expect(createTauriSource(fake(async () => noVersion)).sample()).rejects.toThrow(/version undefined is not 1/);
    await expect(createTauriSource(fake(async () => null)).sample()).rejects.toBeInstanceOf(ProtocolError);
    await expect(createTauriSource(fake(async () => "1")).sample()).rejects.toBeInstanceOf(ProtocolError);
  });

  it("rejects a v1 answer with a malformed body", async () => {
    const bad = { ...fixture, flows: [{ ...fixture.flows[0], state: "listening" }] };
    await expect(createTauriSource(fake(async () => bad)).sample()).rejects.toThrow(/flows\[0\]\.state/);
  });

  it("a mismatch reaches the UI as an error with no data (poller and store)", async () => {
    const store = createStore(1000);
    const poller = createPoller({
      source: createTauriSource(fake(async () => ({ ...fixture, v: 2 }))),
      store,
      clock: stillClock,
    });
    poller.start();
    await flush();
    const s = store.getState();
    poller.stop();
    expect(s.status.error).toMatch(/version 2 is not 1/);
    expect(s.snapshots).toHaveLength(0);
    // The status chip reads "No data" with the message as its title.
    expect(phase(s)).toBe("error");
  });

  it("passes the Rust error through (no fallback data)", async () => {
    const src = createTauriSource(fake(async () => Promise.reject("reading the Tcp4 connection table failed (Windows error 87)")));
    await expect(src.sample()).rejects.toBe("reading the Tcp4 connection table failed (Windows error 87)");
  });

  it("records each good sample's per-app active flows into persisted history, never a rejected one", async () => {
    const records: unknown[] = [];
    let v = 1;
    const invoke = (async (cmd: string, args?: Record<string, unknown>) => {
      if (cmd === "history_record") return void records.push(args?.record);
      return { ...fixture, v };
    }) as Invoke;
    const src = createTauriSource(invoke);
    await src.sample();
    v = 2;
    await expect(src.sample()).rejects.toBeInstanceOf(ProtocolError);
    expect(records).toHaveLength(1);
    const r = records[0] as HistoryRecord;
    expect(r.t).toBe(fixture.t);
    // fixture: 4 active flows (2 established, 1 time_wait, 1 syn_sent; listeners and UDP excluded)
    expect(r.apps.reduce((s, a) => s + a.flows, 0)).toBe(4);
    expect(r).toEqual(historyRecord(parseSnapshot(fixture)));
  });

  it("an app the user turned off is not saved to history (Off stops tracking)", async () => {
    const records: HistoryRecord[] = [];
    const invoke = (async (cmd: string, args?: Record<string, unknown>) => {
      if (cmd === "history_record") return void records.push(args?.record as HistoryRecord);
      return fixture;
    }) as Invoke;
    let off: ReadonlySet<string> = new Set(["google chrome"]);
    const src = createTauriSource(invoke, () => off);
    const snap = await src.sample();
    // The sample itself is whole: the Apps screen still lists the app so it can be turned back on.
    expect(snap).toEqual(fixture);
    expect(records[0].apps.map((a) => a.app)).not.toContain("google chrome");
    expect(historyRecord(parseSnapshot(fixture)).apps.map((a) => a.app)).toContain("google chrome");
    // Read at every sample: turned back on, it is saved again.
    off = new Set();
    await src.sample();
    expect(records[1].apps.map((a) => a.app)).toContain("google chrome");
  });

  it("reads history through history_buckets and validates it", async () => {
    const asked: unknown[] = [];
    const src = createTauriSource((async (cmd: string, args?: Record<string, unknown>) => {
      asked.push([cmd, args]);
      return historyFixture;
    }) as Invoke);
    const query = { from: 0, to: 1, grain: "minute" as const, step: 300_000 };
    await expect(src.history(query)).resolves.toEqual(historyFixture);
    expect(asked).toEqual([["history_buckets", { query }]]);
    const bad = createTauriSource((async () => ({ ...historyFixture, grain: "week" })) as Invoke);
    await expect(bad.history(query)).rejects.toThrow(/grain/);
  });

  it("a failed history write does not fail the sample; history reads report it until a write succeeds", async () => {
    let failWrites = true;
    const src = createTauriSource((async (cmd: string) => {
      if (cmd === "history_record") return failWrites ? Promise.reject("history database: disk I/O error") : undefined;
      if (cmd === "history_buckets") return historyFixture;
      return fixture;
    }) as Invoke);
    const q = { from: 0, to: 1, grain: "hour" as const, step: 3_600_000 };
    await expect(src.sample()).resolves.toEqual(fixture);
    await flush();
    await expect(src.history(q)).rejects.toThrow(/not being saved: history database: disk I\/O error/);
    failWrites = false;
    await src.sample();
    await flush();
    await expect(src.history(q)).resolves.toEqual(historyFixture);
  });

  it("never reaches for mock data: the module does not import the mock source", () => {
    const text = readFileSync(resolve(__dirname, "tauri-source.ts"), "utf8");
    expect(text).not.toMatch(/from\s+["'][^"']*mock/);
    expect(text).not.toMatch(/createMockSource|MOCK_APPS/);
  });

});
