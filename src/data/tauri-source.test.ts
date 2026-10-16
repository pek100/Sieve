import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { createStore, phase } from "@/core/store";
import fixture from "./fixtures/snapshot-v1.json";
import { createPoller, type Clock } from "./poller";
import { ProtocolError } from "./protocol";
import { createTauriSource } from "./tauri-source";

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
    expect(calls).toEqual(["net_snapshot"]);
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

  it("a mismatched sample is not folded into history", async () => {
    let v = 1;
    const src = createTauriSource(fake(async () => ({ ...fixture, v })));
    await src.sample();
    v = 2;
    await expect(src.sample()).rejects.toBeInstanceOf(ProtocolError);
    const [b] = await src.history({ from: 0, to: Number.MAX_SAFE_INTEGER });
    expect(b.flows).toBe(4);
  });

  it("passes the Rust error through (no fallback data)", async () => {
    const src = createTauriSource(fake(async () => Promise.reject("reading the Tcp4 connection table failed (Windows error 87)")));
    await expect(src.sample()).rejects.toBe("reading the Tcp4 connection table failed (Windows error 87)");
  });

  it("never reaches for mock data: the module does not import the mock source", () => {
    const text = readFileSync(resolve(__dirname, "tauri-source.ts"), "utf8");
    expect(text).not.toMatch(/from\s+["'][^"']*mock/);
    expect(text).not.toMatch(/createMockSource|MOCK_APPS/);
  });

  it("folds samples into session-only hourly history", async () => {
    const src = createTauriSource(fake(async () => fixture));
    await src.sample();
    await src.sample();
    const hour = Math.floor(fixture.t / 3_600_000) * 3_600_000;
    // fixture: 4 active flows per sample (2 established, 1 time_wait, 1 syn_sent; listeners and UDP excluded)
    const [b] = await src.history({ from: 0, to: Number.MAX_SAFE_INTEGER });
    expect(b.t).toBe(hour);
    expect(b.flows).toBe(8);
  });
});
