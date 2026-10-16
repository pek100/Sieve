import { describe, expect, it } from "vitest";
import fixture from "./fixtures/snapshot-v1.json";
import { createTauriSource } from "./tauri-source";

type Invoke = Parameters<typeof createTauriSource>[0];

const fake = (impl: (cmd: string) => Promise<unknown>): Invoke => ((cmd: string) => impl(cmd)) as Invoke;

describe("tauri source (seam law: validated, never silently empty)", () => {
  it("calls net_snapshot and returns the validated snapshot", async () => {
    const calls: string[] = [];
    const src = createTauriSource(fake(async (cmd) => (calls.push(cmd), fixture)));
    await expect(src.sample()).resolves.toEqual(fixture);
    expect(calls).toEqual(["net_snapshot"]);
  });

  it("throws on a version mismatch", async () => {
    const src = createTauriSource(fake(async () => ({ ...fixture, v: 2 })));
    await expect(src.sample()).rejects.toThrow(/version/);
  });

  it("passes the Rust error through (no fallback data)", async () => {
    const src = createTauriSource(fake(async () => Promise.reject("the connection reader is not implemented yet (slice S1)")));
    await expect(src.sample()).rejects.toBe("the connection reader is not implemented yet (slice S1)");
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
