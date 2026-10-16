import { describe, expect, it } from "vitest";
import { isActiveFlow } from "@/core/apps";
import { createMockSource } from "./mock-source";
import { parseSnapshot, type Snapshot } from "./protocol";

const fixedNow = () => 1_792_224_000_000;

async function run(seed: number, n: number, scenario?: "steady" | "busy" | "empty"): Promise<Snapshot[]> {
  const src = createMockSource({ seed, scenario, now: fixedNow });
  const out: Snapshot[] = [];
  for (let i = 0; i < n; i++) out.push(await src.sample());
  return out;
}

const flowId = (f: Snapshot["flows"][number]) => `${f.pid}|${f.local.addr}:${f.local.port}|${f.remote?.addr}:${f.remote?.port}`;

describe("mock source (seam law: deterministic and protocol valid)", () => {
  it("gives the same sequence for the same seed and a different one for another seed", async () => {
    const a = await run(1, 5);
    expect(await run(1, 5)).toEqual(a);
    expect(await run(2, 5)).not.toEqual(a);
  });

  it("emits valid v1 snapshots", async () => {
    for (const s of await run(1, 3)) expect(parseSnapshot(s)).toEqual(s);
  });

  it("keeps flows alive between ticks so lines move smoothly", async () => {
    const [a, b] = await run(1, 2);
    const before = new Set(a.flows.filter(isActiveFlow).map(flowId));
    const after = new Set(b.flows.filter(isActiveFlow).map(flowId));
    const kept = [...before].filter((id) => after.has(id)).length;
    expect(before.size).toBeGreaterThan(10);
    expect(kept / before.size).toBeGreaterThan(0.8);
  });

  it("uses documentation address ranges only", async () => {
    const [s] = await run(3, 1, "busy");
    const ok = /^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2001:db8:)/;
    for (const f of s.flows) if (f.remote) expect(f.remote.addr).toMatch(ok);
  });

  it("scenario empty has processes but no active flows; error rejects", async () => {
    const [s] = await run(1, 1, "empty");
    expect(s.processes.length).toBeGreaterThan(10);
    expect(s.flows.filter(isActiveFlow)).toEqual([]);
    const err = createMockSource({ seed: 1, scenario: "error" });
    await expect(err.sample()).rejects.toThrow(/scenario error/);
  });

  it("busy has more active flows than steady", async () => {
    const [steady] = await run(1, 1, "steady");
    const [busy] = await run(1, 1, "busy");
    expect(busy.flows.filter(isActiveFlow).length).toBeGreaterThan(steady.flows.filter(isActiveFlow).length);
  });

  it("history returns up to 4 weeks of hourly buckets, oldest first", async () => {
    const src = createMockSource({ seed: 1, now: fixedNow });
    const to = fixedNow();
    const buckets = await src.history({ from: to - 60 * 86_400_000, to });
    expect(buckets.length).toBe(28 * 24);
    for (let i = 1; i < buckets.length; i++) expect(buckets[i].t - buckets[i - 1].t).toBe(3_600_000);
    expect(buckets.every((b) => b.flows >= 0)).toBe(true);
  });
});
