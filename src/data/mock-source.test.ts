import { describe, expect, it } from "vitest";
import { isActiveFlow } from "@/core/apps";
import { createMockSource } from "./mock-source";
import { parseHistory, parseSnapshot, type Snapshot } from "./protocol";

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

  it("history returns up to 4 weeks of hourly buckets, oldest first, in the persisted shape", async () => {
    const src = createMockSource({ seed: 1, now: fixedNow });
    const to = fixedNow();
    const h = parseHistory(await src.history({ from: to - 60 * 86_400_000, to, grain: "hour", step: 3_600_000 }));
    expect(h.samples.length).toBe(28 * 24);
    for (let i = 1; i < h.samples.length; i++) expect(h.samples[i].t - h.samples[i - 1].t).toBe(3_600_000);
    expect(h.samples.every((b) => b.n === 3600)).toBe(true);
    // Rows are oldest first, then by app key, and only for apps with flows.
    expect(h.apps.every((a) => a.flows > 0)).toBe(true);
    const order = h.apps.map((a) => `${String(a.t).padStart(15, "0")}|${a.app}`);
    expect(order).toEqual([...order].sort());
    // App keys are the live chart's identities: Windows' own exes are one app.
    expect(new Set(h.apps.map((a) => a.app))).toContain("microsoft windows operating system");
  });

  it("history honours each grain's retention like the Rust store", async () => {
    const src = createMockSource({ seed: 1, now: fixedNow });
    const to = fixedNow();
    const minutes = await src.history({ from: to - 7 * 86_400_000, to, grain: "minute", step: 3_600_000 });
    // Minutes are kept 2 days: a week asked at minute grain answers 2 days (48 or 49 partial hours).
    expect(minutes.samples.length).toBeGreaterThanOrEqual(48);
    expect(minutes.samples.length).toBeLessThanOrEqual(49);
    // Hour totals agree with the minutes rolled up, within rounding.
    const hours = await src.history({ from: to - 86_400_000, to, grain: "hour", step: 3_600_000 });
    const m = await src.history({ from: to - 86_400_000, to, grain: "minute", step: 3_600_000 });
    const sum = (x: typeof hours) => x.apps.reduce((s, a) => s + a.flows, 0);
    expect(Math.abs(sum(m) - sum(hours)) / sum(hours)).toBeLessThan(0.02);
    // A step that is not a whole number of grain buckets answers nothing.
    expect((await src.history({ from: to - 86_400_000, to, grain: "hour", step: 90 * 60_000 })).samples).toEqual([]);
  });

  it("history mixes apps differently over the week: work apps in office hours, leisure apps at night and weekends", async () => {
    // Four weeks ending Monday 2026-10-12 00:00 local time.
    const to = new Date(2026, 9, 12).getTime();
    const h = await createMockSource({ seed: 1, now: () => to }).history({ from: to - 28 * 86_400_000, to, grain: "hour", step: 3_600_000 });
    /** Each app's share of an hour, by app key. */
    const mix = (day: number, hour: number) => {
      const t = new Date(2026, 9, 12 - 7 + day, hour).getTime();
      const rows = h.apps.filter((a) => a.t === t);
      const total = rows.reduce((s, a) => s + a.flows, 0);
      return new Map(rows.map((a) => [a.app, a.flows / total]));
    };
    const wed14 = mix(2, 14);
    const wed21 = mix(2, 21);
    const sat15 = mix(5, 15);
    const wed3 = mix(2, 3);
    expect(wed14.get("microsoft teams")!).toBeGreaterThan(4 * (wed21.get("microsoft teams") ?? 0));
    expect(wed21.get("discord")!).toBeGreaterThan(4 * (wed14.get("discord") ?? 0));
    expect(sat15.get("discord")!).toBeGreaterThan(4 * (sat15.get("slack") ?? 0));
    // At night the background apps (Windows' own services, OneDrive) lead.
    const top = [...wed3.entries()].sort((a, b) => b[1] - a[1])[0][0];
    expect(["microsoft windows operating system", "microsoft onedrive", "google chrome"]).toContain(top);
  });

  it("scenario empty has no history and error rejects", async () => {
    const q = { from: 0, to: fixedNow(), grain: "hour" as const, step: 3_600_000 };
    expect((await createMockSource({ seed: 1, scenario: "empty", now: fixedNow }).history(q)).samples).toEqual([]);
    await expect(createMockSource({ seed: 1, scenario: "error", now: fixedNow }).history(q)).rejects.toThrow(/scenario error/);
  });
});
