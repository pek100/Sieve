import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/snapshot-v1.json";
import type { Snapshot } from "@/data/protocol";
import { capacityFor, createStore, newest, phase } from "./store";

const snap = (t: number): Snapshot => ({ ...(fixture as Snapshot), t });

describe("store (seam law: ring sized by the longest declared window)", () => {
  it("keeps only the newest sample when nobody declared a window", () => {
    const s = createStore(1000);
    s.push(snap(1));
    s.push(snap(2));
    expect(s.getState().snapshots.map((x) => x.t)).toEqual([2]);
  });

  it("sizes the ring from the longest window and shrinks when it is released", () => {
    const s = createStore(1000);
    const undoShort = s.declareWindow(5_000);
    const undoLong = s.declareWindow(60_000);
    expect(s.getState().capacity).toBe(capacityFor(60_000, 1000));
    for (let t = 0; t < 100; t++) s.push(snap(t));
    expect(s.getState().snapshots).toHaveLength(61);
    expect(newest(s.getState())?.t).toBe(99);
    undoLong();
    expect(s.getState().snapshots).toHaveLength(6);
    undoShort();
    expect(s.getState().capacity).toBe(1);
  });

  it("re-sizes when the interval changes", () => {
    const s = createStore(1000);
    s.declareWindow(10_000);
    s.setInterval(2000);
    expect(s.getState().capacity).toBe(6);
  });

  it("derives the phase instead of storing it", () => {
    const s = createStore();
    expect(phase(s.getState())).toBe("off");
    s.setStatus({ running: true });
    expect(phase(s.getState())).toBe("starting");
    s.push(snap(1));
    expect(phase(s.getState())).toBe("live");
    s.setStatus({ error: "x" });
    expect(phase(s.getState())).toBe("error");
    s.setStatus({ pausedUntil: 5 });
    expect(phase(s.getState())).toBe("paused");
  });
});
