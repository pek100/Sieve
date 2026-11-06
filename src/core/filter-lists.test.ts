import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/filter-lists-v1.json";
import { parseFilterCatalogue, type FilterList } from "@/data/protocol";
import {
  countText,
  groupState,
  isGated,
  listGroup,
  listOn,
  nothingLoaded,
  selectedListIds,
  setGroupOn,
  setListOn,
  withEngineReports,
} from "./filter-lists";

const { lists } = parseFilterCatalogue(fixture.examples.pending);
const loaded = parseFilterCatalogue(fixture.examples.loaded).lists;
const byDefault = (d: FilterList["default"]) => lists.find((l) => l.default === d)!;
const group = (id: string) => lists.filter((l) => listGroup(l) === id);

describe("selection", () => {
  it("stores only differences from the default", () => {
    const on = byDefault("on");
    const off = byDefault("off");
    expect(listOn(on, {})).toBe(true);
    expect(listOn(off, {})).toBe(false);
    const a = setListOn({}, on, false);
    expect(a).toEqual({ [on.id]: "off" });
    expect(setListOn(a, on, true)).toEqual({});
    expect(setListOn({}, off, true)).toEqual({ [off.id]: "on" });
    expect(setListOn({}, on, true)).toEqual({});
  });

  it("a stored on for a gated list reads off, and setListOn refuses it", () => {
    const gated = byDefault("gated");
    expect(listOn(gated, { [gated.id]: "on" })).toBe(false);
    const selection = {};
    expect(setListOn(selection, gated, true)).toBe(selection);
  });

  it("unknown ids survive a write, and a junk stored value reads as the default", () => {
    const on = byDefault("on");
    expect(setListOn({ "from-a-newer-sieve": "on" }, on, false)).toEqual({ "from-a-newer-sieve": "on", [on.id]: "off" });
    expect(listOn(on, { [on.id]: "loud" })).toBe(true);
  });
});

describe("groups", () => {
  it("every list has a group; tracking and annoyances are not empty", () => {
    expect(group("tracking").length).toBeGreaterThan(0);
    expect(group("annoyances").length).toBeGreaterThan(0);
    expect(group("tracking").length + group("annoyances").length + group("general").length).toBe(lists.length);
  });

  it("setGroupOn skips gated lists", () => {
    const general = group("general");
    expect(general.some(isGated)).toBe(true);
    const next = setGroupOn({}, general, true);
    for (const l of general) expect(next[l.id], l.id).toBeUndefined();
    const off = setGroupOn({}, general, false);
    expect(Object.keys(off).sort()).toEqual(general.filter((l) => !isGated(l)).map((l) => l.id).sort());
  });

  it("groupState gives all, none and the count, over selectable lists only", () => {
    const annoyances = group("annoyances");
    expect(annoyances).toHaveLength(5);
    expect(groupState(annoyances, {})).toMatchObject({ kind: "none", text: "0 of 5 on" });
    const two = setListOn(setListOn({}, annoyances[0], true), annoyances[1], true);
    expect(groupState(annoyances, two)).toMatchObject({ kind: "some", on: 2, text: "2 of 5 on" });
    expect(groupState(annoyances, setGroupOn({}, annoyances, true))).toMatchObject({ kind: "all", text: "5 of 5 on" });
    // General: three gated lists are not offered, so its default is "all".
    expect(groupState(group("general"), {})).toMatchObject({ kind: "all", selectable: 2, text: "2 of 2 on" });
  });
});

describe("counts", () => {
  it("absent is not zero", () => {
    expect(countText(null)).toBe("Not loaded yet");
    expect(countText({ applied: 0, skipped: 0, reasons: {} })).toBe("0 applied, 0 skipped");
    expect(countText({ applied: 48211, skipped: 12, reasons: {} })).toBe("48,211 applied, 12 skipped");
    expect(nothingLoaded(lists)).toBe(true);
    expect(nothingLoaded(loaded)).toBe(false);
  });
});

describe("selectedListIds", () => {
  it("is the lists on, never a gated one or an id the catalogue lacks", () => {
    const off = byDefault("off");
    const on = byDefault("on");
    const gated = byDefault("gated");
    const ids = selectedListIds({ [off.id]: "on", [on.id]: "off", [gated.id]: "on", "from-the-future": "on" }, { lists });
    expect(ids).toContain(off.id);
    expect(ids).not.toContain(on.id);
    expect(ids).not.toContain(gated.id);
    expect(ids).not.toContain("from-the-future");
  });
});

describe("withEngineReports", () => {
  const row = (id: string, enabled: boolean, network: number, skipped = 0) => ({
    id,
    enabled,
    fetched_at_ms: null,
    refresh_s: null,
    last_error: null,
    network,
    cosmetic: 0,
    skipped,
    skip_reasons: (skipped ? { "bad option": skipped } : {}) as Record<string, number>,
    skipped_exceptions: [],
    skipped_exceptions_total: 0,
  });
  const reportOf = (list: { lists: FilterList[] }, id: string) => list.lists.find((l) => l.id === id)?.report;

  it("puts the engine's own counts on each list it reports", () => {
    const on = byDefault("on");
    const got = withEngineReports({ lists }, { lists: [row(on.id, true, 120, 2)], compile_ms: 5 });
    expect(reportOf(got, on.id)).toEqual({ applied: 120, skipped: 2, reasons: { "bad option": 2 } });
  });

  it("says nothing of a list with no rules in force: absent is not zero", () => {
    const on = byDefault("on");
    const off = byDefault("off");
    const got = withEngineReports({ lists: loaded }, { lists: [row(on.id, true, 0), row(off.id, false, 90)], compile_ms: null });
    expect(reportOf(got, on.id)).toBeNull();
    expect(reportOf(got, off.id), "turned off: a report of old counts claims nothing").toBeNull();
  });

  it("leaves what the seam gave when the engine gave no answer or no row", () => {
    const catalogue = { lists: loaded };
    expect(withEngineReports(catalogue, null)).toBe(catalogue);
    expect(withEngineReports(catalogue, { lists: [], compile_ms: null }).lists).toEqual(loaded);
  });
});
