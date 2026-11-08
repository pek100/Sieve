import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/filter-lists-v1.json";
import { parseFilterCatalogue, type FilterList } from "@/data/protocol";
import {
  PROFILES,
  RECOMMENDED_PROFILE,
  countText,
  groupState,
  inProfileScope,
  isGated,
  listGroup,
  listOn,
  listProfile,
  nothingLoaded,
  primaryLanguages,
  selectedListIds,
  setGroupOn,
  setListOn,
  suggestedLists,
  withEngineReports,
  withProfile,
} from "./filter-lists";
import { CUSTOM } from "./profiles";

const { lists } = parseFilterCatalogue(fixture.examples.pending);
const loaded = parseFilterCatalogue(fixture.examples.loaded).lists;
const byDefault = (d: FilterList["default"]) => lists.find((l) => l.default === d)!;
const group = (id: string) => lists.filter((l) => listGroup(l) === id);
const onIds = (selection: Record<string, string>) => lists.filter((l) => listOn(l, selection)).map((l) => l.id);

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
  it("every list is in the group of its kind, and the groups cover the catalogue", () => {
    for (const id of ["ads", "tracking", "security", "annoyances", "language"]) expect(group(id).length, id).toBeGreaterThan(0);
    expect(["ads", "tracking", "security", "annoyances", "language"].reduce((n, id) => n + group(id).length, 0)).toBe(lists.length);
  });

  it("setGroupOn skips gated lists", () => {
    const ads = group("ads");
    expect(ads.some(isGated)).toBe(true);
    const next = setGroupOn({}, ads, true);
    for (const l of ads) expect(next[l.id], l.id).toBeUndefined();
    const off = setGroupOn({}, ads, false);
    expect(Object.keys(off).sort()).toEqual(ads.filter((l) => !isGated(l)).map((l) => l.id).sort());
  });

  it("groupState gives all, none and the count, over selectable lists only", () => {
    const annoyances = group("annoyances");
    expect(annoyances).toHaveLength(5);
    expect(groupState(annoyances, {})).toMatchObject({ kind: "none", text: "0 of 5 on" });
    const two = setListOn(setListOn({}, annoyances[0], true), annoyances[1], true);
    expect(groupState(annoyances, two)).toMatchObject({ kind: "some", on: 2, text: "2 of 5 on" });
    expect(groupState(annoyances, setGroupOn({}, annoyances, true))).toMatchObject({ kind: "all", text: "5 of 5 on" });
    // Ads: three gated lists are not offered, so its default is "all".
    expect(groupState(group("ads"), {})).toMatchObject({ kind: "all", selectable: 2, text: "2 of 2 on" });
  });
});

describe("profiles", () => {
  const scope = lists.filter(inProfileScope);

  it("a person who changed nothing is on the recommended profile, Balanced", () => {
    expect(RECOMMENDED_PROFILE).toBe("balanced");
    expect(listProfile(lists, {})).toBe("balanced");
    expect(withProfile({}, lists, "balanced")).toEqual({});
  });

  it.each(PROFILES)("%s maps to exactly its lists: every list at its level or milder on, the rest of the scope off", (profile) => {
    const selection = withProfile({}, lists, profile);
    expect(listProfile(lists, selection)).toBe(profile);
    const rank = (l: string | null) => PROFILES.indexOf(l as (typeof PROFILES)[number]);
    const want = scope.filter((l) => rank(l.level) >= 0 && rank(l.level) <= rank(profile)).map((l) => l.id);
    expect(onIds(selection)).toEqual(want);
  });

  it("the profiles are nested and each adds a list, so no two read the same", () => {
    const on = PROFILES.map((p) => onIds(withProfile({}, lists, p)));
    for (let i = 1; i < on.length; i++) {
      expect(on[i].length, PROFILES[i]).toBeGreaterThan(on[i - 1].length);
      for (const id of on[i - 1]) expect(on[i], `${PROFILES[i]} keeps ${id}`).toContain(id);
    }
    expect(onIds(withProfile({}, lists, "minimal")).map((id) => lists.find((l) => l.id === id)!.kind)).toEqual(["ads", "ads"]);
    expect(onIds(withProfile({}, lists, "balanced")).map((id) => lists.find((l) => l.id === id)!.kind)).toContain("security");
  });

  it("any one change to a list the profile decides shows Custom, from every profile", () => {
    for (const profile of PROFILES) {
      const at = withProfile({}, lists, profile);
      for (const l of scope) expect(listProfile(lists, setListOn(at, l, !listOn(l, at))), `${profile}, ${l.id}`).toBe(CUSTOM);
    }
  });

  it("language lists, gated lists and unknown ids are outside the profile: changing them keeps it", () => {
    const german = group("language")[0];
    const gated = byDefault("gated");
    for (const profile of PROFILES) {
      const at = { ...withProfile({}, lists, profile), "from-a-newer-sieve": "on" };
      expect(listProfile(lists, setListOn(at, german, true)), profile).toBe(profile);
      expect(listProfile(lists, { ...at, [gated.id]: "on" }), profile).toBe(profile);
    }
  });

  it("back to recommended restores exactly the defaults and keeps the language lists as they were", () => {
    const german = group("language")[0];
    const messy = setListOn(setListOn(setListOn(withProfile({}, lists, "strict"), scope[0], false), german, true), scope.at(-1)!, true);
    expect(listProfile(lists, messy)).toBe(CUSTOM);
    const back = withProfile(messy, lists, RECOMMENDED_PROFILE);
    expect(listProfile(lists, back)).toBe("balanced");
    expect(back).toEqual({ [german.id]: "on" });
  });

  it("a row from an older build, with no level, is outside every profile: it never makes one Custom and no profile turns it off", () => {
    const old = parseFilterCatalogue({ v: 1, lists: [{ id: "a", title: "A", url: "", licence: "", default: "on", trusted: true, report: null }] }).lists;
    expect(old[0]).toMatchObject({ kind: "ads", level: null, description: "", languages: [] });
    expect(inProfileScope(old[0])).toBe(false);
    const mixed = [...lists, ...old];
    expect(listProfile(mixed, {}), "on by default, and Balanced still").toBe("balanced");
    expect(listProfile(mixed, { a: "off" })).toBe("balanced");
    for (const profile of PROFILES) expect(withProfile({}, mixed, profile), profile).not.toHaveProperty("a");
  });
});

describe("languages", () => {
  it("reads the primary subtag of each language the person uses, once", () => {
    expect(primaryLanguages(["de-DE", "en-US", "de", "pt_BR", "x", "zh-Hant-TW"])).toEqual(["de", "en", "pt", "zh"]);
  });

  it("suggests the language lists of those languages, the first preferred first", () => {
    expect(suggestedLists(lists, ["pt-BR", "de-DE"]).map((l) => l.languages[0])).toEqual(["es", "de"]);
    expect(suggestedLists(lists, ["en-US"])).toEqual([]);
    expect(suggestedLists(lists, [])).toEqual([]);
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
    fetched_at_ms: 7,
    refresh_s: null,
    last_error: null,
    network,
    cosmetic: 0,
    skipped,
    skip_reasons: (skipped ? { "bad option": skipped } : {}) as Record<string, number>,
    skipped_exceptions: [],
    skipped_exceptions_total: 0,
  });
  const listOf = (list: { lists: FilterList[] }, id: string) => list.lists.find((l) => l.id === id);

  it("puts the engine's own counts and copy facts on each list it reports", () => {
    const on = byDefault("on");
    const got = withEngineReports({ lists }, { lists: [row(on.id, true, 120, 2)], compile_ms: 5 });
    expect(listOf(got, on.id)?.report).toEqual({ applied: 120, skipped: 2, reasons: { "bad option": 2 } });
    expect(listOf(got, on.id)?.fetch).toEqual({ fetchedAtMs: 7, lastError: null, enabled: true });
  });

  it("says nothing of a list with no rules in force: absent is not zero", () => {
    const on = byDefault("on");
    const off = byDefault("off");
    const got = withEngineReports({ lists: loaded }, { lists: [row(on.id, true, 0), row(off.id, false, 90)], compile_ms: null });
    expect(listOf(got, on.id)?.report).toBeNull();
    expect(listOf(got, off.id)?.report, "turned off: a report of old counts claims nothing").toBeNull();
  });

  it("leaves what the seam gave when the engine gave no answer or no row", () => {
    const catalogue = { lists: loaded };
    expect(withEngineReports(catalogue, null)).toBe(catalogue);
    expect(withEngineReports(catalogue, { lists: [], compile_ms: null }).lists).toEqual(loaded);
  });
});
