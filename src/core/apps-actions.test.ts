import { describe, expect, it } from "vitest";
import { createMockSource, MOCK_APPS } from "@/data/mock-source";
import { appIdentity, isSieved } from "./apps";
import {
  isPinnablePath,
  levelOf,
  listApps,
  matchesQuery,
  pin,
  resetLevels,
  sections,
  setLevel,
  sievedCount,
  stopAll,
  unpin,
  watchAll,
} from "./apps-actions";
import { ceiling, LEVEL_REQUIRES, LEVELS, levelRank, type Level } from "./policy";
import { createStore, newest } from "./store";

const DNS = LEVEL_REQUIRES.sieve!;
const top = (switchOn: boolean, checkPassed: boolean) =>
  ceiling(
    (k) => k === DNS && switchOn,
    (k) => k === DNS && checkPassed,
  );

async function mockSnapshot(ticks = 40) {
  const source = createMockSource({ seed: 1, now: () => 1_000_000 });
  let s = await source.sample();
  for (let i = 1; i < ticks; i++) s = await source.sample();
  return s;
}

describe("setLevel is clamped to the ceiling", () => {
  it("sieve with DNS filtering off is stored and read as watch", () => {
    const t = top(false, false);
    expect(t).toBe("watch");
    const levels = setLevel({}, "google chrome", "sieve", t);
    expect(levels["google chrome"]).toBeUndefined(); // watch is the default, so nothing is stored
    expect(levelOf(levels, "google chrome", t)).toBe("watch");
  });

  it("switch on but live check not passed still yields watch", () => {
    const t = top(true, false);
    expect(levelOf(setLevel({}, "k", "sieve", t), "k", t)).toBe("watch");
  });

  it("switch on and live check passed yields sieve", () => {
    const t = top(true, true);
    const levels = setLevel({}, "k", "sieve", t);
    expect(levels.k).toBe("sieve");
    expect(levelOf(levels, "k", t)).toBe("sieve");
  });

  it("never stores or reads a level above the ceiling, for every ceiling and request", () => {
    for (const t of LEVELS) {
      for (const want of LEVELS) {
        const levels = setLevel({}, "k", want, t);
        for (const v of Object.values(levels)) expect(levelRank(v)).toBeLessThanOrEqual(levelRank(t));
        expect(levelRank(levelOf(levels, "k", t))).toBeLessThanOrEqual(levelRank(t));
      }
    }
    // A value stored when the ceiling was higher reads clamped once it drops.
    expect(levelOf({ k: "sieve" }, "k", "watch")).toBe("watch");
  });

  it("off is stored; going back to watch removes the entry", () => {
    const off = setLevel({}, "k", "off", "watch");
    expect(off).toEqual({ k: "off" });
    expect(setLevel(off, "k", "watch", "watch")).toEqual({});
  });
});

describe("bulk actions", () => {
  it("resetLevels empties apps.levels and every app reads the default watch", () => {
    const levels = resetLevels();
    expect(levels).toEqual({});
    for (const k of ["google chrome", "discord", "anything"]) expect(levelOf(levels, k, "sieve")).toBe("watch");
  });

  it("stopAll sets each key off; watchAll brings off apps back and keeps sieve", () => {
    const stopped = stopAll({ a: "sieve" }, ["a", "b"]);
    expect(stopped).toEqual({ a: "off", b: "off" });
    expect(watchAll({ a: "off", b: "sieve" })).toEqual({ b: "sieve" });
  });
});

describe("pinning", () => {
  it("absorbs the same path twice, in any letter case, and blank paths", () => {
    const once = pin([], "C:\\Tools\\thing.exe");
    expect(pin(once, "C:\\Tools\\thing.exe")).toBe(once);
    expect(pin(once, "c:\\tools\\THING.exe")).toBe(once);
    expect(pin(once, "   ")).toBe(once);
    expect(once).toEqual(["C:\\Tools\\thing.exe"]);
  });

  it("only .exe paths are pinnable", () => {
    expect(isPinnablePath("C:\\Tools\\thing.exe")).toBe(true);
    expect(isPinnablePath(" D:\\x\\Y.EXE ")).toBe(true);
    expect(isPinnablePath("C:\\Tools\\notes.txt")).toBe(false);
    expect(isPinnablePath(".exe")).toBe(false);
  });

  it("a pinned app that is not running shows under Mine with zero connections, and unpin removes it", () => {
    const pinned = pin([], "D:\\Games\\Quiet\\quiet.exe");
    const apps = listApps(null, pinned);
    expect(apps).toHaveLength(1);
    expect(apps[0]).toMatchObject({ key: "quiet", name: "quiet", category: "mine", activeCount: 0, pids: [] });
    expect(unpin(pinned, "quiet", apps)).toEqual([]);
  });

  it("pinning a running exe moves that app to Mine", async () => {
    const s = await mockSnapshot();
    const chromeExe = MOCK_APPS[0].exe!;
    const apps = listApps(s, pin([], chromeExe.toUpperCase()));
    const chrome = apps.find((a) => a.key === "google chrome")!;
    expect(chrome.category).toBe("mine");
    expect(chrome.pinnedPaths).toEqual([chromeExe.toUpperCase()]);
    expect(apps.filter((a) => a.key === "google chrome")).toHaveLength(1);
  });
});

describe("categories are derived from paths (no per-app list)", () => {
  it("every mock app is listed, under the category its path implies", async () => {
    const s = await mockSnapshot();
    const apps = listApps(s, []);
    const byKey = new Map(apps.map((a) => [a.key, a]));
    for (const m of MOCK_APPS) {
      const { key } = appIdentity({ pid: 0, exe: m.exe, name: m.name ?? "", product: m.product });
      const app = byKey.get(key);
      expect(app, key).toBeDefined();
      const expected = m.exe === null || /^[a-z]:\\windows\\/i.test(m.exe) ? "system" : "apps";
      expect(app!.category, key).toBe(expected);
    }
    // explorer.exe lives in C:\Windows\, so its app lands in System.
    const explorer = apps.find((a) => a.exes.some((e) => e.toLowerCase() === "c:\\windows\\explorer.exe"))!;
    expect(explorer.category).toBe("system");
  });

  it("sections come in order Mine, Apps, System, each sorted by name", async () => {
    const s = await mockSnapshot();
    const out = sections(listApps(s, ["C:\\Tools\\mine.exe"]));
    expect(out.map((x) => x.category)).toEqual(["mine", "apps", "system"]);
    for (const sec of out) {
      const names = sec.apps.map((a) => a.name);
      expect(names).toEqual([...names].sort((a, b) => a.localeCompare(b)));
    }
    expect(out[0].apps.map((a) => a.key)).toEqual(["mine"]);
  });
});

describe("search", () => {
  it("matches name, key or path, case-insensitive; blank matches all", () => {
    const app = { name: "Google Chrome", key: "google chrome", exes: ["C:\\Program Files\\Google\\chrome.exe"] };
    expect(matchesQuery(app, "CHROME")).toBe(true);
    expect(matchesQuery(app, "program files")).toBe(true);
    expect(matchesQuery(app, "  ")).toBe(true);
    expect(matchesQuery(app, "zzzz")).toBe(false);
  });
});

describe("being-sieved count through the store", () => {
  it("setting an app to off removes it from the count", async () => {
    const store = createStore();
    store.push(await mockSnapshot());
    const s = newest(store.getState());
    const t: Level = "watch";
    const target = listApps(s, []).find((a) => a.activeCount > 0)!;
    expect(target).toBeDefined();
    expect(isSieved(target, levelOf({}, target.key, t))).toBe(true);

    const before = sievedCount(s, {}, t);
    const levels = setLevel({}, target.key, "off", t);
    expect(sievedCount(newest(store.getState()), levels, t)).toBe(before - 1);
    expect(sievedCount(s, stopAll({}, listApps(s, []).map((a) => a.key)), t)).toBe(0);
    expect(sievedCount(null, {}, t)).toBe(0);
  });
});
