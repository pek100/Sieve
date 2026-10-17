import { describe, expect, it } from "vitest";
import { createMockSource, MOCK_APPS } from "@/data/mock-source";
import { appIdentity, isSieved } from "./apps";
import {
  isPinnablePath,
  listApps,
  matchesQuery,
  offAll,
  pin,
  sections,
  setAppState,
  sieveAll,
  sievedCount,
  unpin,
} from "./apps-actions";
import { effectiveOn } from "./policy";
import { createStore, newest } from "./store";

async function mockSnapshot(ticks = 40) {
  const source = createMockSource({ seed: 1, now: () => 1_000_000 });
  let s = await source.sample();
  for (let i = 1; i < ticks; i++) s = await source.sample();
  return s;
}

describe("setAppState stores only Off", () => {
  it("off is stored; back on removes the entry", () => {
    const off = setAppState({}, "k", "off");
    expect(off).toEqual({ k: "off" });
    expect(setAppState(off, "k", "sieve")).toEqual({});
    expect(setAppState({}, "k", "sieve")).toEqual({});
  });
});

describe("bulk actions", () => {
  it("offAll sets each key off; sieveAll forgets every Off", () => {
    expect(offAll({ a: "off" }, ["a", "b"])).toEqual({ a: "off", b: "off" });
    expect(sieveAll()).toEqual({});
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
  it("turning an app off removes it from the count; global off counts nothing", async () => {
    const store = createStore();
    store.push(await mockSnapshot());
    const s = newest(store.getState());
    const target = listApps(s, []).find((a) => a.activeCount > 0)!;
    expect(target).toBeDefined();
    expect(isSieved(target, effectiveOn(true, {}, target.key))).toBe(true);

    const before = sievedCount(s, {}, true);
    expect(sievedCount(newest(store.getState()), setAppState({}, target.key, "off"), true)).toBe(before - 1);
    expect(sievedCount(s, offAll({}, listApps(s, []).map((a) => a.key)), true)).toBe(0);
    expect(sievedCount(s, {}, false)).toBe(0);
    expect(sievedCount(null, {}, true)).toBe(0);
  });
});
