import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/snapshot-v1.json";
import type { Snapshot } from "@/data/protocol";
import { category, groupApps, iconExe, iconExes, isActiveFlow, isSieved, trackedSnapshot } from "./apps";

const snapshot = fixture as Snapshot;

describe("groupApps", () => {
  const apps = groupApps(snapshot);
  const byKey = Object.fromEntries(apps.map((a) => [a.key, a]));

  it("identifies an app by product name and folds its processes in", () => {
    const chrome = byKey["google chrome"];
    expect(chrome.name).toBe("Google Chrome");
    expect(chrome.pids).toEqual([9120, 9188]);
    expect(chrome.exes).toHaveLength(1);
    expect(chrome.flows).toHaveLength(2);
  });

  it("falls back to the process name when the OS hid the exe", () => {
    expect(byKey["system"].exes).toEqual([]);
    expect(byKey["pid 15500"].flows).toHaveLength(1);
  });
});

describe("category (derived from paths, no app list)", () => {
  it("puts Windows dir exes and unreadable processes in system, others in apps", () => {
    expect(category({ exes: ["C:\\Windows\\System32\\svchost.exe"] }, [])).toBe("system");
    expect(category({ exes: ["d:\\WINDOWS\\explorer.exe"] }, [])).toBe("system");
    expect(category({ exes: [] }, [])).toBe("system");
    expect(category({ exes: ["C:\\Program Files\\App\\app.exe"] }, [])).toBe("apps");
  });

  it("pinned wins, case-insensitively", () => {
    expect(category({ exes: ["C:\\Program Files\\App\\app.exe"] }, ["c:\\program files\\app\\APP.exe"])).toBe("mine");
  });
});

describe("isSieved", () => {
  const code = groupApps(snapshot).find((a) => a.key === "visual studio code")!;
  const system = groupApps(snapshot).find((a) => a.key === "system")!;

  it("needs the app effectively on and at least one active flow", () => {
    expect(isSieved(code, true)).toBe(true);
    expect(isSieved(code, false)).toBe(false);
  });

  it("listening sockets alone do not count", () => {
    expect(system.flows.every((f) => !isActiveFlow(f))).toBe(true);
    expect(isSieved(system, true)).toBe(false);
  });
});

describe("trackedSnapshot (the one place per-app Off applies)", () => {
  it("drops the processes and flows of apps turned off, by app key", () => {
    const off = new Set(["google chrome"]);
    const s = trackedSnapshot(snapshot, off);
    expect(s.processes.some((p) => p.pid === 9120 || p.pid === 9188)).toBe(false);
    expect(s.flows.some((f) => f.pid === 9120 || f.pid === 9188)).toBe(false);
    expect(groupApps(s).map((a) => a.key)).not.toContain("google chrome");
    // Everything else is untouched.
    expect(s.flows.length).toBe(snapshot.flows.filter((f) => f.pid !== 9120 && f.pid !== 9188).length);
  });

  it("is the snapshot itself with nothing off, and the same object for the same off set", () => {
    expect(trackedSnapshot(snapshot, new Set())).toBe(snapshot);
    const off = new Set(["google chrome"]);
    expect(trackedSnapshot(snapshot, off)).toBe(trackedSnapshot(snapshot, off));
  });
});

describe("app icons by app", () => {
  it("an app's icon is its first exe's; apps whose exes Windows hides have none", () => {
    expect(iconExe({ exes: ["C:\\b\\b.exe", "C:\\a\\a.exe"].sort() })).toBe("C:\\a\\a.exe");
    expect(iconExe({ exes: [] })).toBeNull();
    const map = iconExes(snapshot);
    for (const g of groupApps(snapshot)) expect(map.get(g.key) ?? null).toBe(g.exes[0] ?? null);
    // Cached per snapshot: the same map back.
    expect(iconExes(snapshot)).toBe(map);
  });
});