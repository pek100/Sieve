import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/snapshot-v1.json";
import type { Snapshot } from "@/data/protocol";
import { category, groupApps, isActiveFlow, isSieved } from "./apps";

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

  it("needs level watch or higher and at least one active flow", () => {
    expect(isSieved(code, "watch")).toBe(true);
    expect(isSieved(code, "sieve")).toBe(true);
    expect(isSieved(code, "off")).toBe(false);
  });

  it("listening sockets alone do not count", () => {
    expect(system.flows.every((f) => !isActiveFlow(f))).toBe(true);
    expect(isSieved(system, "watch")).toBe(false);
  });
});
