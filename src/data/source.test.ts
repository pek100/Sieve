import { describe, expect, it } from "vitest";
import { createEngineSource, createWindowsDnsSource, sourceOptions } from "./source";

describe("source choice (seam law: Tauri when present, mock forced by ?source=mock)", () => {
  it("picks tauri inside Tauri and mock in a plain browser", () => {
    expect(sourceOptions({ search: "", isTauri: true }).kind).toBe("tauri");
    expect(sourceOptions({ search: "", isTauri: false }).kind).toBe("mock");
  });

  it("?source=mock forces the mock even inside Tauri", () => {
    expect(sourceOptions({ search: "?source=mock", isTauri: true }).kind).toBe("mock");
  });

  it("reads seed and scenario, falling back to seed 1 and steady", () => {
    expect(sourceOptions({ search: "?seed=7&scenario=busy", isTauri: false })).toEqual({
      kind: "mock",
      seed: 7,
      scenario: "busy",
      pointed: false,
      icons: false,
      engine: "missing",
      logError: false,
      cert: "not_installed",
    });
    expect(sourceOptions({ search: "?seed=abc&scenario=nope", isTauri: false })).toEqual({
      kind: "mock",
      seed: 1,
      scenario: "steady",
      pointed: false,
      icons: false,
      engine: "missing",
      logError: false,
      cert: "not_installed",
    });
  });

  it("?engine=<scenario> picks the mock engine's answer, default not installed; Tauri asks the command", async () => {
    expect(sourceOptions({ search: "?engine=idle", isTauri: false }).engine).toBe("idle");
    expect(sourceOptions({ search: "?engine=nope", isTauri: false }).engine).toBe("missing");
    const idle = await createEngineSource(sourceOptions({ search: "?engine=idle", isTauri: false })).probe();
    expect(idle.pipe?.kind).toBe("welcome");
    expect(createEngineSource(sourceOptions({ search: "", isTauri: true })).kind).toBe("tauri");
  });

  it("?icons=1 gives the mock generated app icons (outside the Windows dir); without it there are none", async () => {
    expect(sourceOptions({ search: "?icons=1", isTauri: false }).icons).toBe(true);
    const { createMockSource } = await import("./mock-source");
    const { parseAppIcon } = await import("./protocol");
    const withIcons = createMockSource({ seed: 1, icons: true });
    const icon = await withIcons.appIcon("C:\\Program Files\\App\\app.exe");
    expect(parseAppIcon(icon)).toEqual(icon);
    // A PNG: the signature, base64 encoded.
    expect(icon?.x1.startsWith("iVBORw0KGgo")).toBe(true);
    expect(await withIcons.appIcon("C:\\Windows\\explorer.exe")).toBeNull();
    expect(await createMockSource({ seed: 1 }).appIcon("C:\\Program Files\\App\\app.exe")).toBeNull();
  });

  it("reads a pointed adapter, and the safety net's read follows it", async () => {
    expect(sourceOptions({ search: "?pointed=1", isTauri: false }).pointed).toBe(true);
    const pointed = await createWindowsDnsSource(sourceOptions({ search: "?pointed=1", isTauri: false })).windowsDns();
    expect(pointed.adapters[0].servers).toEqual(["127.0.0.1", "::1"]);
    const own = await createWindowsDnsSource(sourceOptions({ search: "", isTauri: false })).windowsDns();
    expect(own.adapters.flatMap((a) => a.servers)).not.toContain("127.0.0.1");
  });

  it("?log=error makes the mock's log unreadable", async () => {
    expect(sourceOptions({ search: "?log=error", isTauri: false }).logError).toBe(true);
    const engine = createEngineSource(sourceOptions({ search: "?engine=hosts&log=error", isTauri: false }));
    await expect(engine.logTail(0)).rejects.toThrow();
  });
});
