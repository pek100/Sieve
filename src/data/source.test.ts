import { describe, expect, it } from "vitest";
import { createDnsSource, sourceOptions } from "./source";

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
      dns: "off",
      adguard: false,
      icons: false,
    });
    expect(sourceOptions({ search: "?seed=abc&scenario=nope", isTauri: false })).toEqual({
      kind: "mock",
      seed: 1,
      scenario: "steady",
      dns: "off",
      adguard: false,
      icons: false,
    });
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

  it("reads the mock DNS scenario and the AdGuard flag; the DNS seam follows the source kind", () => {
    expect(sourceOptions({ search: "?dns=running&adguard=1", isTauri: false })).toMatchObject({ dns: "running", adguard: true });
    expect(sourceOptions({ search: "?dns=nope", isTauri: false }).dns).toBe("off");
    expect(createDnsSource(sourceOptions({ search: "", isTauri: true })).kind).toBe("tauri");
    expect(createDnsSource(sourceOptions({ search: "?source=mock&dns=error", isTauri: true })).kind).toBe("mock");
  });
});
