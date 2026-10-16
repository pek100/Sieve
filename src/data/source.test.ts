import { describe, expect, it } from "vitest";
import { sourceOptions } from "./source";

describe("source choice (seam law: Tauri when present, mock forced by ?source=mock)", () => {
  it("picks tauri inside Tauri and mock in a plain browser", () => {
    expect(sourceOptions({ search: "", isTauri: true }).kind).toBe("tauri");
    expect(sourceOptions({ search: "", isTauri: false }).kind).toBe("mock");
  });

  it("?source=mock forces the mock even inside Tauri", () => {
    expect(sourceOptions({ search: "?source=mock", isTauri: true }).kind).toBe("mock");
  });

  it("reads seed and scenario, falling back to seed 1 and steady", () => {
    expect(sourceOptions({ search: "?seed=7&scenario=busy", isTauri: false })).toEqual({ kind: "mock", seed: 7, scenario: "busy" });
    expect(sourceOptions({ search: "?seed=abc&scenario=nope", isTauri: false })).toEqual({ kind: "mock", seed: 1, scenario: "steady" });
  });
});
