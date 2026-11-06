import { describe, expect, it } from "vitest";
import fixture from "./fixtures/filter-lists-v1.json";
import { MOCK_LISTS_ERROR, createMockFilterLists } from "./filter-lists-mock";
import { createTauriFilterLists } from "./filter-lists-source";
import { ProtocolError, parseFilterCatalogue, parseRuleProblems } from "./protocol";

describe("filter list sources", () => {
  it("Tauri asks its commands and validates the answers", async () => {
    const calls: [string, unknown][] = [];
    const invoke = async <T,>(cmd: string, args?: unknown): Promise<T> => {
      calls.push([cmd, args]);
      return (cmd === "rule_check" ? [{ line: 2, reason: "network filter error: unrecognised option" }] : fixture.examples.pending) as T;
    };
    const s = createTauriFilterLists(invoke);
    expect((await s.catalogue()).lists).toHaveLength(fixture.examples.pending.lists.length);
    expect(await s.checkRules(["a", "b"])).toEqual([{ line: 2, reason: "network filter error: unrecognised option" }]);
    expect(calls).toEqual([
      ["filter_catalogue", undefined],
      ["rule_check", { lines: ["a", "b"] }],
    ]);
  });

  it("the mock serves each scenario; default is the truth today, nothing loaded", async () => {
    expect((await createMockFilterLists().catalogue()).lists.every((l) => l.report === null)).toBe(true);
    expect((await createMockFilterLists("loaded").catalogue()).lists.some((l) => l.report !== null)).toBe(true);
    expect((await createMockFilterLists("empty").catalogue()).lists).toEqual([]);
    await expect(createMockFilterLists("error").catalogue()).rejects.toThrow(MOCK_LISTS_ERROR);
    expect(await createMockFilterLists().checkRules(["||x"])).toEqual([]);
  });
});

describe("parseFilterCatalogue", () => {
  const row = fixture.examples.pending.lists[0];

  it("a wrong version, null or a missing array throws, for the block's error state", () => {
    for (const bad of [null, undefined, 3, [], { v: 2, lists: [] }, { lists: [] }, { v: 1 }, { v: 1, lists: {} }]) {
      expect(() => parseFilterCatalogue(bad), JSON.stringify(bad)).toThrow(ProtocolError);
    }
  });

  it("a malformed row is dropped and counted; a bad report reads null; a partial row keeps what is sure", () => {
    const got = parseFilterCatalogue({
      v: 1,
      lists: [
        null,
        { id: "no-title" },
        { ...row, default: "maybe" },
        { ...row, id: "bad-report", report: { applied: -1, skipped: 0, reasons: {} } },
        { ...row, id: "no-reasons", report: { applied: 1, skipped: 0 } },
        { id: "partial", title: "Partial", default: "off" },
      ],
    });
    expect(got.dropped).toBe(3);
    expect(got.lists.map((l) => [l.id, l.report])).toEqual([
      ["bad-report", null],
      ["no-reasons", null],
      ["partial", null],
    ]);
    expect(got.lists[2]).toMatchObject({ url: "", licence: "", trusted: false });
  });

  it("the rule check answer must have its shape", () => {
    expect(() => parseRuleProblems({})).toThrow(ProtocolError);
    expect(() => parseRuleProblems([{ line: "1", reason: "x" }])).toThrow(ProtocolError);
  });
});
