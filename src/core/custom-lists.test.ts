import { describe, expect, it } from "vitest";
import ipc from "@/data/fixtures/engine-ipc-v3.json";
import {
  CUSTOM_TITLE_MAX,
  CUSTOM_URL_MAX,
  MAX_CUSTOM_LISTS,
  MAX_IMPORT_BYTES,
  addProblem,
  customListProblem,
  customListViews,
  fetchWords,
  isCustomList,
  newCustomId,
  parseListUrl,
  titleFromUrl,
  updatedText,
  type CustomList,
} from "./custom-lists";
import { EMPTY_DOC, writeValue } from "./settings/document";
import { SETTINGS_SCHEMA, isValidValue } from "./settings/registry";
import { EXPORT_KIND, planImport } from "./settings/transfer";

const list = (over: Partial<CustomList> = {}): CustomList => ({ id: "custom-a1", title: "My list", url: "https://lists.example/my.txt", enabled: true, ...over });

describe("a custom list", () => {
  it("is judged as the engine judges it, case by case from the shared table", () => {
    expect(ipc.customLists.length).toBeGreaterThanOrEqual(10);
    for (const c of ipc.customLists) expect(customListProblem(c.list as CustomList) === null, JSON.stringify(c.list)).toBe(c.ok);
  });

  it("has the engine's limits", () => {
    expect([MAX_CUSTOM_LISTS, MAX_IMPORT_BYTES, CUSTOM_URL_MAX, CUSTOM_TITLE_MAX]).toEqual([ipc.maxCustomLists, ipc.maxImportBytes, ipc.customUrlMax, ipc.customTitleMax]);
  });

  it("is stored only whole and valid: a broken stored value reads as the default", () => {
    expect(isCustomList(list())).toBe(true);
    expect(isCustomList({ ...list(), extra: 1 })).toBe(false);
    expect(isCustomList({ ...list(), enabled: "yes" })).toBe(false);
    expect(isCustomList("custom-a1")).toBe(false);
    expect(isValidValue("filters.custom", [list(), list({ id: "custom-b2", url: null })])).toBe(true);
    expect(isValidValue("filters.custom", [list({ url: "http://lists.example/x.txt" })])).toBe(false);
  });

  it("an import or a stored value over the budget is refused with a sentence", () => {
    // As many as the engine holds, each at the longest address and name: past the budget.
    const url = (i: number) => `https://lists.example/${String(i).padStart(2, "0")}${"x".repeat(CUSTOM_URL_MAX - 28)}.txt`;
    const many = Array.from({ length: MAX_CUSTOM_LISTS }, (_, i) => list({ id: `custom-${i}`, title: "𝒳".repeat(CUSTOM_TITLE_MAX), url: url(i) }));
    expect(many.every((l) => isCustomList(l) && l.url!.length === CUSTOM_URL_MAX)).toBe(true);
    expect(() => writeValue(EMPTY_DOC, "filters.custom", many)).toThrow(/Your own filter lists.*not saved/);
  });

  it("can be at most so many", () => {
    expect(addProblem(Array.from({ length: MAX_CUSTOM_LISTS - 1 }, () => list()))).toBeNull();
    expect(addProblem(Array.from({ length: MAX_CUSTOM_LISTS }, () => list()))).toMatch(/up to 20/);
  });

  it("an import of more lists than the engine holds, or of an id twice, is refused: the engine would refuse every later policy", () => {
    const lists = (n: number) => Array.from({ length: n }, (_, i) => list({ id: `custom-${i}`, url: null }));
    expect(isValidValue("filters.custom", lists(MAX_CUSTOM_LISTS))).toBe(true);
    expect(isValidValue("filters.custom", lists(MAX_CUSTOM_LISTS + 1))).toBe(false);
    expect(isValidValue("filters.custom", [list(), list({ url: null })])).toBe(false);
    const plan = planImport(EMPTY_DOC, JSON.stringify({ kind: EXPORT_KIND, schema: SETTINGS_SCHEMA, values: { "filters.custom": lists(MAX_CUSTOM_LISTS + 1) } }));
    expect(plan.ok && plan.refused.map((r) => r.key)).toEqual(["filters.custom"]);
  });
});

describe("an address typed or pasted", () => {
  it.each([
    ["https://lists.example/a.txt", "https://lists.example/a.txt"],
    ["  HTTPS://lists.example/a.txt ", "https://lists.example/a.txt"],
    ["lists.example/a.txt", "https://lists.example/a.txt"],
  ])("%j reads as %j", (typed, url) => {
    expect(parseListUrl(typed)).toEqual({ ok: true, url });
  });

  it.each([
    ["", /Paste/],
    ["http://lists.example/a.txt", /https only/],
    ["ftp://lists.example/a.txt", /https only/],
    ["https://user@lists.example/a.txt", /not a web address/],
    ["localhost:8080/list.txt", /internet only.*local network/],
    ["https://192.168.1.10/list.txt", /internet only/],
    [`https://lists.example/${"a".repeat(CUSTOM_URL_MAX)}`, /longer than/],
  ])("%j is refused with a sentence", (typed, why) => {
    const r = parseListUrl(typed);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(why);
  });

  it("names the list after its file, else its site", () => {
    expect(titleFromUrl("https://lists.example/path/EasyList%20Germany.txt?x=1")).toBe("EasyList Germany");
    expect(titleFromUrl("https://lists.example/")).toBe("lists.example");
    expect([...titleFromUrl(`https://lists.example/${"n".repeat(100)}.txt`)].length).toBe(CUSTOM_TITLE_MAX);
  });

  it("strips every control character from the name, so the name is one the engine takes", () => {
    const title = titleFromUrl("https://lists.example/a%0Ab%09c%07.txt");
    expect(title).toBe("abc");
    expect(customListProblem(list({ title }))).toBeNull();
  });
});

describe("ids", () => {
  it("are fresh, the engine's shape, and never a taken one", () => {
    let n = 0;
    const random = (len: number) => new Uint8Array(len).fill(n++ === 0 ? 0 : 1);
    const id = newCustomId([list({ id: "custom-00000000" })], random);
    expect(id).toBe("custom-11111111");
    expect(customListProblem(list({ id }))).toBeNull();
  });
});

describe("what the engine said, in words", () => {
  it("explains each refusal the engine gives, the raw words kept beside", () => {
    expect(fetchWords("an HTML page, not a filter list")).toMatch(/web page/);
    expect(fetchWords("no rule in the response")).toMatch(/no rule/);
    expect(fetchWords("40000000 bytes is over the 33554432 byte limit")).toMatch(/32 MB.*512 KB/);
    expect(fetchWords("not UTF-8: invalid utf-8 sequence")).toMatch(/plain text/);
    expect(fetchWords("HTTP 404")).toMatch(/Nothing was found/);
    expect(fetchWords("HTTP 503")).toMatch(/tries again/);
    expect(fetchWords("no answer in 120 s")).toMatch(/in time/);
    expect(fetchWords("tls: something new")).toMatch(/keeps the last good copy/);
  });

  it("says when a list was updated, and never claims a time it was not told", () => {
    const now = Date.UTC(2026, 10, 8, 12);
    expect(updatedText(null, now)).toBe("Not checked yet");
    expect(updatedText({ fetchedAtMs: null, lastError: null, enabled: true }, now)).toBe("Waiting for the first download");
    expect(updatedText({ fetchedAtMs: null, lastError: "HTTP 404", enabled: true }, now)).toBe("Not downloaded");
    expect(updatedText({ fetchedAtMs: now - 30_000, lastError: null, enabled: true }, now)).toBe("Updated just now");
    expect(updatedText({ fetchedAtMs: now - 5 * 60_000, lastError: null, enabled: true }, now)).toBe("Updated 5 min ago");
    expect(updatedText({ fetchedAtMs: now - 3 * 3_600_000, lastError: null, enabled: true }, now)).toBe("Updated 3 h ago");
    expect(updatedText({ fetchedAtMs: now - 2 * 86_400_000, lastError: null, enabled: true }, now)).toBe("Updated 2 days ago");
  });

  it("lays the engine's rows over the person's lists; a list it did not report says nothing", () => {
    const rows = { compile_ms: 1, lists: [{ id: "custom-a1", enabled: true, fetched_at_ms: 5, refresh_s: 1, last_error: null, network: 9, cosmetic: 0, skipped: 1, skip_reasons: {}, skipped_exceptions: [], skipped_exceptions_total: 0 }] };
    const [a, b] = customListViews([list(), list({ id: "custom-b2" })], rows);
    expect(a.report).toEqual({ applied: 9, skipped: 1, reasons: {} });
    expect(a.fetch).toEqual({ fetchedAtMs: 5, lastError: null, enabled: true });
    expect([b.report, b.fetch]).toEqual([null, null]);
    expect(customListViews([list()], null)[0].report).toBeNull();
  });
});
