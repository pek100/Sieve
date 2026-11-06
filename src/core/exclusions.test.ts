import { describe, expect, it } from "vitest";
import type { EngineSlice } from "@/core/engine";
import { EMPTY_ENGINE } from "@/core/engine";
import { reasonWords } from "@/core/log";
import ipc from "@/data/fixtures/engine-ipc-v3.json";
import lines from "@/data/fixtures/exclusion-lines.json";
import probe from "@/data/fixtures/engine-probe-v3.json";
import { parseEngineProbe, parseExclusionsPage, parseHealNotices, type EngineProbe, type ExclusionRow } from "@/data/protocol";
import {
  DECRYPTS_TEXT,
  DOES_NOT_DECRYPT_TEXT,
  FLOOR_LINE,
  FLOOR_WORDS,
  REFUSED_LINE_WORDS,
  appDecryption,
  canTryAgain,
  exclusionLine,
  exclusionReasonWords,
  exclusionsHref,
  exclusionsLink,
  filterRows,
  groupsOf,
  mergeRows,
  noticeText,
  reasonGroup,
  refusedLineWords,
  firstDateWords,
  rejectedFiles,
  retryWords,
  rowReasonWords,
} from "./exclusions";

const rows = parseExclusionsPage(ipc.engine.find((m) => m.type === "exclusions")).rows;
const CHROME = String.raw`C:\Program Files\Google\Chrome\Application\chrome.exe`;

function welcome(https: boolean): EngineProbe {
  const p = parseEngineProbe(probe.examples.idle);
  if (p.pipe?.kind !== "welcome") throw new Error("the example answers");
  return { ...p, pipe: { ...p.pipe, status: { ...p.pipe.status, policy: { ...p.pipe.status.policy, https } } } };
}

const slice = (https: boolean, scope: "browsers" | "all" = "browsers", browsers = [CHROME.toLowerCase()]): EngineSlice => ({
  ...EMPTY_ENGINE,
  probe: welcome(https),
  exclusions: { revision: 1, rows: [], scope, browsers, skipped: 0 },
});

describe("a browser path as the engine folds it", () => {
  it.each(lines.exes)("$exe reads as in scope", ({ exe, folded }) => {
    expect(appDecryption(slice(true, "browsers", [folded]), { on: true, exes: [exe] }, []).line).toBe(DECRYPTS_TEXT);
  });
});

describe("reason words", () => {
  it.each([
    ["user", "You added this"],
    ["list:banks", "Sensitive site (banks list)"],
    ["list:sensitive", "Sensitive site (Sieve's list)"],
    ["auto:pinning", "Rejected Sieve's certificate (auto)"],
    ["auto:client-cert", "Asks for a client certificate (auto)"],
    ["auto:ev", "EV certificate (auto)"],
  ])("%s", (slug, words) => expect(exclusionReasonWords(slug)).toBe(words));

  it("an unknown slug shows as it came, and groups as other", () => {
    expect(exclusionReasonWords("auto:someday")).toBe("auto:someday");
    expect(reasonGroup("auto:someday")).toBe("other");
    expect(reasonGroup("nonsense")).toBe("other");
  });

  it("the log hands these slugs here (task F13) and keeps its own", () => {
    expect(reasonWords("auto:pinning")).toBe("Rejected Sieve's certificate (auto)");
    expect(reasonWords("list:banks")).toBe("Sensitive site (banks list)");
    expect(reasonWords("user")).toBe("You added this");
    expect(reasonWords("floor:service")).toBe("Windows services");
    expect(reasonWords("no_rule")).toBe("no rule matched");
    expect(reasonWords("a_new_one")).toBe("a new one");
  });

  it("the floor is named once, by every fact's words", () => {
    for (const words of Object.values(FLOOR_WORDS)) expect(FLOOR_LINE.split(words)).toHaveLength(2);
  });

  it("how often it was tried, in words", () => {
    expect([0, 1, 2].map(retryWords)).toEqual([null, "tried again 1 time", "tried again 2 times"]);
    expect(retryWords(undefined as unknown as number)).toBeNull();
  });

  it("the first date, in words; no date says nothing", () => {
    expect(firstDateWords(rows.find((r) => r.reason === "auto:pinning")?.created_ms)).toMatch(/^first on .*2026$/);
    for (const none of [null, undefined, 0, -1, Number.NaN, Number.MAX_SAFE_INTEGER]) expect(firstDateWords(none), String(none)).toBeNull();
  });
});

describe("rows", () => {
  const merged = mergeRows(["mine.example", "shop.example$app=Client.EXE", "not a line"], rows);

  it("the user's lines first, then the engine's, each with what it needs", () => {
    expect(merged.map((r) => [r.line, r.reason])).toEqual([
      ["mine.example", "user"],
      ["shop.example", "user"],
      ["not a line", "user"],
      ["bank.example", "list:sensitive"],
      ['"pin.example"', "auto:pinning"],
      ['"cert.example"', "auto:client-cert"],
      ['"ev.example"', "auto:ev"],
    ]);
    expect(merged[1].apps).toEqual(["client.exe"]);
    expect(merged[1].userLine, "removing it means the whole line").toBe("shop.example$app=Client.EXE");
    expect(merged[4].userLine).toBeNull();
    expect(new Set(merged.map((r) => r.key)).size).toBe(merged.length);
  });

  it("only what the engine wrote can be tried again", () => {
    expect(merged.filter(canTryAgain).map((r) => r.reason)).toEqual(["auto:pinning", "auto:client-cert", "auto:ev"]);
  });

  it("a malformed row from a path no normalizer ran on still merges", () => {
    const bad = mergeRows([], [{ line: "x.example" } as ExclusionRow, null as unknown as ExclusionRow]);
    expect(bad[0].apps).toEqual([]);
    expect(bad[1].line).toBe("");
  });

  it("the filter's groups come from the rows", () => {
    expect(groupsOf(merged)).toEqual(["all", "user", "list", "pinning", "client-cert", "ev"]);
    expect(groupsOf(mergeRows(["a.example"], []))).toEqual(["all", "user"]);
    expect(groupsOf([])).toEqual(["all"]);
  });

  it("filters by reason, by app and by words in the pattern, the app and the reason", () => {
    const by = (group: Parameters<typeof filterRows>[1]["group"], query = "", ...apps: string[]) => filterRows(merged, { group, query, apps }, (e) => (e === "client.exe" ? "The Client" : null)).map((r) => r.line);
    expect(by("pinning")).toEqual(['"pin.example"']);
    expect(by("all", "PIN")).toEqual(['"pin.example"']);
    expect(by("all", "the client")).toEqual(["shop.example", '"pin.example"']);
    expect(by("all", "rejected certificate")).toEqual(['"pin.example"']);
    expect(by("all", "nothing-like-this")).toEqual([]);
    expect(by("all", "", "client.exe"), "what applies to it: its own and every app's").toEqual(["mine.example", "shop.example", "bank.example", '"pin.example"', '"cert.example"', '"ev.example"']);
    expect(by("all", "", "other.exe")).not.toContain('"pin.example"');
    expect(by("pinning", "", "other.exe", "client.exe"), "any of the app's files").toEqual(['"pin.example"']);
  });

  it("a line the engine would skip is marked, shows so it can be removed, and applies to no app", () => {
    const skipped = "space.example$app=a b.exe";
    const [read, refused] = mergeRows(["mine.example", skipped], []);
    expect([read.refused, refused.refused]).toEqual([false, true]);
    expect(merged.filter((r) => r.reason !== "user").every((r) => !r.refused)).toBe(true);
    expect(refused.userLine).toBe(skipped);
    expect(refused.line, "as it was written: nothing of it was read").toBe(skipped);
    expect(rowReasonWords(read)).toBe("You added this");
    expect(rowReasonWords(refused)).toBe(REFUSED_LINE_WORDS);
    expect(filterRows([refused], { group: "all", query: "", apps: [] }, () => null), "it stays on the list").toEqual([refused]);
    expect(filterRows([refused], { group: "all", query: "does nothing", apps: [] }, () => null)).toEqual([refused]);
    expect(filterRows([refused], { group: "all", query: "", apps: ["a b.exe"] }, () => null)).toEqual([]);
  });

  it("says why a new line would do nothing, and nothing of a line the engine reads", () => {
    expect(refusedLineWords(exclusionLine("a.example", "x.exe"))).toBeNull();
    expect(refusedLineWords(exclusionLine("a.example", null))).toBeNull();
    expect(refusedLineWords(exclusionLine("a.example", "code - insiders.exe"))).toMatch(/for all apps/);
    expect(refusedLineWords("not a host")).toMatch(/not a host/);
  });

  it("knows when an app has rejected sites to try again", () => {
    expect(rejectedFiles(merged, ["client.exe"])).toEqual(["client.exe"]);
    expect(rejectedFiles(merged, ["other.exe"])).toEqual([]);
    expect(rejectedFiles(merged, ["other.exe", "client.exe"]), "only the files with something to take back").toEqual(["client.exe"]);
  });

  it("a line and an app make a line of the grammar", () => {
    expect(exclusionLine("a.example", null)).toBe("a.example");
    expect(exclusionLine("a.example", "x.exe")).toBe("a.example$app=x.exe");
  });
});

describe("the deep link", () => {
  it("round trips, and asks nothing with no filter", () => {
    expect(exclusionsHref()).toBe("/settings/#not-decrypted");
    const href = exclusionsHref(["client.exe"], "pinning");
    expect(href).toBe("/settings/?exclusionsApp=client.exe&exclusionsReason=pinning#not-decrypted");
    expect(exclusionsLink(new URL(href, "http://x").search)).toEqual({ apps: ["client.exe"], group: "pinning" });
  });

  it("carries every file of an app", () => {
    const href = exclusionsHref(["helper.exe", "client.exe"]);
    expect(href).toBe("/settings/?exclusionsApp=helper.exe&exclusionsApp=client.exe#not-decrypted");
    expect(exclusionsLink(new URL(href, "http://x").search).apps).toEqual(["helper.exe", "client.exe"]);
  });

  it("other parameters and a nonsense reason mean nothing", () => {
    expect(exclusionsLink("?source=mock&exclusionsReason=everything")).toEqual({ apps: [], group: "all" });
    expect(exclusionsLink("?exclusionsApp=CLIENT.EXE").apps).toEqual(["client.exe"]);
    expect(exclusionsLink("?exclusionsApp=&exclusionsApp=a.exe&exclusionsApp=A.EXE").apps, "none empty, none twice").toEqual(["a.exe"]);
  });
});

describe("the app sheet's line", () => {
  const chrome = { on: true, exes: [CHROME] };
  const other = { on: true, exes: [String.raw`C:\Apps\Other.exe`] };
  const merged = mergeRows(["shop.example$app=chrome.exe"], rows);

  it("none while the app is off, HTTPS is not in force or the engine has not answered", () => {
    expect(appDecryption(slice(true), { ...chrome, on: false }, merged).line).toBeNull();
    expect(appDecryption(slice(false), chrome, merged).line).toBeNull();
    expect(appDecryption({ ...EMPTY_ENGINE, probe: welcome(true) }, chrome, merged).line, "no rows yet").toBeNull();
    expect(appDecryption(EMPTY_ENGINE, chrome, merged).line).toBeNull();
  });

  it("in force and in scope, no exception", () => {
    expect(appDecryption(slice(true), chrome, []).line).toBe(DECRYPTS_TEXT);
  });

  it("in force and in scope, N exceptions, counted by file name, case folded, and linked", () => {
    const shouted = { on: true, exes: [CHROME.toUpperCase()] };
    const appliesToEveryApp = merged.filter((r) => r.apps.length === 0).length;
    const said = appDecryption(slice(true), shouted, merged);
    expect(said).toEqual({ line: `Sieve decrypts this app's HTTPS except ${appliesToEveryApp + 1} sites`, count: appliesToEveryApp + 1, apps: ["chrome.exe"] });
    expect(appDecryption(slice(true), chrome, mergeRows(["one.example"], [])).line).toBe("Sieve decrypts this app's HTTPS except 1 site");
  });

  it("an app of several files: the link opens a view holding every row it counted", () => {
    const helper = String.raw`C:\Program Files\Google\Chrome\Application\agent.exe`;
    const app = { on: true, exes: [helper, CHROME, helper] };
    const held = mergeRows([], [{ line: '"pin.example"', apps: ["chrome.exe"], reason: "auto:pinning", created_ms: 1, retries: 0 }]);
    const said = appDecryption(slice(true), app, held);
    expect(said).toEqual({ line: "Sieve decrypts this app's HTTPS except 1 site", count: 1, apps: ["agent.exe", "chrome.exe"] });
    if (said.line === null) throw new Error("the line says so");
    const { apps } = exclusionsLink(new URL(exclusionsHref(said.apps), "http://x").search);
    expect(filterRows(held, { group: "all", query: "", apps }, () => null)).toHaveLength(said.count);
    expect(rejectedFiles(held, apps), "and it can be tried again from there").toEqual(["chrome.exe"]);
  });

  it("another app's row does not count", () => {
    const only = mergeRows(["shop.example$app=client.exe"], []);
    expect(appDecryption(slice(true), chrome, only).line).toBe(DECRYPTS_TEXT);
  });

  it("a line the engine discards is no exception: the site is decrypted", () => {
    const refused = mergeRows(["space.example$app=a b.exe", "not a line"], []);
    expect(appDecryption(slice(true), chrome, refused).line).toBe(DECRYPTS_TEXT);
  });

  it("in force, out of scope: the words say so, and no row counts", () => {
    expect(appDecryption(slice(true), other, merged).line).toBe(DOES_NOT_DECRYPT_TEXT);
    expect(appDecryption(slice(true), { on: true, exes: [] }, merged).line).toBe(DOES_NOT_DECRYPT_TEXT);
  });

  it("a wider scope takes every app", () => {
    expect(appDecryption(slice(true, "all", []), other, []).line).toBe(DECRYPTS_TEXT);
  });
});

describe("the notice", () => {
  const notice = parseHealNotices(ipc.engine.find((m) => m.type === "heal_notices")).notices[0];

  it("one site and many", () => {
    expect(noticeText("Client", { hosts: ["pin.example"], total: 1 })).toBe("Client rejected Sieve's certificate for pin.example. Sieve stopped decrypting it.");
    expect(noticeText("Client", notice)).toBe("Client rejected Sieve's certificate for 2 sites. Sieve stopped decrypting them.");
    expect(noticeText("Client", { hosts: ["a.example"], total: 1200 })).toContain("1,200 sites");
  });
});
