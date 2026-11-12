import { describe, expect, it } from "vitest";
import ipc from "@/data/fixtures/engine-ipc-v3.json";
import logFixture from "@/data/fixtures/engine-log-v1.json";
import { LOG_OUTCOMES, ProtocolError, parseLogTail, type LogEntry, type LogOutcome } from "@/data/protocol";
import { LOG_RING, LOG_SHOWN, appendRows, changeWords, exeName, listName, matchesFilter, matchesSearch, outcomeWords, reasonWords, rowOwner, rowPath, rowUrl, rowWords, urlFormHost, visibleRows } from "./log";

const rows = parseLogTail(logFixture).rows;
const NO_TITLES = new Map<string, string>();
const TITLES = new Map([["adguard-base", "AdGuard Base filter"]]);
const entry = (seq: number, host = "a.example"): LogEntry => ({ seq, row: { ...rows[0].row, host } });

describe("the ring", () => {
  it("keeps the newest LOG_RING, oldest first", () => {
    const many = Array.from({ length: LOG_RING + 5 }, (_, i) => entry(i + 1));
    const ring = appendRows([], many);
    expect(ring).toHaveLength(LOG_RING);
    expect(ring[0].seq).toBe(6);
    expect(appendRows(ring, [entry(9999)]).at(-1)?.seq).toBe(9999);
    expect(appendRows(ring, [entry(9999)])).toHaveLength(LOG_RING);
  });
});

describe("the outcome in words", () => {
  const cases: [LogOutcome, string][] = [
    [{ kind: "blocked" }, "Blocked"],
    [{ kind: "redirected" }, "Redirected"],
    [{ kind: "params_removed" }, "Parameters removed"],
    [{ kind: "hidden", elements: 3 }, "Hidden 3 elements"],
    [{ kind: "hidden", elements: 1 }, "Hidden 1 element"],
    [{ kind: "scriptlets", count: 2 }, "Scriptlets"],
    [{ kind: "passed", reason: "no_rule" }, "Passed through (no rule matched)"],
    [{ kind: "passed", reason: "exception" }, "Passed through (exception rule)"],
    [{ kind: "passed", reason: "app_off" }, "Passed through (app is off)"],
    [{ kind: "not_decrypted", reason: "no_rule" }, "Not decrypted (no rule matched)"],
  ];
  it.each(cases)("%j says %s", (o, words) => expect(outcomeWords(o)).toBe(words));

  it("every kind has words", () => {
    for (const kind of LOG_OUTCOMES) expect(outcomeWords({ kind, elements: 1, count: 1, reason: "x" } as LogOutcome), kind).not.toBe("Unknown");
  });

  it("an unknown reason shows with its underscores as spaces; a missing outcome degrades", () => {
    expect(reasonWords("pinned_host")).toBe("pinned host");
    expect(rowOwner({ exe: "C:\\x\\Tool.exe" })).toBe("Tool.exe");
    expect(rowOwner({ exe: null })).toBe("Unknown app");
    expect(rowOwner({ exe: null, forwarded: { vm: "DevBox" } })).toBe("DevBox");
    expect(rowOwner({ exe: null, forwarded: { vm: null } })).toBe("Unnamed virtual machine");
    expect(outcomeWords({ kind: "passed", reason: "pinned_host" })).toBe("Passed through (pinned host)");
    expect(outcomeWords(undefined)).toBe("Unknown");
    expect(outcomeWords(null)).toBe("Unknown");
  });
});

describe("filters and search", () => {
  const kinds = (filter: Parameters<typeof matchesFilter>[1]) => rows.filter((e) => matchesFilter(e.row, filter)).map((e) => e.row.outcome.kind);

  it("All, Blocked, Modified, Not decrypted", () => {
    expect(kinds("all")).toHaveLength(rows.length);
    expect(new Set(kinds("blocked"))).toEqual(new Set(["blocked"]));
    expect(new Set(kinds("modified"))).toEqual(new Set(["params_removed", "hidden", "scriptlets", "redirected"]));
    expect(new Set(kinds("not_decrypted"))).toEqual(new Set(["not_decrypted"]));
  });

  it("searches host, exe, rule and list, every word, including the list's name", () => {
    const r = rows[0].row;
    expect(matchesSearch(r, "ADS.example", NO_TITLES)).toBe(true);
    expect(matchesSearch(r, "firefox", NO_TITLES)).toBe(true);
    expect(matchesSearch(r, "||ads", NO_TITLES)).toBe(true);
    expect(matchesSearch(r, "adguard-base", NO_TITLES)).toBe(true);
    expect(matchesSearch(r, "base filter", TITLES)).toBe(true);
    expect(matchesSearch(r, "firefox nope", NO_TITLES)).toBe(false);
    expect(matchesSearch(r, "   ", NO_TITLES)).toBe(true);
    expect(matchesSearch({ host: "a" }, "b", NO_TITLES)).toBe(false);
  });

  it("shows the newest matches first, at most LOG_SHOWN, and counts them all", () => {
    const many = Array.from({ length: LOG_SHOWN + 7 }, (_, i) => entry(i + 1));
    const { shown, matched } = visibleRows(many, "all", "", NO_TITLES);
    expect(matched).toBe(LOG_SHOWN + 7);
    expect(shown).toHaveLength(LOG_SHOWN);
    expect(shown[0].seq).toBe(LOG_SHOWN + 7);
    expect(visibleRows([null as never, { seq: 1 } as never, entry(2)], "all", "", NO_TITLES).matched).toBe(1);
  });
});

describe("what a row stands for", () => {
  it("its URL, else the host's root by protocol, else none", () => {
    const remote = "";
    expect(rowUrl({ url: "https://a.example/x", kind: "tls", host: "a.example", remote })).toBe("https://a.example/x");
    expect(rowUrl({ url: null, kind: "tls", host: "a.example", remote })).toBe("https://a.example/");
    expect(rowUrl({ url: null, kind: "quic", host: "a.example", remote })).toBe("https://a.example/");
    expect(rowUrl({ url: null, kind: "http", host: "a.example", remote })).toBe("http://a.example/");
    expect(rowUrl({ url: null, kind: "dns", host: "a.example", remote })).toBeNull();
    expect(rowUrl({ url: null, kind: "other", host: "198.51.100.25", remote })).toBeNull();
  });

  it("keeps the connection's port unless it is the scheme's own", () => {
    expect(rowUrl({ url: null, kind: "tls", host: "a.example", remote: "192.0.2.1:8443" })).toBe("https://a.example:8443/");
    expect(rowUrl({ url: null, kind: "quic", host: "a.example", remote: "[2001:db8::1]:8443" })).toBe("https://a.example:8443/");
    expect(rowUrl({ url: null, kind: "http", host: "a.example", remote: "192.0.2.1:8080" })).toBe("http://a.example:8080/");
    expect(rowUrl({ url: null, kind: "tls", host: "2001:db8::1", remote: "[2001:db8::1]:8443" })).toBe("https://[2001:db8::1]:8443/");
    expect(rowUrl({ url: null, kind: "tls", host: "a.example", remote: "192.0.2.1:443" })).toBe("https://a.example/");
    expect(rowUrl({ url: null, kind: "http", host: "a.example", remote: "192.0.2.1:80" })).toBe("http://a.example/");
    // Port 443 is not http's default, and port 80 is not https's.
    expect(rowUrl({ url: null, kind: "http", host: "a.example", remote: "192.0.2.1:443" })).toBe("http://a.example:443/");
    expect(rowUrl({ url: null, kind: "tls", host: "a.example", remote: "192.0.2.1:80" })).toBe("https://a.example:80/");
    // An address with no port, its last group not mistaken for one.
    expect(rowUrl({ url: null, kind: "tls", host: "a.example", remote: "2001:db8::1" })).toBe("https://a.example/");
    expect(rowUrl({ url: "https://a.example:9/x", kind: "tls", host: "a.example", remote: "192.0.2.1:8443" }), "a row's own URL stands").toBe("https://a.example:9/x");
  });

  it("an IPv6 host takes brackets in its URL; a name and an IPv4 address do not", () => {
    const remote = "";
    expect(rowUrl({ url: null, kind: "tls", host: "2001:db8::1", remote })).toBe("https://[2001:db8::1]/");
    expect(rowUrl({ url: null, kind: "http", host: "2001:db8::1", remote })).toBe("http://[2001:db8::1]/");
    expect(rowUrl({ url: null, kind: "quic", host: "198.51.100.25", remote })).toBe("https://198.51.100.25/");
    expect(urlFormHost("2001:db8::1")).toBe("[2001:db8::1]");
    expect(urlFormHost("a.example")).toBe("a.example");
  });

  it("the path column, the exe's name, the list's name", () => {
    expect(rowPath({ url: "https://a.example/x/y?z=1" })).toBe("/x/y?z=1");
    expect(rowPath({ url: "https://a.example" })).toBeNull();
    expect(rowPath({ url: null })).toBeNull();
    expect(exeName("C:\\Program Files\\A\\a.exe")).toBe("a.exe");
    expect(exeName(null)).toBeNull();
    expect(listName("user", NO_TITLES)).toBe("Your rules");
    expect(listName("adguard-base", TITLES)).toBe("AdGuard Base filter");
    expect(listName("gone", TITLES)).toBe("gone");
    expect(listName(null, TITLES)).toBeNull();
  });
});

describe("parseLogTail", () => {
  it("reads the fixture with nothing skipped", () => {
    const tail = parseLogTail(logFixture);
    expect(tail.skipped).toBe(0);
    expect(tail.next).toBe(10);
    expect(tail.rows.map((e) => ({ seq: e.seq, row: e.row }))).toEqual(logFixture.rows);
  });

  it("a wrong version or a non-array throws", () => {
    expect(() => parseLogTail({ ...logFixture, v: 2 })).toThrow(ProtocolError);
    expect(() => parseLogTail({ ...logFixture, v: 2 })).toThrow(/version 2/);
    expect(() => parseLogTail({ ...logFixture, rows: "x" })).toThrow(ProtocolError);
    expect(() => parseLogTail(null)).toThrow(ProtocolError);
  });

  it("missing, partial and old-schema rows are skipped and counted; a good one in the batch stays", () => {
    const good = logFixture.rows[0];
    const bad = [
      null,
      7,
      { seq: 2 },
      { row: good.row },
      { seq: -1, row: good.row },
      { seq: 3, row: { ...good.row, t: "soon" } },
      { seq: 4, row: { ...good.row, host: undefined } },
      { seq: 5, row: { ...good.row, host: "" } },
      { seq: 6, row: { ...good.row, outcome: { kind: "sign" } } },
      { seq: 7, row: { ...good.row, outcome: { kind: "hidden" } } },
      { seq: 8, row: { ...good.row, outcome: { kind: "scriptlets", count: -1 } } },
      { seq: 9, row: { ...good.row, outcome: { kind: "passed" } } },
      { seq: 10, row: { ...good.row, outcome: undefined } },
    ];
    const tail = parseLogTail({ v: 1, next: 99, dropped: 2, rows: [good, ...bad] });
    expect(tail.rows.map((e) => e.seq)).toEqual([1]);
    expect(tail.skipped).toBe(bad.length);
    expect(tail.next).toBe(99);
    expect(tail.dropped).toBe(2);
  });

  it("optional fields default to null, so an old row still reads", () => {
    const tail = parseLogTail({ v: 1, next: 1, dropped: 0, rows: [{ seq: 1, row: { t: 5, host: "a.example", outcome: { kind: "blocked" } } }] });
    expect(tail.skipped).toBe(0);
    expect(tail.rows[0].row).toMatchObject({ id: 1, flow_id: 1, pid: null, exe: null, session: null, kind: "other", remote: "", url: null, request_type: null, rule: null, list: null });
  });

  it("a missing next falls back to the newest row, a missing dropped to none", () => {
    const tail = parseLogTail({ v: 1, rows: [logFixture.rows[3]] });
    expect(tail.next).toBe(4);
    expect(tail.dropped).toBe(0);
  });
});

describe("tracking protection's changes (plan 2026-11-09)", () => {
  const changed = (changes: unknown) => parseLogTail({ ...logFixture, rows: [{ seq: 1, row: { ...logFixture.rows[1].row, url: "https://shop.example.net/a", changes } }] }).rows[0].row;

  it("a row carries its changes; a change that does not read is left out, never the row", () => {
    expect(changed([{ what: "queryParams", count: 3 }]).changes).toEqual([{ what: "queryParams", count: 3 }]);
    const odd = parseLogTail({ ...logFixture, rows: [{ seq: 1, row: { ...logFixture.rows[1].row, changes: [{ what: "gpc", count: 2 }, { what: "", count: 1 }, { what: "referrer", count: -1 }, "junk", null] } }] });
    expect(odd.skipped).toBe(0);
    expect(odd.rows[0].row.changes).toEqual([{ what: "gpc", count: 2 }]);
    expect(changed("nope").changes).toBeUndefined();
    expect(changed([]).changes).toBeUndefined();
    expect(rows.every((e) => e.row.changes === undefined), "an older engine's rows have none").toBe(true);
  });

  it.each([
    [{ what: "queryParams", count: 3 }, "Removed 3 tracking parameters"],
    [{ what: "queryParams", count: 1 }, "Removed 1 tracking parameter"],
    [{ what: "gpc", count: 2 }, "Sent Global Privacy Control"], // an older engine's row, which also counted DNT
    [{ what: "gpc", count: 1 }, "Sent Global Privacy Control"],
    [{ what: "clientData", count: 1 }, "Removed the X-Client-Data header"],
    [{ what: "searchQueries", count: 1 }, "Told the site only where you came from, not the page"],
    [{ what: "referrer", count: 1 }, "Removed the page you came from"],
    [{ what: "thirdPartyCookies", count: 2 }, "Limited 2 cookies from another site to an hour"],
    [{ what: "firstPartyCookies", count: 1 }, "Limited a cookie of the site's own to an hour"],
    [{ what: "webRtc", count: 1 }, "Blocked WebRTC in the page"],
    [{ what: "push", count: 1 }, "Blocked push notifications in the page"],
    [{ what: "location", count: 1 }, "Blocked location requests in the page"],
    [{ what: "newThing", count: 4 }, "new thing (4)"],
  ])("%j says %s", (change, words) => expect(changeWords(change)).toBe(words));

  it("every protection the engine names has words of its own", () => {
    for (const what of ipc.trackingNames) expect(changeWords({ what, count: 1 }), what).not.toMatch(/\(1\)$/);
  });

  it("a passed row a protection changed reads Modified and says the change in its column", () => {
    const one = changed([{ what: "queryParams", count: 3 }]);
    expect(matchesFilter(one, "modified")).toBe(true);
    expect(matchesFilter(changed(undefined), "modified")).toBe(false);
    expect(rowWords(one)).toBe("Removed 3 tracking parameters");
    expect(rowWords(changed([{ what: "searchQueries", count: 1 }, { what: "referrer", count: 1 }]))).toBe("Tracking protection made 2 changes");
    expect(rowWords(changed(undefined))).toBe("Passed through (no rule matched)");
    const removed = { ...one, outcome: { kind: "params_removed" } as LogOutcome };
    expect(rowWords(removed), "the rules' own outcome stays first").toBe("Parameters removed");
  });

  // Second review P2-2: gpc and clientData are on at every level, so every
  // decrypted row read Modified and said them instead of its outcome.
  it("the header signals stay in the details: not Modified, not the row's words", () => {
    const signals = changed([{ what: "gpc", count: 2 }, { what: "clientData", count: 1 }]);
    expect(signals.changes).toHaveLength(2);
    expect(matchesFilter(signals, "modified")).toBe(false);
    expect(rowWords(signals)).toBe("Passed through (no rule matched)");
    const withReferrer = changed([{ what: "gpc", count: 2 }, { what: "referrer", count: 1 }]);
    expect(matchesFilter(withReferrer, "modified")).toBe(true);
    expect(rowWords(withReferrer)).toBe("Removed the page you came from");
  });

  it("a page the site sent back to its parameters says so", () => {
    expect(outcomeWords({ kind: "passed", reason: "params_kept" })).toBe("Passed through (the site sends this page back to its tracking parameters, so they were kept)");
  });
});