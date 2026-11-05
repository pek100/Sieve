import { describe, expect, it } from "vitest";
import logFixture from "@/data/fixtures/engine-log-v1.json";
import { parseLogTail, type ListFact } from "@/data/protocol";
import { buildReport, hasQuery, issuePage, reportList, rulesForPage, stripQuery, urlHost } from "./report";

const ADGUARD: ListFact = { id: "adguard-base", title: "AdGuard Base filter", homepage: "https://github.com/AdguardTeam/AdguardFilters", version: "2.3.72", applied: 9, skipped: 1 };
const UBO: ListFact = { id: "ubo-filters", title: "uBlock filters", homepage: "https://github.com/uBlockOrigin/uAssets", version: null, applied: 5, skipped: 0 };
const FIREFOX = "C:\\Users\\Someone\\AppData\\Local\\Mozilla Firefox\\firefox.exe";
const rows = parseLogTail(logFixture).rows;

describe("query strings", () => {
  it("are stripped with the fragment, and only then", () => {
    expect(stripQuery("https://a.example/p?token=x#top")).toBe("https://a.example/p");
    expect(stripQuery("https://a.example/p#top")).toBe("https://a.example/p");
    expect(stripQuery("https://a.example/p")).toBe("https://a.example/p");
    expect(hasQuery("https://a.example/p?x")).toBe(true);
    expect(hasQuery("https://a.example/p#x")).toBe(true);
    expect(hasQuery("https://a.example/p")).toBe(false);
  });
});

describe("urlHost", () => {
  it("reads the host; anything else is none", () => {
    expect(urlHost("https://News.Example.com:8443/a?b")).toBe("news.example.com");
    expect(urlHost("https://u:p@a.example/")).toBe("a.example");
    expect(urlHost("https://[2001:db8::1]/a")).toBe("[2001:db8::1]");
    expect(urlHost("a.example")).toBeNull();
    expect(urlHost("")).toBeNull();
  });
});

describe("rulesForPage", () => {
  it("takes rows of the page's host that carry a rule, each rule once", () => {
    expect(rulesForPage(rows, "https://ads.example.com/", null)).toEqual([
      { rule: "||ads.example.com^", list: "adguard-base" },
    ]);
    expect(rulesForPage(rows, "https://news.example.com/article/42", null).map((r) => r.rule)).toEqual(["$removeparam=utm_source", "news.example.com##.banner"]);
  });

  it("holds to the browser when it is known, and is empty for no URL", () => {
    const firefox = rows[0].row.exe;
    expect(rulesForPage(rows, "https://ads.example.com/", firefox)).toHaveLength(1);
    expect(rulesForPage(rows, "https://ads.example.com/", "C:\\other.exe")).toEqual([]);
    expect(rulesForPage(rows, "", null)).toEqual([]);
    expect(rulesForPage([{ seq: 1 } as never, null as never], "https://a.example/", null)).toEqual([]);
  });
});

describe("the report", () => {
  const facts = {
    url: "https://news.example.com/article/42",
    browser: FIREFOX,
    lists: [ADGUARD, UBO],
    rules: [
      { rule: "news.example.com##.banner", list: "ubo-filters" },
      { rule: "||x.example^", list: "user" },
      { rule: "||y.example^", list: null },
    ],
    resourcePin: "sha256:0f4e2c7a",
    sieveVersion: "0.1.0",
  };

  it("has each listed field", () => {
    const text = buildReport(facts);
    expect(text).toContain("Page URL: https://news.example.com/article/42");
    expect(text).toContain("Browser: firefox.exe");
    expect(text).toContain("AdGuard Base filter: 2.3.72");
    expect(text).toContain("uBlock filters: version not known");
    expect(text).toContain("news.example.com##.banner (uBlock filters)");
    expect(text).toContain("||x.example^ (Your rules)");
    expect(text).toContain("||y.example^ (list not known)");
    expect(text).toContain("Resource library pin: sha256:0f4e2c7a");
    expect(text).toContain("Sieve version: 0.1.0");
  });

  it("holds no account name, pid, session, address or flow id", () => {
    const text = buildReport(facts);
    expect(text).not.toContain("Someone");
    expect(text).not.toMatch(/pid|session|flow|192\.0\.2|4242/i);
  });

  it("uses an edited URL verbatim, a query the user left included", () => {
    expect(buildReport({ ...facts, url: "https://a.example/?kept=1" })).toContain("Page URL: https://a.example/?kept=1");
  });

  it("says what it does not know rather than leaving it out", () => {
    const text = buildReport({ url: " ", browser: null, lists: [], rules: [], resourcePin: null, sieveVersion: "browser preview" });
    expect(text).toContain("Page URL: not known");
    expect(text).toContain("Browser: not known");
    expect(text).toContain("Lists:\n- none reported");
    expect(text).toContain("Rules applied:\n- none");
    expect(text).toContain("Resource library pin: not known");
  });
});

describe("the issue page", () => {
  it("derives from the homepage, and only an https one", () => {
    expect(issuePage(ADGUARD.homepage)).toBe("https://github.com/AdguardTeam/AdguardFilters/issues");
    expect(issuePage(UBO.homepage)).toBe("https://github.com/uBlockOrigin/uAssets/issues");
    expect(issuePage("https://a.example/x/")).toBe("https://a.example/x/issues");
    expect(issuePage("http://a.example/x")).toBeNull();
    expect(issuePage("javascript:alert(1)")).toBeNull();
    expect(issuePage("")).toBeNull();
  });

  it("the list: the first among the rules applied, else the first list, else none", () => {
    expect(reportList([{ rule: "a", list: "ubo-filters" }, { rule: "b", list: "adguard-base" }], [ADGUARD, UBO])).toBe(UBO);
    expect(reportList([{ rule: "a", list: "user" }, { rule: "b", list: "adguard-base" }], [UBO, ADGUARD])).toBe(ADGUARD);
    expect(reportList([], [ADGUARD, UBO])).toBe(ADGUARD);
    expect(reportList([{ rule: "a", list: "user" }], [UBO])).toBe(UBO);
    expect(reportList([], [])).toBeNull();
  });
});
