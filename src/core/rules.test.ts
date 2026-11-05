import { describe, expect, it } from "vitest";
import cases from "@/data/fixtures/user-rules-v1.json";
import {
  MAX_RULE_CHARS,
  MAX_RULE_LINES,
  allowRule,
  blockRule,
  checkRuleLine,
  checkRuleText,
  friendlyRuleReason,
  normalizeDomain,
} from "./rules";

describe("user rule lines", () => {
  it.each(cases.rules)("$line reads as $ts (the fixture Rust reads too)", ({ line, ts }) => {
    expect(checkRuleLine(line).kind).toBe(ts);
  });

  it("the words help: a bare host gets its rule, a trusted scriptlet its reason", () => {
    expect(checkRuleLine("example.com")).toEqual({ kind: "hint", message: "Did you mean ||example.com^?" });
    expect(checkRuleLine("##+js(trusted-x)")).toMatchObject({ kind: "error", message: expect.stringContaining("trusted") });
    expect(checkRuleLine("example.com##+js(trusted-x)")).toMatchObject({ kind: "error" });
    expect(checkRuleLine("||exa mple.com^")).toMatchObject({ kind: "error", message: expect.stringContaining("space") });
    expect(checkRuleLine("||")).toMatchObject({ kind: "error", message: expect.stringContaining("names no site") });
    expect(checkRuleLine("##+js(")).toMatchObject({ kind: "error", message: expect.stringContaining("not closed") });
  });

  it("a cosmetic rule may hold a space, a network rule may not", () => {
    expect(checkRuleLine("example.com##div > .ad")).toEqual({ kind: "ok" });
    expect(checkRuleLine("example.com##+js(set-constant, a, true)")).toEqual({ kind: "ok" });
    expect(checkRuleLine("0.0.0.0 example.com").kind).toBe("error");
  });

  it("over-long input is an error", () => {
    expect(checkRuleLine(`||${"a".repeat(MAX_RULE_CHARS)}^`).kind).toBe("error");
    const many = checkRuleText(Array.from({ length: MAX_RULE_LINES + 1 }, (_, i) => `||a${i}.example^`).join("\n"));
    expect(many.tooLong).toContain("more than");
    expect(many.canSave).toBe(false);
  });
});

describe("a rule text", () => {
  it("names each error's line and refuses the save", () => {
    const t = checkRuleText("! note\n\n||a.example^\n||b c^\nexample.com");
    expect(t.notes.map((l) => [l.n, l.check.kind])).toEqual([
      [4, "error"],
      [5, "hint"],
    ]);
    expect(t.canSave).toBe(false);
    expect(checkRuleText("! note\n\n||a.example^\nexample.com").canSave).toBe(true);
  });

  it("stores comments and rules, not blank lines, trimmed", () => {
    expect(checkRuleText("  ||a.example^  \n\r\n! note\n").stored).toEqual(["||a.example^", "! note"]);
    expect(checkRuleText("").stored).toEqual([]);
  });
});

describe("the parser's words", () => {
  it("become a sentence, and an unknown reason still says something true", () => {
    expect(friendlyRuleReason("network filter error: unrecognised option")).toContain("option");
    expect(friendlyRuleReason("cosmetic filter error: generic script inject")).toContain("name the site");
    expect(friendlyRuleReason("something new")).toBe("This line could not be read as a rule.");
  });
});

describe("normalizeDomain", () => {
  it("the fixture table (Rust checks it against dns::rules::host_name)", () => {
    for (const c of cases.domains) {
      const got = normalizeDomain(c.raw);
      if (c.host === null) expect(got.ok, c.raw).toBe(false);
      else expect(got, c.raw).toEqual({ ok: true, host: c.host });
    }
  });

  it("each failure has its own sentence", () => {
    const words = (raw: string) => {
      const r = normalizeDomain(raw);
      return r.ok ? "" : r.error;
    };
    expect(words("localhost")).toContain("needs a dot");
    expect(words("1.2.3.4")).toContain("IP address");
    expect(words("a b.com")).toContain("space");
    expect(words(`${"a".repeat(250)}.com`)).toContain("at most 253");
    expect(words("bad_char.com")).toContain("letters, digits");
    expect(words("")).toContain("Type a site name");
  });

  it("takes the host out of what people paste", () => {
    for (const raw of ["https://WWW.Example.com/a?b", "www.example.com.", "http://user@www.example.com:8080/x", "WWW.EXAMPLE.COM#top"]) {
      expect(normalizeDomain(raw), raw).toEqual({ ok: true, host: "www.example.com" });
    }
  });
});

describe("derived rules", () => {
  it("an allowlist entry is the fixture's rule (Rust holds what it means against the real engine); a block is the plain host rule", () => {
    expect(allowRule(cases.allowlist.host)).toBe(cases.allowlist.rule);
    expect(blockRule("a.example")).toBe("||a.example^");
    for (const rule of [allowRule("a.example"), blockRule("a.example")]) expect(checkRuleLine(rule).kind).toBe("ok");
  });
});
