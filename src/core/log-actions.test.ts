import { describe, expect, it } from "vitest";
import type { LogOutcome, LogRow } from "@/data/protocol";
import { addLine, blockRule, previewOf, removeLine, rowActions, unblockRule } from "./log-actions";

const row = (outcome: LogOutcome, over: Partial<LogRow> = {}) => ({ url: null, kind: "tls", host: "a.example", outcome, rule: null, ...over });

describe("row actions per outcome", () => {
  it("Unblock only on Blocked with a rule", () => {
    expect(rowActions(row({ kind: "blocked" }, { rule: "||a.example^" }))).toContain("unblock");
    expect(rowActions(row({ kind: "blocked" }))).not.toContain("unblock");
    expect(rowActions(row({ kind: "passed", reason: "no_rule" }, { rule: "@@||a.example^" }))).not.toContain("unblock");
  });

  it("Block only on Passed through with no rule matched: elsewhere the rule it adds would change nothing", () => {
    expect(rowActions(row({ kind: "passed", reason: "no_rule" }))).toContain("block");
    for (const reason of ["exception", "app_off", "a_later_reason"]) {
      expect(rowActions(row({ kind: "passed", reason })), reason).not.toContain("block");
    }
    for (const o of [{ kind: "blocked" }, { kind: "redirected" }, { kind: "hidden", elements: 1 }, { kind: "not_decrypted", reason: "x" }] as LogOutcome[]) {
      expect(rowActions(row(o)), o.kind).not.toContain("block");
    }
  });

  it("Do not decrypt on everything but Not decrypted", () => {
    expect(rowActions(row({ kind: "not_decrypted", reason: "x" }))).not.toContain("do_not_decrypt");
    expect(rowActions(row({ kind: "blocked" }))).toContain("do_not_decrypt");
  });

  it("Copy URL only when the row has a URL: an IP-only row of kind other has none", () => {
    expect(rowActions(row({ kind: "blocked" }))).toContain("copy_url");
    expect(rowActions(row({ kind: "blocked" }, { kind: "other", host: "198.51.100.25" }))).not.toContain("copy_url");
    expect(rowActions(row({ kind: "blocked" }, { kind: "dns" }))).not.toContain("copy_url");
  });

  it("Report always, in menu order", () => {
    expect(rowActions(row({ kind: "not_decrypted", reason: "x" }, { kind: "other" }))).toEqual(["report"]);
    expect(rowActions(row({ kind: "blocked" }, { rule: "r" }))).toEqual(["copy_url", "unblock", "do_not_decrypt", "report"]);
  });
});

describe("the rules and the lines", () => {
  it("are adblock syntax for the host", () => {
    expect(unblockRule("a.example")).toBe("@@||a.example^");
    expect(blockRule("a.example")).toBe("||a.example^");
  });

  it("an IPv6 host goes in a rule in brackets, and bare in the exclusions: each the form its parser reads", () => {
    expect(unblockRule("2001:db8::1")).toBe("@@||[2001:db8::1]^");
    expect(blockRule("2001:db8::1")).toBe("||[2001:db8::1]^");
    expect(blockRule("198.51.100.25")).toBe("||198.51.100.25^");
    expect(previewOf("do_not_decrypt", "2001:db8::1").line).toBe("2001:db8::1");
  });

  it("addLine dedupes and keeps order; removeLine takes it out", () => {
    expect(addLine(["a"], "b")).toEqual(["a", "b"]);
    expect(addLine(["a", "b"], "a")).toEqual(["a", "b"]);
    expect(removeLine(["a", "b"], "a")).toEqual(["b"]);
  });

  it("a preview names the exact line and the setting that takes it, and never claims it is in force", () => {
    expect(previewOf("unblock", "a.example")).toMatchObject({ key: "filtering.userRules", line: "@@||a.example^" });
    expect(previewOf("block", "a.example")).toMatchObject({ key: "filtering.userRules", line: "||a.example^" });
    expect(previewOf("do_not_decrypt", "a.example")).toMatchObject({ key: "filtering.exclusions", line: "a.example" });
    for (const a of ["unblock", "block", "do_not_decrypt"] as const) {
      expect(previewOf(a, "a.example").added).toMatch(/^Added /);
      expect(previewOf(a, "a.example").already).toMatch(/ is already in /);
    }
  });
});
