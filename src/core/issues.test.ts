import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/engine-ipc-v3.json";
import { parseIssues, SIGNALS, type AppIssues, type LogOutcome, type Problem, type Signal } from "@/data/protocol";
import { parseExclusionLine, type ExclusionView } from "./exclusions";
import { outcomeWords } from "./log";
import { rowActions } from "./log-actions";
import {
  appFixes,
  failingOpen,
  failures,
  fixPreview,
  NOTIFY_AFTER_START_MS,
  problemFixes,
  problemText,
  reportText,
  SIGNAL_TEXT,
  startedFailing,
  summaryText,
  troubled,
  verdict,
} from "./issues";

const T = 1_793_000_000_000;
const problem = (signal: Signal, cause: Problem["cause"], over: Partial<Problem> = {}): Problem => ({ signal, cause, host: "cdn.game.example", count: 1, first_ms: T + 1, last_ms: T + 2, ...over });
const app = (problems: Problem[], over: Partial<AppIssues> = {}): AppIssues => ({ key: "game launcher", exe: "launcher.exe", session: 1, since_ms: T, flows: 10, retried: 0, recovered: 0, problems, ...over });

describe("issues in words", () => {
  it("every signal says what happened, plainly, with no engine words", () => {
    for (const s of SIGNALS) {
      expect(SIGNAL_TEXT[s], s).toMatch(/^[A-Z]/);
      expect(SIGNAL_TEXT[s], s).not.toMatch(/egress|SERVFAIL|RST|handshake|signal|flow/i);
    }
    expect(problemText(problem("connect_timeout", "network", { count: 3 }))).toBe("The server did not answer: cdn.game.example, 3 times");
    expect(problemText(problem("dns_unanswered", "unknown", { host: null }))).toBe("Looking up a site's address got no answer, once");
  });

  it("an app's verdict: Sieve if any failure was Sieve's, else cannot tell, else the network; blocks alone are a filter's", () => {
    expect(verdict(app([problem("connect_timeout", "network"), problem("app_refused_certificate", "sieve")]))).toBe("sieve");
    expect(verdict(app([problem("connect_timeout", "network"), problem("stall", "unknown")]))).toBe("unknown");
    expect(verdict(app([problem("connect_refused", "network")]))).toBe("network");
    expect(verdict(app([problem("blocked", "sieve"), problem("quic_refused", "sieve")]))).toBe("intended");
  });

  it("only failures put an app in trouble, in the engine's order", () => {
    const blockedOnly = app([problem("blocked", "sieve")], { key: "browser" });
    const failing = app([problem("stall", "unknown")]);
    expect(troubled([blockedOnly, failing]).map((a) => a.key)).toEqual(["game launcher"]);
    expect(troubled(null)).toEqual([]);
    expect(failures({ problems: undefined as unknown as Problem[] })).toEqual([]);
  });

  it("the summary counts what failed of what was seen, and what was blocked by a filter rule", () => {
    expect(summaryText(app([problem("stall", "unknown", { count: 2 }), problem("blocked", "sieve", { count: 4 })]))).toBe("2 of 10 connections had trouble, 4 blocked by a filter rule");
    expect(summaryText(app([problem("stall", "unknown")], { flows: 0 }))).toBe("1 connection had trouble");
  });
});

describe("telling the user", () => {
  it("repeated failures right after Sieve began filtering tell, unless the network alone explains them", () => {
    expect(startedFailing(app([problem("app_refused_certificate", "sieve", { count: 3 })]))).toBe(true);
    expect(startedFailing(app([problem("app_refused_certificate", "sieve", { count: 2 })])), "not yet repeated").toBe(false);
    expect(startedFailing(app([problem("connect_timeout", "network", { count: 9 })])), "the network's").toBe(false);
    expect(startedFailing(app([problem("blocked", "sieve", { count: 9 })])), "blocks are on purpose").toBe(false);
    const late = problem("stall", "unknown", { count: 5, first_ms: T + NOTIFY_AFTER_START_MS + 1 });
    expect(startedFailing(app([late])), "it worked with Sieve for a while first").toBe(false);
    expect(startedFailing(app([{ ...late, first_ms: T + NOTIFY_AFTER_START_MS }])), "the control").toBe(true);
  });
});

describe("one-step fixes", () => {
  const rows = (reason: string, apps: string[]): ExclusionView[] => [{ key: "k", line: "*", userLine: null, apps, reason, createdMs: T, retries: 0, refused: false }];

  it("a problem offers a fix only where Sieve did it and a site is named", () => {
    expect(problemFixes(problem("blocked", "sieve"), "launcher.exe")).toEqual(["unblock"]);
    expect(problemFixes(problem("app_refused_certificate", "sieve"), "launcher.exe")).toEqual(["stop_decrypting"]);
    expect(problemFixes(problem("app_refused_certificate", "sieve"), null), "no exe, no app-only line").toEqual([]);
    expect(problemFixes(problem("connect_timeout", "network"), "launcher.exe")).toEqual([]);
    expect(problemFixes(problem("blocked", "sieve", { host: null }), "launcher.exe")).toEqual([]);
    expect(problemFixes(problem("handshake_abandoned", "unknown"), "launcher.exe"), "a handshake given up on: cause unknown, nothing to fix").toEqual([]);
  });

  it("the untouched row is found by any of the app's exes, problems or none", () => {
    const untouched = failingOpen(rows("auto:failing", ["launcher.exe"]), [null, "helper.exe", "launcher.exe"]);
    expect(untouched?.reason).toBe("auto:failing");
    expect(failingOpen(rows("auto:failing", ["launcher.exe"]), [])).toBeNull();
    expect(failingOpen([{ ...rows("auto:failing", [])[0], apps: undefined as unknown as string[] }], "launcher.exe"), "a degraded row").toBeNull();
    expect(appFixes(null, untouched, true), "no problems left: keep or try again still").toEqual(["keep_untouched", "try_again"]);
  });

  it("the app offers Off and a report when Sieve may be why, and keep or try again while it passes untouched", () => {
    const untouched = failingOpen(rows("auto:failing", ["launcher.exe"]), "launcher.exe");
    expect(untouched?.reason).toBe("auto:failing");
    expect(failingOpen(rows("auto:pinning", ["launcher.exe"]), "launcher.exe")).toBeNull();
    expect(failingOpen(rows("auto:failing", ["other.exe"]), "launcher.exe")).toBeNull();
    expect(appFixes(app([problem("app_refused_certificate", "sieve")]), untouched, true)).toEqual(["keep_untouched", "try_again", "turn_off", "report"]);
    expect(appFixes(app([problem("connect_timeout", "network")]), null, true), "the network's: nothing of Sieve's to undo").toEqual([]);
    expect(appFixes(app([problem("stall", "unknown")]), null, false), "an app that cannot be turned off").toEqual(["report"]);
  });

  it("every line a fix writes is one the exclusion and rule grammars read", () => {
    const unblock = fixPreview("unblock", "updates.game.example", "launcher.exe");
    expect([unblock?.key, unblock?.line]).toEqual(["filtering.userRules", "@@||updates.game.example^"]);
    const stop = fixPreview("stop_decrypting", "cdn.game.example", "launcher.exe");
    expect([stop?.key, stop?.line]).toEqual(["filtering.exclusions", "cdn.game.example$app=launcher.exe"]);
    const keep = fixPreview("keep_untouched", null, "launcher.exe");
    expect([keep?.key, keep?.line]).toEqual(["filtering.exclusions", "*$app=launcher.exe"]);
    for (const p of [stop, keep]) expect(parseExclusionLine(p!.line), p!.line).not.toHaveProperty("refused");
    expect(fixPreview("keep_untouched", null, null)).toBeNull();
    expect(fixPreview("turn_off", "x.example", "launcher.exe"), "Off is the switch's own write").toBeNull();
  });

  it("the report holds the app's problems in words and names no destination", () => {
    const text = reportText(app([problem("app_refused_certificate", "sieve", { count: 4 })], { retried: 2, recovered: 1 }), "Game Launcher", "0.1.0");
    expect(text).toContain("Sieve 0.1.0: Game Launcher (launcher.exe)");
    expect(text).toContain("Sieve is the likely cause.");
    expect(text).toContain("cdn.game.example, 4 times (Likely Sieve)");
    expect(text).toContain("Sieve tried 2 connections again");
    expect(text).not.toMatch(/https?:\/\//);
  });
});

describe("problems and retries in the log", () => {
  const row = (outcome: LogOutcome) => ({ url: null, kind: "tls", host: "cdn.game.example", remote: "192.0.2.9:443", outcome, rule: null });

  it("say what happened and who most likely caused it, and a retry says whether it worked", () => {
    expect(outcomeWords({ kind: "problem", signal: "connect_timeout", cause: "network" })).toBe("The server did not answer (likely the network or the server, not Sieve)");
    expect(outcomeWords({ kind: "retried", how: "next_address", recovered: true })).toBe("Sieve tried the site's other address: it worked");
    expect(outcomeWords({ kind: "retried", how: "reconnect", recovered: false })).toBe("Sieve tried the connection once more: it still failed");
  });

  it("offer Do not decrypt only where decrypting was the problem, and nothing that writes for a retry", () => {
    expect(rowActions(row({ kind: "problem", signal: "app_refused_certificate", cause: "sieve" }))).toContain("do_not_decrypt");
    expect(rowActions(row({ kind: "problem", signal: "connect_timeout", cause: "network" }))).not.toContain("do_not_decrypt");
    expect(rowActions(row({ kind: "retried", how: "reconnect", recovered: true }))).toEqual(["copy_url", "report"]);
  });
});

describe("degraded data", () => {
  it("the fixture's apps read whole; partial, old-schema and broken apps degrade or drop, never throw", () => {
    const body = Object.fromEntries(Object.entries(fixture.engine.find((m) => m.type === "issues")!).filter(([k]) => k !== "type"));
    expect(parseIssues(body).apps).toHaveLength(2);
    const parsed = parseIssues({
      run: 1,
      revision: 2,
      apps: [
        null,
        { key: "old", problems: [{ signal: "stall", cause: "unknown", count: 1, last_ms: 5 }] },
        { key: "", problems: [{ signal: "stall", cause: "unknown", count: 1, last_ms: 5 }] },
        { key: "future", problems: [{ signal: "teleported", cause: "sieve", count: 1, last_ms: 5 }] },
        { key: "half", flows: "many", problems: [{ signal: "blocked", cause: "maybe", count: 1, last_ms: 5 }, { signal: "blocked", cause: "sieve", count: 2, last_ms: 6 }] },
      ],
    });
    expect(parsed.apps.map((a) => a.key)).toEqual(["old", "half"]);
    expect(parsed.apps[0]).toEqual({ key: "old", exe: null, session: null, since_ms: 5, flows: 0, retried: 0, recovered: 0, problems: [{ signal: "stall", cause: "unknown", host: null, count: 1, first_ms: 5, last_ms: 5 }] });
    expect(parsed.apps[1].problems).toHaveLength(1);
    expect(parsed.dropped, "absent is none").toBe(0);
    expect(() => parseIssues({ run: 1, revision: 1 })).toThrow(/apps/);
    expect(() => parseIssues(null)).toThrow();
  });
});
