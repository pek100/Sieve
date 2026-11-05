/**
 * Report a broken site (plan 8.4), the pure part. The report is assembled
 * locally and holds exactly the listed fields: the page URL, the browser exe,
 * the lists with versions, the rules that applied with their lists, the
 * resource pin and Sieve's version. Never a pid, session, address, flow id, or
 * another row's host. Query strings are out by default: they carry tokens.
 * Nothing here sends anything, and nothing in Sieve ever does.
 */
import type { ListFact, LogEntry } from "@/data/protocol";
import { exeName, listName } from "./log";

const QUERY_START = /[?#]/;

/** The URL without its query string and fragment. */
export function stripQuery(url: string): string {
  const at = url.search(QUERY_START);
  return at < 0 ? url : url.slice(0, at);
}

export function hasQuery(url: string): boolean {
  return QUERY_START.test(url);
}

/** The host of a URL, lower case; null when it is not one. */
export function urlHost(url: string): string | null {
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^/?#@]*@)?(\[[^\]]*\]|[^/?#:]*)/i.exec(url.trim());
  return m && m[1] !== "" ? m[1].toLowerCase() : null;
}

export interface ReportRule {
  rule: string;
  /** A catalogue id, "user", or null. */
  list: string | null;
}

/**
 * The rules that applied to the page: rows of its host (and of the browser,
 * when it is known) that carry a rule, each rule once, oldest first.
 */
export function rulesForPage(rows: readonly LogEntry[], url: string, exe: string | null): ReportRule[] {
  const host = urlHost(url);
  if (host === null) return [];
  const out = new Map<string, ReportRule>();
  for (const e of rows) {
    const r = e?.row;
    if (!r?.rule || r.host?.toLowerCase() !== host || (exe !== null && r.exe !== exe) || out.has(r.rule)) continue;
    out.set(r.rule, { rule: r.rule, list: r.list ?? null });
  }
  return [...out.values()];
}

export interface ReportFacts {
  url: string;
  browser: string | null;
  lists: readonly ListFact[];
  rules: readonly ReportRule[];
  resourcePin: string | null;
  sieveVersion: string;
}

const NOT_KNOWN = "not known";

/**
 * The report's text, for the clipboard. The browser is its file name: a full
 * path can hold the user's Windows account name.
 */
export function buildReport(f: ReportFacts): string {
  const titles = new Map(f.lists.map((l) => [l.id, l.title]));
  const lists = f.lists.map((l) => `- ${l.title}: ${l.version ?? "version not known"}`);
  const rules = f.rules.map((r) => `- ${r.rule} (${listName(r.list, titles) ?? "list not known"})`);
  return [
    `Page URL: ${f.url.trim() === "" ? NOT_KNOWN : f.url}`,
    `Browser: ${exeName(f.browser) ?? NOT_KNOWN}`,
    "Lists:",
    ...(lists.length > 0 ? lists : ["- none reported"]),
    "Rules applied:",
    ...(rules.length > 0 ? rules : ["- none"]),
    `Resource library pin: ${f.resourcePin ?? NOT_KNOWN}`,
    `Sieve version: ${f.sieveVersion}`,
  ].join("\n");
}

/** A list's public issue page, derived from its homepage; null for one that is not https. */
export function issuePage(homepage: string): string | null {
  return homepage.startsWith("https://") ? `${homepage.replace(/\/+$/, "")}/issues` : null;
}

/** Which list a report is about: the first list among the rules applied, else the first list. */
export function reportList(rules: readonly ReportRule[], lists: readonly ListFact[]): ListFact | null {
  for (const r of rules) {
    const hit = lists.find((l) => l.id === r.list);
    if (hit) return hit;
  }
  return lists[0] ?? null;
}
