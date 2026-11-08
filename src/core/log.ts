/**
 * The filtering log, the pure part: the store slice, the ring, the filters and
 * search, what a row says in words. Session only and in memory, on both sides
 * (plan 8.3). The slice has one writer, the log controller
 * (src/data/log-controller.ts).
 */
import type { LogEntry, LogOutcome, LogRow, RetryHow } from "@/data/protocol";
import { exclusionReasonWords, isExclusionReason } from "./exclusions";
import { CAUSE_TEXT, SIGNAL_TEXT } from "./issues";

/** How Sieve tried a connection again, before the app saw anything. */
export const RETRY_TEXT: Readonly<Record<RetryHow, string>> = {
  next_address: "Sieve tried the site's other address",
  reconnect: "Sieve tried the connection once more",
};

/** How often the engine's log tail is read while the engine routes. */
export const LOG_POLL_MS = 1000;
/** Rows the window keeps; older ones drop. */
export const LOG_RING = 2000;
/** The newest rows that match are shown; the rest are counted. 200 rows of 44 px stay bounded with no virtualisation. */
export const LOG_SHOWN = 200;

export interface LogSlice {
  /** Oldest first. Never longer than LOG_RING. */
  rows: readonly LogEntry[];
  /** The newest seq read: the next read asks for rows after it. */
  cursor: number;
  /** Rows the Rust ring dropped before this window read them. */
  dropped: number;
  /** Rows that could not be read. */
  skipped: number;
  paused: boolean;
  /** Why the newest read failed; null after a good one. The rows stay. */
  error: string | null;
}

export const EMPTY_LOG: LogSlice = { rows: [], cursor: 0, dropped: 0, skipped: 0, paused: false, error: null };

/** Appends a batch, keeping the newest LOG_RING. */
export function appendRows(rows: readonly LogEntry[], batch: readonly LogEntry[]): readonly LogEntry[] {
  const all = [...rows, ...batch];
  return all.length > LOG_RING ? all.slice(all.length - LOG_RING) : all;
}

export const LOG_FILTERS = ["all", "blocked", "modified", "not_decrypted"] as const;
export type LogFilter = (typeof LOG_FILTERS)[number];
export const LOG_FILTER_TEXT: Record<LogFilter, string> = {
  all: "All",
  blocked: "Blocked",
  modified: "Modified",
  not_decrypted: "Not decrypted",
};

const MODIFIED: ReadonlySet<LogOutcome["kind"]> = new Set(["redirected", "params_removed", "hidden", "scriptlets"]);

export function matchesFilter(row: Pick<LogRow, "outcome">, filter: LogFilter): boolean {
  const kind = row.outcome?.kind;
  if (filter === "all") return true;
  if (filter === "modified") return MODIFIED.has(kind);
  return kind === filter;
}

const LIST_USER = "user";

/** The name of a row's list: the catalogue's title from the engine's facts, "Your rules", or its id. */
export function listName(id: string | null, titles: ReadonlyMap<string, string>): string | null {
  if (id === null) return null;
  return id === LIST_USER ? "Your rules" : (titles.get(id) ?? id);
}

/** Every word of `query` is in the row's host, exe, rule or list. */
export function matchesSearch(row: Partial<LogRow>, query: string, titles: ReadonlyMap<string, string>): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return true;
  const hay = [row.host, row.exe, row.rule, row.list, listName(row.list ?? null, titles), row.url].filter(Boolean).join(" ").toLowerCase();
  return words.every((w) => hay.includes(w));
}

/** The newest matching entries first, at most LOG_SHOWN, and how many matched. */
export function visibleRows(
  rows: readonly LogEntry[],
  filter: LogFilter,
  query: string,
  titles: ReadonlyMap<string, string>,
): { shown: LogEntry[]; matched: number } {
  const matches = rows.filter((e) => e?.row && matchesFilter(e.row, filter) && matchesSearch(e.row, query, titles));
  return { shown: matches.slice(-LOG_SHOWN).reverse(), matched: matches.length };
}

/** Reasons a row can carry today. Later slices add reasons without a protocol bump; see reasonWords. */
export const REASON_TEXT: Readonly<Record<string, string>> = {
  no_rule: "no rule matched",
  exception: "exception rule",
  app_off: "app is off",
  mixed_names: "the address also serves names no rule blocks",
  no_name: "no name known for this address",
};

/** A reason in words; one this build does not know shows its slug with spaces. */
export function reasonWords(slug: string): string {
  if (isExclusionReason(slug)) return exclusionReasonWords(slug);
  return REASON_TEXT[slug] ?? slug.replaceAll("_", " ");
}

/** The outcome in words (plan 8.3). Words first: colour never carries it alone. */
export function outcomeWords(outcome: LogOutcome | null | undefined): string {
  switch (outcome?.kind) {
    case "blocked":
      return "Blocked";
    case "redirected":
      return "Redirected";
    case "params_removed":
      return "Parameters removed";
    case "hidden":
      return outcome.elements === 1 ? "Hidden 1 element" : `Hidden ${outcome.elements} elements`;
    case "scriptlets":
      return "Scriptlets";
    case "passed":
      return `Passed through (${reasonWords(outcome.reason)})`;
    case "not_decrypted":
      return `Not decrypted (${reasonWords(outcome.reason)})`;
    case "problem": {
      const cause = CAUSE_TEXT[outcome.cause] ?? CAUSE_TEXT.unknown;
      return `${SIGNAL_TEXT[outcome.signal] ?? "A problem"} (${cause.charAt(0).toLowerCase()}${cause.slice(1)})`;
    }
    case "retried":
      return `${RETRY_TEXT[outcome.how] ?? "Sieve tried again"}: ${outcome.recovered ? "it worked" : "it still failed"}`;
    default:
      return "Unknown";
  }
}

/** A row's host as a URL or a filter rule writes it: an IPv6 address (`LogRow.host` has it bare) takes brackets. */
export const urlFormHost = (host: string) => (host.includes(":") ? `[${host}]` : host);

/** A row's host is an address, not a name: what a flow with no name shows. */
export const isAddressHost = (host: string) => host.includes(":") || /^\d{1,3}(\.\d{1,3}){3}$/.test(host);

const HTTPS = { scheme: "https", port: "443" };
/** The URL each web flow kind reads as, and the port such a URL leaves out. Kind comes from a flow's first bytes, not its port. */
const WEB_KINDS: ReadonlyMap<string, { scheme: string; port: string }> = new Map([
  ["tls", HTTPS],
  ["quic", HTTPS],
  ["http", { scheme: "http", port: "80" }],
]);
/** The port of `LogRow.remote`, a socket address: `192.0.2.1:8443` or `[2001:db8::1]:8443`. */
const REMOTE_PORT = /^(?:\[[^\]]*\]|[^:]*):(\d+)$/;

/**
 * The URL a row stands for: its own, else the host's root by what the flow
 * spoke, with the connection's port when it is not the scheme's. Null when the
 * flow is not a web request (DNS, or a protocol not decoded): there is no URL
 * to copy.
 */
export function rowUrl(row: Pick<LogRow, "url" | "kind" | "host" | "remote">): string | null {
  if (row.url) return row.url;
  const web = WEB_KINDS.get(row.kind);
  if (!row.host || !web) return null;
  const port = REMOTE_PORT.exec(row.remote)?.[1];
  return `${web.scheme}://${urlFormHost(row.host)}${port && port !== web.port ? `:${port}` : ""}/`;
}

/** The path and query of a request-level row, for its column; null on a host-level row. */
export function rowPath(row: Pick<LogRow, "url">): string | null {
  if (!row.url) return null;
  const m = /^[a-z]+:\/\/[^/?#]*(.*)$/i.exec(row.url);
  return m && m[1] !== "" ? m[1] : null;
}

/** The file name of an exe path, the way a person names the app. */
export function exeName(exe: string | null | undefined): string | null {
  if (!exe) return null;
  return exe.split(/[\\/]/).pop() || null;
}

/** Who a row belongs to, in words: a process's file name, a VM's name, or that it is not known. */
export function rowOwner(row: Pick<LogRow, "exe" | "forwarded">): string {
  if (row.forwarded) return row.forwarded.vm ?? "Unnamed virtual machine";
  return exeName(row.exe) ?? "Unknown app";
}
