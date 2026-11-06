/**
 * The filtering log, the pure part: the store slice, the ring, the filters and
 * search, what a row says in words. Session only and in memory, on both sides
 * (plan 8.3). The slice has one writer, the log controller
 * (src/data/log-controller.ts).
 */
import type { LogEntry, LogOutcome, LogRow } from "@/data/protocol";

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
    default:
      return "Unknown";
  }
}

/** A row's host as a URL or a filter rule writes it: an IPv6 address (`LogRow.host` has it bare) takes brackets. */
export const urlFormHost = (host: string) => (host.includes(":") ? `[${host}]` : host);

/** A row's host is an address, not a name: what a flow with no name shows. */
export const isAddressHost = (host: string) => host.includes(":") || /^\d{1,3}(\.\d{1,3}){3}$/.test(host);

/**
 * The URL a row stands for: its own, else the host's root by what the flow
 * spoke. Null when the flow is not a web request (DNS, or a protocol not
 * decoded): there is no URL to copy.
 */
export function rowUrl(row: Pick<LogRow, "url" | "kind" | "host">): string | null {
  if (row.url) return row.url;
  if (!row.host) return null;
  if (row.kind === "tls" || row.kind === "quic") return `https://${urlFormHost(row.host)}/`;
  return row.kind === "http" ? `http://${urlFormHost(row.host)}/` : null;
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
