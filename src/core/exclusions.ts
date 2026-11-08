/**
 * What is not decrypted, the pure part (plan 4.3, 8.2): the line grammar as the
 * app reads it, the rows from the user's lines and the engine's layers, their
 * filter and search, what a reason says in words, the app sheet's line and the
 * notice's text. The one owner of all of it.
 *
 * The user's lines live in `filtering.exclusions` and are the app's own, so they
 * show with the engine stopped too; the engine sends the `list:*` and `auto:*`
 * layers, and only while HTTPS is in force (the engine controller reads them).
 */
import type { ExclusionRow, ExclusionScope, HealNotice, Snapshot } from "@/data/protocol";
import { groupApps } from "./apps";
import { engineStatus, factDay, type EngineSlice } from "./engine";

/** The "Not decrypted" group's anchor in Settings. */
export const EXCLUSIONS_ANCHOR = "not-decrypted";
/** Rows shown; the rest are counted. 200 rows of 44 px stay bounded with no virtualisation, as the log's. */
export const EXCLUSIONS_SHOWN = 200;

/** The rows as the engine last said, on the engine slice. */
export interface ExclusionsFacts {
  revision: number;
  rows: readonly ExclusionRow[];
  scope: ExclusionScope;
  browsers: readonly string[];
  /** Rows that could not be read. */
  skipped: number;
}

/** A notice with `key`, its engine run and id: a new run's ids start over. */
export interface HealGroup extends HealNotice {
  key: string;
}

// ---- The line grammar (sieve-filter `exclusions.rs`), one table held to both
// parsers: src/data/fixtures/exclusion-lines.json.

export type LinePatternKind = "subdomains" | "exact" | "wildcard" | "ip";
export type LineRefusal = "BadHost" | "UnterminatedQuote" | "WildcardInExact" | "UnknownModifier" | "EmptyAppList" | "BadAppName";

export interface ParsedLine {
  kind: LinePatternKind;
  value: string;
  apps: string[];
}

const APP_MODIFIER = "app=";
const MAX_HOST_LEN = 253;
const MAX_LABEL_LEN = 63;

/**
 * Lower case as the engine folds names (`to_ascii_lowercase`): everything compared
 * with what it sends goes through this. `toLowerCase` also folds non-ASCII capitals,
 * and then a path with one matches nothing the engine said.
 */
const asciiLower = (s: string) => s.replace(/[A-Z]/g, (c) => c.toLowerCase());

function hostName(raw: string, glob: boolean): string | null {
  const host = asciiLower(raw.endsWith(".") ? raw.slice(0, -1) : raw);
  const letters = glob ? /^[a-z0-9_*-]+$/ : /^[a-z0-9_-]+$/;
  const labelOk = (l: string) => l.length > 0 && l.length <= MAX_LABEL_LEN && !l.startsWith("-") && !l.endsWith("-") && letters.test(l);
  return host !== "" && host.length <= MAX_HOST_LEN && host.split(".").every(labelOk) ? host : null;
}

const isIpv4 = (s: string) => {
  const parts = s.split(".");
  return parts.length === 4 && parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
};

function isIpv6(s: string): boolean {
  if (!s.includes(":") || s.split("::").length > 2) return false;
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  const v4 = tail.includes(".");
  if (v4 && !isIpv4(tail)) return false;
  const head = v4 ? s.slice(0, lastColon + 1) + "0:0" : s;
  const compressed = head.includes("::");
  // Only `::` may stand for no groups: a stray colon beside it leaves an empty one.
  const groups = head.split("::").flatMap((side) => (side === "" ? [] : side.split(":")));
  const groupOk = groups.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g));
  return groupOk && (compressed ? groups.length < 8 : groups.length === 8);
}

/** One line as the engine would read it, or why it would skip it. A comment or a blank line is not a line. */
export function parseExclusionLine(raw: string): ParsedLine | { refused: LineRefusal } {
  const line = raw.trim();
  const dollar = line.indexOf("$");
  const body = dollar < 0 ? line : line.slice(0, dollar).trim();
  let apps: string[] = [];
  if (dollar >= 0) {
    const modifier = line.slice(dollar + 1).trim();
    if (!modifier.startsWith(APP_MODIFIER)) return { refused: "UnknownModifier" };
    const list = modifier.slice(APP_MODIFIER.length);
    if (list.trim() === "") return { refused: "EmptyAppList" };
    apps = list.split("|").map((a) => asciiLower(a.trim()));
    if (apps.some((a) => a === "" || /[\\/ *$"]/.test(a))) return { refused: "BadAppName" };
  }
  if (body.startsWith('"')) {
    if (body.length < 2 || !body.endsWith('"')) return { refused: "UnterminatedQuote" };
    const inner = body.slice(1, -1);
    if (inner.includes("*")) return { refused: "WildcardInExact" };
    const host = hostName(inner, false);
    return host === null ? { refused: "BadHost" } : { kind: "exact", value: host, apps };
  }
  if (body.endsWith('"')) return { refused: "UnterminatedQuote" };
  if (isIpv4(body) || isIpv6(body)) return { kind: "ip", value: body.toLowerCase(), apps };
  const glob = body.includes("*");
  const host = hostName(body, glob);
  if (host === null) return { refused: "BadHost" };
  return { kind: glob ? "wildcard" : "subdomains", value: host, apps };
}

/** The line a new row of the user writes: a host, and an app when one is named. */
export const exclusionLine = (host: string, app: string | null) => (app ? `${host}$${APP_MODIFIER}${app}` : host);

/** What a stored line the engine skips says in place of its reason. */
export const REFUSED_LINE_WORDS = "Sieve cannot read this line, so it does nothing";

/** Why a new line would do nothing, or null when the engine reads it. */
export function refusedLineWords(line: string): string | null {
  const parsed = parseExclusionLine(line);
  if (!("refused" in parsed)) return null;
  return parsed.refused === "BadAppName" ? "A rule cannot name this app, because of a character in its file name. Add the site for all apps instead." : `Sieve cannot read ${line}.`;
}

// ---- Reasons.

const USER = "user";
const LIST = "list:";
const AUTO = "auto:";
const FLOOR = "floor:";
/** The id of Sieve's own list, which reads as Sieve's (`sieve-engine` `exclusions::lists`). */
const SIEVES_LIST = "sensitive";

const AUTO_WORDS: Readonly<Record<string, string>> = {
  "auto:pinning": "Rejected Sieve's certificate (auto)",
  "auto:client-cert": "Asks for a client certificate (auto)",
  "auto:ev": "EV certificate (auto)",
  "auto:failing": "Kept failing while decrypted, so the whole app passes untouched for a day (auto)",
};

/** Every floor fact in words: what cannot be turned off, so never a row (plan 8.2). Held to `Floor::ALL` by a law. */
export const FLOOR_WORDS: Readonly<Record<string, string>> = {
  "floor:forwarded": "virtual machines and WSL",
  "floor:unknown-app": "apps Sieve cannot name",
  "floor:service": "Windows services",
  "floor:app-scope": "apps that are not browsers, for now",
  "floor:no-root": "anything while no certificate is installed",
  "floor:no-exclusion-list": "anything while this list cannot be read",
  "floor:no-sni": "connections that name no site",
  "floor:ech": "connections that hide their site name",
  "floor:alpn": "connections that are not web traffic",
  "floor:protocol": "connections Sieve's encryption cannot speak",
  "floor:restricted-suffix": "government and bank domains",
  "floor:non-public-root": "sites whose certificate no public authority issued",
  "floor:upstream-invalid": "sites whose certificate is not valid",
  "floor:upstream-revoked": "sites whose certificate was revoked",
  "floor:upstream-unavailable": "sites whose certificate could not be checked",
  "floor:upstream-ct": "sites whose certificate a current log list shows is not publicly logged",
};

/** The one line that names the floor, under the list. */
export const FLOOR_LINE = `Sieve never decrypts these, whatever this list says: ${Object.values(FLOOR_WORDS).join("; ")}.`;

/** Says what the list does while it does nothing. */
export const NOT_IN_FORCE_LINE = "Sieve is not decrypting HTTPS right now, so this list has nothing to do yet.";

/** Whether `reasonWords` of the log hands this slug here. */
export const isExclusionReason = (slug: string) => slug === USER || slug.startsWith(LIST) || slug.startsWith(AUTO) || slug.startsWith(FLOOR);

/** A reason in words; one this build does not know shows as it came. */
export function exclusionReasonWords(slug: string): string {
  if (slug === USER) return "You added this";
  if (slug.startsWith(LIST)) {
    const id = slug.slice(LIST.length);
    return `Sensitive site (${id === SIEVES_LIST ? "Sieve's" : id} list)`;
  }
  return AUTO_WORDS[slug] ?? FLOOR_WORDS[slug] ?? slug;
}

export const REASON_GROUPS = ["all", "user", "list", "pinning", "client-cert", "ev", "other"] as const;
export type ReasonGroup = (typeof REASON_GROUPS)[number];

export const REASON_GROUP_TEXT: Record<ReasonGroup, string> = {
  all: "All",
  user: "Yours",
  list: "Sensitive",
  pinning: "Rejected",
  "client-cert": "Client certificate",
  ev: "EV",
  other: "Other",
};

export function reasonGroup(slug: string): ReasonGroup {
  if (slug === USER) return "user";
  if (slug.startsWith(LIST)) return "list";
  const auto = slug.startsWith(AUTO) ? slug.slice(AUTO.length) : "";
  return (REASON_GROUPS as readonly string[]).includes(auto) ? (auto as ReasonGroup) : "other";
}

// ---- Rows.

export interface ExclusionView {
  /** Unique in a list. */
  key: string;
  /** The pattern as the list grammar writes it. */
  line: string;
  /** The user's whole line, for removing it; null on an engine row. */
  userLine: string | null;
  /** Lower-case exe file names; empty means every app. */
  apps: readonly string[];
  reason: string;
  createdMs: number | null;
  retries: number;
  /** A user's line the engine skips: it excludes nothing, for any app. */
  refused: boolean;
}

const isAuto = (r: Pick<ExclusionView, "reason">) => r.reason.startsWith(AUTO);
export const canTryAgain = isAuto;

/** The user's lines first, then the engine's layers. A line the engine would skip still shows, marked, so it can be removed. */
export function mergeRows(userLines: readonly string[], engineRows: readonly ExclusionRow[]): ExclusionView[] {
  const mine = userLines.map((raw): ExclusionView => {
    const parsed = parseExclusionLine(raw);
    const refused = "refused" in parsed;
    return { key: `${USER}|${raw}`, line: refused ? raw : raw.split("$")[0].trim(), userLine: raw, apps: refused ? [] : parsed.apps, reason: USER, createdMs: null, retries: 0, refused };
  });
  const engine = engineRows.map((r, i): ExclusionView => ({ key: `${r?.reason}|${r?.line}|${(r?.apps ?? []).join("|")}|${i}`, line: r?.line ?? "", userLine: null, apps: r?.apps ?? [], reason: r?.reason ?? "", createdMs: r?.created_ms ?? null, retries: r?.retries ?? 0, refused: false }));
  return [...mine, ...engine];
}

/** What a row says of itself: its reason, or that it does nothing. */
export const rowReasonWords = (r: Pick<ExclusionView, "reason" | "refused">) => (r.refused ? REFUSED_LINE_WORDS : exclusionReasonWords(r.reason));

/** The filter's groups: "all", then those the rows hold, in a fixed order. */
export function groupsOf(rows: readonly Pick<ExclusionView, "reason">[]): ReasonGroup[] {
  const present = new Set(rows.map((r) => reasonGroup(r.reason)));
  return REASON_GROUPS.filter((g) => g === "all" || present.has(g));
}

/** The row's words beside its reason: how many times it was tried again. */
export function retryWords(retries: number): string | null {
  if (!(retries > 0)) return null;
  return retries === 1 ? "tried again 1 time" : `tried again ${retries} times`;
}

/** The row's first date, which a try again does not move (plan 4.3). Zero is no date. */
export function firstDateWords(createdMs: number | null | undefined): string | null {
  const day = typeof createdMs === "number" && createdMs > 0 ? factDay(createdMs) : null;
  return day === null ? null : `first on ${day}`;
}

/** Whether a row excludes anything for an app with one of these file names. */
const appliesTo = (r: Pick<ExclusionView, "apps" | "refused">, ...files: readonly string[]) => !r.refused && (r.apps.length === 0 || files.some((f) => r.apps.includes(f)));

export interface ExclusionFilter {
  group: ReasonGroup;
  query: string;
  /** An app's file names, lower case: the rows that apply to it. None means every app. */
  apps: readonly string[];
}

export function filterRows(rows: readonly ExclusionView[], { group, query, apps }: ExclusionFilter, nameOf: (exe: string) => string | null): ExclusionView[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  return rows.filter((r) => {
    if (group !== "all" && reasonGroup(r.reason) !== group) return false;
    if (apps.length > 0 && !appliesTo(r, ...apps)) return false;
    const hay = [r.line, ...r.apps, ...r.apps.map((a) => nameOf(a) ?? ""), rowReasonWords(r)].join(" ").toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}

/** Which of an app's files have rejected sites to try again in bulk. */
export const rejectedFiles = (rows: readonly ExclusionView[], files: readonly string[]) => files.filter((f) => rows.some((r) => r.reason === "auto:pinning" && r.apps.includes(f)));

// ---- Names.

/** An exe path as a line names it: the file name, lower case. */
export const exeFileName = (exe: string) => asciiLower(exe.split(/[\\/]/).pop() ?? "");

/** A running app that has this exe file, for its name and icon. */
export function runningApp(snapshot: Snapshot | null | undefined, exe: string): { key: string; name: string; exe: string } | null {
  if (!snapshot) return null;
  for (const app of groupApps(snapshot)) {
    const path = app.exes.find((e) => exeFileName(e) === exe);
    if (path) return { key: app.key, name: app.name, exe: path };
  }
  return null;
}

// ---- The deep link.

export const APP_PARAM = "exclusionsApp";
export const REASON_PARAM = "exclusionsReason";

/** An app is every file it runs as, so the view holds the rows of each. */
export function exclusionsHref(apps: readonly string[] = [], reason: ReasonGroup | null = null): string {
  const q = new URLSearchParams();
  for (const file of apps) q.append(APP_PARAM, file);
  if (reason) q.set(REASON_PARAM, reason);
  const search = q.toString();
  return `/settings/${search ? `?${search}` : ""}#${EXCLUSIONS_ANCHOR}`;
}

/** What a location's query string asks the view to show. Anything else in it means nothing here. */
export function exclusionsLink(search: string): { apps: string[]; group: ReasonGroup } {
  const q = new URLSearchParams(search);
  const reason = q.get(REASON_PARAM);
  return {
    apps: [...new Set(q.getAll(APP_PARAM).map(asciiLower))].filter(Boolean),
    group: (REASON_GROUPS as readonly string[]).includes(reason ?? "") ? (reason as ReasonGroup) : "all",
  };
}

// ---- The app sheet's line (task D8).

export const DECRYPTS_TEXT = "Sieve decrypts this app's HTTPS.";
export const DOES_NOT_DECRYPT_TEXT = "Sieve does not decrypt this app's HTTPS.";

/** `apps` is what the line links to: the app's files, or none when there is nothing to show. */
export type AppDecryption = { line: null } | { line: string; count: number; apps: readonly string[] };

/**
 * The one line under an app's switch, true for what the engine does. None while
 * the app is Off (the switch's own line says that), the engine reports it is not
 * decrypting, whatever its switch says, or it has not answered: nothing here claims
 * what is not known. The report is the whole engine's: a flow can still end at a
 * floor, as the Settings floor line says.
 */
export function appDecryption(e: EngineSlice, app: { on: boolean; exes: readonly string[] }, rows: readonly Pick<ExclusionView, "apps" | "refused">[]): AppDecryption {
  const facts = e.exclusions;
  if (!app.on || engineStatus(e)?.decrypting !== true || !facts) return { line: null };
  const inScope = facts.scope === "all" || app.exes.some((x) => facts.browsers.includes(asciiLower(x)));
  if (!inScope) return { line: DOES_NOT_DECRYPT_TEXT, count: 0, apps: [] };
  const files = [...new Set(app.exes.map(exeFileName))];
  const count = rows.filter((r) => appliesTo(r, ...files)).length;
  if (count === 0) return { line: DECRYPTS_TEXT, count, apps: [] };
  return { line: `Sieve decrypts this app's HTTPS except ${count.toLocaleString("en-US")} ${count === 1 ? "site" : "sites"}`, count, apps: files };
}

// ---- The notice.

/** What one group of exclusions says (plan 4.3). */
export function noticeText(appName: string, notice: Pick<HealNotice, "hosts" | "total">): string {
  return notice.total <= 1
    ? `${appName} rejected Sieve's certificate for ${notice.hosts[0]}. Sieve stopped decrypting it.`
    : `${appName} rejected Sieve's certificate for ${notice.total.toLocaleString("en-US")} sites. Sieve stopped decrypting them.`;
}
