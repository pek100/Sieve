/**
 * The person's own filter lists (`filters.custom`), the pure part. A list is
 * added by its address, which the engine downloads and judges like any list, or
 * from a file the person picks, whose text the engine judges and keeps. Either
 * way the engine compiles it untrusted: no `trusted-*` scriptlet, ever.
 *
 * `customListProblem` is the engine's rule (sieve_ipc::custom_list_problem); both
 * read the table `customLists` in src/data/fixtures/engine-ipc-v3.json, so they
 * cannot drift. The limits are the crate's, tied by tests/laws/engine-ipc.test.ts.
 */
import type { EngineCustomList, EngineLists, FilterReport, ListFetch } from "@/data/protocol";
import { fetchOf, reportOf } from "./filter-lists";

/** One of the person's own lists, as stored and as the policy carries it. */
export type CustomList = EngineCustomList;

export const MAX_CUSTOM_LISTS = 20;
export const CUSTOM_LIST_PREFIX = "custom-";
export const CUSTOM_ID_MAX = 32;
export const CUSTOM_URL_MAX = 512;
export const CUSTOM_TITLE_MAX = 64;
/** The largest file the engine takes (sieve_ipc::MAX_IMPORT_BYTES). */
export const MAX_IMPORT_BYTES = 512 * 1024;
/** The largest download the engine takes (sieve_filter::lists::MAX_LIST_BYTES). */
export const MAX_LIST_BYTES = 32 * 1024 * 1024;

const ID = new RegExp(`^${CUSTOM_LIST_PREFIX}[a-z0-9]{1,${CUSTOM_ID_MAX}}$`);
const CONTROL = /\p{Cc}/u;
const CONTROLS = /\p{Cc}/gu;
/** A dotted quad as Rust's Ipv4Addr reads one: no leading zeros. */
const IPV4 = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/;

/** Why the engine would refuse this list, or null: the same rule, word for word in effect. */
export function customListProblem(list: CustomList): string | null {
  if (!ID.test(list.id)) return `A custom list's id is ${CUSTOM_LIST_PREFIX} and 1 to ${CUSTOM_ID_MAX} lower-case letters or digits.`;
  if (list.title.trim() === "" || [...list.title].length > CUSTOM_TITLE_MAX || CONTROL.test(list.title)) return `A list's name has 1 to ${CUSTOM_TITLE_MAX} characters.`;
  if (list.url === null) return null;
  return urlProblem(list.url);
}

function urlProblem(url: string): string | null {
  if (new TextEncoder().encode(url).length > CUSTOM_URL_MAX) return `That address is longer than ${CUSTOM_URL_MAX} characters.`;
  if (!url.startsWith("https://")) return "Sieve downloads lists over https only. Ask the list's owner for an https:// address.";
  const host = url.slice("https://".length).split(/[/?#]/)[0] ?? "";
  if (host === "" || host.includes("@") || /\s/.test(url) || CONTROL.test(url)) return "That is not a web address.";
  if (localHost(host)) return "Sieve downloads lists from the internet only, never from this computer or your local network.";
  return null;
}

/** The engine's `local_host` (sieve_ipc), rule for rule: this computer or the local network, by name or address literal. */
function localHost(host: string): boolean {
  if (host.startsWith("[")) return true;
  const lower = host.toLowerCase();
  const colon = lower.lastIndexOf(":");
  const name = (colon === -1 ? lower : lower.slice(0, colon)).replace(/\.+$/, "");
  if (name === "localhost" || name.endsWith(".localhost")) return true;
  const quad = IPV4.exec(name);
  if (quad) {
    const [a, b, c, d] = quad.slice(1).map(Number);
    if ([a, b, c, d].some((o) => o > 255)) return numericLast(name);
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a + b + c + d === 0;
  }
  return numericLast(name);
}

/** A last label a URL parser reads as a number, so the host as an IPv4 address in another spelling. */
function numericLast(name: string): boolean {
  const last = name.split(".").at(-1) ?? "";
  return /^0x[0-9a-f]*$/.test(last) || /^\d+$/.test(last);
}

/** Is this stored value one list the engine would take? The registry's element check for `filters.custom`. */
export function isCustomList(v: unknown): v is CustomList {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const c = v as Record<string, unknown>;
  const shaped = typeof c.id === "string" && typeof c.title === "string" && (c.url === null || typeof c.url === "string") && typeof c.enabled === "boolean";
  return shaped && Object.keys(c).length === 4 && customListProblem(c as unknown as CustomList) === null;
}

export type UrlResult = { ok: true; url: string } | { ok: false; error: string };

/** A list's address from what the person typed or pasted: https assumed when no scheme is given. */
export function parseListUrl(typed: string): UrlResult {
  const t = typed.trim();
  if (t === "") return { ok: false, error: "Paste the list's address, such as https://example.com/list.txt." };
  const url = /^[a-z][a-z0-9+.-]*:\/\//i.test(t) ? t.replace(/^https:\/\//i, "https://") : `https://${t}`;
  const problem = urlProblem(url);
  return problem === null ? { ok: true, url } : { ok: false, error: problem };
}

/** The name a list by address starts with: its file's name, else its site. */
export function titleFromUrl(url: string): string {
  const rest = url.replace(/^https:\/\//, "");
  const [host = "", ...path] = rest.split(/[?#]/)[0]?.split("/") ?? [];
  const file = path.filter(Boolean).at(-1)?.replace(/\.txt$/i, "") ?? "";
  let name = file;
  try {
    name = decodeURIComponent(file);
  } catch {
    // A malformed escape is kept as written.
  }
  const clean = (s: string) => s.replace(CONTROLS, "").trim();
  return [...(clean(name) || clean(host))].slice(0, CUSTOM_TITLE_MAX).join("") || "My list";
}

/** Would the engine hold these lists together: at most MAX_CUSTOM_LISTS, no id twice (sieve_engine::policy::accept)? */
export const customListsFit = (lists: readonly CustomList[]) => lists.length <= MAX_CUSTOM_LISTS && new Set(lists.map((l) => l.id)).size === lists.length;

/** A fresh id no list here has. `random` gives bytes (crypto.getRandomValues in the app). */
export function newCustomId(existing: readonly CustomList[], random: (n: number) => Uint8Array): string {
  for (;;) {
    const id = CUSTOM_LIST_PREFIX + [...random(8)].map((b) => (b % 36).toString(36)).join("");
    if (!existing.some((l) => l.id === id)) return id;
  }
}

/** Why another list cannot be added now, or null. */
export const addProblem = (lists: readonly CustomList[]) => (lists.length >= MAX_CUSTOM_LISTS ? `You can have up to ${MAX_CUSTOM_LISTS} of your own lists. Remove one to add another.` : null);

/** The engine's words for a failed download or import, as a sentence. The raw words stay beside it. */
const FETCH_WORDS: readonly (readonly [RegExp, string])[] = [
  [/HTML page/, "The address gave a web page, not a filter list. Check that it points to the list's file itself."],
  [/no rule/, "There is no rule in it that Sieve can read."],
  [/byte limit/, `It is larger than Sieve takes: ${MAX_LIST_BYTES / 1024 / 1024} MB for a download, ${MAX_IMPORT_BYTES / 1024} KB for a file. A larger list can be added by its address.`],
  [/not UTF-8/, "It is not a plain text file."],
  [/HTTP 404/, "Nothing was found at that address."],
  [/HTTP 40[13]/, "The server refused to give the list."],
  [/HTTP \d+/, "The server could not give the list just now. Sieve tries again later."],
  [/no answer in/, "The server did not answer in time. Sieve tries again later."],
  [/only https/, "Sieve downloads lists over https only."],
  [/not a file|file is not downloaded/, "A list from a file is not downloaded: import the file again to update it."],
];

export function fetchWords(raw: string): string {
  return FETCH_WORDS.find(([re]) => re.test(raw))?.[1] ?? "The download did not work. Sieve keeps the last good copy and tries again later.";
}

/** One own list with what the engine says of it; `report` and `fetch` null while it said nothing. */
export interface CustomListView extends CustomList {
  report: FilterReport | null;
  fetch: ListFetch | null;
}

export function customListViews(lists: readonly CustomList[], report: EngineLists | null): CustomListView[] {
  const rows = new Map((report?.lists ?? []).map((r) => [r.id, r]));
  return lists.map((l) => {
    const row = rows.get(l.id);
    return { ...l, report: row ? reportOf(row) : null, fetch: row ? fetchOf(row) : null };
  });
}

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

/** When the engine last got a good copy, in words. Absent is not "never": the engine may not have said. */
export function updatedText(fetch: ListFetch | null | undefined, nowMs: number): string {
  if (!fetch) return "Not checked yet";
  if (fetch.fetchedAtMs === null) return fetch.lastError ? "Not downloaded" : "Waiting for the first download";
  const ago = Math.max(0, nowMs - fetch.fetchedAtMs);
  if (ago < MINUTE_MS) return "Updated just now";
  if (ago < HOUR_MS) return `Updated ${Math.floor(ago / MINUTE_MS)} min ago`;
  if (ago < DAY_MS) return `Updated ${Math.floor(ago / HOUR_MS)} h ago`;
  const days = Math.floor(ago / DAY_MS);
  return `Updated ${days} ${days === 1 ? "day" : "days"} ago`;
}
