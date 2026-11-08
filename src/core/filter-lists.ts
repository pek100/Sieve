/**
 * Filter lists, the pure part. The catalogue's one owner is the engine crate
 * (sieve_filter::catalogue::LISTS, read through `filter_catalogue`); nothing here
 * names a list. Each list says what it is for (`kind`, its group here) and the
 * lowest profile that turns it on (`level`). The profile in force and a group's
 * state are derived from the lists, never stored, so they can never disagree
 * with the selection (plan D3).
 *
 * The selection is the setting `filters.lists`: only differences from a list's
 * default are stored. A list's default is the recommended profile (catalogue.rs
 * derives one from the other), so a person who changed nothing is on Balanced.
 * A gated list stays off whatever is stored, and nothing here can turn it on, so
 * its slice's acceptance cannot be bypassed (plan D5).
 */
import type { EngineListStatus, EngineLists, FilterCatalogue, FilterList, FilterReport, ListFetch, ListKind, ListLevel } from "@/data/protocol";
import { CUSTOM, inPreset, presetOf } from "./profiles";

export type ListGroupId = ListKind;

/** Groups in display order: one per kind. */
export const LIST_GROUPS: readonly { id: ListGroupId; label: string; text: string }[] = [
  { id: "ads", label: "Ads", text: "Lists that remove ads." },
  { id: "tracking", label: "Trackers", text: "Lists that stop sites and apps following what you do." },
  { id: "security", label: "Security", text: "Lists that keep you away from scams, fake downloads and malware." },
  { id: "annoyances", label: "Annoyances", text: "Lists that hide cookie banners, pop-ups and other clutter. They can hide something a site needs." },
  { id: "language", label: "Other languages", text: "Ads on sites in one language. Add the languages you read; they stay on whatever profile you pick." },
];

export type ListSelection = Readonly<Record<string, string>>;

export const listGroup = (list: Pick<FilterList, "kind">): ListGroupId => list.kind;

export const isGated = (list: Pick<FilterList, "default">) => list.default === "gated";

export function listOn(list: FilterList, selection: ListSelection): boolean {
  if (isGated(list)) return false;
  const stored = selection[list.id];
  return stored === "on" || stored === "off" ? stored === "on" : list.default === "on";
}

/** The selection with `list` set. Unknown ids survive; a gated list is refused (same object back). */
export function setListOn(selection: ListSelection, list: FilterList, on: boolean): ListSelection {
  if (isGated(list)) return selection;
  const next = { ...selection };
  if (on === (list.default === "on")) delete next[list.id];
  else next[list.id] = on ? "on" : "off";
  return next;
}

export function setGroupOn(selection: ListSelection, lists: readonly FilterList[], on: boolean): ListSelection {
  return lists.reduce((acc, list) => setListOn(acc, list, on), selection);
}

export interface GroupState {
  /** `all`: every selectable list on. `none`: none on (also a group with nothing selectable). */
  kind: "all" | "none" | "some";
  on: number;
  selectable: number;
  /** "2 of 5 on". */
  text: string;
}

export function groupState(lists: readonly FilterList[], selection: ListSelection): GroupState {
  const selectable = lists.filter((l) => !isGated(l));
  const on = selectable.filter((l) => listOn(l, selection)).length;
  const kind = on === 0 ? "none" : on === selectable.length ? "all" : "some";
  return { kind, on, selectable: selectable.length, text: `${on} of ${selectable.length} on` };
}

/** The profiles, mildest first: the scale of `profiles.ts`. */
export const PROFILES = ["minimal", "balanced", "strict"] as const;
export type Profile = (typeof PROFILES)[number];
/** What a person gets who changes nothing: the lists' defaults (catalogue.rs `RECOMMENDED`). */
export const RECOMMENDED_PROFILE: Profile = "balanced";

/** Each profile in words, in the order the picker shows them: the recommended one first. */
export const PROFILE_TEXT: Readonly<Record<Profile | typeof CUSTOM, { label: string; text: string }>> = {
  balanced: { label: "Balanced", text: "Blocks ads, trackers and dangerous sites. Rarely breaks a site." },
  strict: { label: "Strict", text: "Also hides cookie banners, pop-ups and social widgets, and blocks more trackers. Some sites may not work as expected." },
  minimal: { label: "Minimal", text: "Blocks ads only. Trackers and dangerous sites are not blocked." },
  custom: { label: "Custom", text: "Your own choice of the lists below." },
};
export const PROFILE_ORDER: readonly Profile[] = ["balanced", "strict", "minimal"];

/**
 * The lists a profile decides: every selectable one but the language lists,
 * which say which sites, not how strict, and so stay as the person set them
 * whatever profile is picked.
 */
export const inProfileScope = (list: FilterList) => !isGated(list) && list.kind !== "language";

const profileLevel = (level: ListLevel): Profile | null => ((PROFILES as readonly string[]).includes(level) ? (level as Profile) : null);

/** The profile the selection is at, or Custom. */
export function listProfile(lists: readonly FilterList[], selection: ListSelection): Profile | typeof CUSTOM {
  return presetOf(
    PROFILES,
    lists.filter(inProfileScope).map((l) => ({ level: profileLevel(l.level), on: listOn(l, selection) })),
  );
}

/** The selection with `profile`'s lists on and the rest of its scope off; language lists and unknown ids untouched. */
export function withProfile(selection: ListSelection, lists: readonly FilterList[], profile: Profile): ListSelection {
  return lists.filter(inProfileScope).reduce((acc, l) => setListOn(acc, l, inPreset(PROFILES, profile, profileLevel(l.level))), selection);
}

/** The primary subtags of the languages the person uses (`navigator.languages`, which follows Windows' display language in the app). */
export function primaryLanguages(tags: readonly string[]): string[] {
  return [...new Set(tags.map((t) => t.split(/[-_]/)[0]?.toLowerCase() ?? "").filter((t) => /^[a-z]{2,3}$/.test(t)))];
}

/** The language lists for the languages the person uses, in their order of preference. */
export function suggestedLists(lists: readonly FilterList[], tags: readonly string[]): FilterList[] {
  const mine = primaryLanguages(tags);
  const rank = (l: FilterList) => Math.min(...l.languages.map((x) => (mine.includes(x) ? mine.indexOf(x) : Infinity)));
  return lists.filter((l) => l.kind === "language" && !isGated(l) && Number.isFinite(rank(l))).sort((a, b) => rank(a) - rank(b));
}

/** Absent is not zero: no report reads "Not loaded yet", never 0. */
export function countText(report: FilterReport | null): string {
  if (report === null) return "Not loaded yet";
  return `${report.applied.toLocaleString("en-US")} applied, ${report.skipped.toLocaleString("en-US")} skipped`;
}

/** No list has counts yet: nothing here is in force. */
export const nothingLoaded = (lists: readonly FilterList[]) => lists.every((l) => l.report === null);

/**
 * The catalogue ids SetPolicy names for a selection the user changed: the one
 * place "on" becomes ids. A gated list is never among them, and an id no
 * catalogue row has (an older or newer build) is left out.
 */
export function selectedListIds(selection: ListSelection, catalogue: Pick<FilterCatalogue, "lists">): string[] {
  return catalogue.lists.filter((l) => listOn(l, selection)).map((l) => l.id);
}

/** A row of the engine's report as a list's counts; null when that list has nothing in force. */
export function reportOf(row: EngineListStatus): FilterReport | null {
  const loaded = row.enabled && row.network + row.cosmetic + row.skipped > 0;
  return loaded ? { applied: row.network, skipped: row.skipped, reasons: row.skip_reasons } : null;
}

/** What a row of the engine's report says about the copy. */
export const fetchOf = (row: EngineListStatus): ListFetch => ({ fetchedAtMs: row.fetched_at_ms, lastError: row.last_error, enabled: row.enabled });

/**
 * The catalogue with the engine's own report on each list. A list the engine
 * did not report keeps what the seam gave it, so with no answer nothing changes
 * and nothing is claimed.
 */
export function withEngineReports<C extends Pick<FilterCatalogue, "lists">>(catalogue: C, report: EngineLists | null): C {
  if (report === null) return catalogue;
  const rows = new Map(report.lists.map((r) => [r.id, r]));
  return {
    ...catalogue,
    lists: catalogue.lists.map((l) => {
      const row = rows.get(l.id);
      return row ? { ...l, report: reportOf(row), fetch: fetchOf(row) } : l;
    }),
  };
}
