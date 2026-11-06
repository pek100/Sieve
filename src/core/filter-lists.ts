/**
 * Filter lists, the pure part. The catalogue's one owner is the engine crate
 * (sieve_filter::catalogue::LISTS, read through `filter_catalogue`); nothing here
 * names a list. Tracking and annoyance options are groups of lists, derived from
 * the titles, and a group's state is derived from its lists: never stored, so it
 * can never disagree with the selection (plan D3).
 *
 * The selection is the setting `filters.lists`: only differences from a list's
 * default are stored. A gated list stays off whatever is stored, and nothing here
 * can turn it on, so its slice's acceptance cannot be bypassed (plan D5).
 */
import type { EngineListStatus, EngineLists, FilterCatalogue, FilterList, FilterReport } from "@/data/protocol";

export type ListGroupId = "tracking" | "annoyances" | "general";

/** Groups in display order. */
export const LIST_GROUPS: readonly { id: ListGroupId; label: string }[] = [
  { id: "general", label: "General" },
  { id: "tracking", label: "Tracking" },
  { id: "annoyances", label: "Annoyances" },
];

export type ListSelection = Readonly<Record<string, string>>;

export function listGroup(list: Pick<FilterList, "title">): ListGroupId {
  if (/annoyance/i.test(list.title)) return "annoyances";
  if (/tracking/i.test(list.title)) return "tracking";
  return "general";
}

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
function reportOf(row: EngineListStatus): FilterReport | null {
  const loaded = row.enabled && row.network + row.cosmetic + row.skipped > 0;
  return loaded ? { applied: row.network, skipped: row.skipped, reasons: row.skip_reasons } : null;
}

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
      return row ? { ...l, report: reportOf(row) } : l;
    }),
  };
}
