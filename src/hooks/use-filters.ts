"use client";

import { useEffect, useState } from "react";
import { setGroupOn, setListOn } from "@/core/filter-lists";
import type { FilterCatalogue, FilterList, RuleProblem } from "@/data/protocol";
import { useRuntime } from "./sieve-provider";
import { useSetting } from "./use-sieve";

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

export interface FiltersModel {
  /** Null while loading and after a failed read. */
  catalogue: FilterCatalogue | null;
  /** Why the catalogue could not be read. */
  failed: string | null;
  selection: Readonly<Record<string, string>>;
  setList: (list: FilterList, on: boolean) => void;
  setGroup: (lists: readonly FilterList[], on: boolean) => void;
  rules: readonly string[];
  /** Saves `lines` unless the parser refuses one; resolves to what it refused. */
  saveRules: (lines: string[]) => Promise<RuleProblem[]>;
  allowlist: readonly string[];
  addAllowed: (host: string) => void;
  removeAllowed: (host: string) => void;
}

/** Everything the Filters screen reads and writes. Writes go through useSetting, so through the write gate. */
export function useFilters(): FiltersModel {
  const { filterLists, settings, notices } = useRuntime();
  const [selection, writeSelection] = useSetting("filters.lists");
  const [rules, writeRules] = useSetting("filters.userRules");
  const [allowlist, writeAllowlist] = useSetting("filters.allowlist");
  const [catalogue, setCatalogue] = useState<FilterCatalogue | null>(null);
  const [failed, setFailed] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    filterLists.catalogue().then(
      (c) => live && setCatalogue(c),
      (e: unknown) => live && setFailed(message(e)),
    );
    return () => {
      live = false;
    };
  }, [filterLists]);

  // Writers read the latest stored value at call time, so undo after other edits stays correct.
  const selectionNow = () => settings.get("filters.lists");
  const allowedNow = () => settings.get("filters.allowlist");

  return {
    catalogue,
    failed,
    selection,
    setList: (list, on) => void writeSelection(setListOn(selectionNow(), list, on)),
    setGroup: (lists, on) => void writeSelection(setGroupOn(selectionNow(), lists, on)),
    rules,
    saveRules: async (lines) => {
      const refused = await filterLists.checkRules(lines);
      if (refused.length === 0) await writeRules(lines);
      return refused;
    },
    allowlist,
    addAllowed: (host) => {
      if (allowedNow().includes(host)) {
        notices.push({ kind: "info", text: `${host} is already on the allowlist` });
        return;
      }
      void writeAllowlist([...allowedNow(), host]);
    },
    removeAllowed: (host) => {
      void writeAllowlist(allowedNow().filter((h) => h !== host));
      notices.push({
        kind: "info",
        text: `Removed ${host} from the allowlist`,
        action: { label: "Undo", run: () => void writeAllowlist(allowedNow().includes(host) ? allowedNow() : [...allowedNow(), host]) },
      });
    },
  };
}
