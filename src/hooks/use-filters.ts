"use client";

import { useEffect, useMemo, useState } from "react";
import { engineLists, engineTakesPolicy } from "@/core/engine";
import { nothingLoaded, setGroupOn, setListOn, withEngineReports } from "@/core/filter-lists";
import type { EngineLists, FilterCatalogue, FilterList, RuleProblem } from "@/data/protocol";
import { useRuntime } from "./sieve-provider";
import { useEngine, useSetting } from "./use-sieve";

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

export interface RuleSave {
  saved: boolean;
  refused: RuleProblem[];
}

export interface FiltersModel {
  /** Null while loading and after a failed read. Each list carries the engine's report, when it has one. */
  catalogue: FilterCatalogue | null;
  /** Why the catalogue could not be read. */
  failed: string | null;
  /** The facts say no list is in force. False while they are missing: nothing is claimed then. */
  nothingInForce: boolean;
  selection: Readonly<Record<string, string>>;
  setList: (list: FilterList, on: boolean) => void;
  setGroup: (lists: readonly FilterList[], on: boolean) => void;
  rules: readonly string[];
  /** Saves `lines` unless the parser refuses one. `saved` is false too when the lock dropped the write. */
  saveRules: (lines: string[]) => Promise<RuleSave>;
  allowlist: readonly string[];
  addAllowed: (host: string) => void;
  removeAllowed: (host: string) => void;
  blocklist: readonly string[];
  addBlocked: (host: string) => void;
  removeBlocked: (host: string) => void;
}

/**
 * Everything the Filters screen reads and writes. Writes go through useSetting,
 * so through the write gate. The rules and both domain lists are the very
 * settings the engine controller sends in the policy: there is no second store.
 */
export function useFilters(): FiltersModel {
  const { filterLists, settings, notices, engine } = useRuntime();
  const [selection, writeSelection] = useSetting("filters.lists");
  const [rules, writeRules] = useSetting("filtering.userRules");
  const [allowlist, writeAllowlist] = useSetting("filtering.allowedDomains");
  const [blocklist, writeBlocklist] = useSetting("filtering.blockedDomains");
  const [catalogue, setCatalogue] = useState<FilterCatalogue | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const [answered, setAnswered] = useState<EngineLists | null>(null);
  // The probe facts the newest answer stands for.
  const [answeredFor, setAnsweredFor] = useState<string | null>(null);

  // The full report is large, so it is read when the probe's small facts say it
  // moved, not on the probe's cadence. A read that failed is asked again at each
  // next probe, with no error of its own: the probe's facts already say what is in force.
  const slice = useEngine();
  const reachable = engineTakesPolicy(slice);
  const lists = engineLists(slice);
  const facts = lists.map((l) => `${l.id}:${l.applied}:${l.skipped}`).join();
  const unanswered = answeredFor !== facts;
  const nextTry = unanswered ? slice.probe : null;
  const noneApplied = slice.error === null && slice.probe !== null && lists.every((l) => l.applied === 0);

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

  useEffect(() => {
    if (!reachable || !unanswered) return;
    let live = true;
    engine.lists().then(
      (l) => {
        if (!live) return;
        setAnswered(l);
        setAnsweredFor(facts);
      },
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [engine, reachable, facts, unanswered, nextTry]);

  const reported = useMemo(() => (catalogue ? withEngineReports(catalogue, reachable ? answered : null) : null), [catalogue, reachable, answered]);
  const nothingInForce = reported !== null && noneApplied && nothingLoaded(reported.lists);

  // Writers read the latest stored value at call time, so undo after other edits stays correct.
  const selectionNow = () => settings.get("filters.lists");

  const hostList = (key: "filtering.allowedDomains" | "filtering.blockedDomains", write: (v: readonly string[]) => Promise<boolean>, name: string) => {
    const now = () => settings.get(key);
    // A refused write says why; it never fails silently.
    const said = (e: unknown) => void notices.push({ kind: "error", text: message(e) });
    return {
      add: (host: string) => {
        if (now().includes(host)) {
          notices.push({ kind: "info", text: `${host} is already on the ${name}` });
          return;
        }
        write([...now(), host]).catch(said);
      },
      remove: (host: string) => {
        write(now().filter((h) => h !== host))
          .then((ran) => {
            if (!ran) return;
            notices.push({
              kind: "info",
              text: `Removed ${host} from the ${name}`,
              action: { label: "Undo", run: () => void write(now().includes(host) ? now() : [...now(), host]).catch(said) },
            });
          })
          .catch(said);
      },
    };
  };
  const allowed = hostList("filtering.allowedDomains", writeAllowlist, "allowlist");
  const blocked = hostList("filtering.blockedDomains", writeBlocklist, "blocklist");

  return {
    catalogue: reported,
    failed,
    nothingInForce,
    selection,
    setList: (list, on) => void writeSelection(setListOn(selectionNow(), list, on)),
    setGroup: (lists, on) => void writeSelection(setGroupOn(selectionNow(), lists, on)),
    rules,
    saveRules: async (lines) => {
      const refused = await filterLists.checkRules(lines);
      return { saved: refused.length === 0 && (await writeRules(lines)), refused };
    },
    allowlist,
    addAllowed: allowed.add,
    removeAllowed: allowed.remove,
    blocklist,
    addBlocked: blocked.add,
    removeBlocked: blocked.remove,
  };
}
