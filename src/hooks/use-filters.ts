"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { addProblem, customListViews, newCustomId, parseListUrl, titleFromUrl, type CustomList, type CustomListView } from "@/core/custom-lists";
import { engineLists, engineStatus, engineTakesPolicy } from "@/core/engine";
import { PROFILE_TEXT, RECOMMENDED_PROFILE, listProfile, nothingLoaded, setGroupOn, setListOn, withEngineReports, withProfile, type Profile } from "@/core/filter-lists";
import { CUSTOM } from "@/core/profiles";
import type { EngineLists, FilterCatalogue, FilterList, ListRules, RuleProblem } from "@/data/protocol";
import { useRuntime } from "./sieve-provider";
import { useEngine, useSetting } from "./use-sieve";

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));
const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));

/** Why the engine cannot answer a question about a list's copy now. */
export const ENGINE_AWAY_TEXT = "Sieve's engine is not running, so it cannot download or show lists now. Your choices are kept.";

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
  /** The engine can answer questions about lists (download now, show rules, import a file). */
  engineAnswers: boolean;
  selection: Readonly<Record<string, string>>;
  /** Derived from the selection, never stored; null until the catalogue is read. */
  profile: Profile | typeof CUSTOM | null;
  setProfile: (profile: Profile) => void;
  setList: (list: FilterList, on: boolean) => void;
  setGroup: (lists: readonly FilterList[], on: boolean) => void;
  /** Downloads one list now; resolves with why not, or null. */
  refreshList: (id: string) => Promise<string | null>;
  /** One list's rules that hold `query`, from the engine's copy. Rejects with the engine's reason. */
  listRules: (id: string, query: string) => Promise<ListRules>;
  own: readonly CustomListView[];
  /** Adds a list by its address; null, or the sentence why not. */
  addOwnUrl: (typed: string) => Promise<string | null>;
  /** The person picks a file; null when it was added or the picker closed, else the engine's or the app's reason. */
  importOwnFile: () => Promise<string | null>;
  setOwnOn: (id: string, on: boolean) => void;
  removeOwn: (id: string) => void;
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
 * so through the write gate. The lists, the person's own lists, the rules and
 * both domain lists are the very settings the engine controller sends in the
 * policy: there is no second store, and the profile is derived from them.
 */
export function useFilters(): FiltersModel {
  const { filterLists, settings, notices, engine } = useRuntime();
  const [selection, writeSelection] = useSetting("filters.lists");
  const [ownLists, writeOwn] = useSetting("filters.custom");
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
  // The own lists the engine holds: when they change, so does its report.
  const heldOwn = (engineStatus(slice)?.policy.custom_lists ?? []).map((l) => `${l.id}:${l.enabled}`).join();
  const facts = `${lists.map((l) => `${l.id}:${l.applied}:${l.skipped}`).join()}|${heldOwn}`;
  const report = reachable ? answered : null;
  const own = useMemo(() => customListViews(ownLists, report), [ownLists, report]);
  // An own list's counts are not in the probe's small facts, so while one that
  // is on has neither counts nor a refusal, the report is read at each probe.
  const waiting = own.some((l) => l.enabled && l.report === null && !l.fetch?.lastError);
  const unanswered = answeredFor !== facts || waiting;
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

  // Stable while the engine stays answerable, so an open rules view asks only when its search changes.
  const listRules = useCallback((id: string, query: string) => (reachable ? engine.listRules(id, query) : Promise.reject(new Error(ENGINE_AWAY_TEXT))), [engine, reachable]);
  const reported = useMemo(() => (catalogue ? withEngineReports(catalogue, report) : null), [catalogue, report]);
  // The probe's facts hold no own list, so their counts come from the report alone.
  const nothingInForce = reported !== null && noneApplied && nothingLoaded([...reported.lists, ...own]);

  // Writers read the latest stored value at call time, so undo after other edits stays correct.
  const selectionNow = () => settings.get("filters.lists");
  const ownNow = () => settings.get("filters.custom");
  // A refused write says why; it never fails silently.
  const said = (e: unknown) => void notices.push({ kind: "error", text: message(e) });

  const hostList = (key: "filtering.allowedDomains" | "filtering.blockedDomains", write: (v: readonly string[]) => Promise<boolean>, name: string) => {
    const now = () => settings.get(key);
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

  // A change far down the page that leaves a named level is said where the
  // person is looking, with the way back, since the level itself is at the top.
  const writeChange = (next: Readonly<Record<string, string>>) => {
    const was = reported ? listProfile(reported.lists, selectionNow()) : null;
    writeSelection(next)
      .then((ran) => {
        if (!ran || !reported || was === null || was === CUSTOM || listProfile(reported.lists, next) !== CUSTOM) return;
        notices.push({ kind: "info", text: `Protection level is now Custom: ${PROFILE_TEXT[was].label} with your change`, action: { label: "Back to recommended", run: () => void writeSelection(withProfile(selectionNow(), reported.lists, RECOMMENDED_PROFILE)).catch(said) } });
      })
      .catch(said);
  };

  const addOwn = async (list: CustomList): Promise<string | null> => {
    try {
      return (await writeOwn([...ownNow(), list])) ? null : "Not added: settings are locked.";
    } catch (e) {
      return message(e);
    }
  };

  return {
    catalogue: reported,
    failed,
    nothingInForce,
    engineAnswers: reachable,
    selection,
    profile: reported ? listProfile(reported.lists, selection) : null,
    setProfile: (profile) => {
      if (!reported) return;
      const before = selectionNow();
      writeSelection(withProfile(before, reported.lists, profile))
        .then((ran) => {
          if (!ran) return;
          const undo = { label: "Undo", run: () => void writeSelection(before).catch(said) };
          notices.push({ kind: "info", text: profile === RECOMMENDED_PROFILE ? "Back to Balanced, the recommended lists" : `Using ${PROFILE_TEXT[profile].label}`, action: undo });
        })
        .catch(said);
    },
    setList: (list, on) => writeChange(setListOn(selectionNow(), list, on)),
    setGroup: (lists, on) => writeChange(setGroupOn(selectionNow(), lists, on)),
    refreshList: async (id) => {
      if (!reachable) return ENGINE_AWAY_TEXT;
      try {
        setAnswered(await engine.listRefresh(id));
        return null;
      } catch (e) {
        return message(e);
      }
    },
    listRules,
    own,
    addOwnUrl: async (typed) => {
      const full = addProblem(ownNow());
      if (full) return full;
      const url = parseListUrl(typed);
      if (!url.ok) return url.error;
      if (ownNow().some((l) => l.url === url.url)) return "That list is already one of yours.";
      return addOwn({ id: newCustomId(ownNow(), randomBytes), title: titleFromUrl(url.url), url: url.url, enabled: true });
    },
    importOwnFile: async () => {
      const full = addProblem(ownNow());
      if (full) return full;
      if (!reachable) return ENGINE_AWAY_TEXT;
      const id = newCustomId(ownNow(), randomBytes);
      try {
        const kept = await engine.listImport(id);
        return kept === null ? null : addOwn({ id, title: kept.name, url: null, enabled: true });
      } catch (e) {
        return message(e);
      }
    },
    setOwnOn: (id, on) => void writeOwn(ownNow().map((l) => (l.id === id ? { ...l, enabled: on } : l))).catch(said),
    removeOwn: (id) => {
      const gone = ownNow().find((l) => l.id === id);
      if (!gone) return;
      writeOwn(ownNow().filter((l) => l.id !== id))
        .then((ran) => {
          if (!ran) return;
          // A list from a file comes back only while the engine still has its copy; by address it downloads again.
          const undo = gone.url !== null ? { label: "Undo", run: () => void writeOwn([...ownNow(), gone]).catch(said) } : undefined;
          notices.push({ kind: "info", text: undo ? `Removed ${gone.title}` : `Removed ${gone.title}. Import its file again to get it back.`, ...(undo ? { action: undo } : {}) });
        })
        .catch(said);
    },
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
