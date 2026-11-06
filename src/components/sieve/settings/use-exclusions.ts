"use client";

import { useCallback, useMemo, useState } from "react";
import { httpsInForce } from "@/core/engine";
import { EXCLUSIONS_SHOWN, exclusionLine, filterRows, groupsOf, hasRejected, mergeRows, runningApp, type ExclusionView, type ReasonGroup } from "@/core/exclusions";
import { addLine, removeLine } from "@/core/log-actions";
import { groupApps } from "@/core/apps";
import { newest, type SieveState } from "@/core/store";
import { useRuntime } from "@/hooks/sieve-provider";
import { useExclusionsLink } from "@/hooks/use-exclusions-link";
import { useEngine, useEngineActions, useSetting, useSieve } from "@/hooks/use-sieve";

const selectNewest = (s: SieveState) => newest(s);
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));
const NO_ROWS: never[] = [];

/** Every row: the user's lines, and what the engine says. The only reader of `exclusions` on the engine slice. */
export function useExclusionRows(): ExclusionView[] {
  const e = useEngine();
  const [lines] = useSetting("filtering.exclusions");
  const engineRows = (httpsInForce(e) ? e.exclusions?.rows : null) ?? NO_ROWS;
  return useMemo(() => mergeRows(lines ?? [], engineRows), [lines, engineRows]);
}

/** A running app, for a row's name and icon and the Add form. */
export interface RunningExe {
  /** The exe file name, lower case: what a line names. */
  file: string;
  name: string;
}

export interface ExclusionsModel {
  inForce: boolean;
  /** The rows that match, at most EXCLUSIONS_SHOWN. */
  shown: readonly ExclusionView[];
  /** How many more match. */
  hidden: number;
  /** Rows of any kind, before the filter. */
  total: number;
  groups: readonly ReasonGroup[];
  group: ReasonGroup;
  setGroup: (g: ReasonGroup) => void;
  query: string;
  setQuery: (q: string) => void;
  /** The one app the view is filtered to, by file name. */
  app: string | null;
  clearApp: () => void;
  clearFilters: () => void;
  /** The filtered app has rejected sites to try again. */
  canTryAll: boolean;
  appInfo: (exe: string) => { key: string; name: string; exe: string | null };
  running: readonly RunningExe[];
  /** Rows the engine sent that could not be read. */
  skipped: number;
  error: string | null;
  actionError: string | null;
  /** Null when added; the words of why not. */
  add: (host: string, app: string | null) => string | null;
  remove: (row: ExclusionView) => void;
  tryAgain: (row: ExclusionView) => void;
  tryAll: () => void;
}

/** The "Not decrypted" view's model (plan 8.2). */
export function useExclusions(): ExclusionsModel {
  const e = useEngine();
  const { notices, settings } = useRuntime();
  const { tryDecryptAgain } = useEngineActions();
  const [, writeLines] = useSetting("filtering.exclusions");
  const rows = useExclusionRows();
  const snapshot = useSieve(selectNewest);
  const { app, group, setGroup, clearApp } = useExclusionsLink();
  const [query, setQuery] = useState("");

  const running = useMemo<RunningExe[]>(() => {
    const byFile = new Map<string, string>();
    for (const a of snapshot ? groupApps(snapshot) : []) {
      for (const exe of a.exes) byFile.set((exe.split(/[\\/]/).pop() ?? "").toLowerCase(), a.name);
    }
    return [...byFile].map(([file, name]) => ({ file, name })).sort((x, y) => x.name.localeCompare(y.name) || x.file.localeCompare(y.file));
  }, [snapshot]);

  const appInfo = useCallback(
    (exe: string) => {
      const found = runningApp(snapshot, exe);
      return found ?? { key: exe, name: exe, exe: null };
    },
    [snapshot],
  );

  const matched = useMemo(() => filterRows(rows, { group, query, app }, (exe) => runningApp(snapshot, exe)?.name ?? null), [rows, group, query, app, snapshot]);

  const said = useCallback((err: unknown) => void notices.push({ kind: "error", text: message(err) }), [notices]);
  const now = useCallback(() => settings.get("filtering.exclusions"), [settings]);

  const add = useCallback(
    (host: string, forApp: string | null) => {
      const line = exclusionLine(host, forApp);
      if (now().includes(line)) return `${line} is already in the list.`;
      writeLines(addLine(now(), line)).catch(said);
      return null;
    },
    [now, said, writeLines],
  );

  const remove = useCallback(
    (row: ExclusionView) => {
      const line = row.userLine;
      if (line === null) return;
      writeLines(removeLine(now(), line))
        .then((wrote) => {
          if (!wrote) return;
          notices.push({
            kind: "info",
            text: `Removed ${line} from the sites not decrypted.`,
            action: { label: "Undo", run: () => void writeLines(addLine(now(), line)).catch(said) },
          });
        })
        .catch(said);
    },
    [notices, now, said, writeLines],
  );

  return {
    inForce: httpsInForce(e),
    shown: matched.slice(0, EXCLUSIONS_SHOWN),
    hidden: Math.max(0, matched.length - EXCLUSIONS_SHOWN),
    total: rows.length,
    groups: groupsOf(rows),
    group,
    setGroup,
    query,
    setQuery,
    app,
    clearApp,
    clearFilters: () => {
      setQuery("");
      setGroup("all");
      clearApp();
    },
    canTryAll: app !== null && hasRejected(rows, app),
    appInfo,
    running,
    skipped: httpsInForce(e) ? (e.exclusions?.skipped ?? 0) : 0,
    error: e.exclusionsError ? `Sieve could not read this list: ${e.exclusionsError}` : null,
    actionError: e.exclusionsActionError ?? null,
    add,
    remove,
    tryAgain: (row) => void tryDecryptAgain(row.line, row.apps[0] ?? null),
    tryAll: () => {
      if (app !== null) void tryDecryptAgain(null, app);
    },
  };
}
