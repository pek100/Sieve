"use client";

import { useCallback, useMemo, useState } from "react";
import { engineDetail, engineLists, engineRoutes, engineStatus } from "@/core/engine";
import { addLine, previewOf, removeLine, type LogAction, type LinePreview, type PreviewAction } from "@/core/log-actions";
import { rowUrl, visibleRows, type LogFilter } from "@/core/log";
import type { LogEntry, LogRow } from "@/data/protocol";
import { useRuntime } from "@/hooks/sieve-provider";
import { useEngine, useLog, useLogActions } from "@/hooks/use-sieve";

/** A row that opens the report dialog, or the same facts from the app sheet. */
export interface ReportSeed {
  url: string | null;
  exe: string | null;
}

/** Everything the Log screen reads, derived once per change. */
export function useLogView() {
  const log = useLog();
  const e = useEngine();
  const actions = useLogActions();
  const [filter, setFilter] = useState<LogFilter>("all");
  const [query, setQuery] = useState("");
  const titles = useMemo(() => new Map(engineLists(e).map((l) => [l.id, l.title])), [e]);
  const { shown, matched } = useMemo(() => visibleRows(log.rows, filter, query, titles), [log.rows, filter, query, titles]);
  return {
    log,
    actions,
    filter,
    setFilter,
    query,
    setQuery,
    titles,
    shown,
    matched,
    routes: engineRoutes(e),
    engineDetail: engineDetail(e),
    answered: engineStatus(e) !== null,
    clearFilters: () => {
      setFilter("all");
      setQuery("");
    },
  };
}

export type LogView = ReturnType<typeof useLogView>;

/**
 * A row's actions: what each one does when pressed. Copy runs now; the ones
 * that write a setting open the preview first; Report opens its dialog.
 */
export function useRowActions() {
  const { settings, notices } = useRuntime();
  const [preview, setPreview] = useState<LinePreview | null>(null);
  const [report, setReport] = useState<ReportSeed | null>(null);

  const run = useCallback(
    (action: LogAction, row: LogRow) => {
      switch (action) {
        case "copy_url": {
          const url = rowUrl(row);
          if (url === null) return;
          void Promise.resolve(navigator.clipboard?.writeText(url)).then(
            () => notices.push({ kind: "success", text: "URL copied" }),
            () => notices.push({ kind: "error", text: "Could not copy. Select the URL in the details and copy it by hand." }),
          );
          return;
        }
        case "report":
          setReport({ url: row.url ?? rowUrl(row), exe: row.exe });
          return;
        default:
          setPreview(previewOf(action as PreviewAction, row.host));
      }
    },
    [notices],
  );

  /** Writes what the preview showed, then says so with an Undo. */
  const confirm = useCallback(async () => {
    if (!preview) return;
    const { key, line, added } = preview;
    setPreview(null);
    await settings.set(key, addLine(settings.get(key), line));
    notices.push({
      kind: "success",
      text: added,
      action: { label: "Undo", run: () => void settings.set(key, removeLine(settings.get(key), line)) },
    });
  }, [preview, settings, notices]);

  return { run, preview, confirm, cancelPreview: () => setPreview(null), report, setReport, closeReport: () => setReport(null) };
}

export type RowActionsModel = ReturnType<typeof useRowActions>;
export type { LogEntry };
