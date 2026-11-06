"use client";

import { useCallback, useMemo, useState } from "react";
import { engineDetail, engineLists, engineRoutes } from "@/core/engine";
import { addLine, previewOf, removeLine, type LogAction, type LinePreview, type PreviewAction } from "@/core/log-actions";
import { rowUrl, visibleRows, type LogFilter } from "@/core/log";
import { reportUrl } from "@/core/report";
import type { LogEntry, LogRow } from "@/data/protocol";
import { useRuntime } from "@/hooks/sieve-provider";
import { useEngine, useLog, useLogActions } from "@/hooks/use-sieve";

const reason = (err: unknown) => (err instanceof Error ? err.message : String(err));

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
  const { settings, notices, lockController } = useRuntime();
  /** The one write here, through the password's gate; undefined when it is locked. */
  const write = useCallback(
    (key: Parameters<typeof settings.set>[0], value: Parameters<typeof settings.set>[1]) => lockController.guard(() => settings.set(key, value).then(() => true)),
    [settings, lockController],
  );
  const [preview, setPreview] = useState<LinePreview | null>(null);
  const [report, setReport] = useState<ReportSeed | null>(null);

  const run = useCallback(
    (action: LogAction, row: LogRow) => {
      switch (action) {
        case "copy_url": {
          const url = rowUrl(row);
          if (url === null) return;
          // In an async function, a missing clipboard is a refusal like any other.
          void (async () => navigator.clipboard.writeText(url))().then(
            () => notices.push({ kind: "success", text: "URL copied" }),
            () => notices.push({ kind: "error", text: "Could not copy. Select the URL in the details and copy it by hand." }),
          );
          return;
        }
        case "report":
          setReport({ url: reportUrl(row), exe: row.exe });
          return;
        default:
          setPreview(previewOf(action as PreviewAction, row.host));
      }
    },
    [notices],
  );

  /**
   * Writes what the preview showed, then says so with an Undo. A line already
   * there is not this action's to undo, so that says so and offers none. The
   * store takes a value before it saves it, so a save that fails puts the list
   * back: what the screen and a retry read is what the disk holds.
   */
  const confirm = useCallback(async () => {
    if (!preview) return;
    const { key, line, added, already } = preview;
    setPreview(null);
    const before = settings.get(key);
    const after = addLine(before, line);
    if (after === before) {
      notices.push({ kind: "info", text: already });
      return;
    }
    const undo = async () => {
      try {
        await write(key, removeLine(settings.get(key), line));
      } catch (err) {
        write(key, addLine(settings.get(key), line)).catch(() => undefined);
        notices.push({ kind: "error", text: `Could not undo: ${reason(err)}. ${line} stays.` });
      }
    };
    try {
      if (!(await write(key, after))) return;
    } catch (err) {
      write(key, removeLine(settings.get(key), line)).catch(() => undefined);
      notices.push({ kind: "error", text: `Could not save ${line}: ${reason(err)}. Nothing was added.` });
      return;
    }
    notices.push({ kind: "success", text: added, action: { label: "Undo", run: () => void undo() } });
  }, [preview, settings, notices]);

  return { run, preview, confirm, cancelPreview: () => setPreview(null), report, setReport, closeReport: () => setReport(null) };
}

export type RowActionsModel = ReturnType<typeof useRowActions>;
export type { LogEntry };
