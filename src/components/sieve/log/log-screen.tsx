"use client";

import { Eraser, Pause, Play } from "lucide-react";
import { useState } from "react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { CardBoundary, CardError } from "@/components/sieve/shell/card";
import { EmptyState } from "@/components/sieve/shell/empty-state";
import { GridRegion, LayoutGrid } from "@/components/sieve/shell/layout-grid";
import { Page } from "@/components/sieve/shell/page";
import { Button } from "@/components/ui/button";
import { LOG_SHOWN } from "@/core/log";
import type { LogRow } from "@/data/protocol";
import { LogDetailsSheet } from "./log-details";
import { LogRowItem } from "./log-row";
import { LogToolbar } from "./log-toolbar";
import { ReportDialog } from "./report-dialog";
import { RulePreview } from "./rule-preview";
import { useLogView, useRowActions } from "./use-log";

const plural = (n: number, one: string, many: string) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;

/**
 * The filtering log (plan 8.3, 8.4): what the engine did, newest first, in
 * words. Session only and in memory. Flat on the page grid: the filters and
 * search, then the rows edge to edge. A row opens its details; its menu offers
 * the same actions. The log's own failure is said above the rows and keeps
 * them; a bad row never takes the screen with it.
 */
export function LogScreen() {
  const view = useLogView();
  const rowActions = useRowActions();
  const [open, setOpen] = useState<LogRow | null>(null);
  const { log, actions, shown, matched, routes } = view;
  const paused = log.paused;

  const empty = log.rows.length === 0;
  const hidden = matched - shown.length;

  return (
    <Page
      title="Log"
      meta={
        <span className="tabular text-label text-on-surface-muted" data-testid="log-count">
          {plural(log.rows.length, "row", "rows")}
        </span>
      }
      action={
        <>
          <IconButton label={paused ? "Resume the log" : "Pause the log"} toggled={paused} onClick={paused ? actions.resume : actions.pause}>
            {paused ? <Play strokeWidth={1.75} /> : <Pause strokeWidth={1.75} />}
          </IconButton>
          <IconButton label="Clear the log" disabled={empty} onClick={actions.clear}>
            <Eraser strokeWidth={1.75} />
          </IconButton>
        </>
      }
    >
      <CardBoundary title="Log">
        <LayoutGrid>
          <GridRegion span={12}>
            <LogToolbar filter={view.filter} onFilter={view.setFilter} query={view.query} onQuery={view.setQuery} />
          </GridRegion>
          {log.error && (
            <GridRegion span={12}>
              <CardError message={log.error} />
            </GridRegion>
          )}
          <GridRegion span={12}>
            <section aria-label="Log rows" className="flex min-w-0 flex-col">
              {empty ? (
                routes ? (
                  <EmptyState line="Nothing yet" body={paused ? "The log is paused. Resume it to see new rows." : "Rows appear here as apps connect through the engine."} />
                ) : (
                  <EmptyState line="Nothing to show" body={view.engineDetail} />
                )
              ) : shown.length === 0 ? (
                <EmptyState
                  line="No row matches"
                  body="Nothing in this session fits that filter and search."
                  action={
                    <Button variant="secondary" onClick={view.clearFilters}>
                      Show every row
                    </Button>
                  }
                />
              ) : (
                <ul className="flex flex-col">
                  {shown.map((e) => (
                    <LogRowItem key={e.seq} row={e.row} titles={view.titles} onOpen={() => setOpen(e.row)} onAction={rowActions.run} />
                  ))}
                </ul>
              )}
              {hidden > 0 && (
                <p className="pt-2 text-caption text-on-surface-faint" data-testid="log-more">
                  {hidden.toLocaleString("en-US")} more not shown. The newest {LOG_SHOWN} that match are listed.
                </p>
              )}
              {(log.dropped > 0 || log.skipped > 0) && (
                <p className="pt-2 text-caption text-on-surface-faint" data-testid="log-lost">
                  {[log.dropped > 0 && `${plural(log.dropped, "row", "rows")} dropped before Sieve read them`, log.skipped > 0 && `${plural(log.skipped, "row", "rows")} could not be read`]
                    .filter(Boolean)
                    .join(". ")}
                  .
                </p>
              )}
            </section>
          </GridRegion>
        </LayoutGrid>
        <CardBoundary title="Log details">
          <LogDetailsSheet row={open} titles={view.titles} onClose={() => setOpen(null)} onAction={rowActions.run} />
        </CardBoundary>
        <RulePreview preview={rowActions.preview} onConfirm={() => void rowActions.confirm()} onCancel={rowActions.cancelPreview} />
        <CardBoundary title="Report a broken site">
          <ReportDialog seed={rowActions.report} onClose={rowActions.closeReport} />
        </CardBoundary>
      </CardBoundary>
    </Page>
  );
}
