"use client";

import type { ReactNode } from "react";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { changeWords, listName, outcomeWords, rowOwner } from "@/core/log";
import type { LogAction } from "@/core/log-actions";
import type { LogRow } from "@/data/protocol";
import { LogActions } from "./log-actions";
import { logTime } from "./log-row";

function Fact({ label, mono, children }: { label: string; mono?: boolean; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1" data-log-fact={label}>
      <dt className="text-label text-on-surface-muted">{label}</dt>
      <dd className={mono ? "font-mono text-mono break-all text-on-surface" : "text-body break-words text-on-surface"}>{children}</dd>
    </div>
  );
}

/** A log row in full (plan slice 12): the outcome, the rule and its list, the request's facts, and the row's actions. */
export function LogDetailsSheet({
  row,
  titles,
  onClose,
  onAction,
}: {
  row: LogRow | null;
  titles: ReadonlyMap<string, string>;
  onClose: () => void;
  onAction: (action: LogAction, row: LogRow) => void;
}) {
  const list = row ? listName(row.list ?? null, titles) : null;
  return (
    <Sheet open={row !== null} onOpenChange={(o) => !o && onClose()}>
      <SheetContent
        side="right"
        className="gap-0 border-outline bg-surface-1 text-on-surface shadow-l4 data-[side=right]:w-full data-[side=right]:sm:max-w-none data-[side=right]:two:max-w-[480px]"
      >
        <SheetHeader className="p-5 pr-10">
          <SheetTitle className="font-mono text-mono break-all text-on-surface">{row?.host ?? ""}</SheetTitle>
          <SheetDescription className="text-body text-on-surface-muted">{row ? outcomeWords(row.outcome) : ""}</SheetDescription>
        </SheetHeader>
        {row && (
          <div className="flex flex-col gap-6 overflow-y-auto px-5 pb-6">
            <dl className="flex flex-col gap-4">
              <Fact label="Rule" mono={row.rule != null}>
                {row.rule ?? "No rule"}
              </Fact>
              <Fact label="List">{list ?? "No list"}</Fact>
              {row.changes && row.changes.length > 0 && (
                <Fact label="Tracking protection">
                  <ul className="flex flex-col gap-1" data-log-changes="">
                    {row.changes.map((c) => (
                      <li key={c.what}>{changeWords(c)}</li>
                    ))}
                  </ul>
                </Fact>
              )}
              <Fact label="App" mono={row.exe != null}>
                {row.exe ?? rowOwner(row)}
              </Fact>
              {row.url && (
                <Fact label="URL" mono>
                  {row.url}
                </Fact>
              )}
              {row.request_type && <Fact label="Request type">{row.request_type}</Fact>}
              <Fact label="Connection">{row.kind ?? "other"}</Fact>
              {row.remote && (
                <Fact label="Remote address" mono>
                  {row.remote}
                </Fact>
              )}
              <Fact label="Time">{logTime(row.t)}</Fact>
            </dl>
            <div className="flex flex-wrap gap-2" data-log-details-actions="">
              <LogActions row={row} kind="buttons" onAction={onAction} />
            </div>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
