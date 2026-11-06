"use client";

import { MoreVertical } from "lucide-react";
import { useState } from "react";
import { Monogram } from "@/components/sieve/apps/monogram";
import { AppIcon } from "@/components/sieve/primitives/app-icon";
import { FloatingTooltip } from "@/components/sieve/primitives/floating-tooltip";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { StateLayer } from "@/components/sieve/primitives/state-layer";
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { listName, outcomeWords, rowOwner, rowPath } from "@/core/log";
import type { LogAction } from "@/core/log-actions";
import type { LogRow as Row } from "@/data/protocol";
import { cn } from "@/lib/utils";
import { LogActions } from "./log-actions";

/** A log time: hours, minutes and seconds, to tell rows apart. */
export function logTime(t: number): string {
  return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

/** The path column: truncated, the whole of it in the floating tooltip on hover. */
function PathCell({ path }: { path: string | null }) {
  const [at, setAt] = useState<{ x: number; y: number } | null>(null);
  return (
    <span
      data-log-path=""
      className="hidden min-w-0 flex-1 truncate font-mono text-mono text-on-surface-muted three:block"
      onPointerMove={path ? (e) => setAt({ x: e.clientX, y: e.clientY }) : undefined}
      onPointerLeave={path ? () => setAt(null) : undefined}
    >
      {path}
      {path && at && (
        <FloatingTooltip x={at.x} y={at.y} className="max-w-96 font-mono text-mono break-all">
          {path}
        </FloatingTooltip>
      )}
    </span>
  );
}

/**
 * One row, not a table row: a stretched button opens the details, and the menu
 * is its sibling, so no button sits inside a button. At 1280: time, icon, host,
 * path, type, outcome, rule and list. Narrow: time, icon, host and outcome on
 * one 44 px line; the rest is in the sheet. The outcome is words first, with
 * the blocked colour only on Blocked.
 */
export function LogRowItem({ row, titles, onOpen, onAction }: { row: Row; titles: ReadonlyMap<string, string>; onOpen: () => void; onAction: (action: LogAction, row: Row) => void }) {
  const words = outcomeWords(row.outcome);
  const name = rowOwner(row);
  const list = listName(row.list ?? null, titles);
  return (
    <li data-testid="log-row" data-outcome={row.outcome?.kind} className="flex h-11 items-center gap-2">
      <button
        type="button"
        onClick={onOpen}
        aria-label={`${row.host}, ${words}, ${name}. Open details`}
        className="relative flex h-11 min-w-0 flex-1 items-center gap-2 overflow-hidden rounded-sm text-left two:gap-3"
      >
        {/* Narrow: hours and minutes only, to leave the host its room. The sheet has the seconds. */}
        <span className="tabular w-10 shrink-0 text-label text-on-surface-muted two:w-16">
          {logTime(row.t).slice(0, 5)}
          <span className="hidden two:inline">{logTime(row.t).slice(5)}</span>
        </span>
        <AppIcon exe={row.exe ?? null} size={16}>
          <Monogram appKey={name.toLowerCase()} name={name} size={16} />
        </AppIcon>
        <span data-log-host="" className="min-w-0 flex-1 truncate font-mono text-mono text-on-surface">
          {row.host}
        </span>
        <PathCell path={rowPath(row)} />
        <span data-log-type="" className="hidden w-20 shrink-0 truncate text-label text-on-surface-muted three:block">
          {row.request_type}
        </span>
        <span data-log-outcome="" className={cn("w-24 shrink-0 truncate text-label two:w-56", row.outcome?.kind === "blocked" ? "text-blocked" : "text-on-surface-muted")}>
          {words}
        </span>
        <span data-log-rule="" className="hidden min-w-0 flex-1 flex-col three:flex">
          <span className="truncate font-mono text-mono text-on-surface-muted">{row.rule}</span>
          {list && <span className="truncate text-caption text-on-surface-faint">{list}</span>}
        </span>
        <StateLayer />
      </button>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <IconButton label={`Actions for ${row.host}`}>
            <MoreVertical strokeWidth={1.75} />
          </IconButton>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <LogActions row={row} kind="menu" onAction={onAction} />
        </DropdownMenuContent>
      </DropdownMenu>
    </li>
  );
}
