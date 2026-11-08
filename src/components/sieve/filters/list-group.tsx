"use client";

import { MoreVertical, RefreshCw, ScrollText, Trash2 } from "lucide-react";
import { useState, type ReactNode } from "react";
import { FloatingTooltip } from "@/components/sieve/primitives/floating-tooltip";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Switch } from "@/components/ui/switch";
import { fetchWords, updatedText } from "@/core/custom-lists";
import { countText, groupState, isGated, listOn, type ListGroupId, type ListSelection } from "@/core/filter-lists";
import type { FilterList, FilterReport, ListFetch } from "@/data/protocol";

const GATED_TEXT = "Waiting on testing before it can be turned on";

/** A list's counts; a skipped count shows the parser's reasons in a tooltip. */
function Counts({ report }: { report: FilterReport | null }) {
  const [at, setAt] = useState<{ x: number; y: number } | null>(null);
  const reasons = Object.entries(report?.reasons ?? {});
  return (
    <>
      <span
        data-list-count=""
        className="tabular"
        tabIndex={reasons.length > 0 ? 0 : undefined}
        onPointerEnter={reasons.length > 0 ? (e) => setAt({ x: e.clientX, y: e.clientY }) : undefined}
        onPointerMove={reasons.length > 0 ? (e) => setAt({ x: e.clientX, y: e.clientY }) : undefined}
        onPointerLeave={() => setAt(null)}
        onFocus={
          reasons.length > 0
            ? (e) => {
                const box = e.currentTarget.getBoundingClientRect();
                setAt({ x: box.left, y: box.bottom });
              }
            : undefined
        }
        onBlur={() => setAt(null)}
      >
        {countText(report)}
      </span>
      {at && (
        <FloatingTooltip x={at.x} y={at.y} data-skip-reasons="">
          <ul className="flex flex-col gap-1">
            {reasons.map(([reason, n]) => (
              <li key={reason}>
                <span className="tabular">{n.toLocaleString("en-US")}</span> {reason}
              </li>
            ))}
          </ul>
        </FloatingTooltip>
      )}
    </>
  );
}

/** What the engine says of a list's copy: its counts, when it was updated, and why the last try failed. Nothing while it said nothing. */
export function ListStatusLine({ report, fetch, nowMs }: { report: FilterReport | null; fetch: ListFetch | null | undefined; nowMs: number }) {
  return (
    <span className="flex flex-col text-label text-on-surface-muted">
      <span>
        <Counts report={report} />
        {fetch && <span data-list-updated=""> · {updatedText(fetch, nowMs)}</span>}
      </span>
      {fetch?.lastError && (
        <span data-list-error="">
          {fetchWords(fetch.lastError)} <span className="font-mono text-mono">{fetch.lastError}</span>
        </span>
      )}
    </span>
  );
}

export interface ListActions {
  onRules?: () => void;
  onRefresh?: () => void;
  onRemove?: () => void;
}

/** A list's menu: what can be done to its copy. A disabled item says why in its `reason`. */
export function ListMenu({ title, actions, reason, disabled }: { title: string; actions: ListActions; reason: string | null; disabled: boolean }) {
  const item = (label: string, icon: ReactNode, run: (() => void) | undefined, needsEngine: boolean) =>
    run && (
      <DropdownMenuItem className="h-9 gap-3 rounded-sm px-3 text-body" disabled={needsEngine && reason !== null} onSelect={run}>
        {icon}
        {label}
      </DropdownMenuItem>
    );
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <IconButton label={`Actions for ${title}`} disabled={disabled}>
          <MoreVertical strokeWidth={1.75} />
        </IconButton>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-auto min-w-48">
        {item("View rules", <ScrollText strokeWidth={1.75} />, actions.onRules, true)}
        {item("Update now", <RefreshCw strokeWidth={1.75} />, actions.onRefresh, true)}
        {item("Remove", <Trash2 strokeWidth={1.75} />, actions.onRemove, false)}
        {reason !== null && (actions.onRules || actions.onRefresh) && <p className="max-w-64 px-3 py-2 text-label text-on-surface-muted">{reason}</p>}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** One list: its name, what it does, what the engine says of it, its menu and its switch. */
export function ListRow({
  list,
  selection,
  onList,
  actions,
  reason,
  disabled,
  nowMs,
  note,
}: {
  list: FilterList;
  selection: ListSelection;
  onList: (list: FilterList, on: boolean) => void;
  actions: ListActions;
  /** Why the engine cannot answer now, or null. */
  reason: string | null;
  disabled: boolean;
  nowMs: number;
  /** Words after the name, such as "Suggested for your language". */
  note?: string;
}) {
  const gated = isGated(list);
  return (
    <li className="flex min-h-11 items-start justify-between gap-3" data-list={list.id}>
      <div className="flex min-w-0 flex-1 flex-col">
        <span className="text-body text-on-surface break-words">
          {list.title}
          {note && <span className="text-label text-on-surface-muted"> {note}</span>}
        </span>
        {list.description && <span className="text-label text-on-surface-muted">{list.description}</span>}
        {gated ? <span className="text-label text-on-surface-muted">{GATED_TEXT}</span> : <ListStatusLine report={list.report} fetch={list.fetch} nowMs={nowMs} />}
      </div>
      <div className="flex shrink-0 items-center gap-1">
        {!gated && <ListMenu title={list.title} actions={actions} reason={reason} disabled={disabled} />}
        <Switch checked={listOn(list, selection)} disabled={disabled || gated} onCheckedChange={(on) => onList(list, on)} aria-label={list.title} />
      </div>
    </li>
  );
}

/** One group: its heading and what it is for, a switch over its lists when it has several, then each list. */
export function ListGroup({
  id,
  label,
  text,
  lists,
  selection,
  onList,
  onGroup,
  actionsOf,
  reason,
  disabled,
  nowMs,
  children,
}: {
  id: ListGroupId;
  label: string;
  text: string;
  lists: readonly FilterList[];
  selection: ListSelection;
  onList: (list: FilterList, on: boolean) => void;
  onGroup: (lists: readonly FilterList[], on: boolean) => void;
  actionsOf: (list: FilterList) => ListActions;
  reason: string | null;
  disabled: boolean;
  nowMs: number;
  /** Rows drawn by the caller instead (the language group's suggestions and its others). */
  children?: ReactNode;
}) {
  if (lists.length === 0) return null;
  const state = groupState(lists, selection);
  const groupSwitch = state.selectable > 1 && !children;
  return (
    <div className="flex flex-col gap-2" data-list-group={id}>
      <div className="flex min-h-11 items-center justify-between gap-4">
        <div className="min-w-0">
          <h3 className="text-body-strong text-on-surface">{label}</h3>
          <p className="text-label text-on-surface-muted">{text}</p>
          {/* One list says its own state: "1 of 1 on" would repeat its switch. */}
          {state.selectable > 1 && (
            <p className="text-label text-on-surface-muted tabular" data-group-state={state.kind}>
              {state.text}
            </p>
          )}
        </div>
        {groupSwitch && <Switch checked={state.kind === "all"} disabled={disabled} onCheckedChange={(on) => onGroup(lists, on)} aria-label={`All ${label.toLowerCase()} lists`} />}
      </div>
      {children ?? (
        <ul className="flex flex-col gap-3">
          {lists.map((l) => (
            <ListRow key={l.id} list={l} selection={selection} onList={onList} actions={actionsOf(l)} reason={reason} disabled={disabled} nowMs={nowMs} />
          ))}
        </ul>
      )}
    </div>
  );
}
