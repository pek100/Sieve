"use client";

import { useState } from "react";
import { FloatingTooltip } from "@/components/sieve/primitives/floating-tooltip";
import { Switch } from "@/components/ui/switch";
import { countText, groupState, isGated, listOn, type ListGroupId, type ListSelection } from "@/core/filter-lists";
import type { FilterList, FilterReport } from "@/data/protocol";

const GATED_TEXT = "Waiting on testing";

/** A list's counts; a skipped count shows the parser's reasons in a tooltip. */
function Counts({ report }: { report: FilterReport | null }) {
  const [at, setAt] = useState<{ x: number; y: number } | null>(null);
  const reasons = Object.entries(report?.reasons ?? {});
  return (
    <>
      <span
        data-list-count=""
        className="text-label text-on-surface-muted tabular"
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

/** One group: a switch over its lists, its state derived ("2 of 5 on"), then each list. A gated list is shown and cannot be turned on. */
export function ListGroup({
  id,
  label,
  lists,
  selection,
  onList,
  onGroup,
  disabled,
}: {
  id: ListGroupId;
  label: string;
  lists: readonly FilterList[];
  selection: ListSelection;
  onList: (list: FilterList, on: boolean) => void;
  onGroup: (lists: readonly FilterList[], on: boolean) => void;
  disabled: boolean;
}) {
  if (lists.length === 0) return null;
  const state = groupState(lists, selection);
  return (
    <div className="flex flex-col gap-1" data-list-group={id}>
      <div className="flex min-h-11 items-center justify-between gap-4">
        <div className="min-w-0">
          <h3 className="text-body-strong text-on-surface">{label}</h3>
          <p className="text-label text-on-surface-muted tabular" data-group-state={state.kind}>
            {state.text}
          </p>
        </div>
        <Switch
          checked={state.kind === "all"}
          disabled={disabled || state.selectable === 0}
          onCheckedChange={(on) => onGroup(lists, on)}
          aria-label={`All ${label.toLowerCase()} lists`}
        />
      </div>
      <ul className="flex flex-col gap-1">
        {lists.map((l) => (
          <li key={l.id} className="flex min-h-11 items-center justify-between gap-4" data-list={l.id}>
            <div className="flex min-w-0 flex-col">
              <span className="text-body text-on-surface break-words">{l.title}</span>
              {isGated(l) ? <span className="text-label text-on-surface-muted">{GATED_TEXT}</span> : <Counts report={l.report} />}
            </div>
            <Switch checked={listOn(l, selection)} disabled={disabled || isGated(l)} onCheckedChange={(on) => onList(l, on)} aria-label={l.title} />
          </li>
        ))}
      </ul>
    </div>
  );
}
