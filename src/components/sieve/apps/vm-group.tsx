"use client";

import { useState } from "react";
import { VM_GROUP_LABEL, VM_NOTE, VM_OFF_MEANS, type GuestRow } from "@/core/guests";
import { cn } from "@/lib/utils";
import { SectionHeader, type RowActions } from "./app-list";
import { AppToggle } from "./app-toggle";

const GROUP_ID = "apps-section-vm";

function VmRow({ row, actions }: { row: GuestRow; actions: Pick<RowActions, "isOn" | "setOn"> }) {
  const on = actions.isOn(row.key);
  const n = row.open;
  return (
    <li data-testid="vm-row" data-app={row.key} data-off={on ? undefined : ""} className="flex h-11 items-center gap-2">
      <span className="flex min-w-0 flex-1 flex-col pr-2">
        <span className={cn("truncate text-body-strong", on ? "text-on-surface" : "text-on-surface-muted")}>{row.name}</span>
        <span className="truncate text-caption text-on-surface-muted">{VM_NOTE}</span>
      </span>
      <span
        className={cn("tabular shrink-0 pr-2 text-label", n > 0 && on ? "text-on-surface" : "text-on-surface-faint")}
        title={`${n} active ${n === 1 ? "connection" : "connections"}`}
      >
        {n}
      </span>
      {/* The toggle is last, so it ends on the header actions' line like every app's. */}
      <AppToggle appName={row.name} on={on} onChange={(v) => actions.setOn(row.key, v)} offMeans={VM_OFF_MEANS} />
    </li>
  );
}

/**
 * "Virtual machines and WSL", above Mine, only once forwarded traffic was
 * seen. Flat: a label and rows. A row has no icon and no detail sheet, because
 * a VM has no exe or PID to show.
 */
export function VmGroup({ rows, actions }: { rows: readonly GuestRow[]; actions: Pick<RowActions, "isOn" | "setOn"> }) {
  const [open, setOpen] = useState(true);
  if (rows.length === 0) return null;
  return (
    <section aria-labelledby={`${GROUP_ID}-title`} className="flex flex-col" data-testid="vm-group">
      <SectionHeader id={GROUP_ID} label={VM_GROUP_LABEL} count={rows.length} open={open} onToggle={() => setOpen((o) => !o)} />
      {open && (
        <ul id={GROUP_ID} className="flex flex-col gap-1">
          {rows.map((r) => (
            <VmRow key={r.key} row={r} actions={actions} />
          ))}
        </ul>
      )}
    </section>
  );
}
