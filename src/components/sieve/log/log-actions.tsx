"use client";

import { Bug, Copy, EyeOff, ShieldCheck, ShieldX, type LucideIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DropdownMenuItem } from "@/components/ui/dropdown-menu";
import { LOG_ACTION_TEXT, rowActions, type LogAction } from "@/core/log-actions";
import type { LogRow } from "@/data/protocol";

const ICONS: Record<LogAction, LucideIcon> = {
  copy_url: Copy,
  unblock: ShieldCheck,
  block: ShieldX,
  do_not_decrypt: EyeOff,
  report: Bug,
};

/**
 * A row's actions, one list for the row menu and the details sheet, so the two
 * can never offer different things. `kind` says which it is drawn as.
 */
export function LogActions({ row, kind, onAction }: { row: LogRow; kind: "menu" | "buttons"; onAction: (action: LogAction, row: LogRow) => void }) {
  return (
    <>
      {rowActions(row).map((action) => {
        const Icon = ICONS[action];
        return kind === "menu" ? (
          <DropdownMenuItem key={action} className="h-9 gap-3 rounded-sm px-3 text-body" onSelect={() => onAction(action, row)}>
            <Icon strokeWidth={1.75} />
            {LOG_ACTION_TEXT[action]}
          </DropdownMenuItem>
        ) : (
          <Button key={action} variant="secondary" onClick={() => onAction(action, row)}>
            <Icon strokeWidth={1.75} />
            {LOG_ACTION_TEXT[action]}
          </Button>
        );
      })}
    </>
  );
}
