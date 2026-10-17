"use client";

import { Eye, EyeOff, MoreVertical } from "lucide-react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

const itemClass = "h-9 gap-3 rounded-sm px-3 text-body";

/** Overflow menu with the bulk on/off actions; each has undo. */
export function BulkMenu({ onSieveAll, onOffAll }: { onSieveAll: () => void; onOffAll: () => void }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <IconButton label="More app actions">
          <MoreVertical strokeWidth={1.75} />
        </IconButton>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-auto min-w-48 rounded-md bg-surface-3 p-1 shadow-l3">
        <DropdownMenuItem className={itemClass} onSelect={onSieveAll}>
          <Eye strokeWidth={1.75} />
          Sieve every app
        </DropdownMenuItem>
        <DropdownMenuItem className={itemClass} onSelect={onOffAll}>
          <EyeOff strokeWidth={1.75} />
          Turn every app off
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
