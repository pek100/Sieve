"use client";

import { Eye, EyeOff, MoreVertical, RotateCcw } from "lucide-react";
import { useState } from "react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

const itemClass = "h-9 gap-3 rounded-sm px-3 text-body";

/** Overflow menu with the bulk level actions. Reset asks first; the other two have undo. */
export function BulkMenu({
  onWatchAll,
  onStopAll,
  onReset,
}: {
  onWatchAll: () => void;
  onStopAll: () => void;
  onReset: () => void;
}) {
  const [confirm, setConfirm] = useState(false);
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <IconButton label="More app actions">
            <MoreVertical strokeWidth={1.75} />
          </IconButton>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-auto min-w-48 rounded-md bg-surface-3 p-1 shadow-l3">
          <DropdownMenuItem className={itemClass} onSelect={onWatchAll}>
            <Eye strokeWidth={1.75} />
            Watch all
          </DropdownMenuItem>
          <DropdownMenuItem className={itemClass} onSelect={onStopAll}>
            <EyeOff strokeWidth={1.75} />
            Stop watching all
          </DropdownMenuItem>
          <DropdownMenuItem className={itemClass} onSelect={() => setConfirm(true)}>
            <RotateCcw strokeWidth={1.75} />
            Reset levels
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <Dialog open={confirm} onOpenChange={setConfirm}>
        <DialogContent className="bg-surface-3 text-on-surface">
          <DialogHeader>
            <DialogTitle className="text-title">Reset every app to watch?</DialogTitle>
            <DialogDescription className="text-body text-on-surface-muted">
              This forgets the level you picked for each app. Your added apps stay.
            </DialogDescription>
          </DialogHeader>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setConfirm(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                onReset();
                setConfirm(false);
              }}
            >
              Reset levels
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
