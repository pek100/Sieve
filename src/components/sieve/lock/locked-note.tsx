"use client";

import { Lock as LockIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { LOCKED_ROW_TEXT, LOCK_UNREADABLE_TEXT, type LockPhase } from "@/core/lock";
import { useLock } from "@/hooks/use-lock";

/** Why a control is shut by the password, with the way to open it. An unreadable file has no way: the words say so. */
export function LockedNote({ phase }: { phase: LockPhase }) {
  const { lock } = useLock();
  return (
    <p data-lock="password" className="flex flex-wrap items-center gap-2 pt-1 text-label text-on-surface-muted">
      <LockIcon aria-hidden="true" className="size-4 shrink-0 text-warning" strokeWidth={1.75} />
      <span className="min-w-0">{phase === "unreadable" ? LOCK_UNREADABLE_TEXT : LOCKED_ROW_TEXT}</span>
      {phase === "locked" && (
        <Button variant="ghost" size="sm" onClick={() => lock.ask()}>
          Unlock
        </Button>
      )}
    </p>
  );
}
