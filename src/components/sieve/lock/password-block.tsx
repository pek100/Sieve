"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { LOCK_PHASE_TEXT, LOCK_SCOPE_TEXT, LOCK_UNREADABLE_TEXT } from "@/core/lock";
import { useLock } from "@/hooks/use-lock";
import { PasswordDialog, type PasswordAction } from "./password-dialog";

/** Settings > Password: where the password stands, what it stands up to, and what can be done now. */
export function PasswordBlock() {
  const { state, lock } = useLock();
  const [open, setOpen] = useState<PasswordAction | null>(null);
  const { phase } = state;
  return (
    <div className="flex flex-col gap-2" data-password-block="" data-lock-phase={phase}>
      <p role="status" className="text-body-strong text-on-surface">
        {LOCK_PHASE_TEXT[phase]}
      </p>
      <p className="text-label text-on-surface-muted">{phase === "unreadable" ? LOCK_UNREADABLE_TEXT : LOCK_SCOPE_TEXT}</p>
      <div className="flex flex-wrap items-center gap-2 pt-1">
        {phase === "none" && <Button onClick={() => setOpen("set")}>Set a password</Button>}
        {phase === "locked" && <Button onClick={() => lock.ask()}>Unlock</Button>}
        {phase === "unlocked" && (
          <>
            <Button variant="secondary" onClick={() => lock.lockNow()}>
              Lock now
            </Button>
            <Button variant="secondary" onClick={() => setOpen("change")}>
              Change password
            </Button>
            <Button variant="ghost" onClick={() => setOpen("remove")}>
              Remove password
            </Button>
          </>
        )}
      </div>
      {open && <PasswordDialog action={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
