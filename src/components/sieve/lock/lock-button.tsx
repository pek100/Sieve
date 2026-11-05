"use client";

import { Lock, LockOpen } from "lucide-react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { hasPassword } from "@/core/lock";
import { useLock } from "@/hooks/use-lock";

/** The top bar's lock, only while a password exists; hidden under 640 (the password block has the same actions). */
export function LockButton() {
  const { state, lock } = useLock();
  if (!hasPassword(state.phase)) return null;
  const locked = state.phase === "locked";
  return (
    <IconButton label={locked ? "Unlock settings" : "Lock now"} className="max-[640px]:hidden" onClick={() => (locked ? lock.ask() : lock.lockNow())}>
      {locked ? <Lock strokeWidth={1.75} /> : <LockOpen strokeWidth={1.75} />}
    </IconButton>
  );
}
