"use client";

import type { ReactNode } from "react";
import { EmptyState } from "@/components/sieve/shell/empty-state";
import { Button } from "@/components/ui/button";
import { LOCK_UNREADABLE_TEXT, canWrite } from "@/core/lock";
import { useLock } from "@/hooks/use-lock";

/**
 * Hides its children until the settings password was given, for what is private
 * to read as well as to change (the log's browsing history). Settings and Filters
 * stay readable, so they do not use it. While the state is unknown nothing shows.
 */
export function LockGate({ children }: { children: ReactNode }) {
  const { state, lock } = useLock();
  if (canWrite(state.phase)) return <>{children}</>;
  if (state.phase === "checking") return null;
  if (state.phase === "unreadable") return <EmptyState line="This is locked" body={LOCK_UNREADABLE_TEXT} />;
  return <EmptyState line="This is locked" body="Your Sieve password opens it." action={<Button onClick={() => lock.ask()}>Unlock</Button>} />;
}
