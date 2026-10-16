"use client";

import { phase, type Phase } from "@/core/store";
import { useSieve } from "@/hooks/use-sieve";
import { cn } from "@/lib/utils";

const COPY: Record<Phase, string> = {
  starting: "Starting",
  live: "Live",
  paused: "Paused",
  off: "Off",
  error: "No data",
};

const DOT: Record<Phase, string> = {
  starting: "bg-on-surface-faint",
  live: "bg-primary",
  paused: "bg-warning",
  off: "bg-on-surface-faint",
  error: "bg-blocked",
};

function clock(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/** Status chip with a live dot. Text says what sampling is doing; colour is never the only signal. */
export function StatusChip({ className }: { className?: string }) {
  const p = useSieve(phase);
  const pausedUntil = useSieve((s) => s.status.pausedUntil);
  const error = useSieve((s) => s.status.error);
  const text = p === "paused" && pausedUntil !== null ? `Paused until ${clock(pausedUntil)}` : COPY[p];
  return (
    <span
      role="status"
      aria-live="polite"
      title={p === "error" && error ? error : undefined}
      data-phase={p}
      className={cn(
        "inline-flex h-8 items-center gap-2 rounded-full bg-surface-2 px-3 text-label text-on-surface-muted",
        className,
      )}
    >
      <span aria-hidden="true" className="relative inline-flex size-2">
        {p === "live" && <span className="absolute inset-0 animate-ping rounded-full bg-primary opacity-60 motion-reduce:hidden" />}
        <span className={cn("relative inline-flex size-2 rounded-full", DOT[p])} />
      </span>
      <span className="max-[480px]:sr-only">{text}</span>
    </span>
  );
}
