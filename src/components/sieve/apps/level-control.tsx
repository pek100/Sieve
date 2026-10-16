"use client";

import { Segmented } from "@/components/sieve/primitives/segmented";
import { LEVELS, type Level } from "@/core/policy";
import { cn } from "@/lib/utils";

export const LEVEL_LABEL: Record<Level, string> = { off: "Off", watch: "Watch", sieve: "Sieve" };

/**
 * Per-app level: off, watch, sieve. A level above the ceiling is disabled and
 * carries its reason as the tooltip (and accessible description). `value` is
 * always the effective level, so nothing above the ceiling is ever shown.
 */
export function LevelControl({
  appName,
  value,
  lockedReason,
  onChange,
  compact = false,
  className,
}: {
  appName: string;
  value: Level;
  lockedReason: (level: Level) => string | null;
  onChange: (level: Level) => void;
  compact?: boolean;
  className?: string;
}) {
  const items = LEVELS.map((l) => {
    const reason = lockedReason(l);
    return { value: l, label: LEVEL_LABEL[l], disabled: reason !== null, hint: reason ?? undefined };
  });
  return (
    <Segmented
      items={items}
      value={value}
      onChange={onChange}
      label={`Level for ${appName}`}
      className={cn(compact && "shrink-0 [&>button]:h-7 [&>button]:px-2", className)}
    />
  );
}
