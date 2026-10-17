"use client";

import { Switch } from "@/components/ui/switch";
import { GLOBAL_SWITCH } from "@/core/policy";
import { REGISTRY } from "@/core/settings/registry";
import { phase, type Phase } from "@/core/store";
import { useSetting, useSieve } from "@/hooks/use-sieve";
import { cn } from "@/lib/utils";

const SPOKEN: Record<Phase, string> = {
  starting: "Starting",
  live: "Live",
  paused: "Paused",
  off: "Off",
  error: "No data",
};

function clock(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/**
 * The master switch: the global Sieving state (policy GLOBAL_SWITCH). Off
 * pauses sampling and puts DNS filtering into pass-through. The one glow in
 * the UI breathes around it while it is on.
 *
 * It is also the window's one status: there is no separate status chip (the
 * switch beside it said the same thing). `data-phase` carries the sampling
 * phase, and a screen-reader-only live region speaks it; a timed pause shows
 * on Home as the banner and the Resume pill.
 */
export function MasterSwitch({ className }: { className?: string }) {
  const [enabled, setEnabled] = useSetting(GLOBAL_SWITCH);
  const p = useSieve(phase);
  const pausedUntil = useSieve((s) => s.status.pausedUntil);
  const def = REGISTRY[GLOBAL_SWITCH];
  const spoken = p === "paused" && pausedUntil !== null ? `Paused until ${clock(pausedUntil)}` : SPOKEN[p];
  return (
    <label data-phase={p} className={cn("inline-flex cursor-pointer items-center gap-2 text-label text-on-surface-muted", className)}>
      <span className="max-[640px]:sr-only">{def.label}</span>
      <Switch
        checked={enabled}
        onCheckedChange={(v) => void setEnabled(v)}
        aria-label={def.label}
        title={def.help}
        className={cn(enabled && "animate-breathe")}
      />
      <span role="status" aria-live="polite" className="sr-only">
        {spoken}
      </span>
    </label>
  );
}
