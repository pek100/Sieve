"use client";

import { Switch } from "@/components/ui/switch";
import { GLOBAL_SWITCH } from "@/core/policy";
import { ON_FOR_NEW_INSTALLS, REGISTRY } from "@/core/settings/registry";
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
 * pauses sampling. The one glow in the UI breathes around it while it is on.
 *
 * It is also the window's one status: there is no separate status chip (the
 * switch beside it said the same thing). `data-phase` carries the sampling
 * phase, and a screen-reader-only live region speaks it; a timed pause shows
 * on Home as the banner and the Resume pill.
 */
export function MasterSwitch({ className }: { className?: string }) {
  const [enabled, setEnabled] = useSetting(GLOBAL_SWITCH);
  const [routing] = useSetting(ON_FOR_NEW_INSTALLS[0]);
  const [https] = useSetting(ON_FOR_NEW_INSTALLS[1]);
  const [content] = useSetting(ON_FOR_NEW_INSTALLS[2]);
  const p = useSieve(phase);
  const pausedUntil = useSieve((s) => s.status.pausedUntil);
  const def = REGISTRY[GLOBAL_SWITCH];
  const spoken = p === "paused" && pausedUntil !== null ? `Paused until ${clock(pausedUntil)}` : SPOKEN[p];
  // On, but not filtering everything it can: the track shows the logo's diagonal lines, and the
  // tooltip names what is off.
  const missing = ON_FOR_NEW_INSTALLS.filter((_, i) => ![routing, https, content][i]);
  const partial = enabled && missing.length > 0;
  const title = partial ? `${def.help} Off now: ${missing.map((k) => REGISTRY[k].label).join(", ")}.` : def.help;
  return (
    <label data-phase={p} data-coverage={enabled ? (partial ? "partial" : "full") : "off"} className={cn("inline-flex cursor-pointer items-center gap-2 text-label text-on-surface-muted", className)}>
      <span className="max-[640px]:sr-only">{def.label}</span>
      <Switch
        checked={enabled}
        onCheckedChange={(v) => void setEnabled(v)}
        aria-label={def.label}
        title={title}
        className={cn(enabled && "animate-breathe", partial && "switch-partial data-checked:bg-surface-3")}
      />
      <span role="status" aria-live="polite" className="sr-only">
        {spoken}
      </span>
    </label>
  );
}
