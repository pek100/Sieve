"use client";

import { Switch } from "@/components/ui/switch";
import { REGISTRY } from "@/core/settings/registry";
import { useSetting } from "@/hooks/use-sieve";
import { cn } from "@/lib/utils";

/**
 * The master switch: sampling on or off (setting sampling.enabled). It is
 * read only; turning it on never implies filtering. The one glow in the UI
 * breathes around it while it is on.
 */
export function MasterSwitch({ className }: { className?: string }) {
  const [enabled, setEnabled] = useSetting("sampling.enabled");
  const def = REGISTRY["sampling.enabled"];
  return (
    <label className={cn("inline-flex cursor-pointer items-center gap-2 text-label text-on-surface-muted", className)}>
      <span className="max-[640px]:sr-only">{def.label}</span>
      <Switch
        checked={enabled}
        onCheckedChange={(v) => void setEnabled(v)}
        aria-label={def.label}
        title={def.help}
        className={cn(enabled && "animate-breathe")}
      />
    </label>
  );
}
