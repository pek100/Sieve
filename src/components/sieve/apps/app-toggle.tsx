"use client";

import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";

/**
 * What per-app Off does, said once (the switch's tooltip and accessible
 * description). Only what is true today: Sieve blocks nothing yet (the DNS
 * filter is hidden until engine slice 4), so Off only stops tracking. With
 * the engine, Off becomes a real per-app exemption (plan section 1.4).
 */
export const APP_OFF_MEANS = "Off: Sieve stops tracking and charting this app.";

/**
 * Per-app on/off: Sieve (on, the default) or Off. `on` is the user's choice
 * for this app; the global Sieving switch is shown on its own.
 */
export function AppToggle({
  appName,
  on,
  onChange,
  offMeans = APP_OFF_MEANS,
  className,
}: {
  appName: string;
  on: boolean;
  onChange: (on: boolean) => void;
  /** What Off does here, said once as the tooltip and accessible description. */
  offMeans?: string;
  className?: string;
}) {
  return (
    <Switch
      checked={on}
      onCheckedChange={onChange}
      aria-label={`Sieve ${appName}`}
      aria-description={offMeans}
      title={offMeans}
      data-app-on={on ? "" : undefined}
      className={cn("shrink-0", className)}
    />
  );
}
