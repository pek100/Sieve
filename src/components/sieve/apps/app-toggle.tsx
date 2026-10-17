"use client";

import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";

/**
 * What per-app Off does, said once (the switch's tooltip and accessible
 * description). Honest about DNS: blocking is system wide, so Off cannot
 * exempt an app from it.
 */
export const APP_OFF_MEANS =
  "Off: Sieve stops tracking and charting this app. DNS blocking still covers it, because Windows sends every app's lookups through one service.";

/**
 * Per-app on/off: Sieve (on, the default) or Off. `on` is the user's choice
 * for this app; the global Sieving switch is shown on its own.
 */
export function AppToggle({
  appName,
  on,
  onChange,
  className,
}: {
  appName: string;
  on: boolean;
  onChange: (on: boolean) => void;
  className?: string;
}) {
  return (
    <Switch
      checked={on}
      onCheckedChange={onChange}
      aria-label={`Sieve ${appName}`}
      aria-description={APP_OFF_MEANS}
      title={APP_OFF_MEANS}
      data-app-on={on ? "" : undefined}
      className={cn("shrink-0", className)}
    />
  );
}
