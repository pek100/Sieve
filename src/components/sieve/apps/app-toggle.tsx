"use client";

import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";

/**
 * What per-app Off does, said once (the switch's tooltip and accessible
 * description): tracking stops, and a routing engine relays the app untouched.
 */
export const APP_OFF_MEANS = "Off: Sieve stops tracking and charting this app, and its traffic is left alone.";

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
