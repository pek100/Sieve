"use client";

import { Pause, Play } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { phase } from "@/core/store";
import { useRuntime } from "@/hooks/sieve-provider";
import { useSieve } from "@/hooks/use-sieve";

export const PAUSE_CHOICES = [
  { minutes: 5, label: "For 5 minutes" },
  { minutes: 15, label: "For 15 minutes" },
  { minutes: 60, label: "For 1 hour" },
] as const;

/**
 * Pause pill: pause sampling for 5, 15 or 60 minutes through the poller, or
 * resume. It only drives the poller; the paused banner on Home is derived
 * from status.pausedUntil (home-banner.tsx), so it is right whoever paused
 * (this pill, the tray) and after any navigation.
 */
export function PausePill() {
  const { poller } = useRuntime();
  const p = useSieve(phase);

  if (p === "paused") {
    return (
      <Button variant="default" onClick={() => poller.resume()}>
        <Play strokeWidth={1.75} />
        Resume
      </Button>
    );
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="secondary" disabled={p === "off"} title={p === "off" ? "Sieving is off" : undefined}>
          <Pause strokeWidth={1.75} />
          Pause
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-44 rounded-md bg-surface-3 p-1 shadow-l3">
        {PAUSE_CHOICES.map((c) => (
          <DropdownMenuItem key={c.minutes} onSelect={() => poller.pauseFor(c.minutes)} className="h-9 rounded-sm px-3 text-body">
            {c.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
