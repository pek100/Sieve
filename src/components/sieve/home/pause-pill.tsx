"use client";

import { Pause, Play } from "lucide-react";
import { useEffect, useRef } from "react";
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

function clock(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/**
 * Pause pill: pause sampling for 5, 15 or 60 minutes through the poller, or
 * resume. While paused, a Home banner (notice bus, B7) says until when; it is
 * dismissed when sampling resumes, by hand or when the time is up.
 */
export function PausePill() {
  const { poller, notices, store } = useRuntime();
  const p = useSieve(phase);
  const banner = useRef<number | null>(null);

  useEffect(() => {
    if (p !== "paused" && banner.current !== null) {
      notices.dismiss(banner.current);
      banner.current = null;
    }
  }, [p, notices]);

  const pause = (minutes: number) => {
    poller.pauseFor(minutes);
    if (banner.current !== null) notices.dismiss(banner.current);
    const until = store.getState().status.pausedUntil;
    banner.current = notices.push({
      kind: "info",
      surface: "banner",
      text: `Sampling is paused${until === null ? "" : ` until ${clock(until)}`}. The chart and counts hold their last values.`,
      action: { label: "Resume now", run: () => poller.resume() },
    });
  };

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
          <DropdownMenuItem key={c.minutes} onSelect={() => pause(c.minutes)} className="h-9 rounded-sm px-3 text-body">
            {c.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
