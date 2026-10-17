"use client";

import { Info, X } from "lucide-react";
import type { ReactNode } from "react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { Button } from "@/components/ui/button";
import type { SieveState } from "@/core/store";
import { useRuntime } from "@/hooks/sieve-provider";
import { useNotices, useSieve } from "@/hooks/use-sieve";

const selectPausedUntil = (s: SieveState) => s.status.pausedUntil;

function clock(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function Banner({ text, children }: { text: string; children?: ReactNode }) {
  return (
    <div
      role="note"
      data-banner=""
      className="flex min-h-10 items-center gap-3 text-body text-on-surface"
    >
      <Info aria-hidden="true" className="size-5 shrink-0 text-warning" strokeWidth={1.75} />
      <p className="min-w-0 flex-1">{text}</p>
      {children}
    </div>
  );
}

/**
 * The Home banner slot, mounted in Page's `notice` slot. The paused banner is
 * derived from status.pausedUntil, so it shows for as long as sampling is
 * paused (by the pill or the tray), survives navigating away and back, and
 * goes when sampling resumes. It has no action of its own: Resume is the
 * pill. Other banners come from the notice bus (B7, surface "banner").
 */
export function HomeBanner() {
  const { notices } = useRuntime();
  const pausedUntil = useSieve(selectPausedUntil);
  const banners = useNotices().filter((n) => n.surface === "banner");
  if (pausedUntil === null && banners.length === 0) return null;
  return (
    <div className="flex flex-col gap-2">
      {pausedUntil !== null && (
        <Banner text={`Sampling is paused until ${clock(pausedUntil)}. The chart and counts hold their last values.`} />
      )}
      {banners.map((n) => (
        <Banner key={n.id} text={n.text}>
          {n.action && (
            <Button variant="ghost" size="sm" onClick={() => n.action?.run()}>
              {n.action.label}
            </Button>
          )}
          <IconButton label="Dismiss" onClick={() => notices.dismiss(n.id)}>
            <X strokeWidth={1.75} />
          </IconButton>
        </Banner>
      ))}
    </div>
  );
}
