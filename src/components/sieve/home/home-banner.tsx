"use client";

import { Info, X } from "lucide-react";
import type { ReactNode } from "react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { Button } from "@/components/ui/button";
import { engineRoutes, engineStatus } from "@/core/engine";
import { linkHomeLine } from "@/core/link";
import type { SieveState } from "@/core/store";
import { useRuntime } from "@/hooks/sieve-provider";
import { useEngine, useNotices, useSieve } from "@/hooks/use-sieve";

const selectPausedUntil = (s: SieveState) => s.status.pausedUntil;

function clock(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function Banner({ text, tone = "warning", children, ...data }: { text: string; tone?: "warning" | "neutral"; children?: ReactNode } & { [k: `data-${string}`]: string }) {
  return (
    <div
      role="note"
      data-banner=""
      {...data}
      className="flex min-h-10 flex-wrap items-center gap-3 text-body text-on-surface"
    >
      <Info aria-hidden="true" className={`size-5 shrink-0 ${tone === "warning" ? "text-warning" : "text-on-surface-muted"}`} strokeWidth={1.75} />
      {/* A long notice keeps its width on a phone: the actions wrap under it instead of squeezing it. */}
      <p className="min-w-0 flex-1 basis-60">{text}</p>
      {children}
    </div>
  );
}

/**
 * The Home banner slot, mounted in Page's `notice` slot. The paused banner is
 * derived from status.pausedUntil, so it shows for as long as sampling is
 * paused (by the pill or the tray), survives navigating away and back, and
 * goes when sampling resumes. It has no action of its own: Resume is the
 * pill. Exiting through another device is derived the same way from the
 * engine's `link` fact: a short line while it is up, a notice while it cannot
 * be reached. Other banners come from the notice bus (B7, surface "banner").
 */
export function HomeBanner() {
  const { notices } = useRuntime();
  const pausedUntil = useSieve(selectPausedUntil);
  const banners = useNotices().filter((n) => n.surface === "banner");
  const e = useEngine();
  // Derived from the engine's link fact, as the paused line is from status: true for as long as it holds.
  const exit = linkHomeLine(engineStatus(e)?.link, engineRoutes(e));
  if (pausedUntil === null && banners.length === 0 && exit === null) return null;
  return (
    <div className="flex flex-col gap-2">
      {pausedUntil !== null && (
        <Banner text={`Sampling is paused until ${clock(pausedUntil)}. The chart and counts hold their last values.`} />
      )}
      {exit !== null && <Banner text={exit.text} tone={exit.tone} data-link-home={exit.tone} />}
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
