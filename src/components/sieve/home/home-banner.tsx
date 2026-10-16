"use client";

import { Info, X } from "lucide-react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { Button } from "@/components/ui/button";
import { useRuntime } from "@/hooks/sieve-provider";
import { useNotices } from "@/hooks/use-sieve";

/** The Home banner slot: renders notices pushed with surface "banner" (B7). Mounted in Page's `notice` slot. */
export function HomeBanner() {
  const { notices } = useRuntime();
  const banners = useNotices().filter((n) => n.surface === "banner");
  if (banners.length === 0) return null;
  return (
    <div className="flex flex-col gap-2">
      {banners.map((n) => (
        <div
          key={n.id}
          role="note"
          data-banner=""
          className="flex min-h-12 items-center gap-3 rounded-full bg-surface-2 py-1 pr-1 pl-4 text-body text-on-surface shadow-l1"
        >
          <Info aria-hidden="true" className="size-5 shrink-0 text-warning" strokeWidth={1.75} />
          <p className="min-w-0 flex-1">{n.text}</p>
          {n.action && (
            <Button variant="ghost" size="sm" onClick={() => n.action?.run()}>
              {n.action.label}
            </Button>
          )}
          <IconButton label="Dismiss" onClick={() => notices.dismiss(n.id)}>
            <X strokeWidth={1.75} />
          </IconButton>
        </div>
      ))}
    </div>
  );
}
