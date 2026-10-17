"use client";

import { ListOrdered } from "lucide-react";
import { useMemo } from "react";
import { AppIcon } from "@/components/sieve/primitives/app-icon";
import { Card, type CardState } from "@/components/sieve/shell/card";
import { trackedSnapshot } from "@/core/apps";
import { SERIES_COUNT, tickCounts } from "@/core/series";
import { newest, type SieveState } from "@/core/store";
import { useIconExes } from "@/hooks/use-app-icon";
import { useSieve, useTracking } from "@/hooks/use-sieve";
import { cn } from "@/lib/utils";
import { seriesTone } from "./series-tone";

export interface TopApp {
  key: string;
  name: string;
  count: number;
  slot: number;
}

const selectNewest = (s: SieveState) => newest(s);

/** First letter or digit of a name, for the monogram tile. */
export function monogram(name: string): string {
  const m = name.match(/[\p{L}\p{N}]/u);
  return (m?.[0] ?? "?").toUpperCase();
}

/** Apps ranked by active connections now; tinted with their chart colour (Other tint when not charted). */
export function TopApps({ slots, base, className }: { slots: Readonly<Record<string, number>>; base: CardState; className?: string }) {
  const snap = useSieve(selectNewest);
  const { off } = useTracking();
  const exes = useIconExes();
  const apps = useMemo<TopApp[]>(() => {
    if (!snap) return [];
    // Apps turned off are not tracked (apps.trackedSnapshot).
    const c = tickCounts(trackedSnapshot(snap, off));
    return [...c.byApp.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, SERIES_COUNT)
      .map(([key, count]) => ({ key, count, name: c.names.get(key) ?? key, slot: slots[key] ?? 0 }));
  }, [snap, slots, off]);
  const top = Math.max(1, ...apps.map((a) => a.count));

  return (
    <Card title="Top apps" icon={<ListOrdered strokeWidth={1.75} />} className={className} state={base}>
      {apps.length === 0 ? (
        <p className="py-4 text-body text-on-surface-muted">No app has an open connection right now.</p>
      ) : (
        <ol className="flex flex-col">
          {apps.map((a) => {
            const tone = seriesTone(a.slot);
            return (
              <li key={a.key} data-app={a.key} className="flex h-9 items-center gap-3">
                <AppIcon exe={exes.get(a.key) ?? null}>
                  <span className={cn("inline-flex size-8 items-center justify-center rounded-sm text-label", tone.soft, tone.text)}>{monogram(a.name)}</span>
                </AppIcon>
                <div className="flex min-w-0 flex-1 flex-col gap-1">
                  <span className="truncate text-body-strong text-on-surface">{a.name}</span>
                  <span aria-hidden="true" className="h-1 overflow-hidden rounded-full bg-track">
                    <span
                      className={cn("block h-full rounded-full transition-[width] duration-(--motion-chart) ease-standard", tone.bg)}
                      style={{ width: `${(a.count / top) * 100}%` }}
                    />
                  </span>
                </div>
                <span data-count="" className="w-16 shrink-0 text-right text-label text-on-surface-muted tabular">
                  {a.count} <span className="sr-only">active connections</span>
                </span>
              </li>
            );
          })}
        </ol>
      )}
    </Card>
  );
}
