"use client";

import { AppWindow, ArrowDownRight, ArrowUpRight, Cable, Cpu, Globe, Minus } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import { SectionIcon, type SectionIconTone } from "@/components/sieve/primitives/section-icon";
import { CardBoundary } from "@/components/sieve/shell/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ENGINE_HREF, ENGINE_STATE_TEXT, enginePhase } from "@/core/engine";
import type { DeltaDir, Kpi, KpiId } from "@/core/kpis";
import { useEngine } from "@/hooks/use-sieve";
import { cn } from "@/lib/utils";
import { useTicker } from "./use-home";

/** Snapshot tiles name apps, connections or hosts: what Sieve tracks, never a claim of filtering. */
export const KPI_COPY: Record<KpiId, { label: string; icon: ReactNode; tone: SectionIconTone }> = {
  // The one accent tile on Home: its number is mint (no filled background).
  // Counts sieved apps (effectively on: global and per app) with an active connection, not every app online.
  apps: { label: "Sieved apps", icon: <AppWindow strokeWidth={1.75} />, tone: "mint" },
  connections: { label: "Active connections", icon: <Cable strokeWidth={1.75} />, tone: "neutral" },
  hosts: { label: "Remote hosts", icon: <Globe strokeWidth={1.75} />, tone: "neutral" },
};

const DELTA_ICON: Record<DeltaDir, typeof Minus> = { up: ArrowUpRight, down: ArrowDownRight, flat: Minus };

/** Delta: direction by icon and sign, neutral tone (more connections is not good or bad). Plain text, no chip. */
export function DeltaChip({ delta, dir }: { delta: number; dir: DeltaDir }) {
  const Icon = DELTA_ICON[dir];
  const text = dir === "up" ? `+${delta}` : String(delta);
  const spoken = dir === "flat" ? "No change since the window start" : `${dir === "up" ? "Up" : "Down"} ${Math.abs(delta)} since the window start`;
  return (
    <span title={spoken} aria-label={spoken} data-dir={dir} className="inline-flex items-center gap-1 text-label text-on-surface-muted tabular">
      <Icon aria-hidden="true" className="size-3.5" strokeWidth={1.75} />
      {text}
    </span>
  );
}

function Ticker({ value }: { value: number }) {
  const shown = useTicker(value);
  return <>{shown.toLocaleString()}</>;
}

/** One KPI, flat: icon and label on a line, the number under it, the delta beside the number. */
function Tile({ id, kpi, phase }: { id: KpiId; kpi: Kpi | null; phase: "loading" | "error" | "ready" }) {
  const copy = KPI_COPY[id];
  const accent = copy.tone === "mint";
  return (
    <section aria-label={copy.label} data-kpi={id} data-accent={accent ? "" : undefined} className="flex min-w-0 flex-col text-on-surface">
      <p data-kpi-label="" className="flex h-(--section-header-h) items-center gap-2 text-label text-on-surface-muted">
        <SectionIcon size={16} tone={copy.tone}>
          {copy.icon}
        </SectionIcon>
        {copy.label}
      </p>
      {phase === "loading" ? (
        <Skeleton className="h-8 w-16" />
      ) : phase === "error" || !kpi ? (
        <p className="text-body text-on-surface-muted">No data</p>
      ) : (
        <p className="flex flex-wrap items-baseline gap-x-3">
          <span className={cn("text-kpi tabular", accent && "text-primary")} data-numeric="">
            <Ticker value={kpi.value} />
          </span>
          <DeltaChip delta={kpi.delta} dir={kpi.dir} />
        </p>
      )}
    </section>
  );
}

/**
 * The engine tile: what Sieve's filtering engine is, from facts only (the
 * engine controller's probe: Not installed, Not running, Installed, not
 * filtering, ...), with the way to Settings > Engine. It replaced the DNS
 * filter's tile on 2026-10-18, when the app-hosted DNS filter became
 * unavailable until the engine's slice 4. It says nothing about blocking:
 * nothing Home shows is blocked until the engine filters.
 */
function EngineTile() {
  const phase = enginePhase(useEngine());
  return (
    <section aria-label="Engine" data-kpi="engine" data-engine-phase={phase} className="flex min-w-0 flex-col text-on-surface">
      <p data-kpi-label="" className="flex h-(--section-header-h) items-center gap-2 text-label text-on-surface-muted">
        <SectionIcon size={16} tone={phase === "filtering" ? "mint" : "neutral"}>
          <Cpu strokeWidth={1.75} />
        </SectionIcon>
        Engine
      </p>
      <p className="flex flex-wrap items-baseline gap-x-2 text-body">
        <span className="text-title text-on-surface-muted" data-engine-state="">
          {ENGINE_STATE_TEXT[phase]}
        </span>
        <Link href={ENGINE_HREF} className="text-label text-primary underline-offset-4 hover:underline">
          Details in Settings
        </Link>
      </p>
    </section>
  );
}

/** 2 x 2 KPI tiles, flat: three from snapshots, one from the engine. One error boundary for the block. */
export function KpiBlock({ kpis, phase, className }: { kpis: Kpi[] | null; phase: "loading" | "error" | "ready"; className?: string }) {
  const byId = new Map((kpis ?? []).map((k) => [k.id, k]));
  return (
    <CardBoundary title="Right now">
      <div
        aria-label="Right now"
        role="group"
        className={cn(
          // Beside the chart (960 up) the block runs from the chart header's top to the plot's bottom:
          // the label rows match the header height, the second row sits on the bottom, and the
          // block keeps the chart's time axis row free under it.
          "grid h-full grid-cols-2 content-start gap-x-(--gutter) gap-y-6 two:content-between two:pb-(--chart-axis-h)",
          className,
        )}
      >
        {(Object.keys(KPI_COPY) as KpiId[]).map((id) => (
          <Tile key={id} id={id} kpi={byId.get(id) ?? null} phase={phase} />
        ))}
        <EngineTile />
      </div>
    </CardBoundary>
  );
}
