"use client";

import { AppWindow, ArrowDownRight, ArrowUpRight, Cable, Globe, Minus, RadioTower } from "lucide-react";
import type { ReactNode } from "react";
import { IconTile, type IconTileTone } from "@/components/sieve/primitives/icon-tile";
import { CardBoundary } from "@/components/sieve/shell/card";
import { Skeleton } from "@/components/ui/skeleton";
import type { DeltaDir, Kpi, KpiId } from "@/core/kpis";
import { cn } from "@/lib/utils";
import { useTicker } from "./use-home";

/** Labels name connections, hosts or ports, never anything Sieve is not doing. */
export const KPI_COPY: Record<KpiId, { label: string; icon: ReactNode; tone: IconTileTone }> = {
  // The one accent container tile on Home.
  apps: { label: "Apps with connections", icon: <AppWindow strokeWidth={1.75} />, tone: "mint" },
  connections: { label: "Active connections", icon: <Cable strokeWidth={1.75} />, tone: "neutral" },
  hosts: { label: "Remote hosts", icon: <Globe strokeWidth={1.75} />, tone: "neutral" },
  ports: { label: "Listening ports", icon: <RadioTower strokeWidth={1.75} />, tone: "neutral" },
};

const DELTA_ICON: Record<DeltaDir, typeof Minus> = { up: ArrowUpRight, down: ArrowDownRight, flat: Minus };

/** Delta chip: direction by icon and sign, neutral tone (more connections is not good or bad). */
export function DeltaChip({ delta, dir, onAccent = false }: { delta: number; dir: DeltaDir; onAccent?: boolean }) {
  const Icon = DELTA_ICON[dir];
  const text = dir === "up" ? `+${delta}` : String(delta);
  const spoken = dir === "flat" ? "No change since the window start" : `${dir === "up" ? "Up" : "Down"} ${Math.abs(delta)} since the window start`;
  return (
    <span
      title={spoken}
      aria-label={spoken}
      data-dir={dir}
      className={cn(
        "inline-flex h-6 items-center gap-1 rounded-full px-2 text-label tabular",
        onAccent ? "bg-on-mint-container/10 text-on-mint-container" : "bg-surface-2 text-on-surface-muted",
      )}
    >
      <Icon aria-hidden="true" className="size-3.5" strokeWidth={1.75} />
      {text}
    </span>
  );
}

function Ticker({ value }: { value: number }) {
  const shown = useTicker(value);
  return <>{shown.toLocaleString()}</>;
}

function Tile({ id, kpi, phase }: { id: KpiId; kpi: Kpi | null; phase: "loading" | "error" | "ready" }) {
  const copy = KPI_COPY[id];
  const accent = copy.tone !== "neutral";
  return (
    <section
      aria-label={copy.label}
      data-kpi={id}
      className={cn(
        "flex min-w-0 flex-col gap-3 rounded-lg p-5 shadow-l1",
        accent ? "bg-mint-container text-on-mint-container" : "bg-surface-1 text-on-surface",
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <IconTile tone={accent ? "neutral" : copy.tone} className={cn(accent && "bg-on-mint-container/10 text-on-mint-container")}>
          {copy.icon}
        </IconTile>
        {phase === "ready" && kpi && <DeltaChip delta={kpi.delta} dir={kpi.dir} onAccent={accent} />}
      </div>
      <div className="flex min-w-0 flex-col gap-1">
        <p className={cn("text-label",accent ? "text-on-mint-container" : "text-on-surface-muted")}>{copy.label}</p>
        {phase === "loading" ? (
          <Skeleton className="h-8 w-16" />
        ) : phase === "error" || !kpi ? (
          <p className={cn("text-body", accent ? "text-on-mint-container" : "text-on-surface-muted")}>No data</p>
        ) : (
          <p className="text-kpi tabular" data-numeric="">
            <Ticker value={kpi.value} />
          </p>
        )}
      </div>
    </section>
  );
}

/** 2 x 2 KPI tiles. One error boundary for the block. */
export function KpiBlock({ kpis, phase, className }: { kpis: Kpi[] | null; phase: "loading" | "error" | "ready"; className?: string }) {
  const byId = new Map((kpis ?? []).map((k) => [k.id, k]));
  return (
    <CardBoundary title="Right now">
      <div aria-label="Right now" role="group" className={cn("grid h-full grid-cols-2 grid-rows-2 gap-4", className)}>
        {(Object.keys(KPI_COPY) as KpiId[]).map((id) => (
          <Tile key={id} id={id} kpi={byId.get(id) ?? null} phase={phase} />
        ))}
      </div>
    </CardBoundary>
  );
}
