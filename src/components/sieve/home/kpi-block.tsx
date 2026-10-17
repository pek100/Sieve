"use client";

import { AppWindow, ArrowDownRight, ArrowUpRight, Cable, Globe, Minus, ShieldCheck, ShieldOff } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import { IconTile, type IconTileTone } from "@/components/sieve/primitives/icon-tile";
import { CardBoundary } from "@/components/sieve/shell/card";
import { Skeleton } from "@/components/ui/skeleton";
import { isFiltering } from "@/core/dns";
import type { DeltaDir, Kpi, KpiId } from "@/core/kpis";
import { useDns } from "@/hooks/use-sieve";
import { cn } from "@/lib/utils";
import { useTicker } from "./use-home";

/** Snapshot tiles name apps, connections or hosts: what Sieve watches, never a claim of filtering. */
export const KPI_COPY: Record<KpiId, { label: string; icon: ReactNode; tone: IconTileTone }> = {
  // The one accent container tile on Home.
  // Counts watched apps (level watch or sieve) with an active connection, not every app online.
  apps: { label: "Watched apps", icon: <AppWindow strokeWidth={1.75} />, tone: "mint" },
  connections: { label: "Active connections", icon: <Cable strokeWidth={1.75} />, tone: "neutral" },
  hosts: { label: "Remote hosts", icon: <Globe strokeWidth={1.75} />, tone: "neutral" },
};

/** Where the DNS filter is turned on. */
export const FILTERING_HREF = "/settings/#section-filtering";

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

/**
 * The DNS-derived tile: the filter's blocked lookups while it runs, "Off"
 * with the way to turn it on otherwise. It is the only Home tile that may
 * say "blocked", and only while the filter answers (law in home.test.tsx).
 * Lookups are counted for the whole computer: DNS cannot tell apps apart.
 */
function BlockedTile() {
  const dns = useDns();
  const on = isFiltering(dns);
  const blocked = dns.status?.counters.blocked ?? 0;
  const lookups = dns.status?.counters.queries ?? 0;
  const label = on ? "Blocked lookups" : "DNS filter";
  return (
    <section
      aria-label={label}
      data-kpi="blocked"
      data-dns-derived=""
      className="flex min-w-0 flex-col gap-3 rounded-lg bg-surface-1 p-5 text-on-surface shadow-l1"
    >
      <div className="flex items-center justify-between gap-2">
        <IconTile>{on ? <ShieldCheck strokeWidth={1.75} /> : <ShieldOff strokeWidth={1.75} />}</IconTile>
        {on && (
          <span className="inline-flex h-6 items-center rounded-full bg-surface-2 px-2 text-label text-on-surface-muted tabular">
            of {lookups.toLocaleString()}
          </span>
        )}
      </div>
      <div className="flex min-w-0 flex-col gap-1">
        <p className="text-label text-on-surface-muted">{label}</p>
        {on ? (
          <p className="text-kpi tabular" data-numeric="">
            <Ticker value={blocked} />
          </p>
        ) : (
          <p className="flex flex-wrap items-baseline gap-x-2 text-body">
            <span className="text-title text-on-surface-muted">Off</span>
            <Link href={FILTERING_HREF} className="text-label text-primary underline-offset-4 hover:underline">
              Turn on in Settings
            </Link>
          </p>
        )}
      </div>
    </section>
  );
}

/** 2 x 2 KPI tiles: three from snapshots, one from the DNS filter. One error boundary for the block. */
export function KpiBlock({ kpis, phase, className }: { kpis: Kpi[] | null; phase: "loading" | "error" | "ready"; className?: string }) {
  const byId = new Map((kpis ?? []).map((k) => [k.id, k]));
  return (
    <CardBoundary title="Right now">
      <div aria-label="Right now" role="group" className={cn("grid h-full grid-cols-2 grid-rows-2 gap-4", className)}>
        {(Object.keys(KPI_COPY) as KpiId[]).map((id) => (
          <Tile key={id} id={id} kpi={byId.get(id) ?? null} phase={phase} />
        ))}
        <BlockedTile />
      </div>
    </CardBoundary>
  );
}
