"use client";

import { AppWindow, ArrowDownRight, ArrowUpRight, Cable, Globe, Minus, ShieldCheck, ShieldOff } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import { SectionIcon, type SectionIconTone } from "@/components/sieve/primitives/section-icon";
import { CardBoundary } from "@/components/sieve/shell/card";
import { Skeleton } from "@/components/ui/skeleton";
import { dnsPhase, isFiltering } from "@/core/dns";
import type { DeltaDir, Kpi, KpiId } from "@/core/kpis";
import { useDns } from "@/hooks/use-sieve";
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

/** Where the DNS filter is turned on. */
export const FILTERING_HREF = "/settings/#section-filtering";

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
    <section aria-label={copy.label} data-kpi={id} data-accent={accent ? "" : undefined} className="flex min-w-0 flex-col gap-1 text-on-surface">
      <p className="flex items-center gap-2 text-label text-on-surface-muted">
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
 * The DNS-derived tile: the filter's blocked lookups while it runs, "Paused"
 * while it passes everything through (global Sieving off), "Off" with the way
 * to turn it on otherwise. It is the only Home tile that may say "blocked",
 * and only while the filter blocks (law in home.test.tsx). Lookups are
 * counted for the whole computer: DNS cannot tell apps apart.
 */
function BlockedTile() {
  const dns = useDns();
  const on = isFiltering(dns);
  // Running in pass-through (global Sieving off): answering, blocking nothing.
  const paused = dnsPhase(dns) === "paused";
  const blocked = dns.status?.counters.blocked ?? 0;
  const lookups = dns.status?.counters.queries ?? 0;
  const label = on ? "Blocked lookups" : "DNS filter";
  return (
    <section aria-label={label} data-kpi="blocked" data-dns-derived="" className="flex min-w-0 flex-col gap-1 text-on-surface">
      <p className="flex items-center gap-2 text-label text-on-surface-muted">
        <SectionIcon size={16}>{on ? <ShieldCheck strokeWidth={1.75} /> : <ShieldOff strokeWidth={1.75} />}</SectionIcon>
        {label}
      </p>
      {on ? (
        <p className="flex flex-wrap items-baseline gap-x-3">
          <span className="text-kpi tabular" data-numeric="">
            <Ticker value={blocked} />
          </span>
          <span className="text-label text-on-surface-muted tabular">of {lookups.toLocaleString()}</span>
        </p>
      ) : paused ? (
        <p className="flex flex-wrap items-baseline gap-x-2 text-body" data-dns-paused="">
          <span className="text-title text-on-surface-muted">Paused</span>
          <span className="text-label text-on-surface-muted">Lookups pass through while Sieving is off</span>
        </p>
      ) : (
        <p className="flex flex-wrap items-baseline gap-x-2 text-body">
          <span className="text-title text-on-surface-muted">Off</span>
          <Link href={FILTERING_HREF} className="text-label text-primary underline-offset-4 hover:underline">
            Turn on in Settings
          </Link>
        </p>
      )}
    </section>
  );
}

/** 2 x 2 KPI tiles, flat: three from snapshots, one from the DNS filter. One error boundary for the block. */
export function KpiBlock({ kpis, phase, className }: { kpis: Kpi[] | null; phase: "loading" | "error" | "ready"; className?: string }) {
  const byId = new Map((kpis ?? []).map((k) => [k.id, k]));
  return (
    <CardBoundary title="Right now">
      <div aria-label="Right now" role="group" className={cn("grid h-full grid-cols-2 content-start gap-x-6 gap-y-8 pt-2", className)}>
        {(Object.keys(KPI_COPY) as KpiId[]).map((id) => (
          <Tile key={id} id={id} kpi={byId.get(id) ?? null} phase={phase} />
        ))}
        <BlockedTile />
      </div>
    </CardBoundary>
  );
}
