"use client";

import { useState } from "react";
import { BentoGrid, BentoItem } from "@/components/sieve/shell/bento-grid";
import type { CardState } from "@/components/sieve/shell/card";
import { Page } from "@/components/sieve/shell/page";
import { StatusChip } from "@/components/sieve/shell/status-chip";
import type { SieveState } from "@/core/store";
import { useRuntime } from "@/hooks/sieve-provider";
import { useSetting, useSieve } from "@/hooks/use-sieve";
import { ChartCard } from "./chart-card";
import { Heatmap } from "./heatmap";
import { HomeBanner } from "./home-banner";
import { KpiBlock } from "./kpi-block";
import { PausePill } from "./pause-pill";
import { TopApps } from "./top-apps";
import { useDeclaredWindow, useHeat, useKpis, useSeriesModel, useViewMs, type WindowChoice } from "./use-home";

const selectHasData = (s: SieveState) => s.snapshots.length > 0;
const selectError = (s: SieveState) => s.status.error;

/**
 * Home: what apps are talking right now. Row 1 is the live per-app chart
 * (two thirds) and the 2 x 2 KPI block; row 2 is the top apps list and the
 * hour x weekday heatmap. At 1280 and wider the two rows share the window
 * height, so everything fits at 1280 x 800 without scrolling.
 */
export function HomeScreen() {
  const { source } = useRuntime();
  const [choice, setChoice] = useState<WindowChoice>("5m");
  useDeclaredWindow(choice);
  const view = useViewMs(choice);
  const model = useSeriesModel(view);
  const kpis = useKpis(view);
  const heat = useHeat();
  const hasData = useSieve(selectHasData);
  const error = useSieve(selectError);
  // The setting, not the phase: before settings load the poller is not started yet, which is not "off".
  const [enabled] = useSetting("sampling.enabled");

  // A source error before any data: every data card names the error and shows no numbers.
  const base: CardState = hasData
    ? { kind: "ready" }
    : error !== null
      ? { kind: "error", message: `The data source failed: ${error}` }
      : { kind: "loading" };
  const chartBase: CardState =
    !hasData && !enabled
      ? { kind: "empty", line: "Sieving is off", body: "Turn Sieving on in the top bar to see which apps are talking." }
      : base;
  const kpiPhase = hasData ? "ready" : base.kind === "loading" && enabled ? "loading" : "error";
  const heatBase: CardState =
    heat.kind === "ready" ? { kind: "ready" } : heat.kind === "loading" ? { kind: "loading" } : { kind: "error", message: heat.message };

  return (
    <Page
      title="Sieving now"
      action={
        <>
          <StatusChip announce={false} />
          <PausePill />
        </>
      }
    >
      <HomeBanner />
      <BentoGrid className="three:h-[max(40rem,calc(100dvh-var(--topbar-h)-var(--page-header-h)-var(--page-pad)))] three:grid-rows-[repeat(2,minmax(0,1fr))]">
        <BentoItem span="two-thirds" className="min-h-0">
          <ChartCard model={model} choice={choice} onChoice={setChoice} base={chartBase} />
        </BentoItem>
        <BentoItem span="third" className="min-h-0">
          <KpiBlock kpis={kpis} phase={kpiPhase} />
        </BentoItem>
        <BentoItem span="third" className="min-h-0">
          <TopApps slots={model.slots} base={base} />
        </BentoItem>
        <BentoItem span="two-thirds" className="min-h-0">
          <Heatmap
            grid={heat.kind === "ready" ? heat.grid : null}
            caption={source.kind === "tauri" ? "Since Sieve started" : "Last 4 weeks"}
            base={heatBase}
          />
        </BentoItem>
      </BentoGrid>
    </Page>
  );
}
