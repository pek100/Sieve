"use client";

import { useState } from "react";
import { BentoGrid, BentoItem } from "@/components/sieve/shell/bento-grid";
import type { CardState } from "@/components/sieve/shell/card";
import { Page } from "@/components/sieve/shell/page";
import type { SieveState } from "@/core/store";
import { useSetting, useSieve } from "@/hooks/use-sieve";
import { ChartCard } from "./chart-card";
import { Heatmap } from "./heatmap";
import { HomeBanner } from "./home-banner";
import { KpiBlock } from "./kpi-block";
import { PausePill } from "./pause-pill";
import { TopApps } from "./top-apps";
import {
  isHistoryWindow,
  liveWindow,
  useDeclaredWindow,
  useHeat,
  useHistoryModel,
  useKpis,
  useSeriesModel,
  useViewMs,
  type WindowChoice,
} from "./use-home";

const selectHasData = (s: SieveState) => s.snapshots.length > 0;
const selectError = (s: SieveState) => s.status.error;

/**
 * Home: what apps are talking right now. Row 1 is the live per-app chart
 * (two thirds) and the 2 x 2 KPI block; row 2 is the top apps list and the
 * hour x weekday heatmap. At 1280 and wider the two rows share the height
 * left under the header (Page fill) and the paused banner sits inside the
 * header row (Page notice), so everything fits at 1280 x 800 without
 * scrolling, paused or not. Sampling status lives once,
 * in the top bar chip; the header carries only the pause pill.
 */
export function HomeScreen() {
  const [choice, setChoice] = useState<WindowChoice>("5m");
  // History periods draw persisted history; the KPIs and top apps stay on the live session.
  const live = liveWindow(choice);
  useDeclaredWindow(live);
  const view = useViewMs(live);
  const liveModel = useSeriesModel(view);
  const kpis = useKpis(view);
  const heat = useHeat();
  const past = useHistoryModel(choice);
  const historic = isHistoryWindow(choice);
  const model = historic && past.kind === "ready" ? past.model : liveModel;
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
  const chartBase: CardState = historic
    ? past.kind === "ready"
      ? { kind: "ready" }
      : past.kind === "loading"
        ? { kind: "loading" }
        : { kind: "error", message: `History could not be read: ${past.message}` }
    : !hasData && !enabled
      ? { kind: "empty", line: "Sieving is off", body: "Turn Sieving on in the top bar to see which apps are talking." }
      : base;
  const kpiPhase = hasData ? "ready" : base.kind === "loading" && enabled ? "loading" : "error";
  const heatBase: CardState =
    heat.kind === "ready" ? { kind: "ready" } : heat.kind === "loading" ? { kind: "loading" } : { kind: "error", message: heat.message };

  return (
    <Page title="Sieving now" action={<PausePill />} notice={<HomeBanner />} fill>
      <BentoGrid className="three:min-h-[34rem] three:flex-1 three:grid-rows-[repeat(2,minmax(0,1fr))]">
        <BentoItem span="two-thirds" className="min-h-0">
          <ChartCard model={model} choice={choice} onChoice={setChoice} base={chartBase} />
        </BentoItem>
        <BentoItem span="third" className="min-h-0">
          <KpiBlock kpis={kpis} phase={kpiPhase} />
        </BentoItem>
        <BentoItem span="third" className="min-h-0">
          <TopApps slots={liveModel.slots} base={base} />
        </BentoItem>
        <BentoItem span="two-thirds" className="min-h-0">
          <Heatmap
            grid={heat.kind === "ready" ? heat.grid : null}
            caption={heat.kind === "ready" ? heat.caption : ""}
            base={heatBase}
          />
        </BentoItem>
      </BentoGrid>
    </Page>
  );
}
