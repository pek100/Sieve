"use client";

import { useState } from "react";
import { GridRegion, LayoutGrid } from "@/components/sieve/shell/layout-grid";
import type { CardState } from "@/components/sieve/shell/card";
import { Page } from "@/components/sieve/shell/page";
import type { SeriesModel } from "@/core/series";
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
  useSeriesSet,
  windowMs,
  type WindowChoice,
} from "./use-home";

const selectHasData = (s: SieveState) => s.snapshots.length > 0;
const selectError = (s: SieveState) => s.status.error;

/**
 * Home: what apps are talking right now, on the page grid in two columns
 * that run through both rows: 8 columns for the views over time (the
 * per-app chart, then the hour x weekday heatmap) and 4 for the numbers
 * about now (the 2 x 2 KPI block, then the top apps list). One split line
 * for the whole screen; below 960 everything stacks. The KPI block spans
 * the chart's header top to its plot's bottom. At 1280 and wider the two rows share the height
 * left under the header (Page fill) and the paused banner sits inside the
 * header row (Page notice), so everything fits at 1280 x 800 without
 * scrolling, paused or not. Sampling status lives once,
 * on the top bar's master switch; the header carries only the pause pill.
 */
export function HomeScreen() {
  const [choice, setChoice] = useState<WindowChoice>("5m");
  // History periods draw persisted history; the KPIs and top apps stay on the live session.
  const live = liveWindow(choice);
  // The ring always holds the whole session, the data every window shares: the series set
  // comes from it, and switching between live windows never finds the ring cut short.
  useDeclaredWindow("session");
  const set = useSeriesSet();
  const liveModel = useSeriesModel(windowMs(live), set);
  const kpis = useKpis(windowMs(live));
  const heat = useHeat();
  const past = useHistoryModel(choice, set);
  const historic = isHistoryWindow(choice);
  // While a period loads, the chart keeps its series and takes the period's span with no points yet:
  // only the time range changes, never a flash of a loading card (once there is a set to draw).
  const loadingPeriod: SeriesModel = { series: set.series, points: [], bucketMs: liveModel.bucketMs, windowMs: windowMs(choice), end: liveModel.end };
  const model = !historic ? liveModel : past.kind === "ready" ? past.model : loadingPeriod;
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
        ? set.series.length > 0
          ? { kind: "ready" }
          : { kind: "loading" }
        : { kind: "error", message: `History could not be read: ${past.message}` }
    : !hasData && !enabled
      ? { kind: "empty", line: "Sieving is off", body: "Turn Sieving on in the top bar to see which apps are talking." }
      : base;
  const kpiPhase = hasData ? "ready" : base.kind === "loading" && enabled ? "loading" : "error";
  const heatBase: CardState =
    heat.kind === "ready" ? { kind: "ready" } : heat.kind === "loading" ? { kind: "loading" } : { kind: "error", message: heat.message };

  return (
    <Page title="Sieving now" action={<PausePill />} notice={<HomeBanner />} fill>
      <LayoutGrid className="three:min-h-[34rem] three:flex-1 three:grid-rows-[repeat(2,minmax(0,1fr))]">
        <GridRegion span={8} className="min-h-0">
          <ChartCard
            model={model}
            choice={choice}
            onChoice={setChoice}
            base={chartBase}
            loading={historic && past.kind === "loading"}
            className="h-full"
          />
        </GridRegion>
        <GridRegion span={4} className="min-h-0">
          <KpiBlock kpis={kpis} phase={kpiPhase} />
        </GridRegion>
        <GridRegion span={8} className="min-h-0">
          <Heatmap
            className="h-full"
            grid={heat.kind === "ready" ? heat.grid : null}
            caption={heat.kind === "ready" ? heat.caption : ""}
            base={heatBase}
          />
        </GridRegion>
        <GridRegion span={4} className="min-h-0">
          <TopApps slots={set.slots} base={base} className="h-full" />
        </GridRegion>
      </LayoutGrid>
    </Page>
  );
}
