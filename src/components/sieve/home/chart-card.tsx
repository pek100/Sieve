"use client";

import { ChartArea } from "lucide-react";
import { useState } from "react";
import { Segmented } from "@/components/sieve/primitives/segmented";
import { StateLayer } from "@/components/sieve/primitives/state-layer";
import { Card, type CardState } from "@/components/sieve/shell/card";
import { Button } from "@/components/ui/button";
import type { SeriesDef, SeriesModel } from "@/core/series";
import { cn } from "@/lib/utils";
import { ActivityChart } from "./activity-chart";
import { seriesTone } from "./series-tone";
import { WINDOWS, windowMs, type WindowChoice } from "./use-home";

/** Legend chips double as toggles: off shows a hollow swatch and a muted label. */
export function ChartLegend({
  series,
  hidden,
  onToggle,
}: {
  series: readonly SeriesDef[];
  hidden: ReadonlySet<string>;
  onToggle: (key: string) => void;
}) {
  return (
    <ul aria-label="Series" className="flex flex-wrap gap-2">
      {series.map((s) => {
        const on = !hidden.has(s.key);
        const tone = seriesTone(s.slot);
        return (
          <li key={s.key}>
            <button
              type="button"
              aria-pressed={on}
              title={on ? `Hide ${s.name}` : `Show ${s.name}`}
              onClick={() => onToggle(s.key)}
              className={cn(
                "relative inline-flex h-7 max-w-40 items-center gap-2 overflow-hidden rounded-full bg-surface-2 px-3 text-label transition-colors duration-(--motion-fast) ease-standard",
                on ? "text-on-surface" : "text-on-surface-faint",
              )}
            >
              <span
                aria-hidden="true"
                className={cn("size-2.5 shrink-0 rounded-full border-2", tone.border, on ? tone.bg : "bg-transparent")}
              />
              <span className="truncate">{s.name}</span>
              <StateLayer />
            </button>
          </li>
        );
      })}
    </ul>
  );
}

/** The hero card: live per-app chart with window control and legend toggles. */
export function ChartCard({
  model,
  choice,
  onChoice,
  base,
  className,
}: {
  model: SeriesModel;
  choice: WindowChoice;
  onChoice: (c: WindowChoice) => void;
  /** Loading or error decided by the screen; ready means draw the data. */
  base: CardState;
  className?: string;
}) {
  const [hidden, setHidden] = useState<ReadonlySet<string>>(() => new Set());
  const toggle = (key: string) =>
    setHidden((h) => {
      const next = new Set(h);
      if (!next.delete(key)) next.add(key);
      return next;
    });

  const state: CardState =
    base.kind !== "ready"
      ? base
      : model.series.length === 0
        ? {
            kind: "empty",
            line: "Nothing is talking right now",
            body: "No app holds an open connection in this window.",
            action:
              choice !== "session" ? (
                <Button variant="secondary" onClick={() => onChoice("session")}>
                  Show the whole session
                </Button>
              ) : undefined,
          }
        : { kind: "ready" };

  return (
    <Card
      title="Connections per app"
      icon={<ChartArea strokeWidth={1.75} />}
      tone="neutral"
      className={className}
      action={
        <Segmented
          label="Chart window"
          items={WINDOWS.map((w) => ({ value: w.value, label: w.label }))}
          value={choice}
          onChange={onChoice}
        />
      }
      state={state}
    >
      <div className="flex min-h-0 flex-1 flex-col gap-3">
        <ChartLegend series={model.series} hidden={hidden} onToggle={toggle} />
        {/* Keyed by the window choice only: a view step on a live tick rescales the same paths. */}
        <ActivityChart
          key={choice}
          model={model}
          baseMs={windowMs(choice)}
          hidden={hidden}
          className="h-44 three:h-auto three:flex-1"
        />
      </div>
    </Card>
  );
}
