"use client";

import { ChartArea } from "lucide-react";
import { useState } from "react";
import { Segmented } from "@/components/sieve/primitives/segmented";
import { StateLayer } from "@/components/sieve/primitives/state-layer";
import { Card, type CardState } from "@/components/sieve/shell/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { SeriesDef, SeriesModel } from "@/core/series";
import { cn } from "@/lib/utils";
import { ActivityChart } from "./activity-chart";
import { seriesTone } from "./series-tone";
import { isHistoryWindow, WINDOWS, type WindowChoice } from "./use-home";

/**
 * Compact legend, the same look as the heatmap's (dot and caption text, no pill),
 * so it fits one line at desktop widths. Entries double as toggles: off shows a
 * hollow dot and a faint label.
 */
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
    <ul aria-label="Series" className="flex min-w-0 flex-wrap gap-x-3 gap-y-1">
      {series.map((s) => {
        const on = !hidden.has(s.key);
        const tone = seriesTone(s.slot);
        return (
          <li key={s.key} className="max-w-48 min-w-0">
            <button
              type="button"
              aria-pressed={on}
              title={on ? `Hide ${s.name}` : `Show ${s.name}`}
              onClick={() => onToggle(s.key)}
              className={cn(
                "relative inline-flex h-6 max-w-full items-center gap-2 overflow-hidden rounded-sm pr-1 text-caption transition-colors duration-(--motion-fast) ease-standard",
                on ? "text-on-surface-muted hover:text-on-surface" : "text-on-surface-faint",
              )}
            >
              <span
                aria-hidden="true"
                className={cn("size-2 shrink-0 rounded-full border-2", tone.border, on ? tone.bg : "bg-transparent")}
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
  loading,
  className,
}: {
  model: SeriesModel;
  choice: WindowChoice;
  onChoice: (c: WindowChoice) => void;
  /** Loading or error decided by the screen; ready means draw the data. */
  base: CardState;
  /** A period is being read: the chart keeps its series and span, with no points yet. */
  loading: boolean;
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
        ? isHistoryWindow(choice)
          ? {
              kind: "empty",
              line: "No history for this period yet",
              body: "Sieve keeps per-app counts while it samples. They show here once some are saved.",
            }
          : {
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
  const items = WINDOWS.map((w) => ({ value: w.value, label: w.label }));

  return (
    <Card
      title="Connections per app"
      icon={<ChartArea strokeWidth={1.75} />}
      tone="neutral"
      className={className}
      action={
        <>
          {/* Six choices fit a segmented control from 640 up; narrower, the same choice is a select. */}
          <Segmented label="Chart window" size="sm" items={items} value={choice} onChange={onChoice} className="max-[640px]:hidden" />
          <Select value={choice} onValueChange={(v) => onChoice(v as WindowChoice)}>
            <SelectTrigger aria-label="Chart window" className="hidden h-9 w-28 rounded-full bg-inset px-3 text-label max-[640px]:flex">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {items.map((i) => (
                <SelectItem key={i.value} value={i.value}>
                  {i.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </>
      }
      state={state}
    >
      <div className="flex min-h-0 flex-1 flex-col gap-2">
        <ChartLegend series={model.series} hidden={hidden} onToggle={toggle} />
        {/* Never keyed: a window switch rescales the same paths, so only the time range changes. */}
        <ActivityChart
          model={model}
          source={isHistoryWindow(choice) ? "history" : "live"}
          empty={loading ? null : isHistoryWindow(choice) ? "No history for this period yet" : "No samples in this window yet"}
          hidden={hidden}
          className="h-44 three:h-auto three:flex-1"
        />
      </div>
    </Card>
  );
}
