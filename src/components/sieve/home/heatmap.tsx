"use client";

import { CalendarDays } from "lucide-react";
import { useState } from "react";
import { FloatingTooltip } from "@/components/sieve/primitives/floating-tooltip";
import { Card, type CardState } from "@/components/sieve/shell/card";
import { WEEKDAYS, type HeatCell, type HeatGrid } from "@/core/heat";
import { cn } from "@/lib/utils";

/** Heat steps 0..3 on the mint ramp (tokens --heat-mint-0..3). */
const STEP_BG = ["bg-(--heat-mint-0)", "bg-(--heat-mint-1)", "bg-(--heat-mint-2)", "bg-(--heat-mint-3)"] as const;

const hh = (h: number) => `${String(h).padStart(2, "0")}:00`;

function describe(c: HeatCell): string {
  if (c.hours === 0) return `${WEEKDAYS[c.day]} ${hh(c.hour)}: no data yet`;
  return `${WEEKDAYS[c.day]} ${hh(c.hour)} to ${hh((c.hour + 1) % 24)}: about ${Math.round(c.value).toLocaleString()} connection samples per hour`;
}

/** Hour x weekday activity. Caption says how far back the data goes. */
export function Heatmap({
  grid,
  caption,
  base,
  className,
}: {
  grid: HeatGrid | null;
  caption: string;
  base: CardState;
  className?: string;
}) {
  const [hover, setHover] = useState<{ cell: HeatCell; x: number; y: number } | null>(null);
  const busiest = grid && grid.max > 0 ? grid.cells.reduce((a, b) => (b.value > a.value ? b : a)) : null;

  return (
    <Card
      title="When apps are busy"
      icon={<CalendarDays strokeWidth={1.75} />}
      className={className}
      state={base}
      action={<span className="text-caption text-on-surface-muted">{caption}</span>}
    >
      {!grid || grid.hours === 0 ? (
        <p className="py-4 text-body text-on-surface-muted">No activity recorded yet. The map fills in hour by hour.</p>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col gap-2">
          <div
            role="img"
            aria-label={`Activity by weekday and hour, ${caption.toLowerCase()}.${busiest ? ` Busiest: ${WEEKDAYS[busiest.day]} ${hh(busiest.hour)}.` : ""}`}
            className="relative grid h-44 min-h-0 grid-cols-[auto_repeat(24,minmax(0,1fr))] grid-rows-[repeat(7,minmax(0,1fr))_auto] gap-1 three:h-auto three:flex-1"
            onPointerLeave={() => setHover(null)}
          >
            {WEEKDAYS.map((d, day) => (
              <div key={d} className="contents">
                <span aria-hidden="true" data-day-label="" className="flex items-center pr-2 text-caption text-on-surface-faint">
                  {d}
                </span>
                {grid.cells.slice(day * 24, day * 24 + 24).map((c) => (
                  <span
                    key={c.hour}
                    data-step={c.step}
                    data-day={day}
                    data-hour={c.hour}
                    onPointerMove={(e) => setHover({ cell: c, x: e.clientX, y: e.clientY })}
                    className={cn("min-h-2 rounded-xs", STEP_BG[c.step])}
                  />
                ))}
              </div>
            ))}
            <span aria-hidden="true" />
            {Array.from({ length: 24 }, (_, h) => (
              <span key={h} aria-hidden="true" data-hour-label={h % 6 === 0 ? h : undefined} className="text-caption text-on-surface-faint tabular">
                {h % 6 === 0 ? h : ""}
              </span>
            ))}
            {/* In a portal, fixed, beside the pointer and kept inside the window: never widens the page. */}
            {hover && (
              <FloatingTooltip x={hover.x} y={hover.y} data-heat-tooltip="">
                {describe(hover.cell)}
              </FloatingTooltip>
            )}
          </div>
          <div aria-hidden="true" className="flex items-center justify-end gap-1 text-caption text-on-surface-faint">
            <span className="pr-1">Less</span>
            {STEP_BG.map((bg) => (
              <span key={bg} className={cn("size-3 rounded-xs", bg)} />
            ))}
            <span className="pl-1">More</span>
          </div>
        </div>
      )}
    </Card>
  );
}
