"use client";

import { CalendarDays } from "lucide-react";
import { useState } from "react";
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
      dense
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
                <span aria-hidden="true" className="flex items-center pr-2 text-caption text-on-surface-faint">
                  {d}
                </span>
                {grid.cells.slice(day * 24, day * 24 + 24).map((c) => (
                  <span
                    key={c.hour}
                    data-step={c.step}
                    title={describe(c)}
                    onPointerEnter={(e) => {
                      const el = e.currentTarget;
                      setHover({ cell: c, x: el.offsetLeft + el.offsetWidth / 2, y: el.offsetTop });
                    }}
                    className={cn("min-h-2 rounded-xs", STEP_BG[c.step])}
                  />
                ))}
              </div>
            ))}
            <span aria-hidden="true" />
            {Array.from({ length: 24 }, (_, h) => (
              <span key={h} aria-hidden="true" className="text-caption text-on-surface-faint tabular">
                {h % 6 === 0 ? h : ""}
              </span>
            ))}
            {hover && (
              <div
                role="tooltip"
                className="pointer-events-none absolute z-10 w-max max-w-64 -translate-x-1/2 -translate-y-[calc(100%+8px)] rounded-md bg-surface-3 px-3 py-2 text-label text-on-surface shadow-l3"
                style={{ left: hover.x, top: hover.y }}
              >
                {describe(hover.cell)}
              </div>
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
