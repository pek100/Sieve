"use client";

import { CalendarDays } from "lucide-react";
import { useLayoutEffect, useMemo, useRef, useState, type RefObject } from "react";
import { FloatingTooltip } from "@/components/sieve/primitives/floating-tooltip";
import { Card, type CardState } from "@/components/sieve/shell/card";
import { HEAT_GAP_PX, heatStack, WEEKDAYS, type HeatCell, type HeatGrid } from "@/core/heat";
import type { SeriesDef } from "@/core/series";
import { cn } from "@/lib/utils";
import { seriesTone } from "./series-tone";

/**
 * "When apps are busy": 7 weekdays x 24 hours, each cell a small stacked bar
 * of which apps held the connections in that hour.
 *
 * Encoding (dataviz): a VERTICAL stack whose HEIGHT is the cell's total
 * against the busiest cell, split bottom-up by app share in the chart's
 * series colours and stacking order (slot order, Other on top).
 * - Vertical, because the cells are about 20 px tall at every width but only
 *   9 px wide on a phone: seven segments fit up and down, not across. It also
 *   makes each weekday row read like the chart itself, time across and
 *   amount up.
 * - Height for busyness, not opacity: length is read far more precisely
 *   than fading, and fading the series hues would wash them towards the
 *   background and towards each other, so an app would no longer match its
 *   chart colour (who) exactly when its hour was quiet. Full-strength colour
 *   keeps "who" exact; the stack's height keeps "how busy" readable, and a
 *   row's silhouette is the day's rhythm.
 * Cells with no data are the quiet track alone, never a fake stack; slivers
 * under a pixel fold into Other (heatStack). All cells are rects in one SVG,
 * laid out on the same columns and rows as the HTML day and hour labels.
 */

/** The label grid's gap (gap-1), also between cells in the SVG. */
const GAP = 4;
/** Drawn size until the plot is measured (the first render, tests): the same cells, scaled by the viewBox. */
const FALLBACK = { w: 24 * 20 + 23 * GAP, h: 7 * 20 + 6 * GAP };

const hh = (h: number) => `${String(h).padStart(2, "0")}:00`;

interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** A cell's box in a plot of w x h px: the grid's 24 columns and 7 rows with GAP between, edges on whole pixels. */
export function cellBox(day: number, hour: number, w: number, h: number): Box {
  const cw = (w - 23 * GAP) / 24;
  const ch = (h - 6 * GAP) / 7;
  const x0 = Math.round(hour * (cw + GAP));
  const y0 = Math.round(day * (ch + GAP));
  return { x: x0, y: y0, w: Math.round(hour * (cw + GAP) + cw) - x0, h: Math.round(day * (ch + GAP) + ch) - y0 };
}

/** The cell under a point of the plot (plot px); a point in a gap belongs to the cell before it. */
export function cellAt(x: number, y: number, w: number, h: number): { day: number; hour: number } {
  const cw = (w - 23 * GAP) / 24;
  const ch = (h - 6 * GAP) / 7;
  const clamp = (v: number, n: number) => Math.max(0, Math.min(n - 1, v));
  return { hour: clamp(Math.floor(x / (cw + GAP)), 24), day: clamp(Math.floor(y / (ch + GAP)), 7) };
}

/** The element's content size, kept current by a ResizeObserver; null until measured. */
function useSize(ref: RefObject<HTMLElement | null>): { w: number; h: number } | null {
  const [size, setSize] = useState<{ w: number; h: number } | null>(null);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((entries) => {
      const r = entries[0]?.contentRect;
      if (!r || r.width <= 0 || r.height <= 0) return;
      setSize((s) => (s && s.w === r.width && s.h === r.height ? s : { w: r.width, h: r.height }));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [ref]);
  return size;
}

function describe(c: HeatCell): string {
  if (c.hours === 0) return `${WEEKDAYS[c.day]} ${hh(c.hour)}: no data yet`;
  return `${WEEKDAYS[c.day]} ${hh(c.hour)} to ${hh((c.hour + 1) % 24)}: about ${Math.round(c.total).toLocaleString()} active connections`;
}

/** The 168 cells: a quiet track each, and the stack on it. Pure of hover, so pointer moves never rebuild it. */
function Cells({ grid, w, h }: { grid: HeatGrid; w: number; h: number }) {
  return grid.cells.map((c) => {
    const b = cellBox(c.day, c.hour, w, h);
    const bottom = b.y + b.h;
    const segments = heatStack(c, grid.max, b.h);
    return (
      <g key={c.day * 24 + c.hour} data-cell="" data-day={c.day} data-hour={c.hour} data-segments={segments.length}>
        <rect x={b.x} y={b.y} width={b.w} height={b.h} rx={2} className={cn("fill-surface-2", c.hours === 0 && "opacity-50")} />
        {segments.map((s, i) => (
          <rect
            key={s.key}
            data-series={s.key}
            x={b.x}
            y={bottom - s.y1}
            width={b.w}
            // The surface gap sits under every segment but the bottom one.
            height={Math.max(1, s.y1 - s.y0 - (i > 0 ? HEAT_GAP_PX : 0))}
            rx={1}
            className={seriesTone(s.slot).fill}
          />
        ))}
      </g>
    );
  });
}

/**
 * The map's key: the chart's series in the chart's order and colours, as a
 * compact static list (the chart's chips are toggles; these are not, so they
 * do not look pressable).
 */
export function HeatLegend({ series }: { series: readonly SeriesDef[] }) {
  return (
    <ul aria-label="Apps in the map" className="flex min-w-0 flex-wrap gap-x-4 gap-y-1">
      {series.map((s) => (
        <li key={s.key} className="flex max-w-40 min-w-0 items-center gap-2 text-caption text-on-surface-muted">
          <span aria-hidden="true" className={cn("size-2 shrink-0 rounded-full", seriesTone(s.slot).bg)} />
          <span className="truncate">{s.name}</span>
        </li>
      ))}
    </ul>
  );
}

/** Hour x weekday activity by app. Caption says how far back the data goes. */
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
  const plotRef = useRef<HTMLDivElement>(null);
  const measured = useSize(plotRef);
  const { w, h } = measured ?? FALLBACK;
  const [hover, setHover] = useState<{ index: number; x: number; y: number } | null>(null);
  const busiest = grid && grid.max > 0 ? grid.cells.reduce((a, b) => (b.total > a.total ? b : a)) : null;
  const cells = useMemo(() => (grid ? <Cells grid={grid} w={w} h={h} /> : null), [grid, w, h]);
  const hovered = grid && hover ? grid.cells[hover.index] : null;
  const hoverBox = hovered ? cellBox(hovered.day, hovered.hour, w, h) : null;

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
            className="grid h-44 min-h-0 grid-cols-[auto_repeat(24,minmax(0,1fr))] grid-rows-[repeat(7,minmax(0,1fr))_auto] gap-1 three:h-auto three:flex-1"
          >
            {WEEKDAYS.map((d, day) => (
              <span
                key={d}
                aria-hidden="true"
                data-day-label=""
                style={{ gridColumn: 1, gridRow: day + 1 }}
                className="flex items-center pr-2 text-caption text-on-surface-faint"
              >
                {d}
              </span>
            ))}
            {/* The plot spans the 24 hour columns and 7 day rows; the SVG draws the cells on those same lines. */}
            <div ref={plotRef} style={{ gridColumn: "2 / -1", gridRow: "1 / 8" }} className="relative min-h-0 min-w-0">
              <svg
                aria-hidden="true"
                data-heat-plot=""
                viewBox={`0 0 ${w} ${h}`}
                preserveAspectRatio="none"
                className="absolute inset-0 size-full overflow-visible"
                onPointerMove={(e) => {
                  const r = e.currentTarget.getBoundingClientRect();
                  if (r.width <= 0 || r.height <= 0) return;
                  const at = cellAt(((e.clientX - r.left) * w) / r.width, ((e.clientY - r.top) * h) / r.height, w, h);
                  setHover({ index: at.day * 24 + at.hour, x: e.clientX, y: e.clientY });
                }}
                onPointerLeave={() => setHover(null)}
              >
                {cells}
                {hoverBox && (
                  <rect
                    aria-hidden="true"
                    x={hoverBox.x - 0.5}
                    y={hoverBox.y - 0.5}
                    width={hoverBox.w + 1}
                    height={hoverBox.h + 1}
                    rx={2.5}
                    className="pointer-events-none fill-none stroke-on-surface-muted"
                    strokeWidth={1}
                  />
                )}
              </svg>
            </div>
            {Array.from({ length: 24 }, (_, hr) => (
              <span
                key={hr}
                aria-hidden="true"
                data-hour-label={hr % 6 === 0 ? hr : undefined}
                style={{ gridColumn: hr + 2, gridRow: 8 }}
                className="text-caption text-on-surface-faint tabular"
              >
                {hr % 6 === 0 ? hr : ""}
              </span>
            ))}
            {/* In a portal, fixed, beside the pointer and kept inside the window: never widens the page. */}
            {hover && hovered && (
              <FloatingTooltip x={hover.x} y={hover.y} data-heat-tooltip="">
                {describe(hovered)}
              </FloatingTooltip>
            )}
          </div>
          <HeatLegend series={grid.series} />
        </div>
      )}
    </Card>
  );
}
