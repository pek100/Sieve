"use client";

import { CalendarDays } from "lucide-react";
import { useLayoutEffect, useMemo, useRef, useState, type FocusEvent, type KeyboardEvent, type RefObject } from "react";
import { FloatingTooltip } from "@/components/sieve/primitives/floating-tooltip";
import { Card, type CardState } from "@/components/sieve/shell/card";
import { HEAT_GAP_PX, heatStack, sharePercents, WEEKDAYS, type HeatCell, type HeatGrid } from "@/core/heat";
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

/** A tooltip to show: for which cell, beside which viewport point. */
interface Tip {
  index: number;
  x: number;
  y: number;
}

/** Keyboard moves: [hours, days]. Home and End go to the row's ends. */
const KEY_STEPS: Record<string, readonly [number, number] | undefined> = {
  ArrowLeft: [-1, 0],
  ArrowRight: [1, 0],
  ArrowUp: [0, -1],
  ArrowDown: [0, 1],
  Home: [-24, 0],
  End: [24, 0],
};

/** The cell index a keyboard move lands on, stopping at the map's edges. */
export function moveCell(index: number, [dh, dd]: readonly [number, number]): number {
  const day = Math.max(0, Math.min(6, Math.floor(index / 24) + dd));
  const hour = Math.max(0, Math.min(23, (index % 24) + dh));
  return day * 24 + hour;
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

/** Mean connections as said: whole numbers from 10 up, one decimal below. */
const amount = (x: number) => (x >= 10 ? Math.round(x) : Math.round(x * 10) / 10).toLocaleString();

/** What a cell says, in words: the tooltip and the accessible name both read this. */
export function cellSummary(c: HeatCell) {
  const pcts = sharePercents(c.mix);
  const parts = c.mix
    .map((m, i) => ({ key: m.key, name: m.name, slot: m.slot, share: m.share, pct: pcts[i] === 0 && m.share > 0 ? "<1%" : `${pcts[i]}%` }))
    .sort((a, b) => b.share - a.share);
  const amountLine =
    c.hours === 0 ? "No data for this hour yet" : c.total === 0 ? "No open connections" : `${amount(c.total)} open connections on average`;
  return { when: `${WEEKDAYS[c.day]} ${hh(c.hour)}`, amountLine, parts };
}

/** The accessible name of a cell, for example "Tue 14:00, 31 open connections on average: Chrome 41%, Slack 30%". */
export function cellLabel(c: HeatCell): string {
  const s = cellSummary(c);
  const mix = s.parts.map((p) => `${p.name} ${p.pct}`).join(", ");
  return `${s.when}, ${s.amountLine.charAt(0).toLowerCase()}${s.amountLine.slice(1)}${mix ? `: ${mix}` : ""}`;
}

/** The tooltip body: the hour, how busy, then who, largest first, with their colour dots. */
function HeatTip({ cell }: { cell: HeatCell }) {
  const s = cellSummary(cell);
  return (
    <div className="flex min-w-40 flex-col gap-2">
      <p className="text-caption text-on-surface-muted tabular">
        {s.when} to {hh((cell.hour + 1) % 24)}
      </p>
      <p className="text-label text-on-surface">{s.amountLine}</p>
      {s.parts.length > 0 && (
        <ul className="flex flex-col gap-1">
          {s.parts.map((p) => (
            <li key={p.key} className="flex items-center gap-2">
              <span aria-hidden="true" className={cn("size-2 shrink-0 rounded-full", seriesTone(p.slot).bg)} />
              <span className="min-w-0 flex-1 truncate text-on-surface-muted">{p.name}</span>
              <span className="text-on-surface tabular">{p.pct}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * The 168 cells: a quiet track each, and the stack on it. Each cell is an
 * image with its own accessible name; one of them (`active`) is the map's
 * single tab stop and the arrow keys move it. Pure of hover, so pointer moves
 * never rebuild it.
 */
function Cells({ grid, w, h, active }: { grid: HeatGrid; w: number; h: number; active: number }) {
  return grid.cells.map((c, i) => {
    const b = cellBox(c.day, c.hour, w, h);
    const bottom = b.y + b.h;
    const segments = heatStack(c, grid.max, b.h);
    return (
      <g
        key={c.day * 24 + c.hour}
        role="img"
        aria-label={cellLabel(c)}
        tabIndex={i === active ? 0 : -1}
        data-cell=""
        data-index={i}
        data-day={c.day}
        data-hour={c.hour}
        data-segments={segments.length}
        className="outline-none"
      >
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
  const [hover, setHover] = useState<Tip | null>(null);
  // Keyboard: the cell holding the tab stop, and the focused one (its tooltip sits beside it).
  const [active, setActive] = useState(0);
  const [focused, setFocused] = useState<Tip | null>(null);
  const busiest = grid && grid.max > 0 ? grid.cells.reduce((a, b) => (b.total > a.total ? b : a)) : null;
  const cells = useMemo(() => (grid ? <Cells grid={grid} w={w} h={h} active={active} /> : null), [grid, w, h, active]);
  const tip = hover ?? focused;
  const shown = grid && tip ? grid.cells[tip.index] : null;
  const shownBox = shown ? cellBox(shown.day, shown.hour, w, h) : null;

  const onKeyDown = (e: KeyboardEvent<SVGSVGElement>) => {
    const step = KEY_STEPS[e.key];
    if (!step) return;
    e.preventDefault();
    const next = moveCell(active, step);
    e.currentTarget.querySelector<SVGGElement>(`[data-index="${next}"]`)?.focus();
  };
  const onFocus = (e: FocusEvent<SVGSVGElement>) => {
    const index = Number((e.target as Element).getAttribute("data-index"));
    if (!Number.isInteger(index) || (e.target as Element).getAttribute("data-cell") === null) return;
    const r = (e.target as Element).getBoundingClientRect();
    setActive(index);
    setFocused({ index, x: r.right, y: r.bottom });
  };

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
                role="group"
                aria-label={`Connections by app, weekday and hour, ${caption.toLowerCase()}.${busiest ? ` Busiest: ${WEEKDAYS[busiest.day]} ${hh(busiest.hour)}.` : ""} Arrow keys move between hours and days.`}
                data-heat-plot=""
                onKeyDown={onKeyDown}
                onFocus={onFocus}
                onBlur={(e) => {
                  if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setFocused(null);
                }}
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
                {shownBox && (
                  // The pointed or focused cell: a ring outside it (a focus ring, not a separator).
                  <rect
                    aria-hidden="true"
                    data-heat-ring=""
                    x={shownBox.x - 1}
                    y={shownBox.y - 1}
                    width={shownBox.w + 2}
                    height={shownBox.h + 2}
                    rx={3}
                    className={cn("pointer-events-none fill-none", hover ? "stroke-on-surface-muted" : "stroke-ring")}
                    strokeWidth={hover ? 1 : 2}
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
            {tip && shown && (
              <FloatingTooltip x={tip.x} y={tip.y} data-heat-tooltip="" className="p-3">
                <HeatTip cell={shown} />
              </FloatingTooltip>
            )}
          </div>
          <HeatLegend series={grid.series} />
        </div>
      )}
    </Card>
  );
}
