"use client";

import { useLayoutEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { createPortal } from "react-dom";
import { AppIcon } from "@/components/sieve/primitives/app-icon";
import { niceCeiling, OTHER_KEY, stackSeries, type SeriesModel } from "@/core/series";
import { useIconExes } from "@/hooks/use-app-icon";
import { cn } from "@/lib/utils";
import { placeTooltip } from "@/components/sieve/primitives/floating-tooltip";
import { seriesTone } from "./series-tone";

/**
 * Stacked area chart of active connections per app.
 *
 * Hand-drawn SVG rather than Recharts: Recharts remounts its area paths on
 * every data change, and Home needs live ticks and window switches that keep
 * the same path nodes and never re-grow from zero. How it moves:
 * - x is absolute time from an origin fixed for the life of the mount, in a
 *   fixed unit (UNIT_MS spans W). The window (`model.windowMs`, ending at
 *   `model.end`) lives only in the plot group's transform: translateX puts
 *   `end` at the right edge, scaleX stretches UNIT_MS onto the window. A tick
 *   appends a vertex and slides; switching the window changes the scale and
 *   the offset in the same transform transition (--motion-chart), on the same
 *   path nodes, so the plot keeps its size and place and only the time range
 *   changes. Nothing keys or remounts this component.
 * - When the bucket times did not change (a series toggled, the open bucket
 *   of a long window updated) the path `d` morphs over --motion-chart instead.
 * - Where the data starts after the window does (Sieve started, or history
 *   begins, inside it), a faint boundary says so in the plot.
 * - The first render draws the data as is. Reduced motion sets
 *   --motion-chart to 0, so both become instant.
 */

const W = 1000;
const H = 200;
/** The x unit: one hour spans W. Windows run from 5 min (scale 12) to 14 d (scale 1/336). */
const UNIT_MS = 3_600_000;

const fmt1 = (x: number) => (Math.round(x * 10) / 10).toString();
/** x keeps three decimals: the group scales it by up to 12 (5 min). */
const fmtX = (x: number) => (Math.round(x * 1000) / 1000).toString();

const DAY = 86_400_000;

/** A time label sized to the span: seconds for live minutes, the weekday once a span passes a day. */
function clock(ms: number, seconds = false, spanMs = 0): string {
  const d = new Date(ms);
  const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: seconds && spanMs <= DAY ? "2-digit" : undefined });
  return spanMs > DAY ? `${d.toLocaleDateString([], { month: "short", day: "numeric" })}, ${time}` : time;
}

/** The plot group's transform: `end` at the right edge, the window stretched across the plot. */
export function plotTransform(end: number, origin: number, windowMs: number): { tx: number; scale: number } {
  const scale = UNIT_MS / windowMs;
  return { tx: W - (end - origin) * (W / UNIT_MS) * scale, scale };
}

/** Where the data starts, as a fraction of the plot from the left, or null when it covers the window. */
export function dataStart(firstT: number | undefined, end: number, windowMs: number, bucketMs: number): number | null {
  if (firstT === undefined) return null;
  const f = (firstT - (end - windowMs)) / windowMs;
  // Within a bucket of the left edge the data covers the window.
  return firstT - (end - windowMs) <= bucketMs ? null : Math.min(1, f);
}
export function ActivityChart({
  model,
  source,
  empty,
  hidden,
  className,
}: {
  model: SeriesModel;
  /** Live samples or saved history: names the boundary and the no-data note. */
  source: "live" | "history";
  /** Said in the plot when the window has no points (null while that is expected, such as a read in flight). */
  empty: string | null;
  hidden: ReadonlySet<string>;
  className?: string;
}) {
  const { layers, max } = useMemo(() => stackSeries(model, hidden), [model, hidden]);
  const pts = model.points;
  const end = model.end;
  // Fixed at the first end seen, for the life of this mount.
  const [fixedOrigin, setOrigin] = useState<number | null>(end > 0 ? end : null);
  if (fixedOrigin === null && end > 0) setOrigin(end);
  const origin = fixedOrigin ?? end;
  const yMax = niceCeiling(max);
  const kx = W / UNIT_MS;
  const xs = pts.map((p) => (p.t - origin) * kx);
  const { tx, scale } = plotTransform(end, origin, model.windowMs);
  const start = dataStart(pts[0]?.t, end, model.windowMs, model.bucketMs);
  const startLabel =
    start === null ? null : `${source === "live" ? "Sieve started" : "Saved from"} ${clock(pts[0].t, false, model.windowMs)}`;
  const y = (v: number) => H - (v / yMax) * H;

  const paths = layers.map((l) => {
    // No points yet (a period being read): a degenerate path keeps the node, never an invalid `d`.
    if (xs.length === 0) return { key: l.key, area: `M0 ${H}`, line: `M0 ${H}` };
    const upper = xs.map((x, j) => `${fmtX(x)} ${fmt1(y(l.upper[j]))}`);
    const lower = xs.map((x, j) => `${fmtX(x)} ${fmt1(y(l.lower[j]))}`).reverse();
    return {
      key: l.key,
      area: `M${upper.join("L")}L${lower.join("L")}Z`,
      line: `M${upper.join("L")}`,
    };
  });

  // Mark ticks that moved the bucket times, so paths jump (the group slides)
  // instead of morphing vertex by vertex. Runs before paint, after React set `d`.
  const svgRef = useRef<SVGSVGElement>(null);
  const lastTimes = useRef("");
  const times = `${pts[0]?.t}|${pts.length}|${model.bucketMs}`;
  useLayoutEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    if (lastTimes.current !== "" && lastTimes.current !== times) svg.setAttribute("data-sliding", "");
    else svg.removeAttribute("data-sliding");
    lastTimes.current = times;
  });

  // Crosshair: the pointer's fraction across the plot, mapped to the nearest bucket each render.
  const [hoverF, setHoverF] = useState<number | null>(null);
  // The pointer in viewport coordinates: the tooltip follows it, in a portal with fixed
  // positioning, so neither the plot nor any parent's overflow can clip it.
  const pointer = useRef({ x: 0, y: 0 });
  const tipRef = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const tip = tipRef.current;
    if (tip) placeTooltip(tip, pointer.current.x, pointer.current.y);
  });
  const hover = useMemo(() => {
    if (hoverF === null || pts.length === 0) return null;
    const t = end - (1 - hoverF) * model.windowMs;
    let best = 0;
    for (let j = 1; j < pts.length; j++) if (Math.abs(pts[j].t - t) < Math.abs(pts[best].t - t)) best = j;
    const f = 1 - (end - pts[best].t) / model.windowMs;
    // Left of where the data starts there is nothing to show.
    return f < 0 || (start !== null && hoverF < start - 0.01) ? null : { index: best, f };
  }, [hoverF, pts, end, model.windowMs, start]);

  const exes = useIconExes();
  const visible = model.series.filter((s) => !hidden.has(s.key));
  const now = pts.length ? pts[pts.length - 1].values : {};
  const summary = [...visible]
    .sort((a, b) => (now[b.key] ?? 0) - (now[a.key] ?? 0))
    .slice(0, 3)
    .map((s) => `${s.name} ${fmt1(now[s.key] ?? 0)}`)
    .join(", ");

  return (
    <div className={cn("flex min-h-0 flex-col", className)}>
      <div
        className="relative min-h-0 flex-1 overflow-hidden"
        onPointerMove={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          pointer.current = { x: e.clientX, y: e.clientY };
          if (r.width > 0) setHoverF(Math.min(1, Math.max(0, (e.clientX - r.left) / r.width)));
          // Same bucket, new spot: move the tooltip without a render.
          const tip = tipRef.current;
          if (tip) placeTooltip(tip, e.clientX, e.clientY);
        }}
        onPointerLeave={() => setHoverF(null)}
      >
        {/* Grid lines and y labels; the zero line is the plot's bottom edge (drawn, not a border, so the plot ends exactly there). */}
        {[0.5, 1].map((g) => (
          <div key={g} aria-hidden="true" className="pointer-events-none absolute inset-x-0 h-px bg-outline/60" style={{ top: `${(1 - g) * 100}%` }}>
            <span className="absolute top-1 left-2 text-caption text-on-surface-faint tabular">{fmt1(yMax * g)}</span>
          </div>
        ))}
        <div aria-hidden="true" className="pointer-events-none absolute inset-x-0 bottom-0 h-px bg-outline" />
        {start !== null && (
          // Before this line there is no data: Sieve was not running (live), or nothing was saved yet (history).
          <div aria-hidden="true" data-data-start="" className="pointer-events-none absolute inset-y-0 left-0 transition-[width] duration-(--motion-chart) ease-standard" style={{ width: `${start * 100}%` }}>
            <div className="absolute inset-y-0 right-0 w-px bg-outline-strong" />
            <span
              className={cn(
                "absolute bottom-1 text-caption whitespace-nowrap text-on-surface-muted tabular",
                start > 0.6 ? "right-2" : "left-full pl-2",
              )}
            >
              {startLabel}
            </span>
          </div>
        )}
        {pts.length === 0 && empty && (
          <p className="pointer-events-none absolute inset-0 flex items-center justify-center text-label text-on-surface-muted">{empty}</p>
        )}        <svg
          ref={svgRef}
          role="img"
          aria-label={`Active connections per app, newest on the right.${summary ? ` Now: ${summary}.` : ""}`}
          viewBox={`0 0 ${W} ${H}`}
          preserveAspectRatio="none"
          className="absolute inset-0 size-full overflow-hidden [&_path]:transition-[d] [&_path]:duration-(--motion-chart) [&_path]:ease-standard data-[sliding]:[&_path]:transition-none"
          data-chart-plot=""
        >
          <g
            data-slide=""
            className="transition-transform duration-(--motion-chart) ease-linear"
            data-scale={fmtX(scale)}
            style={{ transform: `translateX(${fmtX(tx)}px) scaleX(${fmtX(scale)})`, transformOrigin: "0 0" }}
          >
            {paths.map((p) => {
              const tone = seriesTone(model.series.find((s) => s.key === p.key)?.slot ?? 0);
              return (
                <g key={p.key}>
                  <path
                    data-series={p.key}
                    data-part="area"
                    d={p.area}
                    style={{ d: `path("${p.area}")` } as CSSProperties}
                    className={tone.fill}
                    fillOpacity={0.32}
                  />
                  <path
                    data-series={p.key}
                    data-part="line"
                    d={p.line}
                    style={{ d: `path("${p.line}")` } as CSSProperties}
                    className={cn(tone.stroke, "fill-none")}
                    strokeWidth={1.5}
                    strokeLinejoin="round"
                    vectorEffect="non-scaling-stroke"
                  />
                </g>
              );
            })}
          </g>
        </svg>
        {hover && (
          <>
            <div
              aria-hidden="true"
              className="pointer-events-none absolute inset-y-0 w-px bg-on-surface-muted"
              style={{ left: `${hover.f * 100}%` }}
            />
            {/* Placed by the layout effect and the pointer handler (tooltipPosition), before paint. */}
            {createPortal(
              <div
                ref={tipRef}
                role="tooltip"
                data-chart-tooltip=""
                className="pointer-events-none fixed top-0 left-0 z-50 max-w-72 min-w-40 rounded-md bg-surface-3 p-3 text-label shadow-l3"
              >
                <p className="pb-2 text-caption text-on-surface-muted tabular">
                  {clock(pts[hover.index].t, model.bucketMs < 60_000, model.windowMs)}
                </p>
                <ul className="flex flex-col gap-1">
                  {visible.map((s) => (
                    <li key={s.key} className="flex items-center gap-2">
                      <span aria-hidden="true" className={cn("size-2 shrink-0 rounded-full", seriesTone(s.slot).bg)} />
                      <AppIcon exe={exes.get(s.key) ?? null} size={16}>
                        <span className="text-caption text-on-surface-faint">{s.key === OTHER_KEY ? "" : (s.name.match(/[\p{L}\p{N}]/u)?.[0] ?? "").toUpperCase()}</span>
                      </AppIcon>
                      <span className="min-w-0 flex-1 truncate text-on-surface-muted">{s.name}</span>
                      <span className="text-on-surface tabular">{fmt1(pts[hover.index].values[s.key] ?? 0)}</span>
                    </li>
                  ))}
                </ul>
              </div>,
              document.body,
            )}
          </>
        )}
      </div>
      <div aria-hidden="true" className="flex h-(--chart-axis-h) shrink-0 items-end justify-between text-caption text-on-surface-faint tabular">
        <span>{clock(end - model.windowMs, false, model.windowMs)}</span>
        <span>Now</span>
      </div>
    </div>
  );
}
