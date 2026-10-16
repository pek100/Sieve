"use client";

import { useLayoutEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { niceCeiling, stackSeries, type SeriesModel } from "@/core/series";
import { cn } from "@/lib/utils";
import { seriesTone } from "./series-tone";

/**
 * Stacked area chart of active connections per app.
 *
 * Hand-drawn SVG rather than Recharts: Recharts remounts its area paths on
 * every data change, and Home needs live ticks that keep the same path nodes
 * and never re-grow from zero. How it moves:
 * - x is absolute time from a fixed origin in units of the whole window
 *   (`baseMs` spans W). The view span (`model.windowMs`, which doubles as data
 *   accumulates) lives only in the plot group's transform: translateX slides
 *   the newest bucket to the right edge, scaleX stretches baseMs onto the view.
 *   A tick appends a vertex and slides; a view step changes the scale in the
 *   same transform transition (--motion-chart). Existing vertices keep their
 *   coordinates either way, and the parent keys this component by the window
 *   choice only, so no live tick remounts it.
 * - When the bucket times did not change (a series toggled, the open bucket
 *   of a long window updated) the path `d` morphs over --motion-chart instead.
 * - The first render draws the data as is. Reduced motion sets
 *   --motion-chart to 0, so both become instant.
 */

const W = 1000;
const H = 200;

const fmt1 = (x: number) => (Math.round(x * 10) / 10).toString();
/** x keeps three decimals: the group can scale it up to baseMs / view (about 100x for Session). */
const fmtX = (x: number) => (Math.round(x * 1000) / 1000).toString();

function clock(ms: number, seconds = false): string {
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: seconds ? "2-digit" : undefined });
}

/** The plot group's transform: newest bucket at the right edge, baseMs stretched onto the view span. */
export function plotTransform(lastT: number, origin: number, baseMs: number, viewMs: number): { tx: number; scale: number } {
  const scale = baseMs / viewMs;
  return { tx: W - (lastT - origin) * (W / baseMs) * scale, scale };
}

export function ActivityChart({
  model,
  baseMs,
  hidden,
  className,
}: {
  model: SeriesModel;
  /** The window choice's full span: the x unit, fixed for this mount. */
  baseMs: number;
  hidden: ReadonlySet<string>;
  className?: string;
}) {
  const { layers, max } = useMemo(() => stackSeries(model, hidden), [model, hidden]);
  const pts = model.points;
  const lastT = pts.length ? pts[pts.length - 1].t : 0;
  // Fixed once the first data arrives, for the life of this mount.
  const [fixedOrigin, setOrigin] = useState<number | null>(pts.length ? lastT : null);
  if (fixedOrigin === null && pts.length) setOrigin(lastT);
  const origin = fixedOrigin ?? lastT;
  const yMax = niceCeiling(max);
  const kx = W / baseMs;
  const xs = pts.map((p) => (p.t - origin) * kx);
  const { tx, scale } = plotTransform(lastT, origin, baseMs, model.windowMs);
  const y = (v: number) => H - (v / yMax) * H;

  const paths = layers.map((l) => {
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
  const hover = useMemo(() => {
    if (hoverF === null || pts.length === 0) return null;
    const t = lastT - (1 - hoverF) * model.windowMs;
    let best = 0;
    for (let j = 1; j < pts.length; j++) if (Math.abs(pts[j].t - t) < Math.abs(pts[best].t - t)) best = j;
    const f = 1 - (lastT - pts[best].t) / model.windowMs;
    return f < 0 ? null : { index: best, f };
  }, [hoverF, pts, lastT, model.windowMs]);

  const visible = model.series.filter((s) => !hidden.has(s.key));
  const now = pts.length ? pts[pts.length - 1].values : {};
  const summary = [...visible]
    .sort((a, b) => (now[b.key] ?? 0) - (now[a.key] ?? 0))
    .slice(0, 3)
    .map((s) => `${s.name} ${fmt1(now[s.key] ?? 0)}`)
    .join(", ");

  return (
    <div className={cn("flex min-h-0 flex-col gap-2", className)}>
      <div
        className="relative min-h-0 flex-1 overflow-hidden rounded-md bg-inset shadow-inset"
        onPointerMove={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          if (r.width > 0) setHoverF(Math.min(1, Math.max(0, (e.clientX - r.left) / r.width)));
        }}
        onPointerLeave={() => setHoverF(null)}
      >
        {/* Grid lines and y labels */}
        {[0.5, 1].map((g) => (
          <div key={g} aria-hidden="true" className="pointer-events-none absolute inset-x-0 border-t border-outline/60" style={{ top: `${(1 - g) * 100}%` }}>
            <span className="absolute top-1 left-2 text-caption text-on-surface-faint tabular">{fmt1(yMax * g)}</span>
          </div>
        ))}
        <svg
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
            <div
              role="tooltip"
              className={cn(
                "pointer-events-none absolute top-2 z-10 min-w-40 rounded-md bg-surface-3 p-3 text-label shadow-l3",
                hover.f > 0.55 ? "-translate-x-[calc(100%+12px)]" : "translate-x-3",
              )}
              style={{ left: `${hover.f * 100}%` }}
            >
              <p className="pb-2 text-caption text-on-surface-muted tabular">{clock(pts[hover.index].t, true)}</p>
              <ul className="flex flex-col gap-1">
                {visible.map((s) => (
                  <li key={s.key} className="flex items-center gap-2">
                    <span aria-hidden="true" className={cn("size-2 shrink-0 rounded-full", seriesTone(s.slot).bg)} />
                    <span className="min-w-0 flex-1 truncate text-on-surface-muted">{s.name}</span>
                    <span className="text-on-surface tabular">{fmt1(pts[hover.index].values[s.key] ?? 0)}</span>
                  </li>
                ))}
              </ul>
            </div>
          </>
        )}
      </div>
      <div aria-hidden="true" className="flex justify-between text-caption text-on-surface-faint tabular">
        <span>{clock(lastT - model.windowMs)}</span>
        <span>Now</span>
      </div>
    </div>
  );
}
