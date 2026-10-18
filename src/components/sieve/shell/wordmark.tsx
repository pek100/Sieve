import { useId } from "react";
import MARK from "./sieve-mark.json";

/**
 * The Sieve mark: a sieve seen from the side, a rim above a bowl cut by
 * diagonal slots fitted to the bowl. Own artwork. scripts/make-icon.mjs
 * derives the geometry into sieve-mark.json and draws the app icons, the
 * tray icon and the favicon from it, so the logo and the icons cannot drift
 * apart. The slots are a mask (truly transparent), and the mark is drawn in
 * currentColor (the mint primary role, so it follows the theme).
 */
export function SieveMark({ size = 24, className }: { size?: number; className?: string }) {
  // useId may contain characters a url(#id) reference does not survive.
  const mask = `sieve-mark-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const { rim, bowl, slots } = MARK;
  return (
    <svg viewBox={`0 0 ${MARK.size} ${MARK.size}`} width={size} height={size} aria-hidden="true" className={className}>
      <defs>
        {/* Mask luminance, not theme colour: white keeps the bowl, black cuts the top half and the slots. */}
        <mask id={mask} maskUnits="userSpaceOnUse" x={-8} y={-8} width={80} height={80}>
          <circle cx={bowl.cx} cy={bowl.cy} r={bowl.r} fill="white" />
          <path d={`M-8 -8H72V${bowl.cy}H-8Z`} fill="black" />
          <g stroke="black" strokeWidth={slots.width}>
            {slots.lines.map(([x1, y1, x2, y2]) => (
              <line key={`${x1}-${y1}`} x1={x1} y1={y1} x2={x2} y2={y2} />
            ))}
          </g>
        </mask>
      </defs>
      <rect x={rim.x} y={rim.y} width={rim.width} height={rim.height} rx={rim.height / 2} fill="currentColor" />
      <path d={`M0 0H${MARK.size}V${MARK.size}H0Z`} fill="currentColor" mask={`url(#${mask})`} />
    </svg>
  );
}

/** Sieve wordmark: the mark in mint and the name. */
export function Wordmark() {
  return (
    <span className="inline-flex items-center gap-2 text-title text-on-surface select-none">
      <SieveMark size={24} className="shrink-0 text-primary" />
      <span className="max-[480px]:sr-only">Sieve</span>
      {/* Next replaces this build-time fact in the static export as well as the client bundle. */}
      {process.env.NODE_ENV !== "production" && <span className="text-label text-on-surface-muted whitespace-nowrap">Dev build</span>}
    </span>
  );
}
