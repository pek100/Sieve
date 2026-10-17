import { useId } from "react";
import MARK from "./sieve-mark.json";

/**
 * The Sieve mark: a ring with parallel diagonal lines clipped inside it (a
 * sieve's mesh). Own artwork. The geometry lives in sieve-mark.json, which
 * scripts/make-icon.mjs also draws the app icons, the tray icon and the
 * favicon from, so the logo and the icons cannot drift apart. Here it is
 * drawn in currentColor (the mint primary role, so it follows the theme).
 */
export function SieveMark({ size = 24, className }: { size?: number; className?: string }) {
  // useId may contain characters a url(#id) reference does not survive.
  const clip = `sieve-mark-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const { ring, lines } = MARK;
  return (
    <svg viewBox={`0 0 ${MARK.size} ${MARK.size}`} width={size} height={size} aria-hidden="true" className={className}>
      <defs>
        <clipPath id={clip}>
          <circle cx={ring.cx} cy={ring.cy} r={ring.r} />
        </clipPath>
      </defs>
      <g clipPath={`url(#${clip})`} stroke="currentColor" strokeWidth={lines.width} strokeLinecap="butt">
        {lines.segments.map(([x1, y1, x2, y2]) => (
          <line key={`${x1}-${y1}`} x1={x1} y1={y1} x2={x2} y2={y2} />
        ))}
      </g>
      <circle cx={ring.cx} cy={ring.cy} r={ring.r} fill="none" stroke="currentColor" strokeWidth={ring.width} />
    </svg>
  );
}

/** Sieve wordmark: the mark in mint and the name. */
export function Wordmark() {
  return (
    <span className="inline-flex items-center gap-2 text-title text-on-surface select-none">
      <SieveMark size={24} className="shrink-0 text-primary" />
      <span className="max-[480px]:sr-only">Sieve</span>
    </span>
  );
}
