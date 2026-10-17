"use client";

import { useLayoutEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { cn } from "@/lib/utils";

/** Gap between the cursor and the tooltip, and the least room kept to the viewport edge. */
const TIP_GAP = 12;
const TIP_EDGE = 8;

/**
 * Where a tooltip of size (w, h) goes for a pointer at (x, y) in a viewport
 * of (vw, vh): right of and below the cursor, flipped to the left or above
 * when it would leave the viewport, and never closer than TIP_EDGE to an edge.
 */
export function tooltipPosition(x: number, y: number, w: number, h: number, vw: number, vh: number): { left: number; top: number } {
  let left = x + TIP_GAP;
  if (left + w > vw - TIP_EDGE) left = x - TIP_GAP - w;
  let top = y + TIP_GAP;
  if (top + h > vh - TIP_EDGE) top = y - TIP_GAP - h;
  return {
    left: Math.max(TIP_EDGE, Math.min(left, vw - TIP_EDGE - w)),
    top: Math.max(TIP_EDGE, Math.min(top, vh - TIP_EDGE - h)),
  };
}

/** Put a fixed element at tooltipPosition for a pointer at (x, y). */
export function placeTooltip(el: HTMLElement, x: number, y: number) {
  const { left, top } = tooltipPosition(x, y, el.offsetWidth, el.offsetHeight, window.innerWidth, window.innerHeight);
  el.style.left = `${left}px`;
  el.style.top = `${top}px`;
}

/**
 * Every custom tooltip in Sieve: rendered into document.body with fixed
 * positioning, beside the pointer, flipped and clamped inside the viewport.
 * So no tooltip is clipped by a parent's overflow, and none can push the page
 * wider than the window (a heatmap tooltip at the right edge once gave the
 * whole window a horizontal scrollbar). The element it describes carries no
 * native `title` as well (one tooltip, not two).
 */
export function FloatingTooltip({
  x,
  y,
  children,
  className,
  ...data
}: {
  /** Pointer position in viewport coordinates. */
  x: number;
  y: number;
  children: ReactNode;
  className?: string;
} & { [k: `data-${string}`]: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    if (ref.current) placeTooltip(ref.current, x, y);
  });
  return createPortal(
    <div
      ref={ref}
      role="tooltip"
      {...data}
      className={cn("pointer-events-none fixed top-0 left-0 z-50 max-w-72 rounded-md bg-surface-3 px-3 py-2 text-label text-on-surface shadow-l3", className)}
    >
      {children}
    </div>,
    document.body,
  );
}
