import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * The page grid: 12 columns with one gutter token (`--gutter`, 24 px, 16 px
 * under 640) between columns and rows, inside the shared page container
 * (`page-container`, see globals.css). Every page lays its regions out on it,
 * so edges land on the same lines on every screen.
 *
 * A region spans `span` columns from 960 px up (the two-column breakpoint)
 * and the full 12 below. Spans that sit side by side add up to 12, so the
 * right edge of a row is the container's right line.
 */
export type GridSpan = 3 | 4 | 6 | 8 | 9 | 12;

// Literal class names so Tailwind sees them.
const SPAN: Record<GridSpan, string> = {
  3: "col-span-12 two:col-span-3",
  4: "col-span-12 two:col-span-4",
  6: "col-span-12 two:col-span-6",
  8: "col-span-12 two:col-span-8",
  9: "col-span-12 two:col-span-9",
  12: "col-span-12",
};

export function LayoutGrid({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("layout-grid", className)}>{children}</div>;
}

export function GridRegion({ span, children, className }: { span: GridSpan; children: ReactNode; className?: string }) {
  return <div className={cn("min-w-0", SPAN[span], className)}>{children}</div>;
}
