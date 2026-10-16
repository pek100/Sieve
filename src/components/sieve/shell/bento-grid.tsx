import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * Bento grid: 12 columns, 16 px gutter. Card widths are named by intent and
 * map to spans per breakpoint:
 *   >= 1280 (three): third 4, two-thirds 8, half 6, full 12
 *   960 to 1279 (two): third 6, two-thirds 12, half 6, full 12
 *   < 960: everything 12 (one column)
 */
export type BentoSpan = "third" | "two-thirds" | "half" | "full";

const SPAN: Record<BentoSpan, string> = {
  third: "col-span-12 two:col-span-6 three:col-span-4",
  "two-thirds": "col-span-12 three:col-span-8",
  half: "col-span-12 two:col-span-6",
  full: "col-span-12",
};

export function BentoGrid({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("grid grid-cols-12 gap-4", className)}>{children}</div>;
}

export function BentoItem({
  span,
  children,
  className,
}: {
  span: BentoSpan;
  children: ReactNode;
  className?: string;
}) {
  return <div className={cn("min-w-0", SPAN[span], className)}>{children}</div>;
}
