import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

const TONES = {
  neutral: "text-on-surface-muted",
  mint: "text-primary",
} as const;

export type SectionIconTone = keyof typeof TONES;

/**
 * A plain icon beside a section title or a KPI label: no tile, no
 * background, no radius (the "no containers" rule). Tinted only when it
 * carries meaning (mint: something is on). 20 px by default, 16 px small.
 */
export function SectionIcon({
  children,
  size = 20,
  tone = "neutral",
  className,
}: {
  children: ReactNode;
  size?: 16 | 20;
  tone?: SectionIconTone;
  className?: string;
}) {
  return (
    <span
      aria-hidden="true"
      className={cn("inline-flex shrink-0 items-center", size === 20 ? "[&_svg]:size-5" : "[&_svg]:size-4", TONES[tone], className)}
    >
      {children}
    </span>
  );
}
