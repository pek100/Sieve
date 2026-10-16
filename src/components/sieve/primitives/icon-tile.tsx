import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

const TONES = {
  neutral: "bg-surface-2 text-on-surface",
  mint: "bg-mint-container text-on-mint-container",
  peach: "bg-peach-container text-on-peach-container",
  lilac: "bg-lilac-container text-on-lilac-container",
} as const;

export type IconTileTone = keyof typeof TONES;

/**
 * Rounded-square tile that holds an icon: 32 px in rows, 40 px in card
 * headers and KPI tiles (radius 8). Tinted only when it carries meaning.
 */
export function IconTile({
  children,
  size = 40,
  tone = "neutral",
  className,
}: {
  children: ReactNode;
  size?: 32 | 40;
  tone?: IconTileTone;
  className?: string;
}) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        "inline-flex shrink-0 items-center justify-center rounded-sm",
        size === 40 ? "size-10 [&_svg]:size-5" : "size-8 [&_svg]:size-4",
        TONES[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}
