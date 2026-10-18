"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { StateLayer } from "./state-layer";

/**
 * Segmented control: a pill group with one raised thumb that slides to the
 * selected item (D's top nav and Day/Month/Year control). Items share equal
 * widths so the thumb is a pure transform. Two flavours from one look:
 * `Segmented` (buttons, radiogroup) and `SegmentedNav` (links).
 */

export interface SegmentItem<V extends string> {
  value: V;
  label: string;
  icon?: ReactNode;
  disabled?: boolean;
  /** Shown as a tooltip title, e.g. why the item is disabled. */
  hint?: string;
}

// Items sit 4 px apart (gap-1) so a hover state never touches its neighbour; the thumb accounts for it.
const GAP_PX = 4;
const track = "relative inline-grid auto-cols-fr grid-flow-col gap-1 rounded-full bg-inset p-1 shadow-inset";
const itemBase =
  "relative z-10 inline-flex items-center justify-center gap-2 overflow-hidden rounded-full whitespace-nowrap transition-colors duration-(--motion-base) ease-standard [&_svg]:size-4";
/** md: navigation-sized; sm: a control that sits in a section header (the chart window). */
const SIZES = {
  md: "h-8 px-4 text-label max-[640px]:px-3",
  sm: "h-7 px-3 text-caption",
} as const;
export type SegmentedSize = keyof typeof SIZES;

function Thumb({ index, count }: { index: number; count: number }) {
  if (index < 0) return null;
  return (
    <span
      aria-hidden="true"
      className="absolute top-1 bottom-1 left-1 rounded-full bg-surface-3 shadow-l2 transition-transform duration-(--motion-base) ease-standard"
      style={{
        width: `calc((100% - 8px - ${GAP_PX * (count - 1)}px) / ${count})`,
        transform: `translateX(calc(${index * 100}% + ${index * GAP_PX}px))`,
      }}
    />
  );
}

export function Segmented<V extends string>({
  items,
  value,
  onChange,
  label,
  size = "md",
  className,
}: {
  items: readonly SegmentItem<V>[];
  value: V;
  onChange: (v: V) => void;
  /** Accessible name of the group. */
  label: string;
  size?: SegmentedSize;
  className?: string;
}) {
  const index = items.findIndex((i) => i.value === value);
  return (
    <div role="radiogroup" aria-label={label} className={cn(track, className)}>
      <Thumb index={index} count={items.length} />
      {items.map((item) => {
        const selected = item.value === value;
        return (
          <button
            key={item.value}
            type="button"
            role="radio"
            aria-checked={selected}
            disabled={item.disabled}
            title={item.hint}
            onClick={() => onChange(item.value)}
            className={cn(
              itemBase,
              SIZES[size],
              selected ? "text-on-surface" : "text-on-surface-muted hover:text-on-surface",
              "disabled:cursor-not-allowed disabled:opacity-(--disabled-content)",
            )}
          >
            {item.icon}
            {item.label}
            <StateLayer />
          </button>
        );
      })}
    </div>
  );
}

export function SegmentedNav({
  items,
  active,
  label,
  className,
}: {
  items: readonly { href: string; label: string; icon?: ReactNode }[];
  active: string | undefined;
  label: string;
  className?: string;
}) {
  const index = items.findIndex((i) => i.href === active);
  return (
    <nav aria-label={label} className={cn(track, className)}>
      <Thumb index={index} count={items.length} />
      {items.map((item) => {
        const selected = item.href === active;
        return (
          <Link
            key={item.href}
            href={item.href}
            aria-current={selected ? "page" : undefined}
            className={cn(itemBase, SIZES.md, selected ? "text-on-surface" : "text-on-surface-muted hover:text-on-surface")}
          >
            {item.icon}
            {/* Narrow windows keep the icon and move the label to screen readers. */}
            <span className={cn(item.icon && "max-[640px]:sr-only")}>{item.label}</span>
            <StateLayer />
          </Link>
        );
      })}
    </nav>
  );
}
