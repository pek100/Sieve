"use client";

import { forwardRef, type ComponentProps, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { StateLayer } from "./state-layer";

/**
 * Round 36 px icon button (D's top-right cluster). `label` is required and
 * becomes the aria-label. `badge` shows a small dot (D's bell). `toggled`
 * gives the selected look (accent at 16% with accent icon).
 */
export const IconButton = forwardRef<
  HTMLButtonElement,
  Omit<ComponentProps<"button">, "children" | "aria-label"> & {
    label: string;
    children: ReactNode;
    badge?: boolean;
    toggled?: boolean;
  }
>(function IconButton({ label, children, badge, toggled, className, ...props }, ref) {
  return (
    <button
      ref={ref}
      type="button"
      aria-label={label}
      aria-pressed={toggled}
      className={cn(
        "relative isolate inline-flex size-9 shrink-0 items-center justify-center overflow-hidden rounded-full text-on-surface-muted transition-colors duration-(--motion-fast) ease-standard hover:text-on-surface disabled:pointer-events-none disabled:opacity-(--disabled-content) [&_svg]:size-5",
        toggled && "bg-selected text-primary hover:text-primary",
        className,
      )}
      {...props}
    >
      {children}
      {badge && <span aria-hidden="true" className="absolute top-2 right-2 size-2 rounded-full bg-blocked ring-2 ring-bg" />}
      <StateLayer />
    </button>
  );
});
