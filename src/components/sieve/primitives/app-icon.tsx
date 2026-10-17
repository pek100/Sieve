"use client";

import type { ReactNode } from "react";
import { useAppIcon } from "@/hooks/use-app-icon";
import { cn } from "@/lib/utils";

const BOX = { 16: "size-4", 32: "size-8", 40: "size-10" } as const;

/**
 * An app's own icon, read from its exe (Rust `app_icon`), in a fixed box, so
 * nothing moves when it arrives. While it loads, and when there is none (a
 * path Windows hides, a service, the mock without ?icons=1), the box shows
 * `children`: the caller's monogram. The real icon is shown bare, with no
 * tile behind it (flat UI); 64 px art is used on HiDPI screens.
 */
export function AppIcon({ exe, size = 32, children, className }: { exe: string | null; size?: keyof typeof BOX; children: ReactNode; className?: string }) {
  const icon = useAppIcon(exe);
  const src = (b64: string) => `data:image/png;base64,${b64}`;
  return (
    <span aria-hidden="true" data-app-icon={icon ? "image" : "fallback"} className={cn("inline-flex shrink-0 items-center justify-center", BOX[size], className)}>
      {icon ? (
        // A data URL from the exe, in a static export: next/image has nothing to optimise here.
        // eslint-disable-next-line @next/next/no-img-element
        <img alt="" src={src(icon.x1)} srcSet={`${src(icon.x1)} 1x, ${src(icon.x2)} 2x`} draggable={false} className="size-full object-contain" />
      ) : (
        children
      )}
    </span>
  );
}
