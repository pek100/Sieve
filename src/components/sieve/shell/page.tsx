import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * A screen: 24 px outer padding (16 under 640), a 64 px header row with one
 * title and an optional right action, then the content (usually a BentoGrid).
 */
export function Page({
  title,
  action,
  children,
  className,
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <main className={cn("mx-auto w-full max-w-[1440px] px-6 pb-6 max-[640px]:px-4", className)}>
      <div className="flex h-16 items-center justify-between gap-4">
        <h1 className="truncate text-title-lg text-on-surface">{title}</h1>
        {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
      </div>
      {children}
    </main>
  );
}
