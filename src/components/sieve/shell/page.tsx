import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * A screen: 24 px outer padding (16 under 640), a 64 px header row with one
 * title and an optional right action, then the content (usually a BentoGrid).
 *
 * `notice`: a banner slot. At >= 1280 it sits inside the header row, between
 * the title and the action, so a banner costs no height; narrower, it wraps
 * to its own line under them. An empty slot takes no space.
 *
 * `fill`: at >= 1280 the page is a column exactly as tall as the window under
 * the top bar, so a `three:flex-1` child takes whatever height is left after
 * the header. No child has to know the other children's heights. A child's
 * own min-height still wins on a very short window; the page then scrolls.
 */
export function Page({
  title,
  action,
  notice,
  children,
  fill = false,
  className,
}: {
  title: string;
  action?: ReactNode;
  notice?: ReactNode;
  children: ReactNode;
  fill?: boolean;
  className?: string;
}) {
  return (
    <main
      data-fill={fill ? "" : undefined}
      className={cn(
        "mx-auto w-full max-w-[1440px] px-6 pb-6 max-[640px]:px-4",
        // A definite height (not just flex-1 under the shell's min-h-dvh), so grid fr rows resolve against it.
        fill && "three:flex three:h-[calc(100dvh-var(--topbar-h))] three:flex-col",
        className,
      )}
    >
      <div className="grid shrink-0 grid-cols-[minmax(0,1fr)_auto] grid-rows-[4rem] items-center gap-x-4 three:grid-cols-[auto_minmax(0,1fr)_auto]">
        <h1 className="col-start-1 row-start-1 min-w-0 truncate text-title-lg text-on-surface">{title}</h1>
        {notice !== undefined && (
          <div
            data-notice-slot=""
            className="col-span-2 row-start-2 min-w-0 pb-4 empty:hidden three:col-span-1 three:col-start-2 three:row-start-1 three:py-2"
          >
            {notice}
          </div>
        )}
        {action && <div className="col-start-2 row-start-1 flex items-center gap-2 three:col-start-3">{action}</div>}
      </div>
      {children}
    </main>
  );
}
