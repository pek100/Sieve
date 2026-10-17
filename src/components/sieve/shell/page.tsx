import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * A screen, on the shared page container (`page-container`: the same box as
 * the top bar's, so the title starts on the logo's line and the actions end
 * on the right controls' line). A 64 px header row holds the title, an
 * optional `meta` beside it (a count, on the title's baseline) and an
 * optional right action; then the content, laid out on the 12 column
 * `LayoutGrid`.
 *
 * `notice`: a banner slot. At >= 1280 it sits inside the header row, between
 * the title and the action, so a banner costs no height; narrower, it wraps
 * to its own line under them. An empty slot takes no space.
 *
 * `fill`: at >= 1280 the page is a column exactly as tall as the window
 * under the top bar, so a `three:flex-1` child takes whatever height is left
 * after the header. No child has to know the other children's heights. A
 * child's own min-height still wins on a short window; the page then scrolls.
 */
export function Page({
  title,
  meta,
  action,
  notice,
  children,
  fill = false,
  className,
}: {
  title: string;
  meta?: ReactNode;
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
        "page-container pb-6",
        // A definite height (not just flex-1), so grid fr rows resolve against it.
        fill && "three:flex three:h-[calc(100dvh-var(--topbar-h))] three:flex-col",
        className,
      )}
    >
      <div className="grid shrink-0 grid-cols-[minmax(0,1fr)_auto] grid-rows-[4rem] items-center gap-x-4 three:grid-cols-[auto_minmax(0,1fr)_auto]">
        <div className="col-start-1 row-start-1 flex min-w-0 items-baseline gap-3">
          <h1 className="min-w-0 truncate text-title-lg text-on-surface">{title}</h1>
          {meta}
        </div>
        {notice !== undefined && (
          <div
            data-notice-slot=""
            className="col-span-2 row-start-2 min-w-0 pb-4 empty:hidden three:col-span-1 three:col-start-2 three:row-start-1 three:py-2"
          >
            {notice}
          </div>
        )}
        {action && (
          <div data-page-actions="" className="col-start-2 row-start-1 flex items-center justify-end gap-2 three:col-start-3">
            {action}
          </div>
        )}
      </div>
      {children}
    </main>
  );
}
