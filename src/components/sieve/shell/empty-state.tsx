import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * Empty state: the one serif italic line a screen may carry (P's calm),
 * a muted sentence, and at most one action.
 */
export function EmptyState({
  line,
  body,
  action,
  className,
}: {
  line: string;
  body?: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-3 p-10 text-center", className)}>
      <p className="font-serif text-display font-normal text-on-surface italic">{line}</p>
      {body && <p className="max-w-sm text-body text-on-surface-muted">{body}</p>}
      {action && <div className="pt-2">{action}</div>}
    </div>
  );
}
