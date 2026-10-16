"use client";

import { AlertCircle } from "lucide-react";
import { Component, type ErrorInfo, type ReactNode } from "react";
import { IconTile, type IconTileTone } from "@/components/sieve/primitives/icon-tile";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { EmptyState } from "./empty-state";

export type CardState =
  | { kind: "ready" }
  | { kind: "loading" }
  | { kind: "empty"; line: string; body?: string; action?: ReactNode }
  | { kind: "error"; message: string };

/**
 * Card (level 1): surface-1, radius 16, 20 px padding, 5% rim. Header row:
 * 40 px icon tile, title, optional action. Every card carries its own error
 * boundary, so one broken card never blanks the screen.
 */
export function Card({
  title,
  icon,
  tone = "neutral",
  action,
  state = { kind: "ready" },
  dense = false,
  children,
  className,
}: {
  title: string;
  icon?: ReactNode;
  tone?: IconTileTone;
  action?: ReactNode;
  state?: CardState;
  dense?: boolean;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <section
      aria-label={title}
      aria-busy={state.kind === "loading" || undefined}
      className={cn(
        "flex h-full min-w-0 flex-col gap-4 rounded-lg bg-surface-1 text-on-surface shadow-l1",
        dense ? "p-4" : "p-5",
        className,
      )}
    >
      <header className="flex min-h-10 items-center gap-3">
        {icon && <IconTile tone={tone}>{icon}</IconTile>}
        <h2 className="min-w-0 flex-1 truncate text-title">{title}</h2>
        {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
      </header>
      <CardBoundary title={title}>
        <div className="flex min-h-0 flex-1 flex-col">
          <CardBody state={state}>{children}</CardBody>
        </div>
      </CardBoundary>
    </section>
  );
}

function CardBody({ state, children }: { state: CardState; children?: ReactNode }) {
  switch (state.kind) {
    case "loading":
      return (
        <div className="flex flex-1 flex-col gap-3" data-testid="card-skeleton">
          <Skeleton className="h-6 w-1/3" />
          <Skeleton className="min-h-16 flex-1" />
        </div>
      );
    case "empty":
      return <EmptyState line={state.line} body={state.body} action={state.action} className="flex-1 p-6" />;
    case "error":
      return <CardError message={state.message} />;
    case "ready":
      return <>{children}</>;
  }
}

export function CardError({ message }: { message: string }) {
  return (
    <div role="alert" className="flex items-start gap-3 rounded-md border-[1.5px] border-blocked p-4 text-body">
      <AlertCircle className="size-5 shrink-0 text-blocked" strokeWidth={1.75} aria-hidden="true" />
      <div className="min-w-0">
        <p className="text-body-strong text-on-surface">This card could not load</p>
        <p className="break-words text-on-surface-muted">{message}</p>
      </div>
    </div>
  );
}

class CardBoundary extends Component<{ title: string; children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`Card "${this.props.title}" crashed`, error, info.componentStack);
  }

  render() {
    return this.state.error ? <CardError message={this.state.error.message} /> : this.props.children;
  }
}
