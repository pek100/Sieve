"use client";

import { AlertCircle } from "lucide-react";
import { Component, type ErrorInfo, type ReactNode } from "react";
import { SectionIcon, type SectionIconTone } from "@/components/sieve/primitives/section-icon";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { EmptyState } from "./empty-state";

export type CardState =
  | { kind: "ready" }
  | { kind: "loading" }
  | { kind: "empty"; line: string; body?: string; action?: ReactNode }
  | { kind: "error"; message: string };

/**
 * A titled block of content, laid out flat on the page: no surface, border,
 * elevation, radius or inner padding (the user's "no containers" rule).
 * Header row: an optional plain icon, the title, an optional action. Every
 * block carries its own error boundary, so one broken block never blanks the
 * screen. It is as tall as its content; a caller that must fill a grid cell
 * passes `className="h-full"` (Home does), never the block itself, so a
 * block never stretches to a parent that also holds its siblings.
 */
export function Card({
  title,
  icon,
  tone = "neutral",
  action,
  state = { kind: "ready" },
  children,
  className,
}: {
  title: string;
  icon?: ReactNode;
  tone?: SectionIconTone;
  action?: ReactNode;
  state?: CardState;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <section
      aria-label={title}
      aria-busy={state.kind === "loading" || undefined}
      className={cn("flex min-w-0 flex-col gap-3 text-on-surface", className)}
    >
      <header className="flex min-h-9 flex-wrap items-center gap-2">
        {icon && <SectionIcon tone={tone}>{icon}</SectionIcon>}
        {/* flex-auto (basis = text width) so a header too narrow for title and action wraps the action to a second line */}
        <h2 className="min-w-0 flex-auto truncate text-title">{title}</h2>
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

/** A block's body by state: skeleton, empty state, error, or the content. */
export function CardBody({ state, children }: { state: CardState; children?: ReactNode }) {
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
    <div role="alert" className="flex items-start gap-3 py-2 text-body">
      <AlertCircle className="size-5 shrink-0 text-blocked" strokeWidth={1.75} aria-hidden="true" />
      <div className="min-w-0">
        <p className="text-body-strong text-on-surface">This could not load</p>
        <p className="break-words text-on-surface-muted">{message}</p>
      </div>
    </div>
  );
}

/** The per-block error boundary, for blocks that are not a single Card (the Home KPI tiles, the Apps list). */
export class CardBoundary extends Component<{ title: string; children: ReactNode }, { error: Error | null }> {
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
