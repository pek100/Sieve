"use client";

import { ChevronDown, X } from "lucide-react";
import { useState } from "react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { StateLayer } from "@/components/sieve/primitives/state-layer";
import { AppIcon } from "@/components/sieve/primitives/app-icon";
import { iconExe, type Category } from "@/core/apps";
import type { AppEntry, AppSection } from "@/core/apps-actions";
import { cn } from "@/lib/utils";
import { AppToggle } from "./app-toggle";
import { Monogram } from "./monogram";

export const CATEGORY_LABEL: Record<Category, string> = { mine: "Mine", apps: "Apps", system: "System" };

const EMPTY_HINT: Record<Category, string> = {
  mine: "Apps you add show here, even when they are not running.",
  apps: "No other apps have run since Sieve started.",
  system: "No Windows processes seen yet.",
};

export interface RowActions {
  /** The user has not turned this app off. */
  isOn: (key: string) => boolean;
  setOn: (key: string, on: boolean) => void;
  open: (key: string) => void;
  unpin: (key: string) => void;
}

export function AppRow({ app, actions }: { app: AppEntry; actions: RowActions }) {
  const n = app.activeCount;
  const on = actions.isOn(app.key);
  return (
    <li data-testid="app-row" data-app={app.key} data-off={on ? undefined : ""} className="flex h-11 items-center gap-2">
      <button
        type="button"
        onClick={() => actions.open(app.key)}
        aria-label={`${app.name}, ${n} ${n === 1 ? "connection" : "connections"}. Open details`}
        className="relative flex h-11 min-w-0 flex-1 items-center gap-3 overflow-hidden rounded-sm pr-2 text-left"
      >
        <AppIcon exe={iconExe(app)}>
          <Monogram appKey={app.key} name={app.name} />
        </AppIcon>
        <span className="flex min-w-0 flex-1 flex-col">
          <span className={cn("truncate text-body-strong", on ? "text-on-surface" : "text-on-surface-muted")}>{app.name}</span>
          {/* Narrow windows move the count under the name to give the name room. */}
          <span aria-hidden="true" className="tabular hidden truncate text-caption text-on-surface-muted max-[640px]:block">
            {n} {n === 1 ? "connection" : "connections"}
          </span>
        </span>
        <span
          aria-hidden="true"
          className={cn("tabular shrink-0 text-label max-[640px]:hidden", n > 0 && on ? "text-on-surface" : "text-on-surface-faint")}
          title={`${n} active ${n === 1 ? "connection" : "connections"}`}
        >
          {n}
        </span>
        <StateLayer />
      </button>
      {/* The toggle is last, so every toggle ends on the header actions' line. */}
      {app.pinnedPaths.length > 0 && (
        <IconButton label={`Remove ${app.name} from my apps`} onClick={() => actions.unpin(app.key)}>
          <X strokeWidth={1.75} />
        </IconButton>
      )}
      <AppToggle appName={app.name} on={on} onChange={(v) => actions.setOn(app.key, v)} />
    </li>
  );
}

/** A group's collapsible label and its count; the group renders its rows under it. */
export function SectionHeader({
  id,
  label,
  count,
  open,
  onToggle,
}: {
  id: string;
  label: string;
  count: number;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <h3 id={`${id}-title`} className="text-label text-on-surface-muted">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={id}
        onClick={onToggle}
        className="relative flex h-9 w-full items-center gap-2 overflow-hidden rounded-sm text-left"
      >
        <ChevronDown
          className={cn("size-4 transition-transform duration-(--motion-base) ease-standard", !open && "-rotate-90")}
          strokeWidth={1.75}
          aria-hidden="true"
        />
        <span className="flex-1">{label}</span>
        <span className="tabular text-on-surface-faint">{count}</span>
        <StateLayer />
      </button>
    </h3>
  );
}

export function AppSectionView({
  section,
  actions,
  filtered,
}: {
  section: AppSection;
  actions: RowActions;
  /** True while a search narrows the list; empty sections are then hidden. */
  filtered: boolean;
}) {
  const [open, setOpen] = useState(true);
  const { category, apps } = section;
  if (filtered && apps.length === 0) return null;
  const id = `apps-section-${category}`;
  return (
    <section aria-labelledby={`${id}-title`} className="flex flex-col">
      <SectionHeader id={id} label={CATEGORY_LABEL[category]} count={apps.length} open={open} onToggle={() => setOpen((o) => !o)} />
      {open && (
        <div id={id}>
          {apps.length === 0 ? (
            <p className="flex h-11 items-center text-body text-on-surface-faint">{EMPTY_HINT[category]}</p>
          ) : (
            <ul className="flex flex-col gap-1">
              {apps.map((a) => (
                <AppRow key={a.key} app={a} actions={actions} />
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
