"use client";

import { Activity, AppWindow, List, Settings } from "lucide-react";
import { usePathname } from "next/navigation";
import { SegmentedNav } from "@/components/sieve/primitives/segmented";
import { activeRoute, ROUTES, type RouteDef } from "@/core/routes";
import { MasterSwitch } from "./master-switch";
import { StatusChip } from "./status-chip";
import { ThemeMenu } from "./theme-menu";
import { WindowControls } from "./window-controls";
import { Wordmark } from "./wordmark";

const ICONS: Record<RouteDef["icon"], typeof Activity> = {
  activity: Activity,
  "app-window": AppWindow,
  list: List,
  settings: Settings,
};

/**
 * Top bar, 56 px, no sidebar (D). Wordmark left, segmented nav centre,
 * status cluster right. The whole bar drags the frameless Tauri window;
 * interactive children keep their own pointer events.
 */
export function TopBar() {
  const pathname = usePathname();
  const active = activeRoute(pathname ?? "/");
  const items = ROUTES.map((r) => {
    const Icon = ICONS[r.icon];
    return { href: r.href, label: r.label, icon: <Icon strokeWidth={1.75} /> };
  });
  return (
    <header
      data-tauri-drag-region
      className="sticky top-0 z-40 grid h-14 grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-3 bg-bg px-6 max-[640px]:gap-2 max-[640px]:px-4"
    >
      <div data-tauri-drag-region className="flex min-w-0 items-center">
        <Wordmark />
      </div>
      <SegmentedNav items={items} active={active?.href} label="Main" />
      <div data-tauri-drag-region className="flex min-w-0 items-center justify-end gap-2 max-[640px]:gap-1">
        <StatusChip />
        <MasterSwitch />
        <ThemeMenu />
        <WindowControls />
      </div>
    </header>
  );
}
