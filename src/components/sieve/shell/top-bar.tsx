"use client";

import { Activity, AppWindow, List, Settings } from "lucide-react";
import { usePathname } from "next/navigation";
import { SegmentedNav } from "@/components/sieve/primitives/segmented";
import { activeRoute, ROUTES, type RouteDef } from "@/core/routes";
import { MasterSwitch } from "./master-switch";
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
    <header data-tauri-drag-region className="sticky top-0 z-40 h-14 shrink-0 bg-bg">
      <div
        data-tauri-drag-region
        className={
          // The page container (globals.css): the logo starts on the page title's line, the right
          // cluster ends on the header actions' line. Under 480 the side columns stop being equal:
          // the right cluster takes its own width and the nav centres in what is left.
          "page-container grid h-full grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-3 max-[640px]:gap-2 max-[480px]:grid-cols-[auto_minmax(0,1fr)_auto] max-[480px]:justify-items-center"
        }
      >
        <div data-tauri-drag-region className="flex min-w-0 items-center">
          <Wordmark />
        </div>
        <SegmentedNav items={items} active={active?.href} label="Main" />
        <div data-tauri-drag-region className="flex min-w-0 items-center justify-end gap-2 max-[640px]:gap-1">
          <MasterSwitch />
          <ThemeMenu />
          <WindowControls />
        </div>
      </div>
    </header>
  );
}
