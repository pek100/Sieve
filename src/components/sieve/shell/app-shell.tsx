"use client";

import type { ReactNode } from "react";
import { UnlockDialog } from "@/components/sieve/lock/unlock-dialog";
import { WelcomeGate } from "@/components/sieve/welcome/welcome-gate";
import { TooltipProvider } from "@/components/ui/tooltip";
import type { Runtime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { useHealNotices } from "@/hooks/use-heal-notices";
import { useThemeSync } from "@/hooks/use-theme";
import { NoticeToaster } from "./notice-toaster";
import { TopBar } from "./top-bar";

function ThemeSync() {
  useThemeSync();
  return null;
}

function HealNotices() {
  useHealNotices();
  return null;
}

/** The window: runtime, theme, top bar, the routed screen in the scrolling content area, toasts. Mounted once in the root layout. */
export function AppShell({ children, runtime }: { children: ReactNode; runtime?: Runtime }) {
  return (
    <SieveProvider runtime={runtime}>
      <ThemeSync />
      <TooltipProvider delayDuration={300}>
        {/*
          The window never scrolls (overflow hidden, a backstop for anything wider than it): the
          top bar stays put and only the content area under it scrolls, vertically only, with the
          thin token scrollbar (globals.css, [data-scroll-root]). Both are positioned, so an absolutely
          positioned descendant (a visually hidden native select, for one) is clipped and scrolls with
          the content instead of stretching the document below the window.
        */}
        <div className="relative flex h-dvh flex-col overflow-hidden">
          <TopBar />
          <div data-scroll-root="" className="relative flex min-h-0 flex-1 flex-col overflow-x-hidden overflow-y-auto">
            <WelcomeGate>{children}</WelcomeGate>
          </div>
        </div>
        <UnlockDialog />
        <NoticeToaster />
        <HealNotices />
      </TooltipProvider>
    </SieveProvider>
  );
}
